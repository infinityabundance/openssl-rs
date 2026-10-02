//! `crypto/ess/ess_asn1.c` — the ESS item groups and their generated lifecycles. Phase 12.7.
//!
//! The file is 58 lines and transcribes whole: five `ASN1_SEQUENCE` templates and their
//! `IMPLEMENT_ASN1_FUNCTIONS`/`IMPLEMENT_ASN1_DUP_FUNCTION` expansions. `ESS_SIGNING_CERT` and
//! `ESS_SIGNING_CERT_V2` close with the non-`static_` end macro and so publish their `_it`
//! accessors; `ESS_ISSUER_SERIAL`, `ESS_CERT_ID` and `ESS_CERT_ID_V2` use `static_ASN1_SEQUENCE_END`
//! and their item descriptors stay file-local, with only `new`/`free`/`dup`/`d2i`/`i2d` exported.
//! That split is exactly the authority's `nm -D` on the object and is mirrored here.
//!
//! The layouts are `crypto/ess.h`'s (`struct ESS_issuer_serial`, `struct ESS_cert_id`,
//! `struct ESS_signing_cert`, `struct ESS_cert_id_v2_st`, `struct ESS_signing_cert_v2_st`).
//!
//! SPDX-License-Identifier: Apache-2.0
#![allow(dead_code, non_snake_case)]
#![allow(non_upper_case_globals)]

use core::ffi::{c_int, c_long, c_uchar, c_void};
use core::ptr;

use crate::asn1::a_dup::ASN1_item_dup;
use crate::asn1::d2i::ASN1_item_d2i;
use crate::asn1::fre::ASN1_item_free;
use crate::asn1::i2d::ASN1_item_i2d;
use crate::asn1::items::{ASN1_INTEGER_it, ASN1_OCTET_STRING_it};
use crate::asn1::layout::*;
use crate::asn1::new::ASN1_item_new;
use crate::asn1::x_algor::{X509Algor, X509_ALGOR_it};
use crate::runtime::stack::OpenSslStack;
use crate::x509::v3_cpols::POLICYINFO_it;
use crate::x509::v3_genn::GENERAL_NAME_it;

/// The authority translation unit this module is a projection of.
pub(crate) const FILE: &core::ffi::CStr = c"crypto/ess/ess_asn1.c";

/// `struct ESS_issuer_serial` — `crypto/ess.h:21-24`.
#[repr(C)]
pub struct EssIssuerSerial {
    /// `STACK_OF(GENERAL_NAME) *issuer`.
    pub issuer: *mut OpenSslStack,
    /// `ASN1_INTEGER *serial`.
    pub serial: *mut Asn1String,
}

const _: () = {
    assert!(core::mem::size_of::<EssIssuerSerial>() == 16);
    assert!(core::mem::offset_of!(EssIssuerSerial, issuer) == 0);
    assert!(core::mem::offset_of!(EssIssuerSerial, serial) == 8);
};

/// `struct ESS_cert_id` — `crypto/ess.h:33-36`.
#[repr(C)]
pub struct EssCertId {
    /// `ASN1_OCTET_STRING *hash`.
    pub hash: *mut Asn1String,
    /// `ESS_ISSUER_SERIAL *issuer_serial`.
    pub issuer_serial: *mut EssIssuerSerial,
}

const _: () = {
    assert!(core::mem::size_of::<EssCertId>() == 16);
    assert!(core::mem::offset_of!(EssCertId, hash) == 0);
    assert!(core::mem::offset_of!(EssCertId, issuer_serial) == 8);
};

/// `struct ESS_cert_id_v2_st` — `crypto/ess.h:58-62`.
#[repr(C)]
pub struct EssCertIdV2 {
    /// `X509_ALGOR *hash_alg` — the `DEFAULT id-sha256` field, so optional.
    pub hash_alg: *mut X509Algor,
    /// `ASN1_OCTET_STRING *hash`.
    pub hash: *mut Asn1String,
    /// `ESS_ISSUER_SERIAL *issuer_serial`.
    pub issuer_serial: *mut EssIssuerSerial,
}

const _: () = {
    assert!(core::mem::size_of::<EssCertIdV2>() == 24);
    assert!(core::mem::offset_of!(EssCertIdV2, hash_alg) == 0);
    assert!(core::mem::offset_of!(EssCertIdV2, hash) == 8);
    assert!(core::mem::offset_of!(EssCertIdV2, issuer_serial) == 16);
};

/// `struct ESS_signing_cert` — `crypto/ess.h:45-48`.
#[repr(C)]
pub struct EssSigningCert {
    /// `STACK_OF(ESS_CERT_ID) *cert_ids`.
    pub cert_ids: *mut OpenSslStack,
    /// `STACK_OF(POLICYINFO) *policy_info`.
    pub policy_info: *mut OpenSslStack,
}

const _: () = {
    assert!(core::mem::size_of::<EssSigningCert>() == 16);
    assert!(core::mem::offset_of!(EssSigningCert, cert_ids) == 0);
    assert!(core::mem::offset_of!(EssSigningCert, policy_info) == 8);
};

/// `struct ESS_signing_cert_v2_st` — `crypto/ess.h:71-74`.
#[repr(C)]
pub struct EssSigningCertV2 {
    /// `STACK_OF(ESS_CERT_ID_V2) *cert_ids`.
    pub cert_ids: *mut OpenSslStack,
    /// `STACK_OF(POLICYINFO) *policy_info`.
    pub policy_info: *mut OpenSslStack,
}

const _: () = {
    assert!(core::mem::size_of::<EssSigningCertV2>() == 16);
    assert!(core::mem::offset_of!(EssSigningCertV2, cert_ids) == 0);
    assert!(core::mem::offset_of!(EssSigningCertV2, policy_info) == 8);
};

/// `ASN1_ITEM_ref(type)` in the template's `item` slot: the accessor cast to `void *`.
const fn item_ref(f: extern "C" fn() -> *const Asn1Item) -> *mut c_void {
    f as *mut c_void
}

// ---------------------------------------------------------------------------------------------
// The item descriptors. The three `static_` groups' accessors stay file-local; the two
// `ASN1_SEQUENCE_END` groups' are the exported `_it` functions declared further down.
// ---------------------------------------------------------------------------------------------

static ESS_ISSUER_SERIAL_TT: [Asn1Template; 2] = [
    Asn1Template {
        flags: ASN1_TFLG_SEQUENCE_OF,
        tag: 0,
        offset: 0,
        field_name: c"issuer".as_ptr(),
        item: GENERAL_NAME_it as *mut c_void,
    },
    Asn1Template {
        flags: 0,
        tag: 0,
        offset: 8,
        field_name: c"serial".as_ptr(),
        item: ASN1_INTEGER_it as *mut c_void,
    },
];
/// The `ESS_ISSUER_SERIAL_it` accessor, file-local because `ess_asn1.c:22` is `static_`.
pub(crate) extern "C" fn ess_issuer_serial_it() -> *const Asn1Item {
    &ESS_ISSUER_SERIAL_ITEM
}
static ESS_ISSUER_SERIAL_ITEM: Asn1Item = Asn1Item {
    itype: ASN1_ITYPE_SEQUENCE,
    utype: V_ASN1_SEQUENCE as c_long,
    templates: ESS_ISSUER_SERIAL_TT.as_ptr(),
    tcount: 2,
    funcs: ptr::null(),
    size: core::mem::size_of::<EssIssuerSerial>() as c_long,
    sname: c"ESS_ISSUER_SERIAL".as_ptr(),
};

static ESS_CERT_ID_TT: [Asn1Template; 2] = [
    Asn1Template {
        flags: 0,
        tag: 0,
        offset: 0,
        field_name: c"hash".as_ptr(),
        item: ASN1_OCTET_STRING_it as *mut c_void,
    },
    Asn1Template {
        flags: ASN1_TFLG_OPTIONAL,
        tag: 0,
        offset: 8,
        field_name: c"issuer_serial".as_ptr(),
        item: item_ref(ess_issuer_serial_it),
    },
];
/// The `ESS_CERT_ID_it` accessor, file-local because `ess_asn1.c:30` is `static_`.
pub(crate) extern "C" fn ess_cert_id_it() -> *const Asn1Item {
    &ESS_CERT_ID_ITEM
}
static ESS_CERT_ID_ITEM: Asn1Item = Asn1Item {
    itype: ASN1_ITYPE_SEQUENCE,
    utype: V_ASN1_SEQUENCE as c_long,
    templates: ESS_CERT_ID_TT.as_ptr(),
    tcount: 2,
    funcs: ptr::null(),
    size: core::mem::size_of::<EssCertId>() as c_long,
    sname: c"ESS_CERT_ID".as_ptr(),
};

static ESS_CERT_ID_V2_TT: [Asn1Template; 3] = [
    Asn1Template {
        flags: ASN1_TFLG_OPTIONAL,
        tag: 0,
        offset: 0,
        field_name: c"hash_alg".as_ptr(),
        item: X509_ALGOR_it as *mut c_void,
    },
    Asn1Template {
        flags: 0,
        tag: 0,
        offset: 8,
        field_name: c"hash".as_ptr(),
        item: ASN1_OCTET_STRING_it as *mut c_void,
    },
    Asn1Template {
        flags: ASN1_TFLG_OPTIONAL,
        tag: 0,
        offset: 16,
        field_name: c"issuer_serial".as_ptr(),
        item: item_ref(ess_issuer_serial_it),
    },
];
/// The `ESS_CERT_ID_V2_it` accessor, file-local because `ess_asn1.c:47` is `static_`.
pub(crate) extern "C" fn ess_cert_id_v2_it() -> *const Asn1Item {
    &ESS_CERT_ID_V2_ITEM
}
static ESS_CERT_ID_V2_ITEM: Asn1Item = Asn1Item {
    itype: ASN1_ITYPE_SEQUENCE,
    utype: V_ASN1_SEQUENCE as c_long,
    templates: ESS_CERT_ID_V2_TT.as_ptr(),
    tcount: 3,
    funcs: ptr::null(),
    size: core::mem::size_of::<EssCertIdV2>() as c_long,
    sname: c"ESS_CERT_ID_V2".as_ptr(),
};

static ESS_SIGNING_CERT_TT: [Asn1Template; 2] = [
    Asn1Template {
        flags: ASN1_TFLG_SEQUENCE_OF,
        tag: 0,
        offset: 0,
        field_name: c"cert_ids".as_ptr(),
        item: item_ref(ess_cert_id_it),
    },
    Asn1Template {
        flags: ASN1_TFLG_SEQUENCE_OF | ASN1_TFLG_OPTIONAL,
        tag: 0,
        offset: 8,
        field_name: c"policy_info".as_ptr(),
        item: POLICYINFO_it as *mut c_void,
    },
];
static ESS_SIGNING_CERT_ITEM: Asn1Item = Asn1Item {
    itype: ASN1_ITYPE_SEQUENCE,
    utype: V_ASN1_SEQUENCE as c_long,
    templates: ESS_SIGNING_CERT_TT.as_ptr(),
    tcount: 2,
    funcs: ptr::null(),
    size: core::mem::size_of::<EssSigningCert>() as c_long,
    sname: c"ESS_SIGNING_CERT".as_ptr(),
};

static ESS_SIGNING_CERT_V2_TT: [Asn1Template; 2] = [
    Asn1Template {
        flags: ASN1_TFLG_SEQUENCE_OF,
        tag: 0,
        offset: 0,
        field_name: c"cert_ids".as_ptr(),
        item: item_ref(ess_cert_id_v2_it),
    },
    Asn1Template {
        flags: ASN1_TFLG_SEQUENCE_OF | ASN1_TFLG_OPTIONAL,
        tag: 0,
        offset: 8,
        field_name: c"policy_info".as_ptr(),
        item: POLICYINFO_it as *mut c_void,
    },
];
static ESS_SIGNING_CERT_V2_ITEM: Asn1Item = Asn1Item {
    itype: ASN1_ITYPE_SEQUENCE,
    utype: V_ASN1_SEQUENCE as c_long,
    templates: ESS_SIGNING_CERT_V2_TT.as_ptr(),
    tcount: 2,
    funcs: ptr::null(),
    size: core::mem::size_of::<EssSigningCertV2>() as c_long,
    sname: c"ESS_SIGNING_CERT_V2".as_ptr(),
};

// ---------------------------------------------------------------------------------------------
// The exports — `IMPLEMENT_ASN1_FUNCTIONS` / `IMPLEMENT_ASN1_DUP_FUNCTION` at the cited lines.
// ---------------------------------------------------------------------------------------------

/// `ESS_ISSUER_SERIAL *ESS_ISSUER_SERIAL_new(void)` — `ess_asn1.c:24`.
#[no_mangle]
pub extern "C" fn ESS_ISSUER_SERIAL_new() -> *mut EssIssuerSerial {
    // SAFETY: the accessor answers a static item the crate owns.
    unsafe { ASN1_item_new(ess_issuer_serial_it()) }.cast::<EssIssuerSerial>()
}

/// `void ESS_ISSUER_SERIAL_free(ESS_ISSUER_SERIAL *a)` — the same macro's free half.
///
/// # Safety
/// `a` is NULL or a value this item layer built.
#[no_mangle]
pub unsafe extern "C" fn ESS_ISSUER_SERIAL_free(a: *mut EssIssuerSerial) {
    // SAFETY: `a` is NULL or a live item value per the contract.
    unsafe { ASN1_item_free(a.cast(), ess_issuer_serial_it()) };
}

/// `ESS_ISSUER_SERIAL *ESS_ISSUER_SERIAL_dup(const ESS_ISSUER_SERIAL *a)` — `ess_asn1.c:25`.
///
/// # Safety
/// `a` is NULL or a live `ESS_ISSUER_SERIAL`.
#[no_mangle]
pub unsafe extern "C" fn ESS_ISSUER_SERIAL_dup(a: *const EssIssuerSerial) -> *mut EssIssuerSerial {
    // SAFETY: the caller's contract; the item layer duplicates the value.
    unsafe { ASN1_item_dup(ess_issuer_serial_it(), a.cast()) }.cast::<EssIssuerSerial>()
}

/// `ESS_ISSUER_SERIAL *d2i_ESS_ISSUER_SERIAL(ESS_ISSUER_SERIAL **a, const unsigned char **in,`
/// `long len)` — `ess_asn1.c:24`.
///
/// # Safety
/// `a` is NULL or a writable slot; `in_` points at a readable cursor; `len` describes the input.
#[no_mangle]
pub unsafe extern "C" fn d2i_ESS_ISSUER_SERIAL(
    a: *mut *mut EssIssuerSerial,
    in_: *mut *const c_uchar,
    len: c_long,
) -> *mut EssIssuerSerial {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer here.
    unsafe { ASN1_item_d2i(a.cast(), in_, len, ess_issuer_serial_it()).cast::<EssIssuerSerial>() }
}

/// `int i2d_ESS_ISSUER_SERIAL(const ESS_ISSUER_SERIAL *a, unsigned char **out)`.
///
/// # Safety
/// `a` is NULL or a live value; `out` is NULL or a writable cursor.
#[no_mangle]
pub unsafe extern "C" fn i2d_ESS_ISSUER_SERIAL(
    a: *const EssIssuerSerial,
    out: *mut *mut c_uchar,
) -> c_int {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer here.
    unsafe { ASN1_item_i2d(a.cast(), out, ess_issuer_serial_it()) }
}

/// `ESS_CERT_ID *ESS_CERT_ID_new(void)` — `ess_asn1.c:32`.
#[no_mangle]
pub extern "C" fn ESS_CERT_ID_new() -> *mut EssCertId {
    // SAFETY: the accessor answers a static item the crate owns.
    unsafe { ASN1_item_new(ess_cert_id_it()) }.cast::<EssCertId>()
}

/// `void ESS_CERT_ID_free(ESS_CERT_ID *a)` — the same macro's free half.
///
/// # Safety
/// `a` is NULL or a value this item layer built.
#[no_mangle]
pub unsafe extern "C" fn ESS_CERT_ID_free(a: *mut EssCertId) {
    // SAFETY: `a` is NULL or a live item value per the contract.
    unsafe { ASN1_item_free(a.cast(), ess_cert_id_it()) };
}

/// `ESS_CERT_ID *ESS_CERT_ID_dup(const ESS_CERT_ID *a)` — `ess_asn1.c:33`.
///
/// # Safety
/// `a` is NULL or a live `ESS_CERT_ID`.
#[no_mangle]
pub unsafe extern "C" fn ESS_CERT_ID_dup(a: *const EssCertId) -> *mut EssCertId {
    // SAFETY: the caller's contract; the item layer duplicates the value.
    unsafe { ASN1_item_dup(ess_cert_id_it(), a.cast()) }.cast::<EssCertId>()
}

/// `ESS_CERT_ID *d2i_ESS_CERT_ID(ESS_CERT_ID **a, const unsigned char **in, long len)`.
///
/// # Safety
/// `a` is NULL or a writable slot; `in_` points at a readable cursor; `len` describes the input.
#[no_mangle]
pub unsafe extern "C" fn d2i_ESS_CERT_ID(
    a: *mut *mut EssCertId,
    in_: *mut *const c_uchar,
    len: c_long,
) -> *mut EssCertId {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer here.
    unsafe { ASN1_item_d2i(a.cast(), in_, len, ess_cert_id_it()).cast::<EssCertId>() }
}

/// `int i2d_ESS_CERT_ID(const ESS_CERT_ID *a, unsigned char **out)`.
///
/// # Safety
/// `a` is NULL or a live value; `out` is NULL or a writable cursor.
#[no_mangle]
pub unsafe extern "C" fn i2d_ESS_CERT_ID(a: *const EssCertId, out: *mut *mut c_uchar) -> c_int {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer here.
    unsafe { ASN1_item_i2d(a.cast(), out, ess_cert_id_it()) }
}

/// `const ASN1_ITEM *ESS_SIGNING_CERT_it(void)` — `ess_asn1.c:38`, the non-`static_` end macro.
#[no_mangle]
pub extern "C" fn ESS_SIGNING_CERT_it() -> *const Asn1Item {
    &ESS_SIGNING_CERT_ITEM
}

/// `ESS_SIGNING_CERT *ESS_SIGNING_CERT_new(void)` — `ess_asn1.c:40`.
#[no_mangle]
pub extern "C" fn ESS_SIGNING_CERT_new() -> *mut EssSigningCert {
    // SAFETY: the accessor answers a static item the crate owns.
    unsafe { ASN1_item_new(ESS_SIGNING_CERT_it()) }.cast::<EssSigningCert>()
}

/// `void ESS_SIGNING_CERT_free(ESS_SIGNING_CERT *a)` — the same macro's free half.
///
/// # Safety
/// `a` is NULL or a value this item layer built.
#[no_mangle]
pub unsafe extern "C" fn ESS_SIGNING_CERT_free(a: *mut EssSigningCert) {
    // SAFETY: `a` is NULL or a live item value per the contract.
    unsafe { ASN1_item_free(a.cast(), ESS_SIGNING_CERT_it()) };
}

/// `ESS_SIGNING_CERT *ESS_SIGNING_CERT_dup(const ESS_SIGNING_CERT *a)` — `ess_asn1.c:41`.
///
/// # Safety
/// `a` is NULL or a live `ESS_SIGNING_CERT`.
#[no_mangle]
pub unsafe extern "C" fn ESS_SIGNING_CERT_dup(a: *const EssSigningCert) -> *mut EssSigningCert {
    // SAFETY: the caller's contract; the item layer duplicates the value.
    unsafe { ASN1_item_dup(ESS_SIGNING_CERT_it(), a.cast()) }.cast::<EssSigningCert>()
}

/// `ESS_SIGNING_CERT *d2i_ESS_SIGNING_CERT(ESS_SIGNING_CERT **a, const unsigned char **in,`
/// `long len)` — `ess_asn1.c:40`.
///
/// # Safety
/// `a` is NULL or a writable slot; `in_` points at a readable cursor; `len` describes the input.
#[no_mangle]
pub unsafe extern "C" fn d2i_ESS_SIGNING_CERT(
    a: *mut *mut EssSigningCert,
    in_: *mut *const c_uchar,
    len: c_long,
) -> *mut EssSigningCert {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer here.
    unsafe { ASN1_item_d2i(a.cast(), in_, len, ESS_SIGNING_CERT_it()).cast::<EssSigningCert>() }
}

/// `int i2d_ESS_SIGNING_CERT(const ESS_SIGNING_CERT *a, unsigned char **out)`.
///
/// # Safety
/// `a` is NULL or a live value; `out` is NULL or a writable cursor.
#[no_mangle]
pub unsafe extern "C" fn i2d_ESS_SIGNING_CERT(
    a: *const EssSigningCert,
    out: *mut *mut c_uchar,
) -> c_int {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer here.
    unsafe { ASN1_item_i2d(a.cast(), out, ESS_SIGNING_CERT_it()) }
}

/// `ESS_CERT_ID_V2 *ESS_CERT_ID_V2_new(void)` — `ess_asn1.c:49`.
#[no_mangle]
pub extern "C" fn ESS_CERT_ID_V2_new() -> *mut EssCertIdV2 {
    // SAFETY: the accessor answers a static item the crate owns.
    unsafe { ASN1_item_new(ess_cert_id_v2_it()) }.cast::<EssCertIdV2>()
}

/// `void ESS_CERT_ID_V2_free(ESS_CERT_ID_V2 *a)` — the same macro's free half.
///
/// # Safety
/// `a` is NULL or a value this item layer built.
#[no_mangle]
pub unsafe extern "C" fn ESS_CERT_ID_V2_free(a: *mut EssCertIdV2) {
    // SAFETY: `a` is NULL or a live item value per the contract.
    unsafe { ASN1_item_free(a.cast(), ess_cert_id_v2_it()) };
}

/// `ESS_CERT_ID_V2 *ESS_CERT_ID_V2_dup(const ESS_CERT_ID_V2 *a)` — `ess_asn1.c:50`.
///
/// # Safety
/// `a` is NULL or a live `ESS_CERT_ID_V2`.
#[no_mangle]
pub unsafe extern "C" fn ESS_CERT_ID_V2_dup(a: *const EssCertIdV2) -> *mut EssCertIdV2 {
    // SAFETY: the caller's contract; the item layer duplicates the value.
    unsafe { ASN1_item_dup(ess_cert_id_v2_it(), a.cast()) }.cast::<EssCertIdV2>()
}

/// `ESS_CERT_ID_V2 *d2i_ESS_CERT_ID_V2(ESS_CERT_ID_V2 **a, const unsigned char **in, long len)`.
///
/// # Safety
/// `a` is NULL or a writable slot; `in_` points at a readable cursor; `len` describes the input.
#[no_mangle]
pub unsafe extern "C" fn d2i_ESS_CERT_ID_V2(
    a: *mut *mut EssCertIdV2,
    in_: *mut *const c_uchar,
    len: c_long,
) -> *mut EssCertIdV2 {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer here.
    unsafe { ASN1_item_d2i(a.cast(), in_, len, ess_cert_id_v2_it()).cast::<EssCertIdV2>() }
}

/// `int i2d_ESS_CERT_ID_V2(const ESS_CERT_ID_V2 *a, unsigned char **out)`.
///
/// # Safety
/// `a` is NULL or a live value; `out` is NULL or a writable cursor.
#[no_mangle]
pub unsafe extern "C" fn i2d_ESS_CERT_ID_V2(
    a: *const EssCertIdV2,
    out: *mut *mut c_uchar,
) -> c_int {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer here.
    unsafe { ASN1_item_i2d(a.cast(), out, ess_cert_id_v2_it()) }
}

/// `const ASN1_ITEM *ESS_SIGNING_CERT_V2_it(void)` — `ess_asn1.c:55`.
#[no_mangle]
pub extern "C" fn ESS_SIGNING_CERT_V2_it() -> *const Asn1Item {
    &ESS_SIGNING_CERT_V2_ITEM
}

/// `ESS_SIGNING_CERT_V2 *ESS_SIGNING_CERT_V2_new(void)` — `ess_asn1.c:57`.
#[no_mangle]
pub extern "C" fn ESS_SIGNING_CERT_V2_new() -> *mut EssSigningCertV2 {
    // SAFETY: the accessor answers a static item the crate owns.
    unsafe { ASN1_item_new(ESS_SIGNING_CERT_V2_it()) }.cast::<EssSigningCertV2>()
}

/// `void ESS_SIGNING_CERT_V2_free(ESS_SIGNING_CERT_V2 *a)` — the same macro's free half.
///
/// # Safety
/// `a` is NULL or a value this item layer built.
#[no_mangle]
pub unsafe extern "C" fn ESS_SIGNING_CERT_V2_free(a: *mut EssSigningCertV2) {
    // SAFETY: `a` is NULL or a live item value per the contract.
    unsafe { ASN1_item_free(a.cast(), ESS_SIGNING_CERT_V2_it()) };
}

/// `ESS_SIGNING_CERT_V2 *ESS_SIGNING_CERT_V2_dup(const ESS_SIGNING_CERT_V2 *a)` — `ess_asn1.c:58`.
///
/// # Safety
/// `a` is NULL or a live `ESS_SIGNING_CERT_V2`.
#[no_mangle]
pub unsafe extern "C" fn ESS_SIGNING_CERT_V2_dup(
    a: *const EssSigningCertV2,
) -> *mut EssSigningCertV2 {
    // SAFETY: the caller's contract; the item layer duplicates the value.
    unsafe { ASN1_item_dup(ESS_SIGNING_CERT_V2_it(), a.cast()) }.cast::<EssSigningCertV2>()
}

/// `ESS_SIGNING_CERT_V2 *d2i_ESS_SIGNING_CERT_V2(ESS_SIGNING_CERT_V2 **a, const unsigned char`
/// `**in, long len)` — `ess_asn1.c:57`.
///
/// # Safety
/// `a` is NULL or a writable slot; `in_` points at a readable cursor; `len` describes the input.
#[no_mangle]
pub unsafe extern "C" fn d2i_ESS_SIGNING_CERT_V2(
    a: *mut *mut EssSigningCertV2,
    in_: *mut *const c_uchar,
    len: c_long,
) -> *mut EssSigningCertV2 {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer here.
    unsafe {
        ASN1_item_d2i(a.cast(), in_, len, ESS_SIGNING_CERT_V2_it()).cast::<EssSigningCertV2>()
    }
}

/// `int i2d_ESS_SIGNING_CERT_V2(const ESS_SIGNING_CERT_V2 *a, unsigned char **out)`.
///
/// # Safety
/// `a` is NULL or a live value; `out` is NULL or a writable cursor.
#[no_mangle]
pub unsafe extern "C" fn i2d_ESS_SIGNING_CERT_V2(
    a: *const EssSigningCertV2,
    out: *mut *mut c_uchar,
) -> c_int {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer here.
    unsafe { ASN1_item_i2d(a.cast(), out, ESS_SIGNING_CERT_V2_it()) }
}
