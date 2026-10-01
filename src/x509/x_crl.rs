//! `crypto/x509/x_crl.c` -- the `X509_CRL` object core. Phase 10.8.
//!
//! `crypto/x509/x_crl.c` is 542 lines. This module lands the object core: the `X509_REVOKED`,
//! `X509_CRL_INFO` and `X509_CRL` structures with the authority's own layout, their four item
//! descriptors (`X509_REVOKED_it`, `X509_CRL_INFO_it`, `X509_CRL_it`), the `crl_inf_cb` and
//! `crl_cb` callbacks in the part the item layer can build, the lifecycles
//! (`_new`/`_new_ex`/`_free`/`_dup`, `d2i_`/`i2d_`), the `X509_REVOKED_cmp` comparator,
//! `ossl_x509_crl_set0_libctx`, and the whole CRL method surface: `X509_CRL_add0_revoked`,
//! `X509_CRL_verify`, `X509_CRL_get0_by_serial`/`_by_cert`, the three internal statics
//! `def_crl_verify`/`crl_revoked_issuer_match`/`def_crl_lookup`, and the method object
//! `X509_CRL_set_default_method`, `X509_CRL_METHOD_new`/`_free` and
//! `X509_CRL_set_meth_data`/`X509_CRL_get_meth_data`. **The rest is withheld by name**:
//!
//! | withheld | blocker |
//! |---|---|
//! | `crl_cb`'s `ASN1_OP_D2I_POST` arm | `X509_CRL_digest`, `X509_CRL_get_ext_d2i`, `setup_idp`, `crl_set_issuers` and the `EXFLAG_*` words -- none landed |
//! | `crl_cb`'s cache frees in `D2I_PRE`/`FREE_POST` | `AUTHORITY_KEYID_free`, `ISSUING_DIST_POINT_free`, `sk_GENERAL_NAMES_pop_free` (`v3_akid.c`/`v3_crld.c`/`v3_genn.c`) |
//! | `crl_set_issuers`, `setup_idp` | `X509_REVOKED_get_ext_d2i`, `DIST_POINT_set_dpname` |
//!
//! The `ASN1_OP_NEW_POST` arm installs [`default_crl_method`]'s value, which is `int_crl_meth`
//! unless `X509_CRL_set_default_method` reassigned it, so a CRL carries whatever method was
//! current when it was created -- exactly the authority's read of its mutable global.
//!
//! ## The layout
//!
//! `struct x509_revoked_st` is declared in `include/crypto/x509.h` and the other two in
//! `crypto/x509/x509_local.h`. `courts/layout/measure-x509.c` prints the sizes and offsets the
//! asserts below carry; `X509_CRL`'s trailing `libctx`/`propq` and its `sha1_hash` are what place
//! `meth_data`, `lock` and the reference count the item layer reads through `ref_offset`.
//!
//! ## `X509_CRL_up_ref`
//!
//! The authority defines it in `crypto/x509/x509cset.c:74-84`, not this file, but it is the CRL
//! half of the reference-count pair `X509_CRL_it`'s `ASN1_AFLG_REFCOUNT` maintains and 10.8 lands
//! it beside its object. Its coordinate is cited in its own doc.
//!
//! ## The raise sites
//!
//! `x_crl.c`'s only two raises are in `X509_CRL_add0_revoked` (`:374`) and `def_crl_verify`
//! (`:408`). `crypto/x509/x_crl.c` is deliberately **not** an entry in `gen_err_raise_sites.py`'s
//! `COVERED_FILES`, so both coordinates are declared locally with the `err_sites::ErrSite` shape,
//! as `v3_bitst.rs` and `v3_akid.rs` do. The two `ERR_LIB_*` values and the mismatch reason are
//! typed from `include/openssl/err.h.in` and `x509err.h`, not from memory.
//!
//! SPDX-License-Identifier: Apache-2.0

// The structures below carry the authority's own member names (`serialNumber`, `lastUpdate`, ...)
// and the comparator its own symbol name, so a reader can line them up with the headers without a
// translation table.
#![allow(non_snake_case)]

use core::ffi::{c_char, c_int, c_long, c_uchar, c_void};
use core::ptr;
use core::sync::atomic::{AtomicPtr, Ordering};

use crate::asn1::a_dup::ASN1_item_dup;
use crate::asn1::a_verify::ASN1_item_verify_ex;
use crate::asn1::d2i::ASN1_item_d2i;
use crate::asn1::fre::ASN1_item_free;
use crate::asn1::i2d::ASN1_item_i2d;
use crate::asn1::items::{ASN1_BIT_STRING_it, ASN1_INTEGER_it, ASN1_TIME_it};
use crate::asn1::layout::*;
use crate::asn1::new::ASN1_item_new;
use crate::asn1::prim::ASN1_INTEGER_cmp;
use crate::asn1::string::ASN1_STRING_cmp;
use crate::asn1::x_algor::{X509Algor, X509_ALGOR_cmp, X509_ALGOR_it};
use crate::evp::pkey::EvpPkey;
use crate::runtime::err::err_reasons::X509_R_CRL_SIGNATURE_ALGORITHM_MISMATCH;
use crate::runtime::err::err_sites::ErrSite;
use crate::runtime::err::raise_site;
use crate::runtime::mem::{CRYPTO_free, CRYPTO_malloc, CRYPTO_strdup};
use crate::runtime::stack::{
    OPENSSL_sk_find, OPENSSL_sk_is_sorted, OPENSSL_sk_new, OPENSSL_sk_num, OPENSSL_sk_push,
    OPENSSL_sk_set_cmp_func, OPENSSL_sk_sort, OPENSSL_sk_value, OpenSslStack,
};
use crate::runtime::thread::{CRYPTO_THREAD_unlock, CRYPTO_THREAD_write_lock, CryptoRwlock};
use crate::x509::v3_genn::{GeneralName, GEN_DIRNAME};
use crate::x509::x509_cmp::{X509_NAME_cmp, X509_get0_serialNumber, X509_get_issuer_name};
use crate::x509::x509cset::X509_CRL_get_issuer;
use crate::x509::x_exten::X509_EXTENSION_it;
use crate::x509::x_name::{X509Name, X509_NAME_it};
use crate::x509::x_x509::X509;

/// `CRLDP_ALL_REASONS` — `include/openssl/x509v3.h:316`, the default `idp_reasons` a new CRL
/// carries.
const CRLDP_ALL_REASONS: c_int = 0x807f;

/// The `OPENSSL_FILE` string for this unit's `OPENSSL_free`/`OPENSSL_strdup` expansions, and the
/// lines they expand at.
const FILE: &core::ffi::CStr = c"crypto/x509/x_crl.c";
/// `ossl_x509_crl_set0_libctx`'s `OPENSSL_free(x->propq)` (`:533`).
const LINE_FREE_PROPQ: c_int = 533;
/// `ossl_x509_crl_set0_libctx`'s `OPENSSL_strdup(propq)` (`:536`).
const LINE_STRDUP_PROPQ: c_int = 536;
/// `crl_cb`'s `OPENSSL_free(crl->propq)` (`:269`).
const LINE_FREE_PROPQ_FREE_POST: c_int = 269;
/// `X509_CRL_METHOD_new`'s `OPENSSL_malloc(sizeof(*m))` (`:499`).
const LINE_METHOD_NEW: c_int = 499;
/// `X509_CRL_METHOD_free`'s `OPENSSL_free(m)` (`:515`).
const LINE_METHOD_FREE: c_int = 515;

/// `CRL_REASON_REMOVE_FROM_CRL` -- `include/openssl/x509v3.h.in:230`, the reason `def_crl_lookup`
/// answers `2` for.
const CRL_REASON_REMOVE_FROM_CRL: c_int = 8;
/// `X509_CRL_METHOD_DYNAMIC` -- `crypto/x509/x509_local.h:63`, set on a method
/// `X509_CRL_METHOD_new` allocated.
const X509_CRL_METHOD_DYNAMIC: c_int = 1;

/// `ERR_LIB_X509` -- `include/openssl/err.h.in:85`.
const ERR_LIB_X509: c_int = 11;
/// `ERR_LIB_ASN1` -- `include/openssl/err.h.in:87`.
const ERR_LIB_ASN1: c_int = 13;
/// `ERR_R_CRYPTO_LIB` -- `include/openssl/err.h.in:330`, `ERR_LIB_CRYPTO | ERR_RFLAG_COMMON`
/// (`15 | 0x80000`).
const ERR_R_CRYPTO_LIB: c_int = 524303;

/// One `x_crl.c` raise coordinate, declared locally: `crypto/x509/x_crl.c` is not in
/// `gen_err_raise_sites.py`'s `COVERED_FILES`, so its two sites are built here from the
/// authority's own `__FILE__`/`__LINE__`/`__func__`, as `v3_bitst.rs` does.
const fn x_crl_site(
    line: c_int,
    func: &'static core::ffi::CStr,
    lib: c_int,
    reason: c_int,
) -> ErrSite {
    ErrSite {
        file: c"../../src/openssl-3.6.4/crypto/x509/x_crl.c",
        line,
        func,
        lib,
        reason,
        dynamic_reason: false,
    }
}

/// `X509_CRL_add0_revoked`'s failed `sk_X509_REVOKED_new`/`sk_X509_REVOKED_push` at `x_crl.c:374`
/// (`ERR_LIB_ASN1`/`ERR_R_CRYPTO_LIB`).
const X_CRL_374: ErrSite = x_crl_site(
    374,
    c"X509_CRL_add0_revoked",
    ERR_LIB_ASN1,
    ERR_R_CRYPTO_LIB,
);
/// `def_crl_verify`'s signature-algorithm mismatch at `x_crl.c:408` (`ERR_LIB_X509`/
/// `X509_R_CRL_SIGNATURE_ALGORITHM_MISMATCH`).
const X_CRL_408: ErrSite = x_crl_site(
    408,
    c"def_crl_verify",
    ERR_LIB_X509,
    X509_R_CRL_SIGNATURE_ALGORITHM_MISMATCH,
);

/// `X509_CRL_METHOD` -- `struct x509_crl_method_st`, from `crypto/x509/x509_local.h:65-72`.
///
/// The four callbacks are optional; the default method's `crl_init`/`crl_free` are NULL while its
/// `crl_lookup`/`crl_verify` are [`def_crl_lookup`]/[`def_crl_verify`].
#[repr(C)]
pub struct X509CrlMethod {
    /// `int flags` — `X509_CRL_METHOD_DYNAMIC` for an allocated method.
    pub(crate) flags: c_int,
    /// `int (*crl_init)(X509_CRL *crl)`.
    pub(crate) crl_init: Option<unsafe extern "C" fn(*mut X509Crl) -> c_int>,
    /// `int (*crl_free)(X509_CRL *crl)`.
    pub(crate) crl_free: Option<unsafe extern "C" fn(*mut X509Crl) -> c_int>,
    /// `int (*crl_lookup)(X509_CRL *crl, X509_REVOKED **ret, const ASN1_INTEGER *ser,
    /// const X509_NAME *issuer)`.
    pub(crate) crl_lookup: Option<
        unsafe extern "C" fn(
            *mut X509Crl,
            *mut *mut X509Revoked,
            *const Asn1String,
            *const X509Name,
        ) -> c_int,
    >,
    /// `int (*crl_verify)(X509_CRL *crl, EVP_PKEY *pk)`.
    pub(crate) crl_verify: Option<unsafe extern "C" fn(*mut X509Crl, *mut c_void) -> c_int>,
}

/// `static X509_CRL_METHOD int_crl_meth = { 0, 0, 0, def_crl_lookup, def_crl_verify }` --
/// `crypto/x509/x_crl.c:33-38`.
///
/// `crl_init` and `crl_free` are NULL, exactly as the authority's initialiser leaves them;
/// `crl_lookup` and `crl_verify` are [`def_crl_lookup`] and [`def_crl_verify`].
static INT_CRL_METH: X509CrlMethod = X509CrlMethod {
    flags: 0,
    crl_init: None,
    crl_free: None,
    crl_lookup: Some(def_crl_lookup),
    crl_verify: Some(def_crl_verify),
};

/// `static const X509_CRL_METHOD *default_crl_method = &int_crl_meth` -- `crypto/x509/x_crl.c:40`,
/// reassigned by [`X509_CRL_set_default_method`].
///
/// The authority holds this in a mutable pointer global. The crate models such globals as an
/// `AtomicPtr` so that reading one never forms a reference to mutable static storage -- the same
/// choice the `a_strnid` module makes for its mutable stack -- and, like the authority, reads and
/// writes it without synchronisation (`Relaxed`).
static DEFAULT_CRL_METHOD: AtomicPtr<X509CrlMethod> =
    AtomicPtr::new(&INT_CRL_METH as *const X509CrlMethod as *mut X509CrlMethod);

/// `default_crl_method`'s read -- the method a freshly built `X509_CRL` carries.
fn default_crl_method() -> *const X509CrlMethod {
    DEFAULT_CRL_METHOD.load(Ordering::Relaxed)
}

/// `struct x509_revoked_st` — `X509_REVOKED`, from `include/crypto/x509.h:130-143`.
#[repr(C)]
pub struct X509Revoked {
    /// `ASN1_INTEGER serialNumber` — embedded.
    pub(crate) serialNumber: Asn1String,
    /// `ASN1_TIME *revocationDate`.
    pub(crate) revocationDate: *mut Asn1String,
    /// `STACK_OF(X509_EXTENSION) *extensions` — optional.
    pub(crate) extensions: *mut OpenSslStack,
    /// `STACK_OF(GENERAL_NAME) *issuer` — set only for an indirect CRL.
    pub(crate) issuer: *mut OpenSslStack,
    /// `int reason` — `CRL_REASON_NONE` when the reason extension is absent.
    pub(crate) reason: c_int,
    /// `int sequence` — the load sequence, for fast lookup.
    pub(crate) sequence: c_int,
}

const _: () = {
    assert!(core::mem::size_of::<X509Revoked>() == 56);
    assert!(core::mem::offset_of!(X509Revoked, serialNumber) == 0);
    assert!(core::mem::offset_of!(X509Revoked, revocationDate) == 24);
    assert!(core::mem::offset_of!(X509Revoked, extensions) == 32);
    assert!(core::mem::offset_of!(X509Revoked, issuer) == 40);
    assert!(core::mem::offset_of!(X509Revoked, reason) == 48);
    assert!(core::mem::offset_of!(X509Revoked, sequence) == 52);
};

/// `struct X509_crl_info_st` — `X509_CRL_INFO`, from `include/crypto/x509.h:89-98`.
#[repr(C)]
pub struct X509CrlInfo {
    /// `ASN1_INTEGER *version` — defaults to v1, so nullable.
    pub(crate) version: *mut Asn1String,
    /// `X509_ALGOR sig_alg` — embedded.
    pub(crate) sig_alg: X509Algor,
    /// `X509_NAME *issuer` — mandatory.
    pub(crate) issuer: *mut X509Name,
    /// `ASN1_TIME *lastUpdate`.
    pub(crate) lastUpdate: *mut Asn1String,
    /// `ASN1_TIME *nextUpdate` — optional.
    pub(crate) nextUpdate: *mut Asn1String,
    /// `STACK_OF(X509_REVOKED) *revoked` — optional.
    pub(crate) revoked: *mut OpenSslStack,
    /// `STACK_OF(X509_EXTENSION) *extensions` — optional.
    pub(crate) extensions: *mut OpenSslStack,
    /// `ASN1_ENCODING enc` — the received encoding.
    pub(crate) enc: Asn1Encoding,
}

const _: () = {
    assert!(core::mem::size_of::<X509CrlInfo>() == 88);
    assert!(core::mem::offset_of!(X509CrlInfo, version) == 0);
    assert!(core::mem::offset_of!(X509CrlInfo, sig_alg) == 8);
    assert!(core::mem::offset_of!(X509CrlInfo, issuer) == 24);
    assert!(core::mem::offset_of!(X509CrlInfo, lastUpdate) == 32);
    assert!(core::mem::offset_of!(X509CrlInfo, nextUpdate) == 40);
    assert!(core::mem::offset_of!(X509CrlInfo, revoked) == 48);
    assert!(core::mem::offset_of!(X509CrlInfo, extensions) == 56);
    assert!(core::mem::offset_of!(X509CrlInfo, enc) == 64);
};

/// `struct X509_crl_st` — `X509_CRL`, from `include/crypto/x509.h:100-128`.
///
/// The cache members' own types (`AUTHORITY_KEYID`, `ISSUING_DIST_POINT`, `GENERAL_NAMES`) are
/// Phase 11's and are modelled as `*mut c_void`; each is a pointer, so the layout is exact.
#[repr(C)]
pub struct X509Crl {
    /// `X509_CRL_INFO crl` — the signed body, embedded.
    pub(crate) crl: X509CrlInfo,
    /// `X509_ALGOR sig_alg` — embedded.
    pub(crate) sig_alg: X509Algor,
    /// `ASN1_BIT_STRING signature` — embedded.
    pub(crate) signature: Asn1String,
    /// `CRYPTO_REF_COUNT references` — the count `X509_CRL_up_ref`/`X509_CRL_free` move.
    pub(crate) references: c_int,
    /// `int flags` — the `EXFLAG_*` word.
    pub(crate) flags: c_int,
    /// `AUTHORITY_KEYID *akid` — cached authority key identifier (type withheld).
    pub(crate) akid: *mut c_void,
    /// `ISSUING_DIST_POINT *idp` — cached issuing distribution point (type withheld).
    pub(crate) idp: *mut c_void,
    /// `int idp_flags` — the breakdown of `idp`.
    pub(crate) idp_flags: c_int,
    /// `int idp_reasons` — the reasons `idp` admits.
    pub(crate) idp_reasons: c_int,
    /// `ASN1_INTEGER *crl_number` — the CRL number extension, decoded.
    pub(crate) crl_number: *mut Asn1String,
    /// `ASN1_INTEGER *base_crl_number` — the delta CRL indicator, decoded.
    pub(crate) base_crl_number: *mut Asn1String,
    /// `STACK_OF(GENERAL_NAMES) *issuers` — per-entry issuers (type withheld).
    pub(crate) issuers: *mut OpenSslStack,
    /// `unsigned char sha1_hash[SHA_DIGEST_LENGTH]` — the CRL's SHA-1 fingerprint.
    pub(crate) sha1_hash: [c_uchar; 20],
    /// `const X509_CRL_METHOD *meth` — the method that handles this CRL.
    pub(crate) meth: *const X509CrlMethod,
    /// `void *meth_data` — the method's private attachment.
    pub(crate) meth_data: *mut c_void,
    /// `CRYPTO_RWLOCK *lock` — the lock guarding the method and cache.
    pub(crate) lock: *mut CryptoRwlock,
    /// `OSSL_LIB_CTX *libctx` — the object's library context.
    pub(crate) libctx: *mut c_void,
    /// `char *propq` — the object's property query, owned.
    pub(crate) propq: *mut c_char,
}

const _: () = {
    assert!(core::mem::size_of::<X509Crl>() == 248);
    assert!(core::mem::offset_of!(X509Crl, crl) == 0);
    assert!(core::mem::offset_of!(X509Crl, sig_alg) == 88);
    assert!(core::mem::offset_of!(X509Crl, signature) == 104);
    assert!(core::mem::offset_of!(X509Crl, references) == 128);
    assert!(core::mem::offset_of!(X509Crl, flags) == 132);
    assert!(core::mem::offset_of!(X509Crl, akid) == 136);
    assert!(core::mem::offset_of!(X509Crl, idp) == 144);
    assert!(core::mem::offset_of!(X509Crl, idp_flags) == 152);
    assert!(core::mem::offset_of!(X509Crl, idp_reasons) == 156);
    assert!(core::mem::offset_of!(X509Crl, crl_number) == 160);
    assert!(core::mem::offset_of!(X509Crl, base_crl_number) == 168);
    assert!(core::mem::offset_of!(X509Crl, issuers) == 176);
    assert!(core::mem::offset_of!(X509Crl, sha1_hash) == 184);
    assert!(core::mem::offset_of!(X509Crl, meth) == 208);
    assert!(core::mem::offset_of!(X509Crl, meth_data) == 216);
    assert!(core::mem::offset_of!(X509Crl, lock) == 224);
    assert!(core::mem::offset_of!(X509Crl, libctx) == 232);
    assert!(core::mem::offset_of!(X509Crl, propq) == 240);
};

// ---------------------------------------------------------------------------------------------
// The `X509_REVOKED` item — `ASN1_SEQUENCE(X509_REVOKED)` (`:22-26`)
// ---------------------------------------------------------------------------------------------

/// `X509_REVOKED_seq_tt` — `ASN1_SEQUENCE(X509_REVOKED)`: `ASN1_EMBED(serialNumber)`,
/// `ASN1_SIMPLE(revocationDate, ASN1_TIME)` and `ASN1_SEQUENCE_OF_OPT(extensions,
/// X509_EXTENSION)`.
static X509_REVOKED_TT: [Asn1Template; 3] = [
    Asn1Template {
        flags: ASN1_TFLG_EMBED,
        tag: 0,
        offset: 0,
        field_name: c"serialNumber".as_ptr(),
        item: ASN1_INTEGER_it as *mut c_void,
    },
    Asn1Template {
        flags: 0,
        tag: 0,
        offset: 24,
        field_name: c"revocationDate".as_ptr(),
        item: ASN1_TIME_it as *mut c_void,
    },
    Asn1Template {
        flags: ASN1_TFLG_SEQUENCE_OF | ASN1_TFLG_OPTIONAL,
        tag: 0,
        offset: 32,
        field_name: c"extensions".as_ptr(),
        item: X509_EXTENSION_it as *mut c_void,
    },
];

/// `X509_REVOKED_it`'s descriptor — `ASN1_SEQUENCE_END(X509_REVOKED)` at `crypto/x509/x_crl.c:26`.
static X509_REVOKED_ITEM: Asn1Item = Asn1Item {
    itype: ASN1_ITYPE_SEQUENCE,
    utype: V_ASN1_SEQUENCE as c_long,
    templates: X509_REVOKED_TT.as_ptr(),
    tcount: 3,
    funcs: ptr::null(),
    size: core::mem::size_of::<X509Revoked>() as c_long,
    sname: c"X509_REVOKED".as_ptr(),
};

/// `const ASN1_ITEM *X509_REVOKED_it(void)` — `include/openssl/x509.h`, from
/// `ASN1_SEQUENCE_END(X509_REVOKED)`.
#[no_mangle]
pub extern "C" fn X509_REVOKED_it() -> *const Asn1Item {
    &X509_REVOKED_ITEM
}

/// `X509_REVOKED *X509_REVOKED_new(void)` — `crypto/x509/x_crl.c:337`, from
/// `IMPLEMENT_ASN1_FUNCTIONS(X509_REVOKED)`.
#[no_mangle]
pub extern "C" fn X509_REVOKED_new() -> *mut X509Revoked {
    // SAFETY: `X509_REVOKED_it()` answers a static item the crate owns.
    unsafe { ASN1_item_new(X509_REVOKED_it()).cast::<X509Revoked>() }
}

/// `void X509_REVOKED_free(X509_REVOKED *a)` — the same macro's free half.
///
/// # Safety
///
/// `a` is NULL or a value this item layer built.
#[no_mangle]
pub unsafe extern "C" fn X509_REVOKED_free(a: *mut X509Revoked) {
    // SAFETY: `a` is NULL or a live item value per the contract.
    unsafe { ASN1_item_free(a.cast(), X509_REVOKED_it()) }
}

/// `X509_REVOKED *X509_REVOKED_dup(const X509_REVOKED *a)` —
/// `IMPLEMENT_ASN1_DUP_FUNCTION(X509_REVOKED)` (`:339`).
///
/// # Safety
///
/// `a` is NULL or a live value.
#[no_mangle]
pub unsafe extern "C" fn X509_REVOKED_dup(a: *const X509Revoked) -> *mut X509Revoked {
    // SAFETY: `a` is NULL or live per the contract; `X509_REVOKED_it()` is a static item.
    unsafe { ASN1_item_dup(X509_REVOKED_it(), a.cast()).cast::<X509Revoked>() }
}

/// `X509_REVOKED *d2i_X509_REVOKED(X509_REVOKED **a, const unsigned char **in, long len)` —
/// `crypto/x509/x_crl.c:337`'s generated decoder.
///
/// # Safety
///
/// `a` is NULL or a writable slot; `in_` points at a readable cursor; `len` describes the input.
#[no_mangle]
pub unsafe extern "C" fn d2i_X509_REVOKED(
    a: *mut *mut X509Revoked,
    in_: *mut *const c_uchar,
    len: c_long,
) -> *mut X509Revoked {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer here.
    unsafe { ASN1_item_d2i(a.cast(), in_, len, X509_REVOKED_it()).cast::<X509Revoked>() }
}

/// `int i2d_X509_REVOKED(const X509_REVOKED *a, unsigned char **out)` — the same macro's encoder.
///
/// # Safety
///
/// `a` is NULL or a live value; `out` is NULL or a writable cursor.
#[no_mangle]
pub unsafe extern "C" fn i2d_X509_REVOKED(a: *const X509Revoked, out: *mut *mut c_uchar) -> c_int {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer here.
    unsafe { ASN1_item_i2d(a.cast(), out, X509_REVOKED_it()) }
}

// ---------------------------------------------------------------------------------------------
// The `X509_CRL_INFO` item — `ASN1_SEQUENCE_enc(X509_CRL_INFO, enc, crl_inf_cb)` (`:66-74`)
// ---------------------------------------------------------------------------------------------

/// `X509_REVOKED_cmp` — `crypto/x509/x_crl.c:347-352`.
///
/// The comparator installed on the `revoked` stack, comparing the embedded serial numbers as
/// `ASN1_STRING`s.
///
/// # Safety
/// `a` and `b` are pointers to `X509_REVOKED *` elements of a stack.
unsafe extern "C" fn X509_REVOKED_cmp(a: *const c_void, b: *const c_void) -> c_int {
    // SAFETY: the comparator contract is pointers to elements, and each element is an
    // `X509_REVOKED *`.
    unsafe {
        let ra = *(a.cast::<*const X509Revoked>());
        let rb = *(b.cast::<*const X509Revoked>());
        ASN1_STRING_cmp(&raw const (*ra).serialNumber, &raw const (*rb).serialNumber)
    }
}

/// `static int crl_inf_cb(int operation, ASN1_VALUE **pval, const ASN1_ITEM *it, void *exarg)` —
/// `crypto/x509/x_crl.c:47-64`.
///
/// One arm: on a completed decode, install [`X509_REVOKED_cmp`] on the `revoked` stack so lookups
/// can binary-search. The authority does not sort there, because that would perturb
/// `X509_CRL_print`'s output.
///
/// # Safety
/// The item layer's own callback contract.
unsafe extern "C" fn crl_inf_cb(
    operation: c_int,
    pval: *mut *mut c_void,
    it: *const Asn1Item,
    exarg: *mut c_void,
) -> c_int {
    let _ = (it, exarg);
    // SAFETY: `pval` points at a live `X509_CRL_INFO`.
    let a = unsafe { (*pval).cast::<X509CrlInfo>() };
    if a.is_null() {
        return 1;
    }
    // SAFETY: `a` is non-NULL here and its `revoked` is its own field.
    if unsafe { (*a).revoked.is_null() } {
        return 1;
    }
    if operation == ASN1_OP_D2I_POST {
        // SAFETY: `a` is live and `revoked` is its own stack.
        unsafe { OPENSSL_sk_set_cmp_func((*a).revoked, Some(X509_REVOKED_cmp)) };
    }
    1
}

/// `X509_CRL_INFO`'s `ASN1_AUX` — `ASN1_SEQUENCE_enc(X509_CRL_INFO, enc, crl_inf_cb)`:
/// `ASN1_AFLG_ENCODING`, `enc_offset = offsetof(X509_CRL_INFO, enc)` and `crl_inf_cb`.
struct SyncAuxInfo(Asn1Aux);

// SAFETY: a `static` compiled from constants and one function pointer, written once by the
// loader, with no interior mutability reachable through the shared reference the item takes.
unsafe impl Sync for SyncAuxInfo {}

/// The `ASN1_AUX` block named above.
static X509_CRL_INFO_AUX: SyncAuxInfo = SyncAuxInfo(Asn1Aux {
    app_data: ptr::null_mut(),
    flags: ASN1_AFLG_ENCODING,
    ref_offset: 0,
    ref_lock: 0,
    asn1_cb: Some(crl_inf_cb),
    enc_offset: 64,
    asn1_const_cb: None,
});

/// `X509_CRL_INFO_seq_tt` — `ASN1_SEQUENCE_enc(X509_CRL_INFO, enc, crl_inf_cb)` (`:66-74`):
/// `ASN1_OPT(version)`, `ASN1_EMBED(sig_alg)`, `ASN1_SIMPLE(issuer)`,
/// `ASN1_SIMPLE(lastUpdate)`, `ASN1_OPT(nextUpdate)`, `ASN1_SEQUENCE_OF_OPT(revoked)` and
/// `ASN1_EXP_SEQUENCE_OF_OPT(extensions, 0)`.
static X509_CRL_INFO_TT: [Asn1Template; 7] = [
    Asn1Template {
        flags: ASN1_TFLG_OPTIONAL,
        tag: 0,
        offset: 0,
        field_name: c"version".as_ptr(),
        item: ASN1_INTEGER_it as *mut c_void,
    },
    Asn1Template {
        flags: ASN1_TFLG_EMBED,
        tag: 0,
        offset: 8,
        field_name: c"sig_alg".as_ptr(),
        item: X509_ALGOR_it as *mut c_void,
    },
    Asn1Template {
        flags: 0,
        tag: 0,
        offset: 24,
        field_name: c"issuer".as_ptr(),
        item: X509_NAME_it as *mut c_void,
    },
    Asn1Template {
        flags: 0,
        tag: 0,
        offset: 32,
        field_name: c"lastUpdate".as_ptr(),
        item: ASN1_TIME_it as *mut c_void,
    },
    Asn1Template {
        flags: ASN1_TFLG_OPTIONAL,
        tag: 0,
        offset: 40,
        field_name: c"nextUpdate".as_ptr(),
        item: ASN1_TIME_it as *mut c_void,
    },
    Asn1Template {
        flags: ASN1_TFLG_SEQUENCE_OF | ASN1_TFLG_OPTIONAL,
        tag: 0,
        offset: 48,
        field_name: c"revoked".as_ptr(),
        item: X509_REVOKED_it as *mut c_void,
    },
    Asn1Template {
        flags: ASN1_TFLG_EXPLICIT | ASN1_TFLG_SEQUENCE_OF | ASN1_TFLG_OPTIONAL,
        tag: 0,
        offset: 56,
        field_name: c"extensions".as_ptr(),
        item: X509_EXTENSION_it as *mut c_void,
    },
];

/// `X509_CRL_INFO_it`'s descriptor — `ASN1_SEQUENCE_END_enc(X509_CRL_INFO, X509_CRL_INFO)` at
/// `crypto/x509/x_crl.c:74`.
static X509_CRL_INFO_ITEM: Asn1Item = Asn1Item {
    itype: ASN1_ITYPE_SEQUENCE,
    utype: V_ASN1_SEQUENCE as c_long,
    templates: X509_CRL_INFO_TT.as_ptr(),
    tcount: 7,
    funcs: (&X509_CRL_INFO_AUX.0) as *const Asn1Aux as *const c_void,
    size: core::mem::size_of::<X509CrlInfo>() as c_long,
    sname: c"X509_CRL_INFO".as_ptr(),
};

/// `const ASN1_ITEM *X509_CRL_INFO_it(void)` — `include/openssl/x509.h`, from
/// `ASN1_SEQUENCE_END_enc(X509_CRL_INFO, X509_CRL_INFO)`.
#[no_mangle]
pub extern "C" fn X509_CRL_INFO_it() -> *const Asn1Item {
    &X509_CRL_INFO_ITEM
}

/// `X509_CRL_INFO *X509_CRL_INFO_new(void)` — `crypto/x509/x_crl.c:341`, from
/// `IMPLEMENT_ASN1_FUNCTIONS(X509_CRL_INFO)`.
#[no_mangle]
pub extern "C" fn X509_CRL_INFO_new() -> *mut X509CrlInfo {
    // SAFETY: `X509_CRL_INFO_it()` answers a static item the crate owns.
    unsafe { ASN1_item_new(X509_CRL_INFO_it()).cast::<X509CrlInfo>() }
}

/// `void X509_CRL_INFO_free(X509_CRL_INFO *a)` — the same macro's free half.
///
/// # Safety
///
/// `a` is NULL or a value this item layer built.
#[no_mangle]
pub unsafe extern "C" fn X509_CRL_INFO_free(a: *mut X509CrlInfo) {
    // SAFETY: `a` is NULL or a live item value per the contract.
    unsafe { ASN1_item_free(a.cast(), X509_CRL_INFO_it()) }
}

/// `X509_CRL_INFO *d2i_X509_CRL_INFO(X509_CRL_INFO **a, const unsigned char **in, long len)` —
/// `crypto/x509/x_crl.c:341`'s generated decoder.
///
/// # Safety
///
/// `a` is NULL or a writable slot; `in_` points at a readable cursor; `len` describes the input.
#[no_mangle]
pub unsafe extern "C" fn d2i_X509_CRL_INFO(
    a: *mut *mut X509CrlInfo,
    in_: *mut *const c_uchar,
    len: c_long,
) -> *mut X509CrlInfo {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer here.
    unsafe { ASN1_item_d2i(a.cast(), in_, len, X509_CRL_INFO_it()).cast::<X509CrlInfo>() }
}

/// `int i2d_X509_CRL_INFO(const X509_CRL_INFO *a, unsigned char **out)` — the same macro's
/// encoder.
///
/// # Safety
///
/// `a` is NULL or a live value; `out` is NULL or a writable cursor.
#[no_mangle]
pub unsafe extern "C" fn i2d_X509_CRL_INFO(a: *const X509CrlInfo, out: *mut *mut c_uchar) -> c_int {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer here.
    unsafe { ASN1_item_i2d(a.cast(), out, X509_CRL_INFO_it()) }
}

// ---------------------------------------------------------------------------------------------
// The `crl_cb` callback and the `X509_CRL` item — `crypto/x509/x_crl.c:155-335`
// ---------------------------------------------------------------------------------------------

/// The `ASN1_OP_NEW_POST` body, which `ASN1_OP_D2I_PRE` falls through to.
///
/// # Safety
/// `crl` is a live `X509_CRL`.
unsafe fn crl_new_post(crl: *mut X509Crl) -> c_int {
    // SAFETY: `crl` is live per the contract.
    unsafe {
        (*crl).idp = ptr::null_mut();
        (*crl).akid = ptr::null_mut();
        (*crl).flags = 0;
        (*crl).idp_flags = 0;
        (*crl).idp_reasons = CRLDP_ALL_REASONS;
        (*crl).meth = default_crl_method();
        (*crl).meth_data = ptr::null_mut();
        (*crl).issuers = ptr::null_mut();
        (*crl).crl_number = ptr::null_mut();
        (*crl).base_crl_number = ptr::null_mut();
    }
    1
}

/// `static int crl_cb(int operation, ASN1_VALUE **pval, const ASN1_ITEM *it, void *exarg)` —
/// `crypto/x509/x_crl.c:155-279`.
///
/// The `ASN1_OP_D2I_POST` arm is **withheld whole** (see the module doc): it computes the SHA-1
/// fingerprint through `X509_CRL_digest`, decodes four extensions through `X509_CRL_get_ext_d2i`,
/// runs `setup_idp`/`crl_set_issuers` and sets `EXFLAG_SET` — every one unlanded, and none of them
/// observable through this slice. The cache frees the authority performs in `D2I_PRE`/`FREE_POST`
/// for `akid`/`idp`/`issuers` are withheld at their sites for the same reason as `x509_cb`'s.
///
/// # Safety
/// The item layer's own callback contract.
unsafe extern "C" fn crl_cb(
    operation: c_int,
    pval: *mut *mut c_void,
    it: *const Asn1Item,
    exarg: *mut c_void,
) -> c_int {
    let _ = it;
    // SAFETY: `pval` points at a live `X509_CRL` for every operation.
    let crl = unsafe { (*pval).cast::<X509Crl>() };

    match operation {
        ASN1_OP_D2I_PRE => {
            // SAFETY: `crl` is live. `crl->meth->crl_free` is NULL in the default method (as it is
            // in the authority's), and the `AUTHORITY_KEYID_free`/`ISSUING_DIST_POINT_free`/
            // `sk_GENERAL_NAMES_pop_free` releases are withheld with their units.
            unsafe {
                let meth = (*crl).meth;
                if !meth.is_null() {
                    if let Some(f) = (*meth).crl_free {
                        if f(crl) == 0 {
                            return 0;
                        }
                    }
                }
                crate::asn1::string::ASN1_INTEGER_free((*crl).crl_number);
                crate::asn1::string::ASN1_INTEGER_free((*crl).base_crl_number);
            }
            // The authority's `/* fall through */`.
            // SAFETY: `crl` is live.
            return unsafe { crl_new_post(crl) };
        }
        ASN1_OP_NEW_POST => {
            // SAFETY: `crl` is live.
            return unsafe { crl_new_post(crl) };
        }
        ASN1_OP_D2I_POST => {
            // Withheld whole: see the module doc and the function doc above. Nothing is pretended.
        }
        ASN1_OP_FREE_POST => {
            // SAFETY: `crl` is live. The three withheld cache frees are noted in the function doc.
            unsafe {
                let meth = (*crl).meth;
                if !meth.is_null() {
                    if let Some(f) = (*meth).crl_free {
                        if f(crl) == 0 {
                            return 0;
                        }
                    }
                }
                crate::asn1::string::ASN1_INTEGER_free((*crl).crl_number);
                crate::asn1::string::ASN1_INTEGER_free((*crl).base_crl_number);
                CRYPTO_free(
                    (*crl).propq.cast(),
                    FILE.as_ptr(),
                    LINE_FREE_PROPQ_FREE_POST,
                );
            }
        }
        ASN1_OP_DUP_POST => {
            // SAFETY: `exarg` is the source `X509_CRL` for this operation.
            let old = exarg.cast::<X509Crl>();
            // SAFETY: `crl` and `old` are live.
            if unsafe { ossl_x509_crl_set0_libctx(crl, (*old).libctx, (*old).propq) } == 0 {
                return 0;
            }
        }
        _ => {}
    }
    1
}

/// `X509_CRL`'s `ASN1_AUX` — `ASN1_SEQUENCE_ref(X509_CRL, crl_cb)` (`:331`): `ASN1_AFLG_REFCOUNT`,
/// `ref_offset = offsetof(X509_CRL, references)`, `ref_lock = offsetof(X509_CRL, lock)`,
/// `crl_cb`.
struct SyncAux(Asn1Aux);

// SAFETY: a `static` compiled from constants and one function pointer, written once by the loader,
// with no interior mutability reachable through the shared reference the item takes.
unsafe impl Sync for SyncAux {}

/// The `ASN1_AUX` block named above.
static X509_CRL_AUX: SyncAux = SyncAux(Asn1Aux {
    app_data: ptr::null_mut(),
    flags: ASN1_AFLG_REFCOUNT,
    ref_offset: 128,
    ref_lock: 224,
    asn1_cb: Some(crl_cb),
    enc_offset: 0,
    asn1_const_cb: None,
});

/// `X509_CRL_seq_tt` — `ASN1_SEQUENCE_ref(X509_CRL, crl_cb)` (`:331-335`):
/// `ASN1_EMBED(X509_CRL, crl, X509_CRL_INFO)`, `ASN1_EMBED(X509_CRL, sig_alg, X509_ALGOR)` and
/// `ASN1_EMBED(X509_CRL, signature, ASN1_BIT_STRING)`.
static X509_CRL_TT: [Asn1Template; 3] = [
    Asn1Template {
        flags: ASN1_TFLG_EMBED,
        tag: 0,
        offset: 0,
        field_name: c"crl".as_ptr(),
        item: X509_CRL_INFO_it as *mut c_void,
    },
    Asn1Template {
        flags: ASN1_TFLG_EMBED,
        tag: 0,
        offset: 88,
        field_name: c"sig_alg".as_ptr(),
        item: X509_ALGOR_it as *mut c_void,
    },
    Asn1Template {
        flags: ASN1_TFLG_EMBED,
        tag: 0,
        offset: 104,
        field_name: c"signature".as_ptr(),
        item: ASN1_BIT_STRING_it as *mut c_void,
    },
];

/// `X509_CRL_it`'s descriptor — `ASN1_SEQUENCE_END_ref(X509_CRL, X509_CRL)` at
/// `crypto/x509/x_crl.c:335`.
static X509_CRL_ITEM: Asn1Item = Asn1Item {
    itype: ASN1_ITYPE_SEQUENCE,
    utype: V_ASN1_SEQUENCE as c_long,
    templates: X509_CRL_TT.as_ptr(),
    tcount: 3,
    funcs: (&X509_CRL_AUX.0) as *const Asn1Aux as *const c_void,
    size: core::mem::size_of::<X509Crl>() as c_long,
    sname: c"X509_CRL".as_ptr(),
};

/// `const ASN1_ITEM *X509_CRL_it(void)` — `include/openssl/x509.h`, from
/// `ASN1_SEQUENCE_END_ref(X509_CRL, X509_CRL)`.
#[no_mangle]
pub extern "C" fn X509_CRL_it() -> *const Asn1Item {
    &X509_CRL_ITEM
}

/// `X509_CRL *X509_CRL_new(void)` — `crypto/x509/x_crl.c:343`, from
/// `IMPLEMENT_ASN1_FUNCTIONS(X509_CRL)`.
#[no_mangle]
pub extern "C" fn X509_CRL_new() -> *mut X509Crl {
    // SAFETY: `X509_CRL_it()` answers a static item the crate owns.
    unsafe { ASN1_item_new(X509_CRL_it()).cast::<X509Crl>() }
}

/// `void X509_CRL_free(X509_CRL *a)` — the same macro's free half. The reference count
/// `X509_CRL_it`'s `ASN1_AFLG_REFCOUNT` maintains is decremented by the item layer.
///
/// # Safety
///
/// `a` is NULL or a value this item layer built.
#[no_mangle]
pub unsafe extern "C" fn X509_CRL_free(a: *mut X509Crl) {
    // SAFETY: `a` is NULL or a live item value per the contract.
    unsafe { ASN1_item_free(a.cast(), X509_CRL_it()) }
}

/// `X509_CRL *X509_CRL_dup(const X509_CRL *a)` — `IMPLEMENT_ASN1_DUP_FUNCTION(X509_CRL)`
/// (`:345`).
///
/// # Safety
///
/// `a` is NULL or a live value.
#[no_mangle]
pub unsafe extern "C" fn X509_CRL_dup(a: *const X509Crl) -> *mut X509Crl {
    // SAFETY: `a` is NULL or live per the contract; `X509_CRL_it()` is a static item.
    unsafe { ASN1_item_dup(X509_CRL_it(), a.cast()).cast::<X509Crl>() }
}

/// `X509_CRL *d2i_X509_CRL(X509_CRL **a, const unsigned char **in, long len)` —
/// `crypto/x509/x_crl.c:343`'s generated decoder.
///
/// # Safety
///
/// `a` is NULL or a writable slot; `in_` points at a readable cursor; `len` describes the input.
#[no_mangle]
pub unsafe extern "C" fn d2i_X509_CRL(
    a: *mut *mut X509Crl,
    in_: *mut *const c_uchar,
    len: c_long,
) -> *mut X509Crl {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer here.
    unsafe { ASN1_item_d2i(a.cast(), in_, len, X509_CRL_it()).cast::<X509Crl>() }
}

/// `int i2d_X509_CRL(const X509_CRL *a, unsigned char **out)` — the same macro's encoder.
///
/// # Safety
///
/// `a` is NULL or a live value; `out` is NULL or a writable cursor.
#[no_mangle]
pub unsafe extern "C" fn i2d_X509_CRL(a: *const X509Crl, out: *mut *mut c_uchar) -> c_int {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer here.
    unsafe { ASN1_item_i2d(a.cast(), out, X509_CRL_it()) }
}

/// `X509_CRL *X509_CRL_new_ex(OSSL_LIB_CTX *libctx, const char *propq)` —
/// `crypto/x509/x_crl.c:354-364`.
///
/// # Safety
///
/// `libctx` is NULL or a live context and `propq` NULL or NUL-terminated.
#[no_mangle]
pub unsafe extern "C" fn X509_CRL_new_ex(
    libctx: *mut c_void,
    propq: *const c_char,
) -> *mut X509Crl {
    // SAFETY: `X509_CRL_it()` is a static item the crate owns.
    let crl = unsafe { ASN1_item_new(X509_CRL_it()).cast::<X509Crl>() };
    // SAFETY: `crl` is NULL or a fresh object.
    if unsafe { ossl_x509_crl_set0_libctx(crl, libctx, propq) } == 0 {
        // SAFETY: `crl` is NULL or a fresh object this call owns.
        unsafe { X509_CRL_free(crl) };
        return ptr::null_mut();
    }
    crl
}

// ---------------------------------------------------------------------------------------------
// The CRL method surface -- `crypto/x509/x_crl.c:366-526`
// ---------------------------------------------------------------------------------------------

/// `int X509_CRL_add0_revoked(X509_CRL *crl, X509_REVOKED *rev)` -- `crypto/x509/x_crl.c:366-379`.
///
/// # Safety
///
/// `crl` is live; `rev` is live and, on success, becomes owned by the CRL.
#[no_mangle]
pub unsafe extern "C" fn X509_CRL_add0_revoked(crl: *mut X509Crl, rev: *mut X509Revoked) -> c_int {
    // SAFETY: `crl` is live per the contract.
    unsafe {
        if (*crl).crl.revoked.is_null() {
            (*crl).crl.revoked = OPENSSL_sk_new(Some(X509_REVOKED_cmp));
        }
        if (*crl).crl.revoked.is_null()
            || OPENSSL_sk_push((*crl).crl.revoked, rev.cast::<c_void>()) == 0
        {
            // SAFETY: a compile-time-constant site.
            raise_site(&X_CRL_374);
            return 0;
        }
        (*crl).crl.enc.modified = 1;
    }
    1
}

/// `int X509_CRL_verify(X509_CRL *crl, EVP_PKEY *r)` -- `crypto/x509/x_crl.c:381-386`.
///
/// # Safety
///
/// `crl` is live; `r` is NULL or a live `EVP_PKEY`.
#[no_mangle]
pub unsafe extern "C" fn X509_CRL_verify(crl: *mut X509Crl, r: *mut EvpPkey) -> c_int {
    // SAFETY: `crl` is live per the contract.
    let meth = unsafe { (*crl).meth };
    if !meth.is_null() {
        // SAFETY: `meth` is live here.
        if let Some(f) = unsafe { (*meth).crl_verify } {
            // SAFETY: `f` is `meth`'s own verify callback; `r` is the caller's key.
            return unsafe { f(crl, r.cast::<c_void>()) };
        }
    }
    0
}

/// `int X509_CRL_get0_by_serial(X509_CRL *crl, X509_REVOKED **ret, const ASN1_INTEGER *serial)` --
/// `crypto/x509/x_crl.c:388-394`.
///
/// # Safety
///
/// `crl` is live; `ret` is NULL or writable; `serial` is live.
#[no_mangle]
pub unsafe extern "C" fn X509_CRL_get0_by_serial(
    crl: *mut X509Crl,
    ret: *mut *mut X509Revoked,
    serial: *const Asn1String,
) -> c_int {
    // SAFETY: `crl` is live per the contract.
    let meth = unsafe { (*crl).meth };
    if !meth.is_null() {
        // SAFETY: `meth` is live here.
        if let Some(f) = unsafe { (*meth).crl_lookup } {
            // SAFETY: `f` is `meth`'s own lookup callback; the pointers are the caller's.
            return unsafe { f(crl, ret, serial, ptr::null()) };
        }
    }
    0
}

/// `int X509_CRL_get0_by_cert(X509_CRL *crl, X509_REVOKED **ret, X509 *x)` --
/// `crypto/x509/x_crl.c:396-403`.
///
/// # Safety
///
/// `crl` is live; `ret` is NULL or writable; `x` is live.
#[no_mangle]
pub unsafe extern "C" fn X509_CRL_get0_by_cert(
    crl: *mut X509Crl,
    ret: *mut *mut X509Revoked,
    x: *mut X509,
) -> c_int {
    // SAFETY: `crl` is live per the contract.
    let meth = unsafe { (*crl).meth };
    if !meth.is_null() {
        // SAFETY: `meth` is live here.
        if let Some(f) = unsafe { (*meth).crl_lookup } {
            // SAFETY: `x` is live, so the two accessors return its own fields, which the lookup
            // callback reads without taking ownership.
            return unsafe { f(crl, ret, X509_get0_serialNumber(x), X509_get_issuer_name(x)) };
        }
    }
    0
}

/// `static int def_crl_verify(X509_CRL *crl, EVP_PKEY *r)` -- `crypto/x509/x_crl.c:405-414`.
///
/// # Safety
///
/// `crl` is live; `r` is NULL or a live `EVP_PKEY`.
unsafe extern "C" fn def_crl_verify(crl: *mut X509Crl, r: *mut c_void) -> c_int {
    // SAFETY: `crl` is live per the contract.
    if unsafe { X509_ALGOR_cmp(&raw const (*crl).sig_alg, &raw const (*crl).crl.sig_alg) } != 0 {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&X_CRL_408) };
        return 0;
    }
    // SAFETY: `crl` is live, `X509_CRL_INFO_it()` is the crate's static item, and `r` is the
    // caller's key.
    unsafe {
        ASN1_item_verify_ex(
            X509_CRL_INFO_it(),
            &raw const (*crl).sig_alg,
            &raw const (*crl).signature,
            (&raw const (*crl).crl).cast::<c_void>(),
            ptr::null(),
            r.cast::<EvpPkey>(),
            (*crl).libctx,
            (*crl).propq,
        )
    }
}

/// `static int crl_revoked_issuer_match(X509_CRL *crl, const X509_NAME *nm, X509_REVOKED *rev)` --
/// `crypto/x509/x_crl.c:416-440`.
///
/// # Safety
///
/// `crl` is live; `nm` is NULL or live; `rev` is live.
unsafe fn crl_revoked_issuer_match(
    crl: *mut X509Crl,
    nm: *const X509Name,
    rev: *const X509Revoked,
) -> c_int {
    // SAFETY: `rev` is live per the contract.
    let issuer = unsafe { (*rev).issuer };
    if issuer.is_null() {
        if nm.is_null() {
            return 1;
        }
        // SAFETY: `crl` and `nm` are live.
        if unsafe { X509_NAME_cmp(nm, X509_CRL_get_issuer(crl)) } == 0 {
            return 1;
        }
        return 0;
    }

    // The authority's `if (!nm) nm = X509_CRL_get_issuer(crl);`.
    let nm = if nm.is_null() {
        // SAFETY: `crl` is live.
        unsafe { X509_CRL_get_issuer(crl) }
    } else {
        nm.cast_mut()
    };

    // SAFETY: `issuer` is `rev`'s live `GENERAL_NAME` stack.
    let num = unsafe { OPENSSL_sk_num(issuer) };
    let mut i = 0;
    while i < num {
        // SAFETY: `i` is in range and `issuer` is live.
        let gen = unsafe { OPENSSL_sk_value(issuer, i) }.cast::<GeneralName>();
        // SAFETY: `gen` is a live general name.
        if unsafe { (*gen).type_ } == GEN_DIRNAME {
            // SAFETY: a `GEN_DIRNAME` name carries its directory name in the union.
            if unsafe { X509_NAME_cmp(nm, (*gen).d.directoryName) } == 0 {
                return 1;
            }
        }
        i += 1;
    }
    0
}

/// `static int def_crl_lookup(X509_CRL *crl, X509_REVOKED **ret, const ASN1_INTEGER *serial,
/// const X509_NAME *issuer)` -- `crypto/x509/x_crl.c:442-480`.
///
/// # Safety
///
/// `crl` is live; `ret` is NULL or writable; `serial` is live; `issuer` is NULL or live.
unsafe extern "C" fn def_crl_lookup(
    crl: *mut X509Crl,
    ret: *mut *mut X509Revoked,
    serial: *const Asn1String,
    issuer: *const X509Name,
) -> c_int {
    // SAFETY: `crl` is live per the contract.
    let revoked = unsafe { (*crl).crl.revoked };
    if revoked.is_null() {
        return 0;
    }

    // Sort the entries into serial order if they are not already, under the CRL's own lock.
    // SAFETY: `revoked` is the CRL's live stack.
    if unsafe { OPENSSL_sk_is_sorted(revoked) } == 0 {
        // SAFETY: `crl` is live and its `lock` guards the stack.
        if unsafe { CRYPTO_THREAD_write_lock((*crl).lock) } == 0 {
            return 0;
        }
        // SAFETY: `revoked` is live and the lock is held.
        unsafe { OPENSSL_sk_sort(revoked) };
        // SAFETY: `crl` is live and the lock is held.
        unsafe { CRYPTO_THREAD_unlock((*crl).lock) };
    }

    // The authority copies only `serialNumber` into a stack-local `X509_REVOKED`, because that is
    // the one field the comparator reads; the rest stays uninitialised rather than zero-filled, as
    // the crate's stack-local `X509` in `x509_cmp.rs` is built.
    let mut rtmp = core::mem::MaybeUninit::<X509Revoked>::uninit();
    // The authority's `rtmp.serialNumber = *serial` is a struct copy; `serialNumber` is the first
    // field, so this copies the `ASN1_INTEGER` into the key's first slot.
    // SAFETY: `serial` is live, and `rtmp` has room for the one `Asn1String` written at offset 0.
    unsafe { ptr::copy_nonoverlapping(serial, rtmp.as_mut_ptr().cast::<Asn1String>(), 1) };
    // SAFETY: `revoked` is live and `rtmp` holds the search key.
    let mut idx = unsafe { OPENSSL_sk_find(revoked, rtmp.as_ptr().cast::<c_void>()) };
    if idx < 0 {
        return 0;
    }
    // SAFETY: `revoked` is live.
    let num = unsafe { OPENSSL_sk_num(revoked) };
    while idx < num {
        // SAFETY: `idx` is in range and `revoked` is live.
        let rev = unsafe { OPENSSL_sk_value(revoked, idx) }.cast::<X509Revoked>();
        // SAFETY: `rev` is a live entry and `serial` is live.
        if unsafe { ASN1_INTEGER_cmp(&raw const (*rev).serialNumber, serial) } != 0 {
            return 0;
        }
        // SAFETY: `crl`, `issuer` and `rev` are live.
        if unsafe { crl_revoked_issuer_match(crl, issuer, rev) } != 0 {
            if !ret.is_null() {
                // SAFETY: `ret` is writable per the contract.
                unsafe { *ret = rev };
            }
            // SAFETY: `rev` is live.
            if unsafe { (*rev).reason } == CRL_REASON_REMOVE_FROM_CRL {
                return 2;
            }
            return 1;
        }
        idx += 1;
    }
    0
}

/// `void X509_CRL_set_default_method(const X509_CRL_METHOD *meth)` --
/// `crypto/x509/x_crl.c:482-488`.
///
/// # Safety
///
/// `meth` is NULL or a live method that outlives every CRL created while it is installed.
#[no_mangle]
pub unsafe extern "C" fn X509_CRL_set_default_method(meth: *const X509CrlMethod) {
    if meth.is_null() {
        DEFAULT_CRL_METHOD.store(
            &INT_CRL_METH as *const X509CrlMethod as *mut X509CrlMethod,
            Ordering::Relaxed,
        );
    } else {
        DEFAULT_CRL_METHOD.store(meth.cast_mut(), Ordering::Relaxed);
    }
}

/// `X509_CRL_METHOD *X509_CRL_METHOD_new(...)` -- `crypto/x509/x_crl.c:490-509`.
///
/// # Safety
///
/// Each callback is NULL or valid for the method's lifetime.
#[no_mangle]
pub unsafe extern "C" fn X509_CRL_METHOD_new(
    crl_init: Option<unsafe extern "C" fn(*mut X509Crl) -> c_int>,
    crl_free: Option<unsafe extern "C" fn(*mut X509Crl) -> c_int>,
    crl_lookup: Option<
        unsafe extern "C" fn(
            *mut X509Crl,
            *mut *mut X509Revoked,
            *const Asn1String,
            *const X509Name,
        ) -> c_int,
    >,
    crl_verify: Option<unsafe extern "C" fn(*mut X509Crl, *mut c_void) -> c_int>,
) -> *mut X509CrlMethod {
    // SAFETY: the allocator answers NULL or one `X509_CRL_METHOD`-sized block; the file and line
    // are this unit's `OPENSSL_malloc` expansion.
    let m = CRYPTO_malloc(
        core::mem::size_of::<X509CrlMethod>(),
        FILE.as_ptr(),
        LINE_METHOD_NEW,
    )
    .cast::<X509CrlMethod>();
    if m.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: `m` is a fresh, unaliased allocation.
    unsafe {
        (*m).crl_init = crl_init;
        (*m).crl_free = crl_free;
        (*m).crl_lookup = crl_lookup;
        (*m).crl_verify = crl_verify;
        (*m).flags = X509_CRL_METHOD_DYNAMIC;
    }
    m
}

/// `void X509_CRL_METHOD_free(X509_CRL_METHOD *m)` -- `crypto/x509/x_crl.c:511-516`.
///
/// # Safety
///
/// `m` is NULL or a method `X509_CRL_METHOD_new` allocated and no longer referenced.
#[no_mangle]
pub unsafe extern "C" fn X509_CRL_METHOD_free(m: *mut X509CrlMethod) {
    if m.is_null() {
        return;
    }
    // SAFETY: `m` is live per the contract.
    if unsafe { (*m).flags } & X509_CRL_METHOD_DYNAMIC == 0 {
        return;
    }
    // SAFETY: `m` is the caller's `X509_CRL_METHOD_new` block, freed with this unit's
    // `OPENSSL_free` expansion.
    unsafe { CRYPTO_free(m.cast::<c_void>(), FILE.as_ptr(), LINE_METHOD_FREE) };
}

/// `void X509_CRL_set_meth_data(X509_CRL *crl, void *dat)` -- `crypto/x509/x_crl.c:518-521`.
///
/// # Safety
///
/// `crl` is live.
#[no_mangle]
pub unsafe extern "C" fn X509_CRL_set_meth_data(crl: *mut X509Crl, dat: *mut c_void) {
    // SAFETY: `crl` is live per the contract.
    unsafe { (*crl).meth_data = dat };
}

/// `void *X509_CRL_get_meth_data(X509_CRL *crl)` -- `crypto/x509/x_crl.c:523-526`.
///
/// # Safety
///
/// `crl` is live.
#[no_mangle]
pub unsafe extern "C" fn X509_CRL_get_meth_data(crl: *mut X509Crl) -> *mut c_void {
    // SAFETY: `crl` is live per the contract.
    unsafe { (*crl).meth_data }
}

/// `int X509_CRL_up_ref(X509_CRL *crl)` — `crypto/x509/x509cset.c:74-84`, the CRL half of the
/// reference-count pair `X509_CRL_it` maintains. It is landed here with the object it counts.
///
/// # Safety
/// `crl` is live.
#[no_mangle]
pub unsafe extern "C" fn X509_CRL_up_ref(crl: *mut X509Crl) -> c_int {
    // SAFETY: `crl` is live per the contract.
    let i = unsafe { (*crl).references.wrapping_add(1) };
    // SAFETY: `crl` is live and writable.
    unsafe { (*crl).references = i };
    c_int::from(i > 1)
}

/// `int ossl_x509_crl_set0_libctx(X509_CRL *x, OSSL_LIB_CTX *libctx, const char *propq)` —
/// `crypto/x509/x_crl.c:528-542`.
///
/// # Safety
///
/// `x` is NULL or a live `X509_CRL`; `libctx` is NULL or a live context and `propq` NULL or
/// NUL-terminated.
#[no_mangle]
pub unsafe extern "C" fn ossl_x509_crl_set0_libctx(
    x: *mut X509Crl,
    libctx: *mut c_void,
    propq: *const c_char,
) -> c_int {
    if !x.is_null() {
        // SAFETY: `x` is live per the contract.
        unsafe {
            (*x).libctx = libctx;
            CRYPTO_free((*x).propq.cast(), FILE.as_ptr(), LINE_FREE_PROPQ);
            (*x).propq = ptr::null_mut();
            if !propq.is_null() {
                (*x).propq = CRYPTO_strdup(propq, FILE.as_ptr(), LINE_STRDUP_PROPQ);
                if (*x).propq.is_null() {
                    return 0;
                }
            }
        }
    }
    1
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A blank CRL carries the authority's defaults: a one-valued reference count, the
    /// `CRLDP_ALL_REASONS` default and the default method installed.
    #[test]
    fn a_blank_crl_has_the_authoritys_defaults() {
        // SAFETY: `crl` is a live object this test owns.
        unsafe {
            let crl = X509_CRL_new();
            assert!(!crl.is_null());
            assert_eq!((*crl).references, 1);
            assert_eq!((*crl).idp_reasons, CRLDP_ALL_REASONS);
            assert!(!(*crl).meth.is_null());
            assert!((*crl).crl_number.is_null());
            X509_CRL_free(crl);
        }
    }

    /// `X509_CRL_up_ref` and `X509_CRL_free` move the count, and the object survives until the
    /// last reference goes.
    #[test]
    fn up_ref_keeps_the_object_alive() {
        // SAFETY: `crl` is a live object this test owns.
        unsafe {
            let crl = X509_CRL_new();
            assert_eq!((*crl).references, 1);
            assert_eq!(X509_CRL_up_ref(crl), 1);
            assert_eq!((*crl).references, 2);
            X509_CRL_free(crl);
            assert_eq!((*crl).references, 1);
            X509_CRL_free(crl);
        }
    }

    /// The method object and the CRL's `meth_data` slot round-trip. The process-wide
    /// `X509_CRL_set_default_method` global is deliberately not exercised here, because the test
    /// harness runs tests concurrently and mutating it could race a CRL another test is freeing.
    #[test]
    fn method_object_and_meth_data_round_trip() {
        // SAFETY: every object below is one this test owns.
        unsafe {
            let m = X509_CRL_METHOD_new(None, None, None, None);
            assert!(!m.is_null());
            assert_eq!((*m).flags, X509_CRL_METHOD_DYNAMIC);
            X509_CRL_METHOD_free(m);

            let crl = X509_CRL_new();
            assert!((*crl).meth_data.is_null());
            X509_CRL_set_meth_data(crl, 0x1234 as *mut c_void);
            assert_eq!(X509_CRL_get_meth_data(crl), 0x1234 as *mut c_void);

            // A fresh CRL has no revoked entries, so a serial lookup answers 0 with `ret` NULL.
            let mut rev: *mut X509Revoked = ptr::null_mut();
            assert_eq!(X509_CRL_get0_by_serial(crl, &raw mut rev, ptr::null()), 0);
            assert!(rev.is_null());

            X509_CRL_free(crl);
        }
    }
}
