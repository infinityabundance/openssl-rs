//! `crypto/x509/x_crl.c` — the `X509_CRL` object core, transcribed as far as 10.8's slice reaches.
//! Phase 10.8.
//!
//! `crypto/x509/x_crl.c` is 542 lines and reaches a great deal. **This module lands the object
//! core only**: the `X509_REVOKED`, `X509_CRL_INFO` and `X509_CRL` structures with the authority's
//! own layout, their four item descriptors (`X509_REVOKED_it`, `X509_CRL_INFO_it`, `X509_CRL_it`),
//! the `crl_inf_cb` and `crl_cb` callbacks in the part the item layer can build, the lifecycles
//! (`_new`/`_new_ex`/`_free`/`_dup`, `d2i_`/`i2d_`), the `X509_REVOKED_cmp` comparator and
//! `ossl_x509_crl_set0_libctx`. **The rest is withheld by name**:
//!
//! | withheld | blocker |
//! |---|---|
//! | `crl_cb`'s `ASN1_OP_D2I_POST` arm | `X509_CRL_digest`, `X509_CRL_get_ext_d2i`, `setup_idp`, `crl_set_issuers` and the `EXFLAG_*` words — none landed |
//! | `crl_cb`'s cache frees in `D2I_PRE`/`FREE_POST` | `AUTHORITY_KEYID_free`, `ISSUING_DIST_POINT_free`, `sk_GENERAL_NAMES_pop_free` (`v3_akid.c`/`v3_crld.c`/`v3_genn.c`) |
//! | `def_crl_lookup`, `def_crl_verify`, `crl_revoked_issuer_match` | the `v3_*`/`x509_cmp` graph |
//! | `crl_set_issuers`, `setup_idp` | `X509_REVOKED_get_ext_d2i`, `DIST_POINT_set_dpname` |
//! | `X509_CRL_verify`, `X509_CRL_get0_by_serial`, `X509_CRL_get0_by_cert`, `X509_CRL_add0_revoked` | the method vtable's unlanded entries |
//! | `X509_CRL_set_default_method`, `X509_CRL_METHOD_new`/`_free`, `X509_CRL_set_meth_data`/`get_meth_data` | the method object |
//!
//! The `ASN1_OP_NEW_POST` arm sets `crl->meth` to a **default method whose four callbacks are
//! NULL**, because the two the authority installs (`def_crl_lookup`, `def_crl_verify`) are
//! unlanded. The only observable consequence is inside the withheld accessors that read the
//! vtable; `D2I_PRE`'s `crl->meth->crl_free` guard, which the item layer does reach, tests a slot
//! that is NULL in the authority's own default method too.
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
//! ## No raise in the landed subset
//!
//! `x_crl.c`'s only two raises are in `X509_CRL_add0_revoked` (`:374`) and `def_crl_verify`
//! (`:408`), both withheld, so `crypto/x509/x_crl.c` is deliberately **not** an entry in
//! `gen_err_raise_sites.py`'s `COVERED_FILES`.
//!
//! SPDX-License-Identifier: Apache-2.0

// The structures below carry the authority's own member names (`serialNumber`, `lastUpdate`, ...)
// and the comparator its own symbol name, so a reader can line them up with the headers without a
// translation table.
#![allow(non_snake_case)]

use core::ffi::{c_char, c_int, c_long, c_uchar, c_void};
use core::ptr;

use crate::asn1::a_dup::ASN1_item_dup;
use crate::asn1::d2i::ASN1_item_d2i;
use crate::asn1::fre::ASN1_item_free;
use crate::asn1::i2d::ASN1_item_i2d;
use crate::asn1::items::{ASN1_BIT_STRING_it, ASN1_INTEGER_it, ASN1_TIME_it};
use crate::asn1::layout::*;
use crate::asn1::new::ASN1_item_new;
use crate::asn1::string::ASN1_STRING_cmp;
use crate::asn1::x_algor::{X509Algor, X509_ALGOR_it};
use crate::runtime::mem::{CRYPTO_free, CRYPTO_strdup};
use crate::runtime::stack::{OPENSSL_sk_set_cmp_func, OpenSslStack};
use crate::runtime::thread::CryptoRwlock;
use crate::x509::x_exten::X509_EXTENSION_it;
use crate::x509::x_name::{X509Name, X509_NAME_it};

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

/// `X509_CRL_METHOD` — `struct x509_crl_method_st`, from `crypto/x509/x509_local.h`.
///
/// The four callbacks are optional; the default method's `crl_init`/`crl_free` are NULL and, in
/// this crate, so are `crl_lookup`/`crl_verify` (see the module doc).
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

/// `static X509_CRL_METHOD int_crl_meth` — `crypto/x509/x_crl.c:33-38`.
///
/// The authority's initialiser installs `def_crl_lookup` and `def_crl_verify`; both are withheld
/// (they reach the `v3_*`/`x509_cmp` graph), so their slots are NULL here. `crl_init` and
/// `crl_free` are NULL in the authority too.
static INT_CRL_METH: X509CrlMethod = X509CrlMethod {
    flags: 0,
    crl_init: None,
    crl_free: None,
    crl_lookup: None,
    crl_verify: None,
};

/// `static const X509_CRL_METHOD *default_crl_method = &int_crl_meth` — `crypto/x509/x_crl.c:40`.
fn default_crl_method() -> *const X509CrlMethod {
    &INT_CRL_METH
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
}
