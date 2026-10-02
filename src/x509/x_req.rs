//! `crypto/x509/x_req.c` — the `X509_REQ` object core, transcribed whole. Phase 11.4.
//!
//! `crypto/x509/x_req.c` is 167 lines and publishes the certificate request's ASN.1 items, its
//! lifecycle and its two library-context helpers. **The whole unit lands here**; nothing is
//! withheld and nothing is stubbed.
//!
//! * `rintf_cb` (`:35-46`) and `req_cb` (`:48-101`), the two `ASN1_AUX` callbacks; they are
//!   `static` in the authority and file-private here.
//! * The `X509_REQ_INFO` item — `ASN1_SEQUENCE_enc(X509_REQ_INFO, enc, rinf_cb)` (`:103-111`) and
//!   its `ASN1_SEQUENCE_END_enc` descriptor, with `IMPLEMENT_ASN1_FUNCTIONS(X509_REQ_INFO)`
//!   (`:113`) giving the `_it`/`_new`/`_free`/`d2i_`/`i2d_` group.
//! * The `X509_REQ` item — `ASN1_SEQUENCE_ref(X509_REQ, req_cb)` (`:115-119`), its descriptor and
//!   `IMPLEMENT_ASN1_FUNCTIONS(X509_REQ)` (`:121`) plus `IMPLEMENT_ASN1_DUP_FUNCTION(X509_REQ)`
//!   (`:123`) for `X509_REQ_dup`.
//! * `X509_REQ_set0_distinguishing_id` (`:125-129`) and `X509_REQ_get0_distinguishing_id`
//!   (`:131-134`).
//! * `ossl_x509_req_set0_libctx` (`:141-155`), declared in `include/crypto/x509.h:322` (an
//!   internal header) but exported with `#[no_mangle]` like its `X509_CRL` twin; and
//!   `X509_REQ_new_ex` (`:157-167`), the header's public constructor.
//!
//! The **fourteen public exports** the ledger assigns to this unit are the item/lifecycle group
//! and the two `distinguishing_id` accessors; `ossl_x509_req_set0_libctx` is the fifteenth,
//! internal symbol. [`crate::x509::x509_req`] is where the `X509_REQ_INFO`/`X509_REQ` structures
//! themselves are laid out (that file's doc carries the measured sizes and offsets), so this
//! module names them rather than redeclaring them — the same split `x_crl.c`/`x_crl.rs` has.
//!
//! ## The two callback-bearing templates
//!
//! `ASN1_SEQUENCE_enc(X509_REQ_INFO, enc, rinf_cb)` gives the `X509_REQ_INFO` item an `ASN1_AUX`
//! with `ASN1_AFLG_ENCODING`, `enc_offset = offsetof(X509_REQ_INFO, enc) = 0` and `rinf_cb`.
//! `rinf_cb`'s one arm is `ASN1_OP_NEW_POST`: it installs an empty `STACK_OF(X509_ATTRIBUTE)` in
//! the `attributes` field, which the template's `ASN1_IMP_SET_OF_OPT` left absent — the PKCS#10
//! tolerance the authority's comment block (`:16-33`) documents.
//!
//! `ASN1_SEQUENCE_ref(X509_REQ, req_cb)` gives the `X509_REQ` item `ASN1_AFLG_REFCOUNT`,
//! `ref_offset = offsetof(X509_REQ, references) = 80`, `ref_lock = offsetof(X509_REQ, lock) = 88`
//! and `req_cb`. `req_cb` clears the `distinguishing_id` on `D2I_PRE`/`NEW_POST`, frees
//! `distinguishing_id` and `propq` on `FREE_POST`, propagates the library context and property
//! query on `DUP_POST` (duplicating the public key when the source has one), and answers the
//! `GET0_LIBCTX`/`GET0_PROPQ` queries `ASN1_item_dup` makes of it.
//!
//! ## The raise sites
//!
//! `crypto/x509/x_req.c` is not an entry in `gen_err_raise_sites.py`'s `COVERED_FILES`, so its two
//! coordinates — both in `req_cb`'s `ASN1_OP_DUP_POST` arm — are **declared locally**, their
//! reason values read from the authority's `err.h` (not typed from memory), as `v3_pcons.rs` does:
//! `X_REQ_76` (`ERR_R_EVP_LIB`, when `EVP_PKEY_dup` fails) and `X_REQ_81`
//! (`ERR_R_INTERNAL_ERROR`, when `X509_PUBKEY_set` fails).
//!
//! SPDX-License-Identifier: Apache-2.0

#![allow(non_snake_case)]

use core::ffi::{c_char, c_int, c_long, c_uchar, c_void};
use core::ptr;

use crate::asn1::a_dup::ASN1_item_dup;
use crate::asn1::d2i::ASN1_item_d2i;
use crate::asn1::fre::ASN1_item_free;
use crate::asn1::i2d::ASN1_item_i2d;
use crate::asn1::items::{ASN1_BIT_STRING_it, ASN1_INTEGER_it};
use crate::asn1::layout::*;
use crate::asn1::new::ASN1_item_new;
use crate::asn1::string::ASN1_OCTET_STRING_free;
use crate::asn1::x_algor::X509_ALGOR_it;
use crate::evp::pkey::{EVP_PKEY_dup, EVP_PKEY_free};
use crate::runtime::err::{err_sites::ErrSite, raise_site};
use crate::runtime::mem::{CRYPTO_free, CRYPTO_strdup};
use crate::runtime::stack::OPENSSL_sk_new_null;
use crate::x509::x509_req::{X509Req, X509ReqInfo};
use crate::x509::x_attrib::X509_ATTRIBUTE_it;
use crate::x509::x_name::X509_NAME_it;
use crate::x509::x_pubkey::{X509_PUBKEY_get0, X509_PUBKEY_it, X509_PUBKEY_set};

/// The `OPENSSL_FILE` string for this unit's `OPENSSL_free`/`OPENSSL_strdup` expansions, and the
/// lines they expand at.
const FILE: &core::ffi::CStr = c"crypto/x509/x_req.c";
/// `req_cb`'s `OPENSSL_free(ret->propq)` (`crypto/x509/x_req.c:63`).
const LINE_FREE_PROPQ_FREE_POST: c_int = 63;
/// `ossl_x509_req_set0_libctx`'s `OPENSSL_free(x->propq)` (`:146`).
const LINE_FREE_PROPQ: c_int = 146;
/// `ossl_x509_req_set0_libctx`'s `OPENSSL_strdup(propq)` (`:149`).
const LINE_STRDUP_PROPQ: c_int = 149;

/// `ERR_LIB_X509` — `include/openssl/err.h.in:85`, `11`. Both of `req_cb`'s raises name it.
const ERR_LIB_X509: c_int = 11;
/// `ERR_R_EVP_LIB` — `include/openssl/err.h.in:322`, `(ERR_LIB_EVP | ERR_RFLAG_COMMON)`.
const ERR_R_EVP_LIB: c_int = 524294;
/// `ERR_R_INTERNAL_ERROR` — `include/openssl/err.h.in:357`, `(259 | ERR_R_FATAL)`.
const ERR_R_INTERNAL_ERROR: c_int = 786691;

/// One `x_req.c` raise coordinate, declared locally (see the module doc).
const fn x_req_site(line: c_int, func: &'static core::ffi::CStr, reason: c_int) -> ErrSite {
    ErrSite {
        file: c"../../src/openssl-3.6.4/crypto/x509/x_req.c",
        line,
        func,
        lib: ERR_LIB_X509,
        reason,
        dynamic_reason: false,
    }
}

/// `req_cb`'s failed `EVP_PKEY_dup` at `crypto/x509/x_req.c:76` (`ERR_R_EVP_LIB`).
const X_REQ_76: ErrSite = x_req_site(76, c"req_cb", ERR_R_EVP_LIB);
/// `req_cb`'s failed `X509_PUBKEY_set` at `crypto/x509/x_req.c:81` (`ERR_R_INTERNAL_ERROR`).
const X_REQ_81: ErrSite = x_req_site(81, c"req_cb", ERR_R_INTERNAL_ERROR);

// ---------------------------------------------------------------------------------------------
// The `X509_REQ_INFO` item — `ASN1_SEQUENCE_enc(X509_REQ_INFO, enc, rinf_cb)` (`:103-111`)
// ---------------------------------------------------------------------------------------------

/// `static int rinf_cb(int operation, ASN1_VALUE **pval, const ASN1_ITEM *it, void *exarg)` —
/// `crypto/x509/x_req.c:35-46`.
///
/// The one arm is `ASN1_OP_NEW_POST`: the template's optional `attributes` field is left absent,
/// so a freshly-built request gets the empty stack the PKCS#10 encoding needs.
///
/// # Safety
/// The item layer's own callback contract.
unsafe extern "C" fn rinf_cb(
    operation: c_int,
    pval: *mut *mut c_void,
    it: *const Asn1Item,
    exarg: *mut c_void,
) -> c_int {
    let _ = (it, exarg);
    // SAFETY: `pval` points at a live `X509_REQ_INFO` for every operation.
    let rinf = unsafe { (*pval).cast::<X509ReqInfo>() };
    if operation == ASN1_OP_NEW_POST {
        // SAFETY: `rinf` is a fresh value this operation owns.
        let sk = OPENSSL_sk_new_null();
        if sk.is_null() {
            return 0;
        }
        // SAFETY: `rinf` is live and `attributes` is its own field.
        unsafe { (*rinf).attributes = sk };
    }
    1
}

/// `X509_REQ_INFO`'s `ASN1_AUX` — `ASN1_SEQUENCE_enc(X509_REQ_INFO, enc, rinf_cb)` (`:103`):
/// `ASN1_AFLG_ENCODING`, `enc_offset = offsetof(X509_REQ_INFO, enc) = 0` and `rinf_cb`.
struct SyncAuxInfo(Asn1Aux);

// SAFETY: a `static` compiled from constants and one function pointer, written once by the
// loader, with no interior mutability reachable through the shared reference the item takes.
unsafe impl Sync for SyncAuxInfo {}

/// The `ASN1_AUX` block named above.
static X509_REQ_INFO_AUX: SyncAuxInfo = SyncAuxInfo(Asn1Aux {
    app_data: ptr::null_mut(),
    flags: ASN1_AFLG_ENCODING,
    ref_offset: 0,
    ref_lock: 0,
    asn1_cb: Some(rinf_cb),
    enc_offset: 0,
    asn1_const_cb: None,
});

/// `X509_REQ_INFO_seq_tt` — `ASN1_SEQUENCE_enc(X509_REQ_INFO, enc, rinf_cb)` (`:103-111`):
/// `ASN1_SIMPLE(version, ASN1_INTEGER)`, `ASN1_SIMPLE(subject, X509_NAME)`,
/// `ASN1_SIMPLE(pubkey, X509_PUBKEY)` and `ASN1_IMP_SET_OF_OPT(attributes, X509_ATTRIBUTE, 0)`.
static X509_REQ_INFO_TT: [Asn1Template; 4] = [
    Asn1Template {
        flags: 0,
        tag: 0,
        offset: 24,
        field_name: c"version".as_ptr(),
        item: ASN1_INTEGER_it as *mut c_void,
    },
    Asn1Template {
        flags: 0,
        tag: 0,
        offset: 32,
        field_name: c"subject".as_ptr(),
        item: X509_NAME_it as *mut c_void,
    },
    Asn1Template {
        flags: 0,
        tag: 0,
        offset: 40,
        field_name: c"pubkey".as_ptr(),
        item: X509_PUBKEY_it as *mut c_void,
    },
    Asn1Template {
        flags: ASN1_TFLG_IMPLICIT | ASN1_TFLG_SET_OF | ASN1_TFLG_OPTIONAL,
        tag: 0,
        offset: 48,
        field_name: c"attributes".as_ptr(),
        item: X509_ATTRIBUTE_it as *mut c_void,
    },
];

/// `X509_REQ_INFO_it`'s descriptor — `ASN1_SEQUENCE_END_enc(X509_REQ_INFO, X509_REQ_INFO)` at
/// `crypto/x509/x_req.c:111`.
static X509_REQ_INFO_ITEM: Asn1Item = Asn1Item {
    itype: ASN1_ITYPE_SEQUENCE,
    utype: V_ASN1_SEQUENCE as c_long,
    templates: X509_REQ_INFO_TT.as_ptr(),
    tcount: 4,
    funcs: (&X509_REQ_INFO_AUX.0) as *const Asn1Aux as *const c_void,
    size: core::mem::size_of::<X509ReqInfo>() as c_long,
    sname: c"X509_REQ_INFO".as_ptr(),
};

/// `const ASN1_ITEM *X509_REQ_INFO_it(void)` — `include/openssl/x509.h:746`, from
/// `ASN1_SEQUENCE_END_enc(X509_REQ_INFO, X509_REQ_INFO)`.
#[no_mangle]
pub extern "C" fn X509_REQ_INFO_it() -> *const Asn1Item {
    &X509_REQ_INFO_ITEM
}

/// `X509_REQ_INFO *X509_REQ_INFO_new(void)` — `crypto/x509/x_req.c:113`, from
/// `IMPLEMENT_ASN1_FUNCTIONS(X509_REQ_INFO)`.
#[no_mangle]
pub extern "C" fn X509_REQ_INFO_new() -> *mut X509ReqInfo {
    // SAFETY: `X509_REQ_INFO_it()` answers a static item the crate owns.
    unsafe { ASN1_item_new(X509_REQ_INFO_it()).cast::<X509ReqInfo>() }
}

/// `void X509_REQ_INFO_free(X509_REQ_INFO *a)` — the same macro's free half.
///
/// # Safety
///
/// `a` is NULL or a value this item layer built.
#[no_mangle]
pub unsafe extern "C" fn X509_REQ_INFO_free(a: *mut X509ReqInfo) {
    // SAFETY: `a` is NULL or a live item value per the contract.
    unsafe { ASN1_item_free(a.cast(), X509_REQ_INFO_it()) }
}

/// `X509_REQ_INFO *d2i_X509_REQ_INFO(X509_REQ_INFO **a, const unsigned char **in, long len)` —
/// `crypto/x509/x_req.c:113`'s generated decoder.
///
/// # Safety
///
/// `a` is NULL or a writable slot; `in_` points at a readable cursor; `len` describes the input.
#[no_mangle]
pub unsafe extern "C" fn d2i_X509_REQ_INFO(
    a: *mut *mut X509ReqInfo,
    in_: *mut *const c_uchar,
    len: c_long,
) -> *mut X509ReqInfo {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer here.
    unsafe { ASN1_item_d2i(a.cast(), in_, len, X509_REQ_INFO_it()).cast::<X509ReqInfo>() }
}

/// `int i2d_X509_REQ_INFO(const X509_REQ_INFO *a, unsigned char **out)` — the same macro's
/// encoder.
///
/// # Safety
///
/// `a` is NULL or a live value; `out` is NULL or a writable cursor.
#[no_mangle]
pub unsafe extern "C" fn i2d_X509_REQ_INFO(a: *const X509ReqInfo, out: *mut *mut c_uchar) -> c_int {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer here.
    unsafe { ASN1_item_i2d(a.cast(), out, X509_REQ_INFO_it()) }
}

// ---------------------------------------------------------------------------------------------
// The `req_cb` callback and the `X509_REQ` item — `crypto/x509/x_req.c:48-123`
// ---------------------------------------------------------------------------------------------

/// `static int req_cb(int operation, ASN1_VALUE **pval, const ASN1_ITEM *it, void *exarg)` —
/// `crypto/x509/x_req.c:48-101`.
///
/// The authority's `ASN1_OP_D2I_PRE` falls through to its `ASN1_OP_NEW_POST` arm after freeing the
/// old `distinguishing_id`; the two are kept as separate arms here with the free repeated, which
/// is what the fall-through means. The `DUP_POST` arm duplicates the source's public key through
/// `EVP_PKEY_dup`/`X509_PUBKEY_set`, raising `X_REQ_76`/`X_REQ_81` on either failure.
///
/// # Safety
/// The item layer's own callback contract.
unsafe extern "C" fn req_cb(
    operation: c_int,
    pval: *mut *mut c_void,
    it: *const Asn1Item,
    exarg: *mut c_void,
) -> c_int {
    let _ = it;
    // SAFETY: `pval` points at a live `X509_REQ` for every operation.
    let ret = unsafe { (*pval).cast::<X509Req>() };

    match operation {
        ASN1_OP_D2I_PRE => {
            // SAFETY: `ret` is live; `distinguishing_id` is its own field.
            unsafe {
                ASN1_OCTET_STRING_free((*ret).distinguishing_id);
                (*ret).distinguishing_id = ptr::null_mut();
            }
        }
        ASN1_OP_NEW_POST => {
            // SAFETY: `ret` is live; `distinguishing_id` is its own field.
            unsafe { (*ret).distinguishing_id = ptr::null_mut() };
        }
        ASN1_OP_FREE_POST => {
            // SAFETY: `ret` is live; the two fields are its own.
            unsafe {
                ASN1_OCTET_STRING_free((*ret).distinguishing_id);
                CRYPTO_free(
                    (*ret).propq.cast(),
                    FILE.as_ptr(),
                    LINE_FREE_PROPQ_FREE_POST,
                );
            }
        }
        ASN1_OP_DUP_POST => {
            // SAFETY: `exarg` is the source `X509_REQ` for this operation.
            let old = exarg.cast::<X509Req>();
            // SAFETY: `ret` and `old` are live per the item layer's contract.
            unsafe {
                if ossl_x509_req_set0_libctx(ret, (*old).libctx, (*old).propq) == 0 {
                    return 0;
                }
                if !(*old).req_info.pubkey.is_null() {
                    let mut pkey = X509_PUBKEY_get0((*old).req_info.pubkey);
                    if !pkey.is_null() {
                        pkey = EVP_PKEY_dup(pkey);
                        if pkey.is_null() {
                            // SAFETY: a compiled-in site coordinate.
                            raise_site(&X_REQ_76);
                            return 0;
                        }
                        if X509_PUBKEY_set(&raw mut (*ret).req_info.pubkey, pkey) == 0 {
                            // SAFETY: `pkey` is this arm's own duplicate.
                            EVP_PKEY_free(pkey);
                            // SAFETY: a compiled-in site coordinate.
                            raise_site(&X_REQ_81);
                            return 0;
                        }
                        // SAFETY: `pkey` is this arm's own duplicate.
                        EVP_PKEY_free(pkey);
                    }
                }
            }
        }
        ASN1_OP_GET0_LIBCTX => {
            let libctx = exarg.cast::<*mut c_void>();
            // SAFETY: `libctx` is the caller's out-slot; `ret` is live.
            unsafe { *libctx = (*ret).libctx };
        }
        ASN1_OP_GET0_PROPQ => {
            let propq = exarg.cast::<*const c_char>();
            // SAFETY: `propq` is the caller's out-slot; `ret` is live.
            unsafe { *propq = (*ret).propq };
        }
        _ => {}
    }
    1
}

/// `X509_REQ`'s `ASN1_AUX` — `ASN1_SEQUENCE_ref(X509_REQ, req_cb)` (`:115`): `ASN1_AFLG_REFCOUNT`,
/// `ref_offset = offsetof(X509_REQ, references) = 80`, `ref_lock = offsetof(X509_REQ, lock) = 88`
/// and `req_cb`.
struct SyncAux(Asn1Aux);

// SAFETY: a `static` compiled from constants and one function pointer, written once by the loader,
// with no interior mutability reachable through the shared reference the item takes.
unsafe impl Sync for SyncAux {}

/// The `ASN1_AUX` block named above.
static X509_REQ_AUX: SyncAux = SyncAux(Asn1Aux {
    app_data: ptr::null_mut(),
    flags: ASN1_AFLG_REFCOUNT,
    ref_offset: 80,
    ref_lock: 88,
    asn1_cb: Some(req_cb),
    enc_offset: 0,
    asn1_const_cb: None,
});

/// `X509_REQ_seq_tt` — `ASN1_SEQUENCE_ref(X509_REQ, req_cb)` (`:115-119`):
/// `ASN1_EMBED(X509_REQ, req_info, X509_REQ_INFO)`, `ASN1_EMBED(X509_REQ, sig_alg, X509_ALGOR)`
/// and `ASN1_SIMPLE(X509_REQ, signature, ASN1_BIT_STRING)`.
static X509_REQ_TT: [Asn1Template; 3] = [
    Asn1Template {
        flags: ASN1_TFLG_EMBED,
        tag: 0,
        offset: 0,
        field_name: c"req_info".as_ptr(),
        item: X509_REQ_INFO_it as *mut c_void,
    },
    Asn1Template {
        flags: ASN1_TFLG_EMBED,
        tag: 0,
        offset: 56,
        field_name: c"sig_alg".as_ptr(),
        item: X509_ALGOR_it as *mut c_void,
    },
    Asn1Template {
        flags: 0,
        tag: 0,
        offset: 72,
        field_name: c"signature".as_ptr(),
        item: ASN1_BIT_STRING_it as *mut c_void,
    },
];

/// `X509_REQ_it`'s descriptor — `ASN1_SEQUENCE_END_ref(X509_REQ, X509_REQ)` at
/// `crypto/x509/x_req.c:119`.
static X509_REQ_ITEM: Asn1Item = Asn1Item {
    itype: ASN1_ITYPE_SEQUENCE,
    utype: V_ASN1_SEQUENCE as c_long,
    templates: X509_REQ_TT.as_ptr(),
    tcount: 3,
    funcs: (&X509_REQ_AUX.0) as *const Asn1Aux as *const c_void,
    size: core::mem::size_of::<X509Req>() as c_long,
    sname: c"X509_REQ".as_ptr(),
};

/// `const ASN1_ITEM *X509_REQ_it(void)` — `include/openssl/x509.h:747`, from
/// `ASN1_SEQUENCE_END_ref(X509_REQ, X509_REQ)`.
#[no_mangle]
pub extern "C" fn X509_REQ_it() -> *const Asn1Item {
    &X509_REQ_ITEM
}

/// `X509_REQ *X509_REQ_new(void)` — `crypto/x509/x_req.c:121`, from
/// `IMPLEMENT_ASN1_FUNCTIONS(X509_REQ)`.
#[no_mangle]
pub extern "C" fn X509_REQ_new() -> *mut X509Req {
    // SAFETY: `X509_REQ_it()` answers a static item the crate owns; its `ASN1_AFLG_REFCOUNT`
    // initialises the reference count to one.
    unsafe { ASN1_item_new(X509_REQ_it()).cast::<X509Req>() }
}

/// `void X509_REQ_free(X509_REQ *a)` — the same macro's free half. The reference count
/// `X509_REQ_it`'s `ASN1_AFLG_REFCOUNT` maintains is decremented by the item layer.
///
/// # Safety
///
/// `a` is NULL or a value this item layer built.
#[no_mangle]
pub unsafe extern "C" fn X509_REQ_free(a: *mut X509Req) {
    // SAFETY: `a` is NULL or a live item value per the contract.
    unsafe { ASN1_item_free(a.cast(), X509_REQ_it()) }
}

/// `X509_REQ *X509_REQ_dup(const X509_REQ *a)` — `IMPLEMENT_ASN1_DUP_FUNCTION(X509_REQ)`
/// (`crypto/x509/x_req.c:123`).
///
/// The duplicate is a round trip through the encoder and decoder, so `req_cb`'s `DUP_POST` arm
/// runs and the copy carries the source's library context and its own public-key duplicate.
///
/// # Safety
///
/// `a` is NULL or a live value.
#[no_mangle]
pub unsafe extern "C" fn X509_REQ_dup(a: *const X509Req) -> *mut X509Req {
    // SAFETY: `a` is NULL or live per the contract; `X509_REQ_it()` is a static item.
    unsafe { ASN1_item_dup(X509_REQ_it(), a.cast()).cast::<X509Req>() }
}

/// `X509_REQ *d2i_X509_REQ(X509_REQ **a, const unsigned char **in, long len)` —
/// `crypto/x509/x_req.c:121`'s generated decoder.
///
/// # Safety
///
/// `a` is NULL or a writable slot; `in_` points at a readable cursor; `len` describes the input.
#[no_mangle]
pub unsafe extern "C" fn d2i_X509_REQ(
    a: *mut *mut X509Req,
    in_: *mut *const c_uchar,
    len: c_long,
) -> *mut X509Req {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer here.
    unsafe { ASN1_item_d2i(a.cast(), in_, len, X509_REQ_it()).cast::<X509Req>() }
}

/// `int i2d_X509_REQ(const X509_REQ *a, unsigned char **out)` — the same macro's encoder.
///
/// # Safety
///
/// `a` is NULL or a live value; `out` is NULL or a writable cursor.
#[no_mangle]
pub unsafe extern "C" fn i2d_X509_REQ(a: *const X509Req, out: *mut *mut c_uchar) -> c_int {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer here.
    unsafe { ASN1_item_i2d(a.cast(), out, X509_REQ_it()) }
}

/// `void X509_REQ_set0_distinguishing_id(X509_REQ *x, ASN1_OCTET_STRING *d_id)` —
/// `crypto/x509/x_req.c:125-129`.
///
/// Frees the request's current `distinguishing_id` and takes ownership of `d_id`.
///
/// # Safety
///
/// `x` is live; `d_id` is NULL or owned by the caller and handed over.
#[no_mangle]
pub unsafe extern "C" fn X509_REQ_set0_distinguishing_id(x: *mut X509Req, d_id: *mut Asn1String) {
    // SAFETY: `x` is live per the contract; `distinguishing_id` is its own field.
    unsafe {
        ASN1_OCTET_STRING_free((*x).distinguishing_id);
        (*x).distinguishing_id = d_id;
    }
}

/// `ASN1_OCTET_STRING *X509_REQ_get0_distinguishing_id(X509_REQ *x)` —
/// `crypto/x509/x_req.c:131-134`.
///
/// # Safety
///
/// `x` is live.
#[no_mangle]
pub unsafe extern "C" fn X509_REQ_get0_distinguishing_id(x: *mut X509Req) -> *mut Asn1String {
    // SAFETY: `x` is live per the contract.
    unsafe { (*x).distinguishing_id }
}

/// `int ossl_x509_req_set0_libctx(X509_REQ *x, OSSL_LIB_CTX *libctx, const char *propq)` —
/// `crypto/x509/x_req.c:141-155`.
///
/// Declared in `include/crypto/x509.h:322`. A NULL `x` answers 1; otherwise the library context is
/// stored, the old property query freed and (when `propq` is non-NULL) a copy strdup'd in.
///
/// # Safety
///
/// `x` is NULL or a live `X509_REQ`; `libctx` is NULL or a live context and `propq` NULL or
/// NUL-terminated.
#[no_mangle]
pub unsafe extern "C" fn ossl_x509_req_set0_libctx(
    x: *mut X509Req,
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

/// `X509_REQ *X509_REQ_new_ex(OSSL_LIB_CTX *libctx, const char *propq)` —
/// `crypto/x509/x_req.c:157-167`.
///
/// Builds the item with `ASN1_item_new` (the authority does not use `ASN1_item_new_ex` here) and
/// installs the context through [`ossl_x509_req_set0_libctx`], freeing the request if that fails.
///
/// # Safety
///
/// `libctx` is NULL or a live context and `propq` NULL or NUL-terminated.
#[no_mangle]
pub unsafe extern "C" fn X509_REQ_new_ex(
    libctx: *mut c_void,
    propq: *const c_char,
) -> *mut X509Req {
    // SAFETY: `X509_REQ_it()` is a static item the crate owns.
    let req = unsafe { ASN1_item_new(X509_REQ_it()).cast::<X509Req>() };
    // SAFETY: `req` is NULL or a fresh object; the context arguments are the caller's contract.
    if unsafe { ossl_x509_req_set0_libctx(req, libctx, propq) } == 0 {
        // SAFETY: `req` is NULL or a fresh object this call owns.
        unsafe { X509_REQ_free(req) };
        return ptr::null_mut();
    }
    req
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime::stack::OPENSSL_sk_num;

    /// A blank request carries the authority's new-object state: a one-valued reference count, the
    /// mandatory `subject`/`pubkey` allocated by the item layer and the empty `attributes` stack
    /// `rinf_cb` installs.
    ///
    /// A blank request is **not** duplicable — its empty `X509_PUBKEY` has a NULL algorithm OID, so
    /// the encode half of `ASN1_item_dup` refuses it, exactly as the authority's does — which is
    /// why `X509_REQ_dup` is exercised only through a request a caller has filled in.
    #[test]
    fn a_blank_request_has_the_authoritys_defaults() {
        // SAFETY: `req` is a live object this test owns.
        unsafe {
            let req = X509_REQ_new();
            assert!(!req.is_null());
            assert_eq!((*req).references, 1);
            assert!(!(*req).req_info.subject.is_null());
            assert!(!(*req).req_info.pubkey.is_null());
            assert!(!(*req).req_info.attributes.is_null());
            assert_eq!(OPENSSL_sk_num((*req).req_info.attributes), 0);
            X509_REQ_free(req);
        }
    }
}
