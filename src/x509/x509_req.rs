//! `crypto/x509/x509_req.c` — the `X509_REQ` object's accessor and mutator layer. **Phase 10.11
//! landed the pulled-forward subset** (the two layouts and the three accessors
//! `crypto/x509/v3_san.c`'s `v2i_subject_alt` reaches: `X509_REQ_get_subject_name`,
//! `X509_REQ_get_version` and `X509_REQ_get0_signature`); **Phase 11.4 lands the rest**.
//!
//! `crypto/x509/x509_req.c` is 350 lines. This unit lands **all twenty-four of its remaining
//! exports**: the public-key accessors (`X509_REQ_get_pubkey`/`_get0_pubkey`/
//! `_get_X509_PUBKEY`), `X509_REQ_check_private_key`, the three extension-NID table functions
//! (`X509_REQ_extension_nid`/`_get_extension_nids`/`_set_extension_nids`), the attribute surface
//! (`X509_REQ_get_attr_count`/`_get_attr_by_NID`/`_get_attr_by_OBJ`/`_get_attr`/`_delete_attr` and
//! the four `_add1_attr*` spellings), the signature setters (`X509_REQ_set0_signature`,
//! `X509_REQ_set1_signature_algo`, `X509_REQ_get_signature_nid`), `i2d_re_X509_REQ_tbs` and --
//! 11.4b's addition, on the `X509_EXTENSIONS` item `crate::x509::x_exten` lands --
//! `X509_REQ_get_extensions`, `X509_REQ_add_extensions_nid` and `X509_REQ_add_extensions`.
//! `X509_to_X509_REQ` joined them once 11.4 landed `X509_REQ_sign` (`crypto/x509/x_all.c`);
//! **nothing in the unit is withheld now.**
//!
//! The `X509_REQ` object's lifecycle and its `ASN1_ITEM` descriptors -- `X509_REQ_new_ex`,
//! `X509_REQ_free`, `X509_REQ_INFO_it`, `d2i_X509_REQ`, `i2d_X509_REQ`, ... -- are
//! `crypto/x509/x_req.c`, a **separate** authority translation unit, and are
//! [`crate::x509::x_req`]'s; that is why the two structs below carry no item descriptor. They are
//! laid out here because the landed accessors read them.
//!
//! ## The two layouts
//!
//! `struct X509_req_info_st` (`X509_REQ_INFO`) -- `include/crypto/x509.h:63-74`:
//!
//! ```text
//! struct X509_req_info_st {
//!     ASN1_ENCODING enc;          /* cached encoding of the signed part          */
//!     ASN1_INTEGER *version;      /* defaults to v1(0) so this can be NULL        */
//!     X509_NAME *subject;         /* certificate request DN                      */
//!     X509_PUBKEY *pubkey;        /* public key of the request                   */
//!     STACK_OF(X509_ATTRIBUTE) *attributes; /* optional; may be NULL             */
//! };
//! ```
//!
//! `struct X509_req_st` (`X509_REQ`) -- `include/crypto/x509.h:76-87`:
//!
//! ```text
//! struct X509_req_st {
//!     X509_REQ_INFO req_info;     /* signed certificate request data, embedded    */
//!     X509_ALGOR sig_alg;         /* signature algorithm, embedded                */
//!     ASN1_BIT_STRING *signature;
//!     CRYPTO_REF_COUNT references;/* struct { _Atomic int val; } -- modelled c_int */
//!     CRYPTO_RWLOCK *lock;
//!     ASN1_OCTET_STRING *distinguishing_id;
//!     OSSL_LIB_CTX *libctx;
//!     char *propq;
//! };
//! ```
//!
//! `CRYPTO_REF_COUNT` is `struct { _Atomic int val; }` (`include/internal/refcount.h:35-37`), so
//! its field is `c_int`, exactly as [`crate::x509::x_crl::X509Crl`]'s is. `sig_alg` is embedded
//! **by value**, as it is in `X509_CRL_INFO`, so it contributes 16 bytes at 56 rather than a
//! pointer. The sizes and every offset below were read from a measurement program compiled against
//! the pinned authority's own internal headers (`courts/layout`'s include set): `X509_REQ_INFO` is
//! **56** bytes and `X509_REQ` is **120**, the interesting one being `references`, four bytes at
//! 80, so 84..88 is padding before the pointer `lock` at 88.
//!
//! ## `X509_to_X509_REQ` landed last
//!
//! `X509_to_X509_REQ` (`crypto/x509/x509_req.c:22-61`) was withheld by name while `X509_REQ_sign`
//! (`crypto/x509/x_all.c`) was unlanded, which `src/x509/x_all.rs` recorded as a Phase 11.7 face.
//! 11.4 landed that signer and 11.7 lands this, over the whole landed closure (`X509_REQ_new_ex`,
//! `X509_REQ_set_subject_name`, `X509_get_subject_name`, `X509_get0_pubkey`, `X509_REQ_set_pubkey`,
//! `X509_REQ_free`).
//!
//! The four extension functions 11.4b lands depend on `X509_EXTENSIONS`, which
//! `crate::x509::x_exten` withheld through Phase 10.8 and now publishes; `get_extensions_by_nid`
//! raises `X509_R_WRONG_TYPE` (`include/openssl/x509err.h:67`, `122`) at `:133`, and that
//! coordinate is declared here as `X509_REQ_133` because 11.4b makes it reachable.
//!
//! The extension-NID functions themselves need no item and land: `NID_ext_req`, `NID_ms_ext_req`
//! and the `NID_undef` terminator (all landed) build the file-static `ext_nid_list`/`ext_nids` pair
//! (`:93`, `:95`).
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_char, c_int, c_long, c_uchar, c_void};
use core::ptr;

use crate::asn1::d2i::ASN1_item_d2i;
use crate::asn1::i2d::ASN1_item_i2d;
use crate::asn1::layout::{Asn1Encoding, Asn1String, V_ASN1_SEQUENCE};
use crate::asn1::prim::ASN1_INTEGER_get;
use crate::asn1::string::ASN1_BIT_STRING_free;
use crate::asn1::x_algor::{X509Algor, X509_ALGOR_copy};
use crate::evp::digest::EvpMd;
use crate::evp::pkey::EvpPkey;
use crate::runtime::err::err_reasons::X509_R_WRONG_TYPE;
use crate::runtime::err::{err_sites::ErrSite, raise_site};
use crate::runtime::mem::{CRYPTO_free, CRYPTO_malloc};
use crate::runtime::obj::{Asn1Object, NID_ext_req, NID_ms_ext_req, NID_undef, OBJ_obj2nid};
use crate::runtime::stack::{
    OPENSSL_sk_free, OPENSSL_sk_new_null, OPENSSL_sk_num, OPENSSL_sk_pop_free, OpenSslStack,
};
use crate::x509::x509_att::{
    X509_ATTRIBUTE_get0_type, X509at_add1_attr, X509at_add1_attr_by_NID, X509at_add1_attr_by_OBJ,
    X509at_add1_attr_by_txt, X509at_delete_attr, X509at_get_attr, X509at_get_attr_by_NID,
    X509at_get_attr_by_OBJ, X509at_get_attr_count,
};
use crate::x509::x509_cmp::ossl_x509_check_private_key;
use crate::x509::x509_cmp::{X509_get0_pubkey, X509_get_subject_name};
use crate::x509::x509_v3::X509v3_add_extensions;
use crate::x509::x509rset::{X509_REQ_set_pubkey, X509_REQ_set_subject_name};
use crate::x509::x_all::X509_REQ_sign;
use crate::x509::x_attrib::{X509Attribute, X509_ATTRIBUTE_free};
use crate::x509::x_exten::{X509_EXTENSIONS_it, X509_EXTENSION_free};
use crate::x509::x_name::X509Name;
use crate::x509::x_pubkey::{X509Pubkey, X509_PUBKEY_get, X509_PUBKEY_get0};
use crate::x509::x_req::{i2d_X509_REQ_INFO, X509_REQ_free, X509_REQ_new_ex};
use crate::x509::x_x509::X509;

/// `X509_REQ_VERSION_1` -- `include/openssl/x509.h:695`, `0`. The only version
/// `X509_REQ_set_version` (`src/x509/x509rset.rs`) accepts.
pub(crate) const X509_REQ_VERSION_1: c_long = 0;

/// `struct X509_req_info_st` -- `X509_REQ_INFO`, from `include/crypto/x509.h:63-74`.
///
/// The signed part of a certificate request. The `ASN1_ITEM` that names this structure
/// (`X509_REQ_INFO_it`) is `crypto/x509/x_req.c`, a different unit, and is not here.
#[repr(C)]
pub struct X509ReqInfo {
    /// `ASN1_ENCODING enc` -- the cached encoding of the signed part.
    pub(crate) enc: Asn1Encoding,
    /// `ASN1_INTEGER *version` -- defaults to v1 (0), so nullable.
    pub(crate) version: *mut Asn1String,
    /// `X509_NAME *subject` -- the certificate request's distinguished name.
    pub(crate) subject: *mut X509Name,
    /// `X509_PUBKEY *pubkey` -- the public key of the request.
    pub(crate) pubkey: *mut X509Pubkey,
    /// `STACK_OF(X509_ATTRIBUTE) *attributes` -- zero or more attributes, possibly NULL in a
    /// broken encoding that omits the mandatory field.
    pub(crate) attributes: *mut OpenSslStack,
}

const _: () = {
    assert!(core::mem::size_of::<X509ReqInfo>() == 56);
    assert!(core::mem::offset_of!(X509ReqInfo, enc) == 0);
    assert!(core::mem::offset_of!(X509ReqInfo, version) == 24);
    assert!(core::mem::offset_of!(X509ReqInfo, subject) == 32);
    assert!(core::mem::offset_of!(X509ReqInfo, pubkey) == 40);
    assert!(core::mem::offset_of!(X509ReqInfo, attributes) == 48);
};

/// `struct X509_req_st` -- `X509_REQ`, from `include/crypto/x509.h:76-87`.
///
/// The whole certificate request: the embedded [`X509ReqInfo`], the signature and its algorithm,
/// the reference count and the library context. `lock` and `libctx` are opaque here and modelled
/// as `*mut c_void`, exactly as the task's layout contract states; both are pointers, so the
/// layout is exact. The lifecycle that would populate them (`X509_REQ_new_ex`/`X509_REQ_free`) is
/// `crypto/x509/x_req.c` and unlanded, so no landed code reads those fields.
#[repr(C)]
pub struct X509Req {
    /// `X509_REQ_INFO req_info` -- the signed body, embedded.
    pub(crate) req_info: X509ReqInfo,
    /// `X509_ALGOR sig_alg` -- the signature algorithm, embedded.
    pub(crate) sig_alg: X509Algor,
    /// `ASN1_BIT_STRING *signature` -- the signature over `req_info`.
    pub(crate) signature: *mut Asn1String,
    /// `CRYPTO_REF_COUNT references` -- `struct { _Atomic int val; }`, so `c_int`.
    pub(crate) references: c_int,
    /// `CRYPTO_RWLOCK *lock` -- guards the reference count (type opaque here).
    pub(crate) lock: *mut c_void,
    /// `ASN1_OCTET_STRING *distinguishing_id` -- the authentication stamp, optional.
    pub(crate) distinguishing_id: *mut Asn1String,
    /// `OSSL_LIB_CTX *libctx` -- the object's library context (type opaque here).
    pub(crate) libctx: *mut c_void,
    /// `char *propq` -- the object's property query, owned.
    pub(crate) propq: *mut c_char,
}

const _: () = {
    assert!(core::mem::size_of::<X509Req>() == 120);
    assert!(core::mem::offset_of!(X509Req, req_info) == 0);
    assert!(core::mem::offset_of!(X509Req, sig_alg) == 56);
    assert!(core::mem::offset_of!(X509Req, signature) == 72);
    assert!(core::mem::offset_of!(X509Req, references) == 80);
    assert!(core::mem::offset_of!(X509Req, lock) == 88);
    assert!(core::mem::offset_of!(X509Req, distinguishing_id) == 96);
    assert!(core::mem::offset_of!(X509Req, libctx) == 104);
    assert!(core::mem::offset_of!(X509Req, propq) == 112);
};

/// `long X509_REQ_get_version(const X509_REQ *req)` -- `crypto/x509/x509_req.c:306-309`.
///
/// Reads `req->req_info.version` through `ASN1_INTEGER_get`, so a NULL version (the v1 default)
/// answers 0.
///
/// # Safety
///
/// `req` must be a live `X509_REQ`.
#[no_mangle]
#[allow(non_snake_case)]
pub unsafe extern "C" fn X509_REQ_get_version(req: *const X509Req) -> c_long {
    // SAFETY: `req` is live per the contract.
    unsafe { ASN1_INTEGER_get((*req).req_info.version) }
}

/// `X509_NAME *X509_REQ_get_subject_name(const X509_REQ *req)` -- `crypto/x509/x509_req.c:311-314`.
///
/// The one function of `crypto/x509/x509_req.c` this slice exists for: `crypto/x509/v3_san.c`'s
/// `v2i_subject_alt` reads the request's subject DN through it. It is a bare field read, and the
/// returned name is the request's own, not a copy.
///
/// # Safety
///
/// `req` must be a live `X509_REQ`; the returned pointer borrows its `subject`.
#[no_mangle]
#[allow(non_snake_case)]
pub unsafe extern "C" fn X509_REQ_get_subject_name(req: *const X509Req) -> *mut X509Name {
    // SAFETY: `req` is live per the contract.
    unsafe { (*req).req_info.subject }
}

/// `void X509_REQ_get0_signature(const X509_REQ *req, const ASN1_BIT_STRING **psig, const
/// X509_ALGOR **palg)` -- `crypto/x509/x509_req.c:316-324`.
///
/// Writes the request's signature and signature algorithm out through whichever of `psig`/`palg`
/// the caller passed; either slot may be NULL, and both are "get0" borrows of the request's own
/// storage (`palg` points *into* the request, at `req_info`'s sibling `sig_alg`).
///
/// # Safety
///
/// `req` must be a live `X509_REQ` whenever `psig` or `palg` is non-NULL; each of `psig` and
/// `palg` is NULL or a writable slot, and the pointers written borrow the request.
#[no_mangle]
#[allow(non_snake_case)]
pub unsafe extern "C" fn X509_REQ_get0_signature(
    req: *const X509Req,
    psig: *mut *const Asn1String,
    palg: *mut *const X509Algor,
) {
    if !psig.is_null() {
        // SAFETY: `psig` is writable and `req` is live per the contract.
        unsafe { *psig = (*req).signature };
    }
    if !palg.is_null() {
        // SAFETY: `palg` is writable and `req` is live per the contract.
        unsafe { *palg = core::ptr::addr_of!((*req).sig_alg) };
    }
}

/// `ERR_LIB_X509` — `include/openssl/err.h.in:85`, `11`.
const ERR_LIB_X509: c_int = 11;
/// `ERR_R_PASSED_NULL_PARAMETER` — `include/openssl/err.h.in:356`, `(258 | ERR_R_FATAL)`.
const ERR_R_PASSED_NULL_PARAMETER: c_int = 786690;

/// One `x509_req.c` raise coordinate, declared locally because the unit is not in
/// `gen_err_raise_sites.py`'s covered set (see the module doc).
const fn x509_req_site_reason(
    line: c_int,
    func: &'static core::ffi::CStr,
    reason: c_int,
) -> ErrSite {
    ErrSite {
        file: c"../../src/openssl-3.6.4/crypto/x509/x509_req.c",
        line,
        func,
        lib: ERR_LIB_X509,
        reason,
        dynamic_reason: false,
    }
}

/// A `x509_req.c` `ERR_R_PASSED_NULL_PARAMETER` site, the reason most of the file's raises carry.
const fn x509_req_site(line: c_int, func: &'static core::ffi::CStr) -> ErrSite {
    x509_req_site_reason(line, func, ERR_R_PASSED_NULL_PARAMETER)
}

/// `X509_REQ_delete_attr`'s NULL-request refusal at `crypto/x509/x509_req.c:240`.
const X509_REQ_240: ErrSite = x509_req_site(240, c"X509_REQ_delete_attr");
/// `X509_REQ_add1_attr`'s NULL-request refusal at `crypto/x509/x509_req.c:252`.
const X509_REQ_252: ErrSite = x509_req_site(252, c"X509_REQ_add1_attr");
/// `X509_REQ_add1_attr_by_OBJ`'s NULL-request refusal at `crypto/x509/x509_req.c:267`.
const X509_REQ_267: ErrSite = x509_req_site(267, c"X509_REQ_add1_attr_by_OBJ");
/// `X509_REQ_add1_attr_by_NID`'s NULL-request refusal at `crypto/x509/x509_req.c:282`.
const X509_REQ_282: ErrSite = x509_req_site(282, c"X509_REQ_add1_attr_by_NID");
/// `X509_REQ_add1_attr_by_txt`'s NULL-request refusal at `crypto/x509/x509_req.c:297`.
const X509_REQ_297: ErrSite = x509_req_site(297, c"X509_REQ_add1_attr_by_txt");
/// `i2d_re_X509_REQ_tbs`'s NULL-request refusal at `crypto/x509/x509_req.c:345`.
const X509_REQ_345: ErrSite = x509_req_site(345, c"i2d_re_X509_REQ_tbs");
/// `get_extensions_by_nid`'s wrong-type refusal at `crypto/x509/x509_req.c:133`,
/// `X509_R_WRONG_TYPE`.
const X509_REQ_133: ErrSite =
    x509_req_site_reason(133, c"get_extensions_by_nid", X509_R_WRONG_TYPE);

/// `ERR_R_ASN1_LIB` — `include/openssl/err.h.in`, the reason `X509_to_X509_REQ`'s one raise
/// carries. Declared locally because this unit's raises are not in `gen_err_raise_sites.py`'s
/// covered set (see the module doc).
const ERR_R_ASN1_LIB: c_int = 524301;
/// `X509_to_X509_REQ`'s `ERR_raise(ERR_LIB_X509, ERR_R_ASN1_LIB)` at
/// `crypto/x509/x509_req.c:31`.
const X509_REQ_31: ErrSite = x509_req_site_reason(31, c"X509_to_X509_REQ", ERR_R_ASN1_LIB);

/// `crypto/x509/x509_req.c` — the file the one allocator release below names.
const FILE: &core::ffi::CStr = c"crypto/x509/x509_req.c";
/// The authority's `OPENSSL_free(ext)` in `X509_REQ_add_extensions_nid`, at
/// `crypto/x509/x509_req.c:199`.
const LINE_FREE_EXT: c_int = 199;
/// `X509_to_X509_REQ`'s `ri->version->data = OPENSSL_malloc(1)` at
/// `crypto/x509/x509_req.c:38`.
const LINE_MALLOC_VERSION: c_int = 38;

/// The authority's `err:` tail of [`X509_to_X509_REQ`]: free the request and answer NULL.
///
/// # Safety
/// `req` is NULL or this call's own request.
unsafe fn to_req_err(req: *mut X509Req) -> *mut X509Req {
    // SAFETY: `req` is NULL or this frame's own object.
    unsafe { X509_REQ_free(req) };
    ptr::null_mut()
}

/// `X509_REQ *X509_to_X509_REQ(X509 *x, EVP_PKEY *pkey, const EVP_MD *md)` —
/// `crypto/x509/x509_req.c:22-61`.
///
/// Builds a certificate request from a certificate's subject and public key, signing it when a
/// key is supplied. The version is forced to v1 (`0`) by writing the integer's content directly,
/// which is the authority's own spelling: `X509_REQ_new_ex` leaves `version` NULL (the v1
/// default), so the two fields are set on the embedded integer. Every later refusal is the
/// `X509_REQ_free`-and-NULL tail; only the request's own construction raises.
///
/// # Safety
/// `x` must be a live `X509`; `pkey` NULL or live; `md` NULL or live. The answer is owned by the
/// caller.
#[no_mangle]
#[allow(non_snake_case)]
pub unsafe extern "C" fn X509_to_X509_REQ(
    x: *mut X509,
    pkey: *mut EvpPkey,
    md: *const EvpMd,
) -> *mut X509Req {
    // SAFETY: `x` is live per the contract and its two context fields are read from it.
    let ret = unsafe { X509_REQ_new_ex((*x).libctx, (*x).propq) };
    if ret.is_null() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&X509_REQ_31) };
        return ptr::null_mut();
    }

    /* `ri->version->length = 1; ri->version->data = OPENSSL_malloc(1); ... = 0;` — the version is
     * written as a one-byte zero rather than through `ASN1_INTEGER_set`, which is the authority's
     * own shape. */
    // SAFETY: `ret` is live and its `version` is the fresh item's own integer.
    unsafe {
        (*(*ret).req_info.version).length = 1;
        (*(*ret).req_info.version).data =
            CRYPTO_malloc(1, FILE.as_ptr(), LINE_MALLOC_VERSION).cast::<c_uchar>();
        if (*(*ret).req_info.version).data.is_null() {
            return to_req_err(ret);
        }
        *(*(*ret).req_info.version).data = 0;
    }

    // SAFETY: `ret` and `x` are live.
    if unsafe { X509_REQ_set_subject_name(ret, X509_get_subject_name(x)) } == 0 {
        // SAFETY: `ret` is this call's own request.
        return unsafe { to_req_err(ret) };
    }

    // SAFETY: `x` is live.
    let pktmp = unsafe { X509_get0_pubkey(x) };
    if pktmp.is_null() {
        // SAFETY: `ret` is this call's own request.
        return unsafe { to_req_err(ret) };
    }
    // SAFETY: `ret` is live and `pktmp` is the certificate's own key.
    if unsafe { X509_REQ_set_pubkey(ret, pktmp) } == 0 {
        // SAFETY: `ret` is this call's own request.
        return unsafe { to_req_err(ret) };
    }

    if !pkey.is_null() {
        // SAFETY: `ret` is live; `pkey` and `md` are the caller's per the contract.
        if unsafe { X509_REQ_sign(ret, pkey, md) } == 0 {
            // SAFETY: `ret` is this call's own request.
            return unsafe { to_req_err(ret) };
        }
    }
    ret
}

/// `EVP_PKEY *X509_REQ_get_pubkey(X509_REQ *req)` — `crypto/x509/x509_req.c:63-68`.
///
/// Returns a new reference to the request's public key, or NULL for a NULL request.
///
/// # Safety
///
/// `req` is NULL or a live `X509_REQ`.
#[no_mangle]
#[allow(non_snake_case)]
pub unsafe extern "C" fn X509_REQ_get_pubkey(req: *mut X509Req) -> *mut EvpPkey {
    if req.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: `req` is live per the contract; its `pubkey` is its own.
    unsafe { X509_PUBKEY_get((*req).req_info.pubkey) }
}

/// `EVP_PKEY *X509_REQ_get0_pubkey(const X509_REQ *req)` — `crypto/x509/x509_req.c:70-75`.
///
/// The borrowed form: the request's own key, not a copy.
///
/// # Safety
///
/// `req` is NULL or a live `X509_REQ`.
#[no_mangle]
#[allow(non_snake_case)]
pub unsafe extern "C" fn X509_REQ_get0_pubkey(req: *const X509Req) -> *mut EvpPkey {
    if req.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: `req` is live per the contract; its `pubkey` is its own.
    unsafe { X509_PUBKEY_get0((*req).req_info.pubkey) }
}

/// `X509_PUBKEY *X509_REQ_get_X509_PUBKEY(X509_REQ *req)` — `crypto/x509/x509_req.c:77-80`.
///
/// A bare `req_info.pubkey` field read; the authority has no NULL guard here.
///
/// # Safety
///
/// `req` is a live `X509_REQ`.
#[no_mangle]
#[allow(non_snake_case)]
pub unsafe extern "C" fn X509_REQ_get_X509_PUBKEY(req: *mut X509Req) -> *mut X509Pubkey {
    // SAFETY: `req` is live per the contract; its `pubkey` is its own.
    unsafe { (*req).req_info.pubkey }
}

/// `int X509_REQ_check_private_key(const X509_REQ *req, EVP_PKEY *pkey)` —
/// `crypto/x509/x509_req.c:82-85`.
///
/// Delegates to `ossl_x509_check_private_key` over the request's borrowed public key.
///
/// # Safety
///
/// `req` is a live `X509_REQ`; `pkey` is a live `EVP_PKEY`.
#[no_mangle]
#[allow(non_snake_case)]
pub unsafe extern "C" fn X509_REQ_check_private_key(
    req: *const X509Req,
    pkey: *mut EvpPkey,
) -> c_int {
    // SAFETY: `req` and `pkey` are live per the contract; `get0_pubkey` answers the request's
    // own key, which `ossl_x509_check_private_key` only compares.
    unsafe { ossl_x509_check_private_key(X509_REQ_get0_pubkey(req), pkey) }
}

/// `static int ext_nid_list[] = { NID_ext_req, NID_ms_ext_req, NID_undef };` —
/// `crypto/x509/x509_req.c:93`. [`X509_REQ_extension_nid`] walks it and stops at the `NID_undef`.
static EXT_NID_LIST: [c_int; 3] = [NID_ext_req, NID_ms_ext_req, NID_undef];

/// `static int *ext_nids = ext_nid_list;` — `crypto/x509/x509_req.c:95`.
///
/// Replaced by [`X509_REQ_set_extension_nids`]; `static mut` because the authority's is a writable
/// file-static pointer, not because this crate writes through it.
static mut EXT_NIDS: *mut c_int = core::ptr::addr_of!(EXT_NID_LIST) as *mut c_int;

/// `int X509_REQ_extension_nid(int req_nid)` — `crypto/x509/x509_req.c:97-108`.
///
/// Answers 1 when `req_nid` is one of the configured extension OIDs, 0 at the `NID_undef`
/// terminator.
///
/// # Safety
///
/// The module's `ext_nids` table must be a `NID_undef`-terminated `int` array — the file's own
/// default or one installed through [`X509_REQ_set_extension_nids`].
#[no_mangle]
#[allow(non_snake_case)]
pub unsafe extern "C" fn X509_REQ_extension_nid(req_nid: c_int) -> c_int {
    // SAFETY: `EXT_NIDS` holds a `NID_undef`-terminated table per the contract.
    let nids = unsafe { EXT_NIDS };
    let mut i: isize = 0;
    loop {
        // SAFETY: the table is `NID_undef`-terminated, so this read stops before running off it.
        let nid = unsafe { *nids.offset(i) };
        if nid == NID_undef {
            return 0;
        }
        if req_nid == nid {
            return 1;
        }
        i += 1;
    }
}

/// `int *X509_REQ_get_extension_nids(void)` — `crypto/x509/x509_req.c:110-113`.
///
/// # Safety
///
/// Nothing beyond this module's own `ext_nids` global; the returned pointer borrows it.
#[no_mangle]
#[allow(non_snake_case)]
pub unsafe extern "C" fn X509_REQ_get_extension_nids() -> *mut c_int {
    // SAFETY: reads this unit's own `ext_nids` global.
    unsafe { EXT_NIDS }
}

/// `void X509_REQ_set_extension_nids(int *nids)` — `crypto/x509/x509_req.c:115-118`.
///
/// # Safety
///
/// `nids` must be NULL or a `NID_undef`-terminated `int` array that outlives every subsequent
/// [`X509_REQ_extension_nid`] call.
#[no_mangle]
#[allow(non_snake_case)]
pub unsafe extern "C" fn X509_REQ_set_extension_nids(nids: *mut c_int) {
    // SAFETY: writes this unit's own `ext_nids` global.
    unsafe { EXT_NIDS = nids };
}

/// The `X509_EXTENSION` destructor in the shape `OPENSSL_sk_pop_free` takes.
///
/// # Safety
///
/// `p` is NULL or a live `X509_EXTENSION` this call owns.
unsafe extern "C" fn x509_extension_free_void(p: *mut c_void) {
    // SAFETY: `p` is NULL or owned per the contract; the item layer accepts NULL.
    unsafe { X509_EXTENSION_free(p.cast()) }
}

/// `static STACK_OF(X509_EXTENSION) *get_extensions_by_nid(const X509_REQ *req, int nid)` —
/// `crypto/x509/x509_req.c:120-140`.
///
/// The request's attribute named by `nid` is decoded as an `X509_EXTENSIONS` stack. A missing
/// attribute is an empty stack (`:126-127`, "no extensions is not an error"); an attribute whose
/// first `ASN1_TYPE` is not a `SEQUENCE` raises `X509_R_WRONG_TYPE` (`X509_REQ_133`) and answers
/// NULL (`:131-134`).
///
/// # Safety
///
/// `req` is a live `X509_REQ`.
unsafe fn get_extensions_by_nid(req: *const X509Req, nid: c_int) -> *mut OpenSslStack {
    // SAFETY: `req` is live per the contract.
    let idx = unsafe { X509_REQ_get_attr_by_NID(req, nid, -1) };
    if idx < 0 {
        return OPENSSL_sk_new_null();
    }
    // SAFETY: `req` is live per the contract and `idx >= 0` is a live attribute index.
    let attr = unsafe { X509_REQ_get_attr(req, idx) };
    // SAFETY: `attr` is NULL or live per the item layer's own contract.
    let ext = unsafe { X509_ATTRIBUTE_get0_type(attr, 0) };
    if ext.is_null() {
        // SAFETY: a compiled-in site coordinate.
        unsafe { raise_site(&X509_REQ_133) };
        return ptr::null_mut();
    }
    // SAFETY: `ext` is non-NULL per the guard above, so it is a live `ASN1_TYPE`.
    if unsafe { (*ext).type_ } != V_ASN1_SEQUENCE {
        // SAFETY: a compiled-in site coordinate.
        unsafe { raise_site(&X509_REQ_133) };
        return ptr::null_mut();
    }
    // SAFETY: `ext` is non-NULL and of type `V_ASN1_SEQUENCE`, so its union holds an
    // `ASN1_STRING *`.
    let seq = unsafe { (*ext).value.ptr }.cast::<Asn1String>();
    // SAFETY: a `SEQUENCE`-typed `ASN1_TYPE` carries a live `ASN1_STRING`; `data` is its buffer.
    let mut p: *const c_uchar = unsafe { (*seq).data };
    // SAFETY: `p` and `seq.length` describe the value's own bytes; `pval` is NULL, so the item
    // layer allocates the answer rather than writing through the caller's slot.
    unsafe {
        ASN1_item_d2i(
            ptr::null_mut(),
            &raw mut p,
            (*seq).length as c_long,
            X509_EXTENSIONS_it(),
        )
        .cast::<OpenSslStack>()
    }
}

/// `STACK_OF(X509_EXTENSION) *X509_REQ_get_extensions(X509_REQ *req)` —
/// `crypto/x509/x509_req.c:142-159`.
///
/// Walks the configured extension OIDs and answers the first attribute that decodes to a non-empty
/// stack. A NULL request or a NULL `ext_nids` table answers NULL (`:145-146`); no matching
/// attribute at all is an empty stack (`:158`).
///
/// # Safety
///
/// `req` is NULL or a live `X509_REQ`.
#[no_mangle]
#[allow(non_snake_case)]
pub unsafe extern "C" fn X509_REQ_get_extensions(req: *mut X509Req) -> *mut OpenSslStack {
    // SAFETY: reads this unit's own `ext_nids` global.
    let nids = unsafe { EXT_NIDS };
    if req.is_null() || nids.is_null() {
        return ptr::null_mut();
    }
    let mut i: isize = 0;
    loop {
        // SAFETY: `nids` is non-NULL and `NID_undef`-terminated per this module's contract.
        let nid = unsafe { *nids.offset(i) };
        if nid == NID_undef {
            break;
        }
        // SAFETY: `req` is live per the contract.
        let exts = unsafe { get_extensions_by_nid(req, nid) };
        if exts.is_null() {
            return ptr::null_mut();
        }
        // SAFETY: `exts` is a live stack.
        if unsafe { OPENSSL_sk_num(exts) } > 0 {
            return exts;
        }
        // SAFETY: `exts` is a live stack this call owns.
        unsafe { OPENSSL_sk_free(exts) };
        i += 1;
    }
    OPENSSL_sk_new_null()
}

/// The tail of `X509_REQ_add_extensions_nid` from the authority's `:186` to its `end:` label
/// (`:201-203`), kept apart so `mod_exts` is released exactly once on every path.
///
/// # Safety
///
/// `req` is a live `X509_REQ`; `exts` is a live stack; `mod_exts` is NULL or a live stack this
/// call owns; `loc` is the attribute index `X509at_get_attr_by_NID` answered when `mod_exts` is
/// non-NULL and is unused otherwise.
unsafe fn add_extensions_nid_tail(
    req: *mut X509Req,
    exts: *const OpenSslStack,
    nid: c_int,
    loc: c_int,
    mod_exts: *const OpenSslStack,
) -> c_int {
    let mut ext: *mut c_uchar = ptr::null_mut();
    // SAFETY: the stack encoded is `mod_exts` when the attribute existed, else `exts`; both are
    // live stacks of extensions, and `ext` is the writable cursor the item layer fills.
    let extlen = unsafe {
        ASN1_item_i2d(
            (if mod_exts.is_null() { exts } else { mod_exts }).cast(),
            &raw mut ext,
            X509_EXTENSIONS_it(),
        )
    };
    if extlen <= 0 {
        return 0;
    }
    if !mod_exts.is_null() {
        // SAFETY: `req` is live per the contract; `loc` is a live attribute index.
        let att = unsafe { X509at_delete_attr((*req).req_info.attributes, loc) };
        if att.is_null() {
            // SAFETY: `ext` was allocated by the item layer above.
            unsafe { CRYPTO_free(ext.cast::<c_void>(), FILE.as_ptr(), LINE_FREE_EXT) };
            return 0;
        }
        // SAFETY: `att` is a live attribute this call owns.
        unsafe { X509_ATTRIBUTE_free(att) };
    }
    // SAFETY: `req` is live per the contract; the remaining arguments are the caller's contract,
    // and `ext`/`extlen` are the encoding built above.
    let rv = unsafe { X509_REQ_add1_attr_by_NID(req, nid, V_ASN1_SEQUENCE, ext, extlen) };
    // SAFETY: `ext` was allocated by the item layer above.
    unsafe { CRYPTO_free(ext.cast::<c_void>(), FILE.as_ptr(), LINE_FREE_EXT) };
    rv
}

/// `int X509_REQ_add_extensions_nid(X509_REQ *req, const STACK_OF(X509_EXTENSION) *exts, int nid)`
/// — `crypto/x509/x509_req.c:165-204`.
///
/// An empty or NULL `exts` is a no-op answering 1 (`:175-176`). When the attribute already exists
/// its extensions and the new ones are merged through `X509v3_add_extensions` (a batch add
/// replaces by OID) and the old attribute is deleted.
///
/// # Safety
///
/// `req` is a live `X509_REQ`; `exts` is NULL or a live stack of extensions.
#[no_mangle]
#[allow(non_snake_case)]
pub unsafe extern "C" fn X509_REQ_add_extensions_nid(
    req: *mut X509Req,
    exts: *const OpenSslStack,
    nid: c_int,
) -> c_int {
    // SAFETY: `exts` is NULL or a live stack per the contract.
    if unsafe { OPENSSL_sk_num(exts) } <= 0 {
        return 1;
    }
    // SAFETY: `req` is live per the contract; `attributes` is its own stack or NULL.
    let loc = unsafe { X509at_get_attr_by_NID((*req).req_info.attributes, nid, -1) };
    let mut mod_exts: *mut OpenSslStack = ptr::null_mut();
    if loc != -1 {
        // SAFETY: `req` is live per the contract.
        mod_exts = unsafe { get_extensions_by_nid(req, nid) };
        if mod_exts.is_null() {
            return 0;
        }
        // SAFETY: `mod_exts` is a live stack this call owns and `exts` is live; both hold
        // extensions, and `X509v3_add_extensions` may replace `mod_exts` in place.
        if unsafe { X509v3_add_extensions(&raw mut mod_exts, exts) }.is_null() {
            // SAFETY: `mod_exts` is a live stack this call owns.
            unsafe { OPENSSL_sk_pop_free(mod_exts, Some(x509_extension_free_void)) };
            return 0;
        }
    }
    // SAFETY: the tail's contract; `mod_exts` is NULL or a live stack this call owns.
    let rv = unsafe { add_extensions_nid_tail(req, exts, nid, loc, mod_exts) };
    // SAFETY: `mod_exts` is NULL or a live stack this call owns (the authority's `end:` label).
    unsafe { OPENSSL_sk_pop_free(mod_exts, Some(x509_extension_free_void)) };
    rv
}

/// `int X509_REQ_add_extensions(X509_REQ *req, const STACK_OF(X509_EXTENSION) *exts)` —
/// `crypto/x509/x509_req.c:207-210`.
///
/// The "official" OID is `NID_ext_req`.
///
/// # Safety
///
/// `req` is a live `X509_REQ`; `exts` is NULL or a live stack of extensions.
#[no_mangle]
#[allow(non_snake_case)]
pub unsafe extern "C" fn X509_REQ_add_extensions(
    req: *mut X509Req,
    exts: *const OpenSslStack,
) -> c_int {
    // SAFETY: the callee's contract is this function's contract.
    unsafe { X509_REQ_add_extensions_nid(req, exts, NID_ext_req) }
}

/// `int X509_REQ_get_attr_count(const X509_REQ *req)` — `crypto/x509/x509_req.c:214-217`.
///
/// # Safety
///
/// `req` is a live `X509_REQ`.
#[no_mangle]
#[allow(non_snake_case)]
pub unsafe extern "C" fn X509_REQ_get_attr_count(req: *const X509Req) -> c_int {
    // SAFETY: `req` is live per the contract; `attributes` is its own stack or NULL.
    unsafe { X509at_get_attr_count((*req).req_info.attributes) }
}

/// `int X509_REQ_get_attr_by_NID(const X509_REQ *req, int nid, int lastpos)` —
/// `crypto/x509/x509_req.c:219-222`.
///
/// # Safety
///
/// `req` is a live `X509_REQ`.
#[no_mangle]
#[allow(non_snake_case)]
pub unsafe extern "C" fn X509_REQ_get_attr_by_NID(
    req: *const X509Req,
    nid: c_int,
    lastpos: c_int,
) -> c_int {
    // SAFETY: `req` is live per the contract; `attributes` is its own stack or NULL.
    unsafe { X509at_get_attr_by_NID((*req).req_info.attributes, nid, lastpos) }
}

/// `int X509_REQ_get_attr_by_OBJ(const X509_REQ *req, const ASN1_OBJECT *obj, int lastpos)` —
/// `crypto/x509/x509_req.c:224-228`.
///
/// # Safety
///
/// `req` is a live `X509_REQ`; `obj` is a live `ASN1_OBJECT`.
#[no_mangle]
#[allow(non_snake_case)]
pub unsafe extern "C" fn X509_REQ_get_attr_by_OBJ(
    req: *const X509Req,
    obj: *const Asn1Object,
    lastpos: c_int,
) -> c_int {
    // SAFETY: `req` is live per the contract, `attributes` is its own stack or NULL, and `obj` is
    // live per the contract.
    unsafe { X509at_get_attr_by_OBJ((*req).req_info.attributes, obj, lastpos) }
}

/// `X509_ATTRIBUTE *X509_REQ_get_attr(const X509_REQ *req, int loc)` —
/// `crypto/x509/x509_req.c:230-233`.
///
/// # Safety
///
/// `req` is a live `X509_REQ`.
#[no_mangle]
#[allow(non_snake_case)]
pub unsafe extern "C" fn X509_REQ_get_attr(req: *const X509Req, loc: c_int) -> *mut X509Attribute {
    // SAFETY: `req` is live per the contract; `attributes` is its own stack or NULL.
    unsafe { X509at_get_attr((*req).req_info.attributes, loc) }
}

/// `X509_ATTRIBUTE *X509_REQ_delete_attr(X509_REQ *req, int loc)` —
/// `crypto/x509/x509_req.c:235-247`.
///
/// A NULL request is `ERR_R_PASSED_NULL_PARAMETER` (`X509_REQ_240`); otherwise the attribute is
/// removed and the cached encoding marked stale.
///
/// # Safety
///
/// `req` is NULL or a live `X509_REQ`.
#[no_mangle]
#[allow(non_snake_case)]
pub unsafe extern "C" fn X509_REQ_delete_attr(req: *mut X509Req, loc: c_int) -> *mut X509Attribute {
    if req.is_null() {
        // SAFETY: a compiled-in site coordinate.
        unsafe { raise_site(&X509_REQ_240) };
        return ptr::null_mut();
    }
    // SAFETY: `req` is live per the contract; `attributes` is its own stack or NULL.
    let attr = unsafe { X509at_delete_attr((*req).req_info.attributes, loc) };
    if !attr.is_null() {
        // SAFETY: `req` is live and `enc.modified` is its own field.
        unsafe { (*req).req_info.enc.modified = 1 };
    }
    attr
}

/// `int X509_REQ_add1_attr(X509_REQ *req, X509_ATTRIBUTE *attr)` —
/// `crypto/x509/x509_req.c:249-259`.
///
/// # Safety
///
/// `req` is NULL or a live `X509_REQ`; `attr` is a live `X509_ATTRIBUTE`.
#[no_mangle]
#[allow(non_snake_case)]
pub unsafe extern "C" fn X509_REQ_add1_attr(req: *mut X509Req, attr: *mut X509Attribute) -> c_int {
    if req.is_null() {
        // SAFETY: a compiled-in site coordinate.
        unsafe { raise_site(&X509_REQ_252) };
        return 0;
    }
    // SAFETY: `req` is live, so `&mut (*req).req_info.attributes` is a live slot; `attr` is live.
    if unsafe { X509at_add1_attr(&raw mut (*req).req_info.attributes, attr) }.is_null() {
        return 0;
    }
    // SAFETY: `req` is live and `enc.modified` is its own field.
    unsafe { (*req).req_info.enc.modified = 1 };
    1
}

/// `int X509_REQ_add1_attr_by_OBJ(X509_REQ *req, const ASN1_OBJECT *obj, int type, const unsigned
/// char *bytes, int len)` — `crypto/x509/x509_req.c:261-274`.
///
/// # Safety
///
/// `req` is NULL or a live `X509_REQ`; `obj` is a live `ASN1_OBJECT`; `bytes` is NULL or
/// `len` readable bytes.
#[no_mangle]
#[allow(non_snake_case)]
pub unsafe extern "C" fn X509_REQ_add1_attr_by_OBJ(
    req: *mut X509Req,
    obj: *const Asn1Object,
    type_: c_int,
    bytes: *const c_uchar,
    len: c_int,
) -> c_int {
    if req.is_null() {
        // SAFETY: a compiled-in site coordinate.
        unsafe { raise_site(&X509_REQ_267) };
        return 0;
    }
    // SAFETY: `req` is live, so the `attributes` slot is live; the remaining arguments are the
    // caller's contract.
    if unsafe {
        X509at_add1_attr_by_OBJ(&raw mut (*req).req_info.attributes, obj, type_, bytes, len)
    }
    .is_null()
    {
        return 0;
    }
    // SAFETY: `req` is live and `enc.modified` is its own field.
    unsafe { (*req).req_info.enc.modified = 1 };
    1
}

/// `int X509_REQ_add1_attr_by_NID(X509_REQ *req, int nid, int type, const unsigned char *bytes,
/// int len)` — `crypto/x509/x509_req.c:276-289`.
///
/// # Safety
///
/// `req` is NULL or a live `X509_REQ`; `bytes` is NULL or `len` readable bytes.
#[no_mangle]
#[allow(non_snake_case)]
pub unsafe extern "C" fn X509_REQ_add1_attr_by_NID(
    req: *mut X509Req,
    nid: c_int,
    type_: c_int,
    bytes: *const c_uchar,
    len: c_int,
) -> c_int {
    if req.is_null() {
        // SAFETY: a compiled-in site coordinate.
        unsafe { raise_site(&X509_REQ_282) };
        return 0;
    }
    // SAFETY: `req` is live, so the `attributes` slot is live; the remaining arguments are the
    // caller's contract.
    if unsafe {
        X509at_add1_attr_by_NID(&raw mut (*req).req_info.attributes, nid, type_, bytes, len)
    }
    .is_null()
    {
        return 0;
    }
    // SAFETY: `req` is live and `enc.modified` is its own field.
    unsafe { (*req).req_info.enc.modified = 1 };
    1
}

/// `int X509_REQ_add1_attr_by_txt(X509_REQ *req, const char *attrname, int type, const unsigned
/// char *bytes, int len)` — `crypto/x509/x509_req.c:291-304`.
///
/// # Safety
///
/// `req` is NULL or a live `X509_REQ`; `attrname` is a NUL-terminated name; `bytes` is NULL or
/// `len` readable bytes.
#[no_mangle]
#[allow(non_snake_case)]
pub unsafe extern "C" fn X509_REQ_add1_attr_by_txt(
    req: *mut X509Req,
    attrname: *const c_char,
    type_: c_int,
    bytes: *const c_uchar,
    len: c_int,
) -> c_int {
    if req.is_null() {
        // SAFETY: a compiled-in site coordinate.
        unsafe { raise_site(&X509_REQ_297) };
        return 0;
    }
    // SAFETY: `req` is live, so the `attributes` slot is live; the remaining arguments are the
    // caller's contract.
    if unsafe {
        X509at_add1_attr_by_txt(
            &raw mut (*req).req_info.attributes,
            attrname,
            type_,
            bytes,
            len,
        )
    }
    .is_null()
    {
        return 0;
    }
    // SAFETY: `req` is live and `enc.modified` is its own field.
    unsafe { (*req).req_info.enc.modified = 1 };
    1
}

/// `void X509_REQ_set0_signature(X509_REQ *req, ASN1_BIT_STRING *psig)` —
/// `crypto/x509/x509_req.c:325-330`.
///
/// Frees the request's current signature and takes ownership of `psig`.
///
/// # Safety
///
/// `req` is a live `X509_REQ`; `psig` is NULL or owned by the caller and handed over.
#[no_mangle]
#[allow(non_snake_case)]
pub unsafe extern "C" fn X509_REQ_set0_signature(req: *mut X509Req, psig: *mut Asn1String) {
    // SAFETY: `req` is live per the contract; `signature` is its own field.
    unsafe {
        if !(*req).signature.is_null() {
            ASN1_BIT_STRING_free((*req).signature);
        }
        (*req).signature = psig;
    }
}

/// `int X509_REQ_set1_signature_algo(X509_REQ *req, X509_ALGOR *palg)` —
/// `crypto/x509/x509_req.c:332-335`.
///
/// Copies `palg` over the request's own `sig_alg` through `X509_ALGOR_copy`.
///
/// # Safety
///
/// `req` is a live `X509_REQ`; `palg` is a live `X509_ALGOR`.
#[no_mangle]
#[allow(non_snake_case)]
pub unsafe extern "C" fn X509_REQ_set1_signature_algo(
    req: *mut X509Req,
    palg: *mut X509Algor,
) -> c_int {
    // SAFETY: `req` and `palg` are live per the contract; `sig_alg` is the request's own.
    unsafe { X509_ALGOR_copy(&raw mut (*req).sig_alg, palg) }
}

/// `int X509_REQ_get_signature_nid(const X509_REQ *req)` — `crypto/x509/x509_req.c:337-340`.
///
/// The NID of the signature algorithm's OID, through `OBJ_obj2nid`.
///
/// # Safety
///
/// `req` is a live `X509_REQ`.
#[no_mangle]
#[allow(non_snake_case)]
pub unsafe extern "C" fn X509_REQ_get_signature_nid(req: *const X509Req) -> c_int {
    // SAFETY: `req` is live per the contract; `sig_alg.algorithm` is its own.
    unsafe { OBJ_obj2nid((*req).sig_alg.algorithm) }
}

/// `int i2d_re_X509_REQ_tbs(X509_REQ *req, unsigned char **pp)` —
/// `crypto/x509/x509_req.c:342-350`.
///
/// Marks the cached TBS encoding stale, then re-encodes `req_info` through the item now landed in
/// [`crate::x509::x_req`]. A NULL request is `ERR_R_PASSED_NULL_PARAMETER` (`X509_REQ_345`).
///
/// # Safety
///
/// `req` is NULL or a live `X509_REQ`; `pp` is NULL or a writable cursor.
#[no_mangle]
#[allow(non_snake_case)]
pub unsafe extern "C" fn i2d_re_X509_REQ_tbs(req: *mut X509Req, pp: *mut *mut c_uchar) -> c_int {
    if req.is_null() {
        // SAFETY: a compiled-in site coordinate.
        unsafe { raise_site(&X509_REQ_345) };
        return 0;
    }
    // SAFETY: `req` is live per the contract; `req_info` is its own embedded value.
    unsafe {
        (*req).req_info.enc.modified = 1;
        i2d_X509_REQ_INFO(&raw const (*req).req_info, pp)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::asn1::string::ASN1_BIT_STRING_new;
    use crate::x509::x_exten::{d2i_X509_EXTENSIONS, i2d_X509_EXTENSIONS};
    use crate::x509::x_req::{X509_REQ_free, X509_REQ_new};

    /// A blank request reads back with an empty attribute stack, and the signature `set0` installs
    /// is the one `get0` returns — the two layouts and the accessors that share them, after the
    /// mutator layer landed.
    #[test]
    fn a_request_reads_back_its_attributes_and_signature() {
        // SAFETY: `req` is a live object this test owns, and every pointer is its own.
        unsafe {
            let req = X509_REQ_new();
            assert!(!req.is_null());
            assert_eq!(X509_REQ_get_attr_count(req), 0);

            let sig = ASN1_BIT_STRING_new();
            assert!(!sig.is_null());
            X509_REQ_set0_signature(req, sig);

            let mut out: *const Asn1String = ptr::null();
            X509_REQ_get0_signature(req, &raw mut out, ptr::null_mut());
            assert_eq!(out, sig);

            X509_REQ_free(req);
        }
    }

    /// An empty `SEQUENCE OF Extension` decodes to an empty stack and re-encodes to the same
    /// bytes: the `X509_EXTENSIONS` wrapper 11.4b lands in `crate::x509::x_exten`.
    #[test]
    fn an_empty_extensions_sequence_round_trips() {
        let der = [0x30u8, 0x00];
        // SAFETY: every pointer is a local's, and the item layer only reads the slice `p` points
        // into; `out` is filled and released with the item layer's own allocator.
        unsafe {
            let mut p: *const c_uchar = der.as_ptr();
            let stack = d2i_X509_EXTENSIONS(ptr::null_mut(), &raw mut p, 2);
            assert!(!stack.is_null());
            assert_eq!(OPENSSL_sk_num(stack), 0);

            let mut out: *mut c_uchar = ptr::null_mut();
            let n = i2d_X509_EXTENSIONS(stack, &raw mut out);
            assert_eq!(n, 2);
            assert_eq!(core::slice::from_raw_parts(out, 2), &der[..]);
            CRYPTO_free(out.cast::<c_void>(), FILE.as_ptr(), LINE_FREE_EXT);
            OPENSSL_sk_free(stack);
        }
    }

    /// A request's extension attribute survives `X509_REQ_add_extensions` and
    /// `X509_REQ_get_extensions`: both sides of the round trip are the `X509_EXTENSIONS` encoding of
    /// one `basicConstraints` extension.
    #[test]
    fn a_request_extension_attribute_round_trips() {
        // `SEQUENCE OF Extension` holding `basicConstraints = SEQUENCE {}` (OID 2.5.29.19):
        // 30 0B { 30 09 { 06 03 55 1D 13 , 04 02 30 00 } }.
        let der: [u8; 13] = [
            0x30, 0x0B, 0x30, 0x09, 0x06, 0x03, 0x55, 0x1D, 0x13, 0x04, 0x02, 0x30, 0x00,
        ];
        // SAFETY: the request, the two stacks and the encoded buffer are all locals owned here;
        // each is released exactly once with the destructor that matches its element type.
        unsafe {
            let mut p: *const c_uchar = der.as_ptr();
            let exts = d2i_X509_EXTENSIONS(ptr::null_mut(), &raw mut p, der.len() as c_long);
            assert!(!exts.is_null());
            assert_eq!(OPENSSL_sk_num(exts), 1);

            let req = X509_REQ_new();
            // `X509_REQ_add_extensions` borrows the stack; the caller keeps it.
            assert_eq!(X509_REQ_add_extensions(req, exts), 1);
            assert_eq!(X509_REQ_get_attr_count(req), 1);

            let back = X509_REQ_get_extensions(req);
            assert!(!back.is_null());
            assert_eq!(OPENSSL_sk_num(back), 1);

            let mut out: *mut c_uchar = ptr::null_mut();
            let n = i2d_X509_EXTENSIONS(back, &raw mut out);
            assert_eq!(n, der.len() as c_int);
            assert_eq!(core::slice::from_raw_parts(out, der.len()), &der[..]);

            CRYPTO_free(out.cast::<c_void>(), FILE.as_ptr(), LINE_FREE_EXT);
            OPENSSL_sk_pop_free(back, Some(x509_extension_free_void));
            OPENSSL_sk_pop_free(exts, Some(x509_extension_free_void));
            X509_REQ_free(req);
        }
    }
}
