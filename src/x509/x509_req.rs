//! `crypto/x509/x509_req.c` — the `X509_REQ` object's accessor and mutator layer. **Phase 10.11
//! landed the pulled-forward subset** (the two layouts and the three accessors
//! `crypto/x509/v3_san.c`'s `v2i_subject_alt` reaches: `X509_REQ_get_subject_name`,
//! `X509_REQ_get_version` and `X509_REQ_get0_signature`); **Phase 11.4 lands the rest**.
//!
//! `crypto/x509/x509_req.c` is 350 lines. This slice lands **twenty of its twenty-four remaining
//! exports**: the public-key accessors (`X509_REQ_get_pubkey`/`_get0_pubkey`/`_get_X509_PUBKEY`),
//! `X509_REQ_check_private_key`, the three extension-NID table functions
//! (`X509_REQ_extension_nid`/`_get_extension_nids`/`_set_extension_nids`), the attribute surface
//! (`X509_REQ_get_attr_count`/`_get_attr_by_NID`/`_get_attr_by_OBJ`/`_get_attr`/`_delete_attr` and
//! the four `_add1_attr*` spellings), the signature setters (`X509_REQ_set0_signature`,
//! `X509_REQ_set1_signature_algo`, `X509_REQ_get_signature_nid`) and `i2d_re_X509_REQ_tbs`.
//! **Four are withheld by name, each with its blocker, below.**
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
//! ## Withheld by name, with each name's blocker
//!
//! Four of the twenty-four open exports this unit still owes:
//!
//! * `X509_to_X509_REQ` (`crypto/x509/x509_req.c:22-61`) -- calls `X509_REQ_sign`
//!   (`crypto/x509/x_all.c`), withheld by name in `src/x509/x_all.rs` as a Phase 11.7 face. Every
//!   other callee it names (`X509_REQ_new_ex`, `X509_REQ_set_subject_name`, `X509_get_subject_name`,
//!   `X509_get0_pubkey`, `X509_REQ_set_pubkey`, `X509_REQ_free`) is landed.
//! * `get_extensions_by_nid` (`:120-140`, static), `X509_REQ_get_extensions` (`:142-159`),
//!   `X509_REQ_add_extensions_nid` (`:165-204`) and `X509_REQ_add_extensions` (`:207-210`) -- all
//!   four decode through `ASN1_ITEM_rptr(X509_EXTENSIONS)`, and the `X509_EXTENSIONS` item is
//!   withheld in `src/x509/x_exten.rs` (`crypto/x509/x_exten.c`, a sibling Phase 11.4 unit this
//!   slice may not edit). `get_extensions_by_nid` also raises `X509_R_WRONG_TYPE`
//!   (`include/openssl/x509err.h:67`, `122`) at `:133`, but it is reachable only through the three
//!   withheld callers, so its coordinate is not declared either.
//!
//! The extension-NID functions themselves need no item and land: `NID_ext_req`, `NID_ms_ext_req`
//! and the `NID_undef` terminator (all landed) build the file-static `ext_nid_list`/`ext_nids` pair
//! (`:93`, `:95`).
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_char, c_int, c_long, c_uchar, c_void};
use core::ptr;

use crate::asn1::layout::{Asn1Encoding, Asn1String};
use crate::asn1::prim::ASN1_INTEGER_get;
use crate::asn1::string::ASN1_BIT_STRING_free;
use crate::asn1::x_algor::{X509Algor, X509_ALGOR_copy};
use crate::evp::pkey::EvpPkey;
use crate::runtime::err::{err_sites::ErrSite, raise_site};
use crate::runtime::obj::{Asn1Object, NID_ext_req, NID_ms_ext_req, NID_undef, OBJ_obj2nid};
use crate::runtime::stack::OpenSslStack;
use crate::x509::x509_att::{
    X509at_add1_attr, X509at_add1_attr_by_NID, X509at_add1_attr_by_OBJ, X509at_add1_attr_by_txt,
    X509at_delete_attr, X509at_get_attr, X509at_get_attr_by_NID, X509at_get_attr_by_OBJ,
    X509at_get_attr_count,
};
use crate::x509::x509_cmp::ossl_x509_check_private_key;
use crate::x509::x_attrib::X509Attribute;
use crate::x509::x_name::X509Name;
use crate::x509::x_pubkey::{X509Pubkey, X509_PUBKEY_get, X509_PUBKEY_get0};
use crate::x509::x_req::i2d_X509_REQ_INFO;

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
const fn x509_req_site(line: c_int, func: &'static core::ffi::CStr) -> ErrSite {
    ErrSite {
        file: c"../../src/openssl-3.6.4/crypto/x509/x509_req.c",
        line,
        func,
        lib: ERR_LIB_X509,
        reason: ERR_R_PASSED_NULL_PARAMETER,
        dynamic_reason: false,
    }
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
}
