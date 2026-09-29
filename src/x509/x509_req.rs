//! Phase 10.11's pulled-forward subset of `crypto/x509/x509_req.c`: the `X509_REQ` object's two
//! layouts and the three accessors `crypto/x509/v3_san.c`'s `v2i_subject_alt` reaches.
//!
//! `crypto/x509/x509_req.c` is Phase 11's unit. It is pulled forward here by name, on D442/D444's
//! precedent, for the one frontier `src/x509/v3_san.rs` records: `v2i_subject_alt`
//! (`crypto/x509/v3_san.c:377-413`) names `X509_REQ_get_subject_name` (`x509_req.c:311-314`), and
//! that one line cannot be typed while the crate has no `X509_REQ` type. The other two accessors
//! that read the same structures and call no unlanded callee -- `X509_REQ_get_version`
//! (`:306-309`) and `X509_REQ_get0_signature` (`:316-324`) -- land with it. **Everything else in
//! the unit is withheld by name below.** Nothing is stubbed: no withheld name is declared, so the
//! crate's symbol surface gains exactly the three exports.
//!
//! The `X509_REQ` object's lifecycle and its `ASN1_ITEM` descriptor -- `X509_REQ_new_ex`,
//! `X509_REQ_free`, `X509_REQ_INFO_it`, `d2i_X509_REQ`, `i2d_X509_REQ` -- are
//! `crypto/x509/x_req.c`, a **separate** authority translation unit, and are not this module's.
//! That is why the two structs below carry no item descriptor; they are laid out here only because
//! the three landed accessors read them.
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
//! The rest of `crypto/x509/x509_req.c`, every one withheld rather than stubbed. Two groups: names
//! that wait on an unlanded authority name, and names whose callees are all landed but which are
//! not on the frontier this pull-forward opens (they land with Phase 11's unit proper).
//!
//! Blocked on an unlanded callee or type:
//!
//! * `X509_to_X509_REQ` (`:22-61`) -- needs `X509_REQ_new_ex`/`X509_REQ_free`
//!   (`crypto/x509/x_req.c`, unlanded) and `X509_REQ_sign` (`crypto/x509/x_all.c`, withheld by
//!   name in `src/x509/x_all.rs`).
//! * `get_extensions_by_nid` (`:120-140`, static) -- decodes through
//!   `ASN1_ITEM_rptr(X509_EXTENSIONS)`, and the `X509_EXTENSIONS` item is withheld in
//!   `src/x509/x_exten.rs`.
//! * `X509_REQ_get_extensions` (`:142-159`) -- reached only through `get_extensions_by_nid`.
//! * `X509_REQ_add_extensions_nid` (`:165-204`) -- the same `X509_EXTENSIONS` item
//!   (`X509v3_add_extensions` itself is landed).
//! * `X509_REQ_add_extensions` (`:207-210`) -- the `NID_ext_req`-fixed wrapper of the above.
//! * `X509_REQ_check_private_key` (`:82-85`) -- calls the withheld `X509_REQ_get0_pubkey`
//!   (`ossl_x509_check_private_key` itself is landed in `src/x509/x509_cmp.rs`).
//! * `i2d_re_X509_REQ_tbs` (`:342-350`) -- needs `i2d_X509_REQ_INFO`/`X509_REQ_INFO_it`
//!   (`crypto/x509/x_req.c`, unlanded).
//!
//! Withheld by scope (their callees are landed; they are not reached by `v2i_subject_alt` and land
//! with Phase 11's unit):
//!
//! * `X509_REQ_get_pubkey` (`:63-68`) / `X509_REQ_get0_pubkey` (`:70-75`) -- `X509_PUBKEY_get`/
//!   `X509_PUBKEY_get0` are landed (`src/x509/x_pubkey.rs`).
//! * `X509_REQ_get_X509_PUBKEY` (`:77-80`) -- a bare `req_info.pubkey` field read.
//! * `X509_REQ_get_attr_count` (`:214-217`), `X509_REQ_get_attr_by_NID` (`:219-222`),
//!   `X509_REQ_get_attr_by_OBJ` (`:224-228`), `X509_REQ_get_attr` (`:230-233`),
//!   `X509_REQ_delete_attr` (`:235-247`), `X509_REQ_add1_attr` (`:249-259`),
//!   `X509_REQ_add1_attr_by_OBJ` (`:261-274`), `X509_REQ_add1_attr_by_NID` (`:276-289`) and
//!   `X509_REQ_add1_attr_by_txt` (`:291-304`) -- the `X509at_*` family they call is landed
//!   (`src/x509/x509_att.rs`).
//! * `X509_REQ_set0_signature` (`:325-330`) -- `ASN1_BIT_STRING_free` is landed.
//! * `X509_REQ_set1_signature_algo` (`:332-335`) -- `X509_ALGOR_copy` is landed
//!   (`src/asn1/x_algor.rs`).
//! * `X509_REQ_get_signature_nid` (`:337-340`) -- `OBJ_obj2nid` is landed.
//! * `ext_nid_list`/`ext_nids` (`:93`, `:95`, the file-static table) and its three readers
//!   `X509_REQ_extension_nid` (`:97-108`), `X509_REQ_get_extension_nids` (`:110-113`) and
//!   `X509_REQ_set_extension_nids` (`:115-118`) -- transcribable over `NID_ext_req`/`NID_ms_ext_req`
//!   (landed), but the table's only consumer is the blocked `X509_REQ_get_extensions` above.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_char, c_int, c_long, c_void};

use crate::asn1::layout::{Asn1Encoding, Asn1String};
use crate::asn1::prim::ASN1_INTEGER_get;
use crate::asn1::x_algor::X509Algor;
use crate::runtime::stack::OpenSslStack;
use crate::x509::x_name::X509Name;
use crate::x509::x_pubkey::X509Pubkey;

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
