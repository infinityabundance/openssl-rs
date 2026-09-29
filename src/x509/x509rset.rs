//! Phase 10.11 -- `crypto/x509/x509rset.c`: the three `X509_REQ` field setters, **now landed**.
//!
//! `crypto/x509/x509rset.c` is three functions and nothing else, and all three write through a
//! field of `X509_REQ`'s `req_info` sub-structure (`x->req_info.enc.modified`, `:version`,
//! `:subject`, `:pubkey`). They were **withheld whole** while `struct X509_req_st` /
//! `struct X509_req_info_st` had no crate type to name -- `crypto/x509/x509_req.c` is 10.14.11's.
//! That type is now landed in [`crate::x509::x509_req`] as [`X509Req`]/[`X509ReqInfo`] (the
//! pulled-forward subset `crypto/x509/v3_san.c`'s `v2i_subject_alt` needed), and all three
//! functions' non-field callees were already landed, so all three transcribe directly:
//!
//! * [`X509_REQ_set_version`] (`crypto/x509/x509rset.c:18-26`) -- refuses a NULL request or a
//!   version other than `X509_REQ_VERSION_1` (0) with
//!   `ERR_LIB_X509`/`ERR_R_PASSED_INVALID_ARGUMENT`, then marks the cached encoding stale and
//!   stores the version through `ASN1_INTEGER_set` (landed, `src/asn1/prim.rs`). The version
//!   pointer is not allocated here, exactly as in the authority: a request whose `version` is
//!   NULL (the v1 default) simply fails `ASN1_INTEGER_set`.
//! * [`X509_REQ_set_subject_name`] (`:28-34`) -- a NULL request answers 0; otherwise it marks the
//!   encoding stale and delegates to `X509_NAME_set` (landed, `src/x509/x_name.rs`).
//! * [`X509_REQ_set_pubkey`] (`:36-42`) -- a NULL request answers 0; otherwise it marks the
//!   encoding stale and delegates to `X509_PUBKEY_set` (landed, `src/x509/x_pubkey.rs`).
//!
//! `crypto/x509/x509rset.c` is not in `gen_err_raise_sites.py`'s covered set, so the one raise
//! coordinate is declared here against the authority's own line and reason, as `v3_conf.rs` does;
//! both constants are read from `include/openssl/err.h.in` rather than typed from memory.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_int, c_long};

use crate::asn1::prim::ASN1_INTEGER_set;
use crate::evp::pkey::EvpPkey;
use crate::runtime::err::{err_sites::ErrSite, raise_site};
use crate::x509::x509_req::{X509Req, X509_REQ_VERSION_1};
use crate::x509::x_name::{X509Name, X509_NAME_set};
use crate::x509::x_pubkey::X509_PUBKEY_set;

/// `ERR_LIB_X509` -- `include/openssl/err.h.in:85`.
const ERR_LIB_X509: c_int = 11;
/// `ERR_R_PASSED_INVALID_ARGUMENT` -- `include/openssl/err.h.in:360`, `262 | ERR_RFLAG_COMMON`
/// (`ERR_RFLAG_COMMON` is `0x2 << ERR_RFLAGS_OFFSET`, and `ERR_RFLAGS_OFFSET` is 18).
const ERR_R_PASSED_INVALID_ARGUMENT: c_int = 524550;

/// `X509_REQ_set_version`'s refusal at `crypto/x509/x509rset.c:21`: a NULL request or a version
/// other than `X509_REQ_VERSION_1`.
const X509RSET_21: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/x509/x509rset.c",
    line: 21,
    func: c"X509_REQ_set_version",
    lib: ERR_LIB_X509,
    reason: ERR_R_PASSED_INVALID_ARGUMENT,
    dynamic_reason: false,
};

/// `int X509_REQ_set_version(X509_REQ *x, long version)` -- `crypto/x509/x509rset.c:18-26`.
///
/// # Safety
///
/// `x` must be NULL or a live `X509_REQ`.
#[no_mangle]
#[allow(non_snake_case)]
pub unsafe extern "C" fn X509_REQ_set_version(x: *mut X509Req, version: c_long) -> c_int {
    if x.is_null() || version != X509_REQ_VERSION_1 {
        // SAFETY: `X509RSET_21` is a compile-time constant whose `CStr`s are static.
        unsafe { raise_site(&X509RSET_21) };
        return 0;
    }
    // SAFETY: `x` is live per the contract.
    unsafe {
        (*x).req_info.enc.modified = 1;
        ASN1_INTEGER_set((*x).req_info.version, version)
    }
}

/// `int X509_REQ_set_subject_name(X509_REQ *x, const X509_NAME *name)` --
/// `crypto/x509/x509rset.c:28-34`.
///
/// # Safety
///
/// `x` must be NULL or a live `X509_REQ`; `name` is NULL or a live `X509_NAME`.
#[no_mangle]
#[allow(non_snake_case)]
pub unsafe extern "C" fn X509_REQ_set_subject_name(
    x: *mut X509Req,
    name: *const X509Name,
) -> c_int {
    if x.is_null() {
        return 0;
    }
    // SAFETY: `x` is live per the contract, so `&mut (*x).req_info.subject` is a live slot;
    // `name` is NULL or live per the contract.
    unsafe {
        (*x).req_info.enc.modified = 1;
        X509_NAME_set(&mut (*x).req_info.subject, name)
    }
}

/// `int X509_REQ_set_pubkey(X509_REQ *x, EVP_PKEY *pkey)` -- `crypto/x509/x509rset.c:36-42`.
///
/// # Safety
///
/// `x` must be NULL or a live `X509_REQ`; `pkey` is NULL or a live `EVP_PKEY`.
#[no_mangle]
#[allow(non_snake_case)]
pub unsafe extern "C" fn X509_REQ_set_pubkey(x: *mut X509Req, pkey: *mut EvpPkey) -> c_int {
    if x.is_null() {
        return 0;
    }
    // SAFETY: `x` is live per the contract, so `&mut (*x).req_info.pubkey` is a live slot;
    // `pkey` is NULL or live per the contract.
    unsafe {
        (*x).req_info.enc.modified = 1;
        X509_PUBKEY_set(&mut (*x).req_info.pubkey, pkey)
    }
}
