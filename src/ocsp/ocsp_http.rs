//! `crypto/ocsp/ocsp_http.c` — the two OCSP HTTP request entry points that build on the landed HTTP
//! client. Phase 12.6.
//!
//! `crypto/ocsp/ocsp_http.c` is 68 lines and exports two names, in source order:
//!
//! * [`OCSP_sendreq_new`] (`:15-49`) — an `OSSL_HTTP_REQ_CTX` configured as a `POST` with the
//!   `application/ocsp-request` body (when a request is supplied) and an ASN.1, non-keep-alive
//!   expectation.
//! * [`OCSP_sendreq_bio`] (`:51-67`) — exchange the context and decode the reply as an
//!   `OCSP_RESPONSE`.
//!
//! The network transport itself is `crate::http`'s (`OSSL_HTTP_REQ_CTX_exchange`); this unit only
//! configures and drives it, so a memory-BIO pair exercises it in-process. `crypto/ocsp/ocsp_http.c`
//! has **no** `ERR_raise` and no declared raise coordinate.
//!
//! SPDX-License-Identifier: Apache-2.0

#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]

use core::ffi::{c_int, c_void};
use core::ptr;

use crate::asn1::a_d2i_fp::ASN1_item_d2i_bio;
use crate::http::http_client::{
    OSSL_HTTP_REQ_CTX_exchange, OSSL_HTTP_REQ_CTX_free, OSSL_HTTP_REQ_CTX_new,
    OSSL_HTTP_REQ_CTX_set1_req, OSSL_HTTP_REQ_CTX_set_expected, OSSL_HTTP_REQ_CTX_set_request_line,
    OsslHttpReqCtx,
};
use crate::ocsp::ocsp_asn::{OCSP_REQUEST_it, OCSP_RESPONSE_it, OcspRequest, OcspResponse};
use crate::runtime::bio::Bio;

/// `OSSL_HTTP_REQ_CTX *OCSP_sendreq_new(BIO *io, const char *path, const OCSP_REQUEST *req, int
/// buf_size)` — `crypto/ocsp/ocsp_http.c:15-49`.
///
/// Builds a request context over the single `io` BIO for both directions, sets the `POST` request
/// line for `path`, expects an ASN.1 reply with no timeout or keep-alive, and — when `req` is
/// non-NULL — installs `application/ocsp-request` as the body from `OCSP_REQUEST`'s item. Any
/// failure frees the context and answers NULL.
///
/// # Safety
/// `io` must be a live BIO; `path` must be a NUL-terminated string; `req` must be NULL or a live
/// `OCSP_REQUEST`; the returned context borrows `io`, so `io` must outlive it.
#[no_mangle]
pub unsafe extern "C" fn OCSP_sendreq_new(
    io: *mut Bio,
    path: *const core::ffi::c_char,
    req: *const OcspRequest,
    buf_size: c_int,
) -> *mut OsslHttpReqCtx {
    // SAFETY: the pointers are NULL-or-live per the contract; every HTTP callee obeys its own.
    unsafe {
        let rctx = OSSL_HTTP_REQ_CTX_new(io, io, buf_size);
        if rctx.is_null() {
            return ptr::null_mut();
        }
        if OSSL_HTTP_REQ_CTX_set_request_line(rctx, 1, ptr::null(), ptr::null(), path) == 0 {
            OSSL_HTTP_REQ_CTX_free(rctx);
            return ptr::null_mut();
        }
        if OSSL_HTTP_REQ_CTX_set_expected(rctx, ptr::null(), 1, 0, 0) == 0 {
            OSSL_HTTP_REQ_CTX_free(rctx);
            return ptr::null_mut();
        }
        if !req.is_null()
            && OSSL_HTTP_REQ_CTX_set1_req(
                rctx,
                c"application/ocsp-request".as_ptr(),
                OCSP_REQUEST_it(),
                req.cast::<c_void>(),
            ) == 0
        {
            OSSL_HTTP_REQ_CTX_free(rctx);
            return ptr::null_mut();
        }
        rctx
    }
}

/// `OCSP_RESPONSE *OCSP_sendreq_bio(BIO *b, const char *path, OCSP_REQUEST *req)` —
/// `crypto/ocsp/ocsp_http.c:51-67`.
///
/// Builds a request context with [`OCSP_sendreq_new`], exchanges it, and decodes the returned
/// memory BIO as an `OCSP_RESPONSE` (the decoder accepts a NULL BIO and answers NULL). The context
/// is freed on every path.
///
/// # Safety
/// `b` must be a live BIO; `path` must be a NUL-terminated string; `req` must be a live
/// `OCSP_REQUEST`.
#[no_mangle]
pub unsafe extern "C" fn OCSP_sendreq_bio(
    b: *mut Bio,
    path: *const core::ffi::c_char,
    req: *mut OcspRequest,
) -> *mut OcspResponse {
    // SAFETY: the pointers are live per the contract; each callee obeys its own contract.
    unsafe {
        let ctx = OCSP_sendreq_new(b, path, req, 0);
        if ctx.is_null() {
            return ptr::null_mut();
        }
        let mem = OSSL_HTTP_REQ_CTX_exchange(ctx);
        // `ASN1_item_d2i_bio` handles a NULL BIO gracefully.
        let resp =
            ASN1_item_d2i_bio(OCSP_RESPONSE_it(), mem, ptr::null_mut()).cast::<OcspResponse>();

        OSSL_HTTP_REQ_CTX_free(ctx);
        resp
    }
}
