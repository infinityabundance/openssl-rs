//! `crypto/cmp/cmp_http.c` — the CMP HTTP transport arm. Phase 12.4.
//!
//! `OSSL_CMP_MSG_http_perform` is a thin driver over the `crypto/http/` client landed in 12.1:
//! it DER-encodes the request into a memory BIO, hands it to `OSSL_HTTP_transfer`, and decodes the
//! response with the same `OSSL_CMP_MSG` item. No transport is fabricated here.
//!
//! SPDX-License-Identifier: Apache-2.0
#![allow(dead_code, non_snake_case)]
#![allow(private_interfaces)]

use core::ffi::{c_char, c_int, c_void};
use core::ptr;

use crate::asn1::a_d2i_fp::ASN1_item_d2i_bio;
use crate::asn1::a_i2d_fp::ASN1_item_i2d_mem_bio;
use crate::cmp::cmp_asn::{cmp_msg_it, CmpMsg};
use crate::cmp::cmp_ctx::{
    ossl_cmp_print_log, OSSL_CMP_CTX_get_http_cb_arg, OSSL_CMP_CTX_get_transfer_cb_arg, OsslCmpCtx,
};
use crate::cmp::cmp_util::OSSL_CMP_LOG_DEBUG;
use crate::http::http_client::{OSSL_HTTP_bio_cb_t, OSSL_HTTP_transfer, OsslHttpReqCtx};
use crate::runtime::bio::print::BIO_snprintf;
use crate::runtime::bio::{BIO_free, Bio};
use crate::runtime::conf::types::ConfValue;
use crate::runtime::err::err_sites::ErrSite;
use crate::runtime::err::raise_site;
use crate::runtime::stack::{OPENSSL_sk_pop_free, OpenSslStack};
use crate::x509::v3_utl::{X509V3_add_value, X509V3_conf_free};

/// The authority translation unit for this module.
pub(crate) const FILE: &core::ffi::CStr = c"crypto/cmp/cmp_http.c";

/// `ERR_LIB_CMP`.
const ERR_LIB_CMP: c_int = 58;
/// `CMP_R_NULL_ARGUMENT` — `include/openssl/cmperr.h`.
const CMP_R_NULL_ARGUMENT: c_int = 103;
/// `OSSL_HTTP_DEFAULT_MAX_RESP_LEN` — `include/openssl/http.h:43`.
const OSSL_HTTP_DEFAULT_MAX_RESP_LEN: usize = 100 * 1024;

/// The `OSSL_CMP_PKIBODY_*` selectors this unit names — `cmp_local.h:903-928`.
const OSSL_CMP_PKIBODY_IR: c_int = 0;
const OSSL_CMP_PKIBODY_CR: c_int = 2;
const OSSL_CMP_PKIBODY_P10CR: c_int = 4;
const OSSL_CMP_PKIBODY_KUR: c_int = 7;
const OSSL_CMP_PKIBODY_POLLREQ: c_int = 25;

/// `ERR_raise(ERR_LIB_CMP, reason)` at an authority coordinate of this unit.
///
/// # Safety
/// The site is a compile-time constant.
unsafe fn raise_cmp(line: c_int, func: &'static core::ffi::CStr, reason: c_int) {
    // SAFETY: the site is a compile-time constant.
    unsafe {
        raise_site(&ErrSite {
            file: FILE,
            line,
            func,
            lib: ERR_LIB_CMP,
            reason,
            dynamic_reason: false,
        })
    };
}

/// `static int keep_alive(int keep_alive, int body_type, BIO **bios)` — `cmp_http.c:14-28`.
///
/// # Safety
/// No preconditions.
unsafe fn keep_alive(keep_alive: c_int, body_type: c_int, bios: *mut *mut Bio) -> c_int {
    if keep_alive != 0
        && bios.is_null()
        /*
         * Ask for persistent connection only if may need more round trips.
         * Do so even with disableConfirm because polling might be needed.
         */
        && body_type != OSSL_CMP_PKIBODY_IR
        && body_type != OSSL_CMP_PKIBODY_CR
        && body_type != OSSL_CMP_PKIBODY_P10CR
        && body_type != OSSL_CMP_PKIBODY_KUR
        && body_type != OSSL_CMP_PKIBODY_POLLREQ
    {
        return 0;
    }
    keep_alive
}

/// `void (*)(void *)` shape `OPENSSL_sk_pop_free` takes for `X509V3_conf_free`.
///
/// # Safety
/// `conf` is NULL or a `CONF_VALUE` the extension layer built.
unsafe extern "C" fn conf_value_free_void(conf: *mut c_void) {
    // SAFETY: `conf` is NULL or a live `CONF_VALUE`.
    unsafe { X509V3_conf_free(conf.cast::<ConfValue>()) };
}

/// One CMP debug line: format through `BIO_snprintf` and hand the result to
/// [`ossl_cmp_print_log`], mirroring the no-trace arm of the authority's `ossl_cmp_log*` macros.
///
/// # Safety
/// `ctx` is NULL or live; `format` and every `%s` argument are NULL or NUL-terminated.
#[allow(clippy::too_many_arguments)]
unsafe fn cmp_debug(
    ctx: *const OsslCmpCtx,
    func: *const c_char,
    line: c_int,
    format: *const c_char,
    a0: *const c_char,
    a1: *const c_char,
    a2: *const c_char,
    a3: *const c_char,
) {
    let mut buf = [0 as c_char; 256];
    // SAFETY: `buf` is writable for its length; the format and up-to-four `%s` arguments are the
    // caller's. `BIO_snprintf` truncates rather than overruns.
    unsafe {
        BIO_snprintf(buf.as_mut_ptr(), buf.len(), format, a0, a1, a2, a3);
        ossl_cmp_print_log(
            OSSL_CMP_LOG_DEBUG,
            ctx,
            func,
            FILE.as_ptr(),
            line,
            buf.as_ptr(),
        );
    }
}

/// `sk_CONF_VALUE_pop_free(headers, X509V3_conf_free)` at the `err:` label.
///
/// # Safety
/// `headers` is NULL or a live `STACK_OF(CONF_VALUE)`.
unsafe fn pop_headers(headers: *mut OpenSslStack) {
    // SAFETY: `headers` is NULL or live.
    unsafe { OPENSSL_sk_pop_free(headers, Some(conf_value_free_void)) };
}

/// `OSSL_CMP_MSG *OSSL_CMP_MSG_http_perform(OSSL_CMP_CTX *ctx, const OSSL_CMP_MSG *req)`
/// — `cmp_http.c:33-107`.
///
/// # Safety
/// `ctx` is NULL or a live `OSSL_CMP_CTX`; `req` NULL or a live `OSSL_CMP_MSG`.
#[no_mangle]
pub unsafe extern "C" fn OSSL_CMP_MSG_http_perform(
    ctx: *mut OsslCmpCtx,
    req: *const CmpMsg,
) -> *mut CmpMsg {
    let mut server_port = [0 as c_char; 32];
    let mut headers: *mut OpenSslStack = ptr::null_mut();
    let content_type_pkix: &core::ffi::CStr = c"application/pkixcmp";

    if ctx.is_null() || req.is_null() {
        // SAFETY: the site is a compile-time constant.
        unsafe { raise_cmp(46, c"OSSL_CMP_MSG_http_perform", CMP_R_NULL_ARGUMENT) };
        return ptr::null_mut();
    }

    // SAFETY: the two strings are statics and `&mut headers` is writable.
    if unsafe { X509V3_add_value(c"Pragma".as_ptr(), c"no-cache".as_ptr(), &mut headers) } == 0 {
        return ptr::null_mut();
    }
    // SAFETY: the accessor answers a static item and `req` is live.
    let req_mem = unsafe { ASN1_item_i2d_mem_bio(cmp_msg_it(), req.cast::<c_void>()) };
    if req_mem.is_null() {
        // SAFETY: `headers` is NULL or a live stack.
        unsafe { pop_headers(headers) };
        return ptr::null_mut();
    }

    // SAFETY: `ctx` and `req` are live.
    let (
        bios,
        body_type,
        server,
        server_path,
        proxy,
        no_proxy,
        http_cb,
        msg_timeout,
        tls_used,
        keep,
    ) = unsafe {
        (
            OSSL_CMP_CTX_get_transfer_cb_arg(ctx).cast::<*mut Bio>(),
            (*(*req).body).type_,
            (*ctx).server,
            (*ctx).server_path,
            (*ctx).proxy,
            (*ctx).no_proxy,
            (*ctx).http_cb,
            (*ctx).msg_timeout,
            (*ctx).tls_used,
            (*ctx).keep_alive,
        )
    };
    // SAFETY: `ctx` is live.
    if unsafe { (*ctx).server_port } != 0 {
        // SAFETY: `server_port` is writable for its length; `%d` takes the port.
        unsafe {
            BIO_snprintf(
                server_port.as_mut_ptr(),
                server_port.len(),
                c"%d".as_ptr(),
                (*ctx).server_port,
            )
        };
    }
    let tls_used = if tls_used >= 0 {
        c_int::from(tls_used != 0)
    } else {
        /* backward compat */
        // SAFETY: `ctx` is live.
        c_int::from(!unsafe { OSSL_CMP_CTX_get_http_cb_arg(ctx) }.is_null())
    };

    // SAFETY: `ctx` is live.
    if unsafe { (*ctx).http_ctx }.is_null() {
        /* using existing connection or yet not set up own connection */
        let mut path: *const c_char = server_path;
        if path.is_null() {
            path = c"".as_ptr();
        }
        // SAFETY: `path` is NUL-terminated.
        if unsafe { *path } == b'/' as c_char {
            // SAFETY: `path` points at a NUL-terminated string, so the next byte is readable.
            path = unsafe { path.add(1) };
        }
        if bios.is_null() {
            // SAFETY: every argument is NULL or NUL-terminated.
            unsafe {
                cmp_debug(
                    ctx,
                    c"OSSL_CMP_MSG_http_perform".as_ptr(),
                    68,
                    c"connecting to CMP server via http%s://%s:%s/%s".as_ptr(),
                    if tls_used != 0 {
                        c"s".as_ptr()
                    } else {
                        c"".as_ptr()
                    },
                    server,
                    server_port.as_ptr(),
                    path,
                )
            };
        } else {
            // SAFETY: every argument is NULL or NUL-terminated.
            unsafe {
                cmp_debug(
                    ctx,
                    c"OSSL_CMP_MSG_http_perform".as_ptr(),
                    72,
                    c"using existing connection with CMP server %s:%s and HTTP path /%s".as_ptr(),
                    server,
                    server_port.as_ptr(),
                    path,
                    ptr::null(),
                )
            };
        }
    }

    // SAFETY: every argument is live and follows `OSSL_HTTP_transfer`'s contract.
    let rsp = unsafe {
        OSSL_HTTP_transfer(
            core::ptr::addr_of_mut!((*ctx).http_ctx).cast::<*mut OsslHttpReqCtx>(),
            server,
            server_port.as_ptr(),
            server_path,
            tls_used,
            proxy,
            no_proxy,
            if bios.is_null() {
                ptr::null_mut()
            } else {
                *bios
            }, /* bio */
            if bios.is_null() {
                ptr::null_mut()
            } else {
                *bios.add(1)
            }, /* rbio */
            core::mem::transmute::<*mut c_void, OSSL_HTTP_bio_cb_t>(http_cb),
            OSSL_CMP_CTX_get_http_cb_arg(ctx),
            0, /* buf_size */
            headers,
            content_type_pkix.as_ptr(),
            req_mem,
            content_type_pkix.as_ptr(),
            1, /* expect_asn1 */
            OSSL_HTTP_DEFAULT_MAX_RESP_LEN,
            msg_timeout,
            keep_alive(keep, body_type, bios),
        )
    };
    // SAFETY: `req_mem` is live.
    unsafe { BIO_free(req_mem) };
    // SAFETY: `rsp` is NULL or live; the item layer decodes it.
    let res = unsafe { ASN1_item_d2i_bio(cmp_msg_it(), rsp, ptr::null_mut()) }.cast::<CmpMsg>();
    // SAFETY: `rsp` is NULL or live.
    unsafe { BIO_free(rsp) };

    // SAFETY: `ctx` is live.
    if unsafe { (*ctx).http_ctx }.is_null() {
        // SAFETY: `ctx` is live and the message is a static.
        unsafe {
            cmp_debug(
                ctx,
                c"OSSL_CMP_MSG_http_perform".as_ptr(),
                94,
                c"disconnected from CMP server".as_ptr(),
                ptr::null(),
                ptr::null(),
                ptr::null(),
                ptr::null(),
            )
        };
    }
    /*
     * Note that on normal successful end of the transaction the
     * HTTP connection is not closed at this level if keep_alive(...) != 0.
     * It should be closed by the CMP client application
     * using OSSL_CMP_CTX_free() or OSSL_CMP_CTX_reinit().
     * Any pre-existing bio (== ctx->transfer_cb_arg) is not freed.
     */
    if !res.is_null() {
        // SAFETY: `ctx` is live and the message is a static.
        unsafe {
            cmp_debug(
                ctx,
                c"OSSL_CMP_MSG_http_perform".as_ptr(),
                103,
                c"finished reading response from CMP server".as_ptr(),
                ptr::null(),
                ptr::null(),
                ptr::null(),
                ptr::null(),
            )
        };
    }
    // SAFETY: `headers` is NULL or a live stack.
    unsafe { pop_headers(headers) };
    res
}
