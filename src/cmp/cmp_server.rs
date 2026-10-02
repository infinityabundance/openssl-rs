//! `crypto/cmp/cmp_server.c` — the generic CMP server context. Phase 12.4.
//!
//! This unit lands the `OSSL_CMP_SRV_CTX` plumbing: the constructor/destructor, the callback
//! installer, the transaction initialiser and the four accept/grant switches. The server *engine*
//! (`OSSL_CMP_SRV_process_request` and `OSSL_CMP_CTX_server_perform`) is left open: its
//! `process_cert_request`/`process_pollReq`/`delayed_delivery` arms build request and response
//! messages through the `cmp_protect.c` protection engine, whose PasswordBasedMAC path needs the
//! `crmf_pbm.c` public surface the plan lands in 12.7.
//!
//! SPDX-License-Identifier: Apache-2.0
#![allow(dead_code, non_snake_case)]
#![allow(private_interfaces, non_camel_case_types)]

use core::ffi::{c_char, c_int, c_void};
use core::ptr;

use crate::asn1::layout::Asn1String;
use crate::cmp::cmp_asn::{CmpItav, CmpMsg, CmpPkisi};
use crate::cmp::cmp_ctx::{OSSL_CMP_CTX_free, OSSL_CMP_CTX_new, OsslCmpCtx};
use crate::cmp::crmf_asn::CrmfMsg;
use crate::runtime::err::err_sites::ErrSite;
use crate::runtime::err::raise_site;
use crate::runtime::mem::{CRYPTO_free, CRYPTO_zalloc};
use crate::runtime::stack::OpenSslStack;
use crate::x509::x509_req::X509Req;
use crate::x509::x_name::X509Name;
use crate::x509::x_x509::X509;

/// The authority translation unit for this module.
pub(crate) const FILE: &core::ffi::CStr = c"crypto/cmp/cmp_server.c";

/// `ERR_LIB_CMP`.
const ERR_LIB_CMP: c_int = 58;
/// `CMP_R_NULL_ARGUMENT` — `include/openssl/cmperr.h:91`.
const CMP_R_NULL_ARGUMENT: c_int = 103;
/// `OSSL_CMP_CERTREQID_INVALID` — `cmp_local.h:934`.
const OSSL_CMP_CERTREQID_INVALID: c_int = -2;

/// `OSSL_CMP_SRV_cert_request_cb_t` — `include/openssl/cmp.h.in:655-657`.
pub type OSSL_CMP_SRV_cert_request_cb_t = Option<
    unsafe extern "C" fn(
        *mut OsslCmpSrvCtx,
        *const CmpMsg,
        c_int,
        *const CrmfMsg,
        *const X509Req,
        *mut *mut X509,
        *mut *mut OpenSslStack,
        *mut *mut OpenSslStack,
    ) -> *mut CmpPkisi,
>;
/// `OSSL_CMP_SRV_rr_cb_t` — `include/openssl/cmp.h.in:658-661`.
pub type OSSL_CMP_SRV_rr_cb_t = Option<
    unsafe extern "C" fn(
        *mut OsslCmpSrvCtx,
        *const CmpMsg,
        *const X509Name,
        *const Asn1String,
    ) -> *mut CmpPkisi,
>;
/// `OSSL_CMP_SRV_genm_cb_t` — `include/openssl/cmp.h.in:662-665`.
pub type OSSL_CMP_SRV_genm_cb_t = Option<
    unsafe extern "C" fn(
        *mut OsslCmpSrvCtx,
        *const CmpMsg,
        *const OpenSslStack,
        *mut *mut OpenSslStack,
    ) -> c_int,
>;
/// `OSSL_CMP_SRV_error_cb_t` — `include/openssl/cmp.h.in:666-670`.
pub type OSSL_CMP_SRV_error_cb_t = Option<
    unsafe extern "C" fn(
        *mut OsslCmpSrvCtx,
        *const CmpMsg,
        *const CmpPkisi,
        *const Asn1String,
        *const OpenSslStack,
    ),
>;
/// `OSSL_CMP_SRV_certConf_cb_t` — `include/openssl/cmp.h.in:671-675`.
pub type OSSL_CMP_SRV_certConf_cb_t = Option<
    unsafe extern "C" fn(
        *mut OsslCmpSrvCtx,
        *const CmpMsg,
        c_int,
        *const Asn1String,
        *const CmpPkisi,
    ) -> c_int,
>;
/// `OSSL_CMP_SRV_pollReq_cb_t` — `include/openssl/cmp.h.in:676-679`.
pub type OSSL_CMP_SRV_pollReq_cb_t = Option<
    unsafe extern "C" fn(
        *mut OsslCmpSrvCtx,
        *const CmpMsg,
        c_int,
        *mut *mut CmpMsg,
        *mut i64,
    ) -> c_int,
>;
/// `OSSL_CMP_SRV_delayed_delivery_cb_t` — `include/openssl/cmp.h.in:687-688`.
pub type OSSL_CMP_SRV_delayed_delivery_cb_t =
    Option<unsafe extern "C" fn(*mut OsslCmpSrvCtx, *const CmpMsg) -> c_int>;
/// `OSSL_CMP_SRV_clean_transaction_cb_t` — `include/openssl/cmp.h.in:689-690`.
pub type OSSL_CMP_SRV_clean_transaction_cb_t =
    Option<unsafe extern "C" fn(*mut OsslCmpSrvCtx, *const Asn1String) -> c_int>;

/// `struct ossl_cmp_srv_ctx_st` — `cmp_server.c:17-37`.
#[repr(C)]
pub(crate) struct OsslCmpSrvCtx {
    ctx: *mut OsslCmpCtx,
    custom_ctx: *mut c_void,
    cert_req_id: c_int,
    polling: c_int,
    process_cert_request: OSSL_CMP_SRV_cert_request_cb_t,
    process_rr: OSSL_CMP_SRV_rr_cb_t,
    process_genm: OSSL_CMP_SRV_genm_cb_t,
    process_error: OSSL_CMP_SRV_error_cb_t,
    process_cert_conf: OSSL_CMP_SRV_certConf_cb_t,
    process_poll_req: OSSL_CMP_SRV_pollReq_cb_t,
    delayed_delivery: OSSL_CMP_SRV_delayed_delivery_cb_t,
    clean_transaction: OSSL_CMP_SRV_clean_transaction_cb_t,
    send_unprotected_errors: c_int,
    accept_unprotected: c_int,
    accept_raverified: c_int,
    grant_implicit_confirm: c_int,
}

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

/// `void OSSL_CMP_SRV_CTX_free(OSSL_CMP_SRV_CTX *srv_ctx)` — `cmp_server.c:39-46`.
///
/// # Safety
/// `srv_ctx` is NULL or a live `OSSL_CMP_SRV_CTX`.
#[no_mangle]
pub unsafe extern "C" fn OSSL_CMP_SRV_CTX_free(srv_ctx: *mut OsslCmpSrvCtx) {
    if srv_ctx.is_null() {
        return;
    }
    // SAFETY: `srv_ctx` is live; its `ctx` is NULL or owned by it.
    unsafe {
        OSSL_CMP_CTX_free((*srv_ctx).ctx);
        CRYPTO_free(srv_ctx.cast(), FILE.as_ptr(), 45);
    }
}

/// `OSSL_CMP_SRV_CTX *OSSL_CMP_SRV_CTX_new(OSSL_LIB_CTX *libctx, const char *propq)`
/// — `cmp_server.c:48-65`.
///
/// # Safety
/// `libctx` is NULL or live; `propq` NULL or NUL-terminated.
#[no_mangle]
pub unsafe extern "C" fn OSSL_CMP_SRV_CTX_new(
    libctx: *mut c_void,
    propq: *const c_char,
) -> *mut OsslCmpSrvCtx {
    // SAFETY: `CRYPTO_zalloc` returns zeroed memory or NULL.
    let ctx = CRYPTO_zalloc(core::mem::size_of::<OsslCmpSrvCtx>(), FILE.as_ptr(), 50)
        .cast::<OsslCmpSrvCtx>();
    if ctx.is_null() {
        return ptr::null_mut();
    }

    // SAFETY: `ctx` is live and zeroed.
    unsafe {
        (*ctx).ctx = OSSL_CMP_CTX_new(libctx, propq);
        if (*ctx).ctx.is_null() {
            // SAFETY: `ctx` is live.
            OSSL_CMP_SRV_CTX_free(ctx);
            return ptr::null_mut();
        }
        (*ctx).cert_req_id = OSSL_CMP_CERTREQID_INVALID;
        (*ctx).polling = 0;
    }
    /* all other elements are initialized to 0 or NULL, respectively */
    ctx
}

/// `int OSSL_CMP_SRV_CTX_init(OSSL_CMP_SRV_CTX *srv_ctx, void *custom_ctx, ...)`
/// — `cmp_server.c:67-87`.
///
/// # Safety
/// `srv_ctx` is NULL or a live `OSSL_CMP_SRV_CTX`; every callback is NULL or a valid function.
#[no_mangle]
pub unsafe extern "C" fn OSSL_CMP_SRV_CTX_init(
    srv_ctx: *mut OsslCmpSrvCtx,
    custom_ctx: *mut c_void,
    process_cert_request: OSSL_CMP_SRV_cert_request_cb_t,
    process_rr: OSSL_CMP_SRV_rr_cb_t,
    process_genm: OSSL_CMP_SRV_genm_cb_t,
    process_error: OSSL_CMP_SRV_error_cb_t,
    process_cert_conf: OSSL_CMP_SRV_certConf_cb_t,
    process_poll_req: OSSL_CMP_SRV_pollReq_cb_t,
) -> c_int {
    if srv_ctx.is_null() {
        // SAFETY: the site is a compile-time constant.
        unsafe { raise_cmp(76, c"OSSL_CMP_SRV_CTX_init", CMP_R_NULL_ARGUMENT) };
        return 0;
    }
    // SAFETY: `srv_ctx` is live.
    unsafe {
        (*srv_ctx).custom_ctx = custom_ctx;
        (*srv_ctx).process_cert_request = process_cert_request;
        (*srv_ctx).process_rr = process_rr;
        (*srv_ctx).process_genm = process_genm;
        (*srv_ctx).process_error = process_error;
        (*srv_ctx).process_cert_conf = process_cert_conf;
        (*srv_ctx).process_poll_req = process_poll_req;
    }
    1
}

/// `int OSSL_CMP_SRV_CTX_init_trans(OSSL_CMP_SRV_CTX *srv_ctx, ...)` — `cmp_server.c:89-100`.
///
/// # Safety
/// `srv_ctx` is NULL or live; the callbacks are NULL or valid.
#[no_mangle]
pub unsafe extern "C" fn OSSL_CMP_SRV_CTX_init_trans(
    srv_ctx: *mut OsslCmpSrvCtx,
    delay: OSSL_CMP_SRV_delayed_delivery_cb_t,
    clean: OSSL_CMP_SRV_clean_transaction_cb_t,
) -> c_int {
    if srv_ctx.is_null() {
        // SAFETY: the site is a compile-time constant.
        unsafe { raise_cmp(94, c"OSSL_CMP_SRV_CTX_init_trans", CMP_R_NULL_ARGUMENT) };
        return 0;
    }
    // SAFETY: `srv_ctx` is live.
    unsafe {
        (*srv_ctx).delayed_delivery = delay;
        (*srv_ctx).clean_transaction = clean;
    }
    1
}

/// `OSSL_CMP_CTX *OSSL_CMP_SRV_CTX_get0_cmp_ctx(const OSSL_CMP_SRV_CTX *srv_ctx)`
/// — `cmp_server.c:102-109`.
///
/// # Safety
/// `srv_ctx` is NULL or live.
#[no_mangle]
pub unsafe extern "C" fn OSSL_CMP_SRV_CTX_get0_cmp_ctx(
    srv_ctx: *const OsslCmpSrvCtx,
) -> *mut OsslCmpCtx {
    if srv_ctx.is_null() {
        // SAFETY: the site is a compile-time constant.
        unsafe { raise_cmp(105, c"OSSL_CMP_SRV_CTX_get0_cmp_ctx", CMP_R_NULL_ARGUMENT) };
        return ptr::null_mut();
    }
    // SAFETY: `srv_ctx` is live.
    unsafe { (*srv_ctx).ctx }
}

/// `void *OSSL_CMP_SRV_CTX_get0_custom_ctx(const OSSL_CMP_SRV_CTX *srv_ctx)`
/// — `cmp_server.c:111-118`.
///
/// # Safety
/// `srv_ctx` is NULL or live.
#[no_mangle]
pub unsafe extern "C" fn OSSL_CMP_SRV_CTX_get0_custom_ctx(
    srv_ctx: *const OsslCmpSrvCtx,
) -> *mut c_void {
    if srv_ctx.is_null() {
        // SAFETY: the site is a compile-time constant.
        unsafe {
            raise_cmp(
                114,
                c"OSSL_CMP_SRV_CTX_get0_custom_ctx",
                CMP_R_NULL_ARGUMENT,
            )
        };
        return ptr::null_mut();
    }
    // SAFETY: `srv_ctx` is live.
    unsafe { (*srv_ctx).custom_ctx }
}

/// `int OSSL_CMP_SRV_CTX_set_send_unprotected_errors(OSSL_CMP_SRV_CTX *srv_ctx, int val)`
/// — `cmp_server.c:120-129`.
///
/// # Safety
/// `srv_ctx` is NULL or live.
#[no_mangle]
pub unsafe extern "C" fn OSSL_CMP_SRV_CTX_set_send_unprotected_errors(
    srv_ctx: *mut OsslCmpSrvCtx,
    val: c_int,
) -> c_int {
    if srv_ctx.is_null() {
        // SAFETY: the site is a compile-time constant.
        unsafe {
            raise_cmp(
                124,
                c"OSSL_CMP_SRV_CTX_set_send_unprotected_errors",
                CMP_R_NULL_ARGUMENT,
            )
        };
        return 0;
    }
    // SAFETY: `srv_ctx` is live.
    unsafe { (*srv_ctx).send_unprotected_errors = c_int::from(val != 0) };
    1
}

/// `int OSSL_CMP_SRV_CTX_set_accept_unprotected(OSSL_CMP_SRV_CTX *srv_ctx, int val)`
/// — `cmp_server.c:131-139`.
///
/// # Safety
/// `srv_ctx` is NULL or live.
#[no_mangle]
pub unsafe extern "C" fn OSSL_CMP_SRV_CTX_set_accept_unprotected(
    srv_ctx: *mut OsslCmpSrvCtx,
    val: c_int,
) -> c_int {
    if srv_ctx.is_null() {
        // SAFETY: the site is a compile-time constant.
        unsafe {
            raise_cmp(
                135,
                c"OSSL_CMP_SRV_CTX_set_accept_unprotected",
                CMP_R_NULL_ARGUMENT,
            )
        };
        return 0;
    }
    // SAFETY: `srv_ctx` is live.
    unsafe { (*srv_ctx).accept_unprotected = c_int::from(val != 0) };
    1
}

/// `int OSSL_CMP_SRV_CTX_set_accept_raverified(OSSL_CMP_SRV_CTX *srv_ctx, int val)`
/// — `cmp_server.c:141-149`.
///
/// # Safety
/// `srv_ctx` is NULL or live.
#[no_mangle]
pub unsafe extern "C" fn OSSL_CMP_SRV_CTX_set_accept_raverified(
    srv_ctx: *mut OsslCmpSrvCtx,
    val: c_int,
) -> c_int {
    if srv_ctx.is_null() {
        // SAFETY: the site is a compile-time constant.
        unsafe {
            raise_cmp(
                145,
                c"OSSL_CMP_SRV_CTX_set_accept_raverified",
                CMP_R_NULL_ARGUMENT,
            )
        };
        return 0;
    }
    // SAFETY: `srv_ctx` is live.
    unsafe { (*srv_ctx).accept_raverified = c_int::from(val != 0) };
    1
}

/// `int OSSL_CMP_SRV_CTX_set_grant_implicit_confirm(OSSL_CMP_SRV_CTX *srv_ctx, int val)`
/// — `cmp_server.c:151-160`.
///
/// # Safety
/// `srv_ctx` is NULL or live.
#[no_mangle]
pub unsafe extern "C" fn OSSL_CMP_SRV_CTX_set_grant_implicit_confirm(
    srv_ctx: *mut OsslCmpSrvCtx,
    val: c_int,
) -> c_int {
    if srv_ctx.is_null() {
        // SAFETY: the site is a compile-time constant.
        unsafe {
            raise_cmp(
                155,
                c"OSSL_CMP_SRV_CTX_set_grant_implicit_confirm",
                CMP_R_NULL_ARGUMENT,
            )
        };
        return 0;
    }
    // SAFETY: `srv_ctx` is live.
    unsafe { (*srv_ctx).grant_implicit_confirm = c_int::from(val != 0) };
    1
}

/// Keeps the `CmpItav` import used by the callback aliases' documentation.
#[allow(dead_code)]
type _Itav = *mut CmpItav;
