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
use crate::cmp::cmp_asn::{CmpItav, CmpMsg, CmpPkisi, OSSL_CMP_PKISI_free};
use crate::cmp::cmp_ctx::{
    ossl_cmp_ctx_set1_recipNonce, OSSL_CMP_CTX_free, OSSL_CMP_CTX_get_option,
    OSSL_CMP_CTX_get_transfer_cb_arg, OSSL_CMP_CTX_new, OSSL_CMP_CTX_print_errors,
    OSSL_CMP_CTX_set1_recipient, OSSL_CMP_CTX_set1_senderNonce, OSSL_CMP_CTX_set1_transactionID,
    OsslCmpCtx,
};
use crate::cmp::cmp_hdr::ossl_cmp_hdr_get_protection_nid;
use crate::cmp::cmp_msg::{
    ossl_cmp_bodytype_to_string, ossl_cmp_certrep_new, ossl_cmp_error_new, ossl_cmp_genp_new,
    ossl_cmp_is_error_with_waiting, ossl_cmp_pkiconf_new, ossl_cmp_pollRep_new, ossl_cmp_rp_new,
    OSSL_CMP_MSG_free, OSSL_CMP_MSG_get0_header, OSSL_CMP_MSG_get_bodytype,
};
use crate::cmp::cmp_status::OSSL_CMP_STATUSINFO_new;
use crate::cmp::cmp_util::{
    ossl_cmp_log0, ossl_cmp_log_str, OSSL_CMP_LOG_DEBUG, OSSL_CMP_LOG_ERR, OSSL_CMP_LOG_WARNING,
};
use crate::cmp::cmp_vfy::ossl_cmp_msg_check_update;
use crate::cmp::crmf_asn::CrmfMsg;
use crate::runtime::err::err_sites::ErrSite;
use crate::runtime::err::{raise_site, ERR_peek_error_all, ERR_reason_error_string};
use crate::runtime::mem::{CRYPTO_free, CRYPTO_zalloc};
use crate::runtime::stack::{OPENSSL_sk_num, OPENSSL_sk_value, OpenSslStack};
use crate::x509::t_x509::OSSL_STACK_OF_X509_free;
use crate::x509::v3_genn::{GeneralName, GEN_DIRNAME};
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

// ---------------------------------------------------------------------------------------------
// The request engine — `cmp_server.c:161-774`
// ---------------------------------------------------------------------------------------------

/// `OSSL_CMP_PKIFAILUREINFO_systemFailure` — `include/openssl/cmp.h.in:137`.
const OSSL_CMP_PKIFAILUREINFO_SYSTEM_FAILURE: c_int = 25;
/// `OSSL_CMP_PKIFAILUREINFO_badPOP` — `include/openssl/cmp.h.in:121`.
const OSSL_CMP_PKIFAILUREINFO_BAD_POP: c_int = 9;
/// `OSSL_CMP_PKIFAILUREINFO_badRequest` — `include/openssl/cmp.h.in:114`.
const OSSL_CMP_PKIFAILUREINFO_BAD_REQUEST: c_int = 2;
/// `OSSL_CMP_PKIBODY_*` selectors — `cmp_local.h:903-931`.
const OSSL_CMP_PKIBODY_IR: c_int = 0;
const OSSL_CMP_PKIBODY_IP: c_int = 1;
const OSSL_CMP_PKIBODY_CR: c_int = 2;
const OSSL_CMP_PKIBODY_CP: c_int = 3;
const OSSL_CMP_PKIBODY_P10CR: c_int = 4;
const OSSL_CMP_PKIBODY_KUR: c_int = 7;
const OSSL_CMP_PKIBODY_KUP: c_int = 8;
const OSSL_CMP_PKIBODY_RR: c_int = 11;
const OSSL_CMP_PKIBODY_RP: c_int = 12;
const OSSL_CMP_PKIBODY_PKICONF: c_int = 19;
const OSSL_CMP_PKIBODY_GENM: c_int = 21;
const OSSL_CMP_PKIBODY_GENP: c_int = 22;
const OSSL_CMP_PKIBODY_ERROR: c_int = 23;
const OSSL_CMP_PKIBODY_CERTCONF: c_int = 24;
const OSSL_CMP_PKIBODY_POLLREQ: c_int = 25;
/// `OSSL_CMP_CERTREQID`/`_NONE` — `cmp_local.h:932-933`.
const OSSL_CMP_CERTREQID: c_int = 0;
const OSSL_CMP_CERTREQID_NONE: c_int = -1;
/// The option selectors this engine reads — `include/openssl/cmp.h.in:370,376`.
const OSSL_CMP_OPT_IMPLICIT_CONFIRM: c_int = 25;
const OSSL_CMP_OPT_UNPROTECTED_ERRORS: c_int = 31;
/// `OSSL_CMP_PKISTATUS_*` — `include/openssl/cmp.h.in:200-211`.
const OSSL_CMP_PKISTATUS_UNSPECIFIED: c_int = -1;
const OSSL_CMP_PKISTATUS_TRANS: c_int = -2;
const OSSL_CMP_PKISTATUS_ACCEPTED: c_int = 0;
const OSSL_CMP_PKISTATUS_REJECTION: c_int = 2;
const OSSL_CMP_PKISTATUS_WAITING: c_int = 3;
/// `NID_id_PasswordBasedMAC` — `include/openssl/obj_mac.h`.
const NID_id_PASSWORD_BASED_MAC: c_int = 782;

/// `static OSSL_CMP_MSG *delayed_delivery(...)` — `cmp_server.c:163-200`.
///
/// # Safety
/// `srv_ctx`/`req` are live.
unsafe fn delayed_delivery(srv_ctx: *mut OsslCmpSrvCtx, req: *const CmpMsg) -> *mut CmpMsg {
    if srv_ctx.is_null()
        // SAFETY: the enclosing function's `# Safety` section is the contract for these raw pointers.
        || unsafe { (*srv_ctx).ctx }.is_null()
        || req.is_null()
        // SAFETY: the enclosing function's `# Safety` section is the contract for these raw pointers.
        || unsafe { (*srv_ctx).delayed_delivery }.is_none()
    {
        return ptr::null_mut();
    }
    // SAFETY: the gate above ensures the callback is installed.
    let cb = match unsafe { (*srv_ctx).delayed_delivery } {
        Some(cb) => cb,
        None => return ptr::null_mut(),
    };
    // SAFETY: `srv_ctx`/`req` are live per the callback's contract.
    let ret = unsafe { cb(srv_ctx, req) };
    if ret == 0 {
        return ptr::null_mut();
    }
    let mut status = OSSL_CMP_PKISTATUS_WAITING;
    let mut fail_info = 0;
    let mut error_code = 0;
    let mut txt: *const c_char = ptr::null();
    if ret == 1 {
        // SAFETY: `srv_ctx` is live.
        unsafe { (*srv_ctx).polling = 1 };
    } else {
        status = OSSL_CMP_PKISTATUS_REJECTION;
        fail_info = 1 << OSSL_CMP_PKIFAILUREINFO_SYSTEM_FAILURE;
        txt = c"server application error".as_ptr();
        // SAFETY: no preconditions.
        let err = crate::runtime::err::ERR_peek_error();
        error_code = (err & 0x7F_FFFF) as c_int;
    }
    // SAFETY: `txt` is NULL or NUL-terminated.
    let si = unsafe { crate::cmp::cmp_status::OSSL_CMP_STATUSINFO_new(status, fail_info, txt) };
    if si.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: `srv_ctx`'s ctx is live.
    let ctx = unsafe { (*srv_ctx).ctx };
    // SAFETY: the enclosing function's `# Safety` section is the contract for these raw pointers.
    let unprotected = unsafe { (*srv_ctx).send_unprotected_errors };
    // SAFETY: `ctx`/`si` are live.
    let msg = unsafe { ossl_cmp_error_new(ctx, si, error_code as i64, ptr::null(), unprotected) };
    // SAFETY: `si` is this call's own.
    unsafe { OSSL_CMP_PKISI_free(si) };
    msg
}

/// `static OSSL_CMP_MSG *process_cert_request(...)` — `cmp_server.c:207-308`.
///
/// # Safety
/// `srv_ctx`/`req` are live.
unsafe fn process_cert_request(srv_ctx: *mut OsslCmpSrvCtx, req: *const CmpMsg) -> *mut CmpMsg {
    // SAFETY: the enclosing function's `# Safety` section is the contract for these raw pointers.
    if srv_ctx.is_null() || unsafe { (*srv_ctx).ctx }.is_null() || req.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: `req` is live.
    let req_type = unsafe { OSSL_CMP_MSG_get_bodytype(req) };
    let bodytype = match req_type {
        OSSL_CMP_PKIBODY_P10CR | OSSL_CMP_PKIBODY_CR => OSSL_CMP_PKIBODY_CP,
        OSSL_CMP_PKIBODY_IR => OSSL_CMP_PKIBODY_IP,
        OSSL_CMP_PKIBODY_KUR => OSSL_CMP_PKIBODY_KUP,
        _ => {
            // SAFETY: the site is a compile-time constant.
            unsafe { raise_cmp(235, c"process_cert_request", 133) };
            return ptr::null_mut();
        }
    };

    let crm: *const crate::crmf::crmf_asn::CrmfMsg;
    let p10cr: *const crate::x509::x509_req::X509Req;
    let cert_req_id: c_int;
    if req_type == OSSL_CMP_PKIBODY_P10CR {
        cert_req_id = OSSL_CMP_CERTREQID_NONE;
        crm = ptr::null();
        // SAFETY: `req` is live.
        p10cr = unsafe { (*(*req).body).value.p10cr }.cast();
    } else {
        p10cr = ptr::null();
        // SAFETY: `req` is live.
        let reqs = unsafe { (*(*req).body).value.ir };
        // SAFETY: `reqs` is live.
        if unsafe { crate::runtime::stack::OPENSSL_sk_num(reqs) } != 1 {
            // SAFETY: the site is a compile-time constant.
            unsafe { raise_cmp(246, c"process_cert_request", 161) };
            return ptr::null_mut();
        }
        // SAFETY: `reqs` is live.
        crm = unsafe { crate::runtime::stack::OPENSSL_sk_value(reqs, 0) }
            .cast::<crate::crmf::crmf_asn::CrmfMsg>();
        if crm.is_null() {
            // SAFETY: the site is a compile-time constant.
            unsafe { raise_cmp(250, c"process_cert_request", 157) };
            return ptr::null_mut();
        }
        // SAFETY: `crm` is live.
        cert_req_id = unsafe { crate::crmf::crmf_lib::OSSL_CRMF_MSG_get_certReqId(crm) };
        if cert_req_id != OSSL_CMP_CERTREQID {
            // SAFETY: the site is a compile-time constant.
            unsafe { raise_cmp(255, c"process_cert_request", 108) };
            return ptr::null_mut();
        }
    }
    // SAFETY: `srv_ctx` is live.
    unsafe { (*srv_ctx).cert_req_id = cert_req_id };

    // SAFETY: `crm`/`p10cr` are NULL or live with at least one non-NULL.
    let central_keygen =
        unsafe { crate::crmf::crmf_lib::OSSL_CRMF_MSG_centralkeygen_requested(crm, p10cr) };
    if central_keygen < 0 {
        return ptr::null_mut();
    }

    let mut cert_out: *mut X509 = ptr::null_mut();
    let mut key_out: *mut crate::evp::pkey::EvpPkey = ptr::null_mut();
    let mut chain_out: *mut OpenSslStack = ptr::null_mut();
    let mut ca_pubs: *mut OpenSslStack = ptr::null_mut();
    let si: *mut CmpPkisi;

    // SAFETY: `srv_ctx`'s ctx is live.
    let ctx = unsafe { (*srv_ctx).ctx };
    if central_keygen == 0 {
        // SAFETY: `ctx`/`req` are live.
        let accept_raverified = unsafe { (*srv_ctx).accept_raverified };
        // SAFETY: the enclosing function's `# Safety` section is the contract for these raw pointers.
        if unsafe { crate::cmp::cmp_vfy::ossl_cmp_verify_popo(ctx, req, accept_raverified) } == 0 {
            /* Proof of possession could not be verified */
            // SAFETY: no preconditions.
            let err = crate::runtime::err::ERR_peek_error();
            // SAFETY: the error string is static or NULL.
            let reason = crate::runtime::err::ERR_reason_error_string(err);
            // SAFETY: `reason` is NULL or NUL-terminated.
            si = unsafe {
                crate::cmp::cmp_status::OSSL_CMP_STATUSINFO_new(
                    OSSL_CMP_PKISTATUS_REJECTION,
                    1 << OSSL_CMP_PKIFAILUREINFO_BAD_POP,
                    reason,
                )
            };
            if si.is_null() {
                return ptr::null_mut();
            }
        } else {
            // SAFETY: `srv_ctx`/`req` are live; the out-slots are writable.
            si = unsafe {
                process_cert_request_inner(
                    srv_ctx,
                    req,
                    cert_req_id,
                    crm,
                    p10cr,
                    &mut cert_out,
                    &mut chain_out,
                    &mut ca_pubs,
                )
            };
            if si.is_null() {
                return ptr::null_mut();
            }
            // SAFETY: `si` is live.
            if unsafe { crate::cmp::cmp_status::ossl_cmp_pkisi_get_status(si) }
                == OSSL_CMP_PKISTATUS_WAITING
            {
                // SAFETY: `srv_ctx` is live.
                unsafe { (*srv_ctx).polling = 1 };
            }
            // SAFETY: `req` is live.
            let hdr = unsafe { OSSL_CMP_MSG_get0_header(req) };
            // SAFETY: `ctx`/`hdr` are live.
            let implicit = unsafe { crate::cmp::cmp_hdr::ossl_cmp_hdr_has_implicitConfirm(hdr) }
                != 0
                && unsafe { (*srv_ctx).grant_implicit_confirm } != 0
                && !cert_out.is_null();
            // SAFETY: `ctx` is live.
            if unsafe {
                crate::cmp::cmp_ctx::OSSL_CMP_CTX_set_option(
                    ctx,
                    OSSL_CMP_OPT_IMPLICIT_CONFIRM,
                    c_int::from(implicit),
                )
            } == 0
            {
                return ptr::null_mut();
            }
            if central_keygen == 1
                // SAFETY: the enclosing function's `# Safety` section is the contract for these raw pointers.
                && unsafe { (*ctx).new_pkey_priv } != 0
                // SAFETY: the enclosing function's `# Safety` section is the contract for these raw pointers.
                && !unsafe { (*ctx).new_pkey }.is_null()
            {
                // SAFETY: the enclosing function's `# Safety` section is the contract for these raw pointers.
                key_out = unsafe { (*ctx).new_pkey };
            }
        }
    } else {
        // SAFETY: `srv_ctx`/`req` are live; the out-slots are writable.
        si = unsafe {
            process_cert_request_inner(
                srv_ctx,
                req,
                cert_req_id,
                crm,
                p10cr,
                &mut cert_out,
                &mut chain_out,
                &mut ca_pubs,
            )
        };
        if si.is_null() {
            return ptr::null_mut();
        }
        if central_keygen == 1
            // SAFETY: the enclosing function's `# Safety` section is the contract for these raw pointers.
            && unsafe { (*ctx).new_pkey_priv } != 0
            // SAFETY: the enclosing function's `# Safety` section is the contract for these raw pointers.
            && !unsafe { (*ctx).new_pkey }.is_null()
        {
            // SAFETY: the enclosing function's `# Safety` section is the contract for these raw pointers.
            key_out = unsafe { (*ctx).new_pkey };
        }
    }

    // SAFETY: the enclosing function's `# Safety` section is the contract for these raw pointers.
    let unprotected = unsafe { (*srv_ctx).send_unprotected_errors };
    // SAFETY: `ctx`/`si` are live; the rest are NULL or live.
    let msg = unsafe {
        ossl_cmp_certrep_new(
            ctx,
            bodytype,
            cert_req_id,
            si,
            cert_out,
            key_out,
            ptr::null(),
            chain_out,
            ca_pubs,
            unprotected,
        )
    };
    if msg.is_null() {
        // SAFETY: the site is a compile-time constant.
        unsafe { raise_cmp(299, c"process_cert_request", 117) };
    }
    // SAFETY: `si` is this call's own; `cert_out` is owned here; the stacks are NULL or owned.
    unsafe {
        OSSL_CMP_PKISI_free(si);
        crate::x509::x_x509::X509_free(cert_out);
        crate::cmp::cmp_ctx::OSSL_CMP_CTX_set0_newPkey(ctx, 0, ptr::null_mut());
        OSSL_STACK_OF_X509_free(chain_out);
        OSSL_STACK_OF_X509_free(ca_pubs);
    }
    msg
}

/// The `process_cert_request` callback dispatch shared by both `central_keygen` arms.
///
/// # Safety
/// `srv_ctx`/`req` are live; the out-slots are writable.
#[allow(clippy::too_many_arguments)]
unsafe fn process_cert_request_inner(
    srv_ctx: *mut OsslCmpSrvCtx,
    req: *const CmpMsg,
    cert_req_id: c_int,
    crm: *const crate::crmf::crmf_asn::CrmfMsg,
    p10cr: *const crate::x509::x509_req::X509Req,
    cert_out: *mut *mut X509,
    chain_out: *mut *mut OpenSslStack,
    ca_pubs: *mut *mut OpenSslStack,
) -> *mut CmpPkisi {
    // SAFETY: the callback is installed per the caller's contract.
    let cb = match unsafe { (*srv_ctx).process_cert_request } {
        Some(cb) => cb,
        None => return ptr::null_mut(),
    };
    // SAFETY: `srv_ctx`/`req`/out-slots are live per the callback's contract.
    unsafe {
        cb(
            srv_ctx,
            req,
            cert_req_id,
            crm,
            p10cr,
            cert_out,
            chain_out,
            ca_pubs,
        )
    }
}

/// `OSSL_CMP_ITAV_free` element releaser for [`crate::runtime::stack::OPENSSL_sk_pop_free`].
///
/// # Safety
/// `p` is an `OSSL_CMP_ITAV`.
unsafe extern "C" fn itav_free_void(p: *mut c_void) {
    // SAFETY: `p` is an ITAV per the contract.
    unsafe { crate::cmp::cmp_asn::OSSL_CMP_ITAV_free(p.cast()) };
}

/// `static OSSL_CMP_MSG *process_rr(...)` — `cmp_server.c:310-352`.
///
/// # Safety
/// `srv_ctx`/`req` are live.
unsafe fn process_rr(srv_ctx: *mut OsslCmpSrvCtx, req: *const CmpMsg) -> *mut CmpMsg {
    // SAFETY: the enclosing function's `# Safety` section is the contract for these raw pointers.
    if srv_ctx.is_null() || unsafe { (*srv_ctx).ctx }.is_null() || req.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: `req` is live.
    let rr = unsafe { (*(*req).body).value.rr };
    // SAFETY: `rr` is live.
    if unsafe { crate::runtime::stack::OPENSSL_sk_num(rr) } != 1 {
        // SAFETY: the site is a compile-time constant.
        unsafe { raise_cmp(325, c"process_rr", 161) };
        return ptr::null_mut();
    }
    // SAFETY: `rr` is live.
    let details = unsafe { crate::runtime::stack::OPENSSL_sk_value(rr, 0) }
        .cast::<crate::cmp::cmp_asn::CmpRevDetails>();
    if details.is_null() {
        // SAFETY: the site is a compile-time constant.
        unsafe { raise_cmp(330, c"process_rr", 158) };
        return ptr::null_mut();
    }
    // SAFETY: `details` is live.
    let tmpl = unsafe { (*details).cert_details };
    // SAFETY: `tmpl` is live.
    let issuer = unsafe { crate::crmf::crmf_lib::OSSL_CRMF_CERTTEMPLATE_get0_issuer(tmpl) };
    // SAFETY: `tmpl` is live.
    let serial = unsafe { crate::crmf::crmf_lib::OSSL_CRMF_CERTTEMPLATE_get0_serialNumber(tmpl) };
    let mut cert_id: *mut crate::crmf::crmf_asn::CrmfCertId = ptr::null_mut();
    if !issuer.is_null() && !serial.is_null() {
        // SAFETY: `issuer`/`serial` are live.
        cert_id = unsafe { crate::crmf::crmf_lib::OSSL_CRMF_CERTID_gen(issuer, serial) };
        if cert_id.is_null() {
            return ptr::null_mut();
        }
    }
    // SAFETY: the callback is installed by the caller (`process_non_polling_request`).
    let cb = match unsafe { (*srv_ctx).process_rr } {
        Some(cb) => cb,
        None => {
            // SAFETY: `cert_id` is NULL or this call's own.
            unsafe { crate::crmf::crmf_asn::OSSL_CRMF_CERTID_free(cert_id) };
            return ptr::null_mut();
        }
    };
    // SAFETY: `srv_ctx`/`req`/`issuer`/`serial` are live per the callback's contract.
    let si = unsafe { cb(srv_ctx, req, issuer, serial) };
    if si.is_null() {
        // SAFETY: `cert_id` is NULL or this call's own.
        unsafe { crate::crmf::crmf_asn::OSSL_CRMF_CERTID_free(cert_id) };
        return ptr::null_mut();
    }
    // SAFETY: the enclosing function's `# Safety` section is the contract for these raw pointers.
    let ctx = unsafe { (*srv_ctx).ctx };
    // SAFETY: the enclosing function's `# Safety` section is the contract for these raw pointers.
    let unprotected = unsafe { (*srv_ctx).send_unprotected_errors };
    // SAFETY: `ctx`/`si`/`cert_id` are live.
    let msg = unsafe { ossl_cmp_rp_new(ctx, si, cert_id, unprotected) };
    if msg.is_null() {
        // SAFETY: the site is a compile-time constant.
        unsafe { raise_cmp(346, c"process_rr", 126) };
    }
    // SAFETY: both are NULL or this call's own.
    unsafe {
        crate::crmf::crmf_asn::OSSL_CRMF_CERTID_free(cert_id);
        OSSL_CMP_PKISI_free(si);
    }
    msg
}

/// `static OSSL_CMP_MSG *process_genm(...)` — `cmp_server.c:358-373`.
///
/// # Safety
/// `srv_ctx`/`req` are live.
unsafe fn process_genm(srv_ctx: *mut OsslCmpSrvCtx, req: *const CmpMsg) -> *mut CmpMsg {
    // SAFETY: the enclosing function's `# Safety` section is the contract for these raw pointers.
    if srv_ctx.is_null() || unsafe { (*srv_ctx).ctx }.is_null() || req.is_null() {
        return ptr::null_mut();
    }
    let mut itavs: *mut OpenSslStack = ptr::null_mut();
    // SAFETY: `req` is live.
    let genm = unsafe { (*(*req).body).value.genm };
    // SAFETY: the callback is installed by the caller (`process_non_polling_request`).
    let cb = match unsafe { (*srv_ctx).process_genm } {
        Some(cb) => cb,
        None => return ptr::null_mut(),
    };
    // SAFETY: `srv_ctx`/`req`/`genm` are live; `itavs` is writable.
    if unsafe { cb(srv_ctx, req, genm, &mut itavs) } == 0 {
        return ptr::null_mut();
    }
    // SAFETY: the enclosing function's `# Safety` section is the contract for these raw pointers.
    let ctx = unsafe { (*srv_ctx).ctx };
    // SAFETY: `ctx`/`itavs` are live or NULL.
    let msg = unsafe { ossl_cmp_genp_new(ctx, itavs) };
    // SAFETY: `itavs` is NULL or a live stack.
    unsafe { crate::runtime::stack::OPENSSL_sk_pop_free(itavs, Some(itav_free_void)) };
    msg
}

/// `static OSSL_CMP_MSG *process_error(...)` — `cmp_server.c:375-390`.
///
/// # Safety
/// `srv_ctx`/`req` are live.
unsafe fn process_error(srv_ctx: *mut OsslCmpSrvCtx, req: *const CmpMsg) -> *mut CmpMsg {
    // SAFETY: the enclosing function's `# Safety` section is the contract for these raw pointers.
    if srv_ctx.is_null() || unsafe { (*srv_ctx).ctx }.is_null() || req.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: `req` is live.
    let error_content = unsafe { (*(*req).body).value.error };
    // SAFETY: the callback is installed by the caller (`process_non_polling_request`).
    let cb = match unsafe { (*srv_ctx).process_error } {
        Some(cb) => cb,
        None => return ptr::null_mut(),
    };
    // SAFETY: `error_content` and the callback args are live.
    unsafe {
        cb(
            srv_ctx,
            req,
            (*error_content).pki_status_info,
            (*error_content).error_code,
            (*error_content).error_details,
        )
    };
    // SAFETY: the enclosing function's `# Safety` section is the contract for these raw pointers.
    let ctx = unsafe { (*srv_ctx).ctx };
    // SAFETY: `ctx` is live.
    let msg = unsafe { ossl_cmp_pkiconf_new(ctx) };
    if msg.is_null() {
        // SAFETY: the site is a compile-time constant.
        unsafe { raise_cmp(388, c"process_error", 122) };
    }
    msg
}

/// `static OSSL_CMP_MSG *process_certConf(...)` — `cmp_server.c:392-448`.
///
/// # Safety
/// `srv_ctx`/`req` are live.
unsafe fn process_certConf(srv_ctx: *mut OsslCmpSrvCtx, req: *const CmpMsg) -> *mut CmpMsg {
    // SAFETY: the enclosing function's `# Safety` section is the contract for these raw pointers.
    if srv_ctx.is_null() || unsafe { (*srv_ctx).ctx }.is_null() || req.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: the enclosing function's `# Safety` section is the contract for these raw pointers.
    let ctx = unsafe { (*srv_ctx).ctx };
    // SAFETY: `req` is live.
    let ccc = unsafe { (*(*req).body).value.cert_conf };
    // SAFETY: `ccc` is live.
    let num = unsafe { crate::runtime::stack::OPENSSL_sk_num(ccc) };
    // SAFETY: `ctx` is live.
    if unsafe { crate::cmp::cmp_ctx::OSSL_CMP_CTX_get_option(ctx, OSSL_CMP_OPT_IMPLICIT_CONFIRM) }
        == 1
        // SAFETY: the enclosing function's `# Safety` section is the contract for these raw pointers.
        || unsafe { (*ctx).status } != OSSL_CMP_PKISTATUS_TRANS
    {
        // SAFETY: the site is a compile-time constant.
        unsafe { raise_cmp(410, c"process_certConf", 160) };
        return ptr::null_mut();
    }
    let status: *mut crate::cmp::cmp_asn::CmpCertStatus = if num == 0 {
        // SAFETY: `ctx` is live.
        unsafe {
            crate::cmp::cmp_util::ossl_cmp_log0(
                crate::cmp::cmp_util::OSSL_CMP_LOG_ERR,
                ctx,
                c"process_certConf",
                415,
                c"certificate rejected by client",
            )
        };
        ptr::null_mut()
    } else {
        // SAFETY: `ccc` is live.
        unsafe { crate::runtime::stack::OPENSSL_sk_value(ccc, 0) }
            .cast::<crate::cmp::cmp_asn::CmpCertStatus>()
    };
    if !status.is_null() {
        // SAFETY: `status` is live.
        let cert_req_id =
            unsafe { crate::cmp::cmp_asn::ossl_cmp_asn1_get_int((*status).cert_req_id) };
        // SAFETY: `status` is live.
        let cert_hash = unsafe { (*status).cert_hash };
        // SAFETY: `status` is live.
        let si = unsafe { (*status).status_info };
        // SAFETY: `srv_ctx` is live.
        if cert_req_id != unsafe { (*srv_ctx).cert_req_id } {
            // SAFETY: the site is a compile-time constant.
            unsafe { raise_cmp(428, c"process_certConf", 108) };
            return ptr::null_mut();
        }
        // SAFETY: the callback is installed by the caller (`process_non_polling_request`).
        let cb = match unsafe { (*srv_ctx).process_cert_conf } {
            Some(cb) => cb,
            None => return ptr::null_mut(),
        };
        // SAFETY: `srv_ctx`/`req` and the status fields are live.
        if unsafe { cb(srv_ctx, req, cert_req_id, cert_hash, si) } == 0 {
            return ptr::null_mut();
        }
        if !si.is_null() {
            // SAFETY: `si` is live.
            let pki_status = unsafe { crate::cmp::cmp_status::ossl_cmp_pkisi_get_status(si) };
            if pki_status != OSSL_CMP_PKISTATUS_ACCEPTED {
                // SAFETY: `pki_status` is a plain integer status value.
                let str_ =
                    unsafe { crate::cmp::cmp_status::ossl_cmp_PKIStatus_to_string(pki_status) };
                // SAFETY: `ctx` is live; `str_` is NULL or static.
                unsafe {
                    crate::cmp::cmp_util::ossl_cmp_log_str(
                        crate::cmp::cmp_util::OSSL_CMP_LOG_INFO,
                        ctx,
                        c"process_certConf",
                        FILE,
                        439,
                        format_args!(
                            "certificate rejected by client {} {}",
                            if str_.is_null() { "without" } else { "with" },
                            if str_.is_null() {
                                "PKIStatus".to_string()
                            } else {
                                std::ffi::CStr::from_ptr(str_)
                                    .to_string_lossy()
                                    .into_owned()
                            },
                        ),
                    )
                };
            }
        }
    }
    // SAFETY: `ctx` is live.
    let msg = unsafe { ossl_cmp_pkiconf_new(ctx) };
    if msg.is_null() {
        // SAFETY: the site is a compile-time constant.
        unsafe { raise_cmp(446, c"process_certConf", 122) };
    }
    msg
}

/// `static OSSL_CMP_MSG *process_non_polling_request(...)` — `cmp_server.c:451-504`.
///
/// # Safety
/// `srv_ctx`/`req` are live.
unsafe fn process_non_polling_request(
    srv_ctx: *mut OsslCmpSrvCtx,
    req: *const CmpMsg,
) -> *mut CmpMsg {
    if srv_ctx.is_null()
        // SAFETY: the enclosing function's `# Safety` section is the contract for these raw pointers.
        || unsafe { (*srv_ctx).ctx }.is_null()
        || req.is_null()
        // SAFETY: the enclosing function's `# Safety` section is the contract for these raw pointers.
        || unsafe { (*req).body }.is_null()
    {
        return ptr::null_mut();
    }
    // SAFETY: `req` is live.
    match unsafe { OSSL_CMP_MSG_get_bodytype(req) } {
        OSSL_CMP_PKIBODY_IR
        | OSSL_CMP_PKIBODY_CR
        | OSSL_CMP_PKIBODY_P10CR
        | OSSL_CMP_PKIBODY_KUR => {
            // SAFETY: the enclosing function's `# Safety` section is the contract for these raw pointers.
            if unsafe { (*srv_ctx).process_cert_request }.is_none() {
                // SAFETY: the site is a compile-time constant.
                unsafe { raise_cmp(466, c"process_non_polling_request", 101) };
                ptr::null_mut()
            } else {
                // SAFETY: `srv_ctx`/`req` are live.
                unsafe { process_cert_request(srv_ctx, req) }
            }
        }
        OSSL_CMP_PKIBODY_RR => {
            // SAFETY: the enclosing function's `# Safety` section is the contract for these raw pointers.
            if unsafe { (*srv_ctx).process_rr }.is_none() {
                // SAFETY: the site is a compile-time constant.
                unsafe { raise_cmp(472, c"process_non_polling_request", 101) };
                ptr::null_mut()
            } else {
                // SAFETY: `srv_ctx`/`req` are live.
                unsafe { process_rr(srv_ctx, req) }
            }
        }
        OSSL_CMP_PKIBODY_GENM => {
            // SAFETY: the enclosing function's `# Safety` section is the contract for these raw pointers.
            if unsafe { (*srv_ctx).process_genm }.is_none() {
                // SAFETY: the site is a compile-time constant.
                unsafe { raise_cmp(478, c"process_non_polling_request", 101) };
                ptr::null_mut()
            } else {
                // SAFETY: `srv_ctx`/`req` are live.
                unsafe { process_genm(srv_ctx, req) }
            }
        }
        OSSL_CMP_PKIBODY_ERROR => {
            // SAFETY: the enclosing function's `# Safety` section is the contract for these raw pointers.
            if unsafe { (*srv_ctx).process_error }.is_none() {
                // SAFETY: the site is a compile-time constant.
                unsafe { raise_cmp(484, c"process_non_polling_request", 101) };
                ptr::null_mut()
            } else {
                // SAFETY: `srv_ctx`/`req` are live.
                unsafe { process_error(srv_ctx, req) }
            }
        }
        OSSL_CMP_PKIBODY_CERTCONF => {
            // SAFETY: the enclosing function's `# Safety` section is the contract for these raw pointers.
            if unsafe { (*srv_ctx).process_cert_conf }.is_none() {
                // SAFETY: the site is a compile-time constant.
                unsafe { raise_cmp(490, c"process_non_polling_request", 101) };
                ptr::null_mut()
            } else {
                // SAFETY: `srv_ctx`/`req` are live.
                unsafe { process_certConf(srv_ctx, req) }
            }
        }
        OSSL_CMP_PKIBODY_POLLREQ => {
            // SAFETY: the site is a compile-time constant.
            unsafe { raise_cmp(496, c"process_non_polling_request", 133) };
            ptr::null_mut()
        }
        _ => {
            // SAFETY: the site is a compile-time constant.
            unsafe { raise_cmp(499, c"process_non_polling_request", 101) };
            ptr::null_mut()
        }
    }
}

/// `static OSSL_CMP_MSG *process_pollReq(...)` — `cmp_server.c:506-547`.
///
/// # Safety
/// `srv_ctx`/`req` are live.
unsafe fn process_pollReq(srv_ctx: *mut OsslCmpSrvCtx, req: *const CmpMsg) -> *mut CmpMsg {
    // SAFETY: the enclosing function's `# Safety` section is the contract for these raw pointers.
    if srv_ctx.is_null() || unsafe { (*srv_ctx).ctx }.is_null() || req.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: the enclosing function's `# Safety` section is the contract for these raw pointers.
    if unsafe { (*srv_ctx).polling } == 0 {
        // SAFETY: the site is a compile-time constant.
        unsafe { raise_cmp(520, c"process_pollReq", 133) };
        return ptr::null_mut();
    }
    // SAFETY: `req` is live.
    let prc = unsafe { (*(*req).body).value.poll_req };
    // SAFETY: `prc` is live.
    if unsafe { OPENSSL_sk_num(prc) } != 1 {
        // SAFETY: the site is a compile-time constant.
        unsafe { raise_cmp(526, c"process_pollReq", 161) };
        return ptr::null_mut();
    }
    // SAFETY: `prc` is live.
    let pr = unsafe { OPENSSL_sk_value(prc, 0) }.cast::<crate::cmp::cmp_asn::CmpPollReq>();
    // SAFETY: `pr` is live.
    let cert_req_id = unsafe { crate::cmp::cmp_asn::ossl_cmp_asn1_get_int((*pr).cert_req_id) };
    let mut orig_req: *mut CmpMsg = ptr::null_mut();
    let mut check_after: i64 = 0;
    // SAFETY: `process_pollReq` is only reached when the callback is installed.
    let cb = match unsafe { (*srv_ctx).process_poll_req } {
        Some(cb) => cb,
        None => return ptr::null_mut(),
    };
    // SAFETY: `srv_ctx`/`req` and the out-slots are live.
    if unsafe { cb(srv_ctx, req, cert_req_id, &mut orig_req, &mut check_after) } == 0 {
        return ptr::null_mut();
    }
    if !orig_req.is_null() {
        // SAFETY: `srv_ctx` is live.
        unsafe { (*srv_ctx).polling = 0 };
        // SAFETY: `srv_ctx`/`orig_req` are live.
        let msg = unsafe { process_non_polling_request(srv_ctx, orig_req) };
        // SAFETY: `orig_req` is this call's own.
        unsafe { OSSL_CMP_MSG_free(orig_req) };
        return msg;
    }
    // SAFETY: the enclosing function's `# Safety` section is the contract for these raw pointers.
    let ctx = unsafe { (*srv_ctx).ctx };
    // SAFETY: `ctx` is live.
    let msg = unsafe { ossl_cmp_pollRep_new(ctx, cert_req_id, check_after) };
    if msg.is_null() {
        // SAFETY: the site is a compile-time constant.
        unsafe { raise_cmp(544, c"process_pollReq", 123) };
    }
    msg
}

/// `static int unprotected_exception(...)` — `cmp_server.c:553-572`.
///
/// # Safety
/// `ctx`/`req` are live.
unsafe extern "C" fn unprotected_exception(
    ctx: *const OsslCmpCtx,
    req: *const CmpMsg,
    invalid_protection: c_int,
    accept_unprotected_requests: c_int,
) -> c_int {
    if ctx.is_null() || req.is_null() {
        return -1;
    }
    if accept_unprotected_requests != 0 {
        // SAFETY: `ctx` is live.
        unsafe {
            ossl_cmp_log_str(
                OSSL_CMP_LOG_WARNING,
                ctx,
                c"unprotected_exception",
                FILE,
                562,
                format_args!(
                    "ignoring {} protection of request message",
                    if invalid_protection != 0 {
                        "invalid"
                    } else {
                        "missing"
                    }
                ),
            )
        };
        return 1;
    }
    // SAFETY: `req`/`ctx` are live.
    if unsafe { OSSL_CMP_MSG_get_bodytype(req) } == OSSL_CMP_PKIBODY_ERROR
        // SAFETY: the enclosing function's `# Safety` section is the contract for these raw pointers.
        && unsafe { OSSL_CMP_CTX_get_option(ctx, OSSL_CMP_OPT_UNPROTECTED_ERRORS) } == 1
    {
        // SAFETY: `ctx` is live.
        unsafe {
            ossl_cmp_log0(
                OSSL_CMP_LOG_WARNING,
                ctx,
                c"unprotected_exception",
                568,
                c"ignoring missing protection of error message",
            )
        };
        return 1;
    }
    0
}

/// `OSSL_CMP_MSG *OSSL_CMP_SRV_process_request(OSSL_CMP_SRV_CTX *srv_ctx, const OSSL_CMP_MSG *req)`
/// — `cmp_server.c:577-750`.
///
/// # Safety
/// `srv_ctx`/`req` are NULL or live.
#[no_mangle]
pub unsafe extern "C" fn OSSL_CMP_SRV_process_request(
    srv_ctx: *mut OsslCmpSrvCtx,
    req: *const CmpMsg,
) -> *mut CmpMsg {
    if srv_ctx.is_null()
        // SAFETY: the enclosing function's `# Safety` section is the contract for these raw pointers.
        || unsafe { (*srv_ctx).ctx }.is_null()
        || req.is_null()
        // SAFETY: the enclosing function's `# Safety` section is the contract for these raw pointers.
        || unsafe { (*req).body }.is_null()
        // SAFETY: the enclosing function's `# Safety` section is the contract for these raw pointers.
        || unsafe { OSSL_CMP_MSG_get0_header(req) }.is_null()
    {
        // SAFETY: the site is a compile-time constant.
        unsafe { raise_cmp(590, c"OSSL_CMP_SRV_process_request", CMP_R_NULL_ARGUMENT) };
        return ptr::null_mut();
    }
    // SAFETY: the enclosing function's `# Safety` section is the contract for these raw pointers.
    let ctx = unsafe { (*srv_ctx).ctx };
    // SAFETY: `ctx` is live.
    let backup_secret = unsafe { (*ctx).secret_value };
    // SAFETY: `req` is live.
    let hdr = unsafe { OSSL_CMP_MSG_get0_header(req) };
    // SAFETY: `req` is live.
    let req_type = unsafe { OSSL_CMP_MSG_get_bodytype(req) };
    // SAFETY: `ctx` is live.
    unsafe {
        ossl_cmp_log_str(
            OSSL_CMP_LOG_DEBUG,
            ctx,
            c"OSSL_CMP_SRV_process_request",
            FILE,
            596,
            format_args!(
                "received {}",
                std::ffi::CStr::from_ptr(ossl_cmp_bodytype_to_string(req_type)).to_string_lossy()
            ),
        )
    };

    let mut req_verified = 0;
    let mut rsp: *mut CmpMsg = ptr::null_mut();

    /*
     * The authority reaches its shared `err:` cleanup (`cmp_server.c:676-748`) on every
     * failure in the processing block (`cmp_server.c:603-674`), so that it can still send
     * an error response where possible. Model that fall-through with a labelled block.
     */
    'srv: {
        // SAFETY: `hdr` is live.
        let sender = unsafe { (*hdr).sender }.cast::<GeneralName>();
        // SAFETY: `sender` is live.
        if unsafe { (*sender).type_ } != GEN_DIRNAME {
            // SAFETY: the site is a compile-time constant.
            unsafe { raise_cmp(604, c"OSSL_CMP_SRV_process_request", 150) };
            break 'srv;
        }
        // SAFETY: `sender` is live.
        let dname = unsafe { (*sender).d.directoryName };
        // SAFETY: `ctx` is live; `dname` is a live X.509 name pointer.
        if unsafe { OSSL_CMP_CTX_set1_recipient(ctx, dname.cast::<c_void>()) } == 0 {
            break 'srv;
        }

        // SAFETY: the enclosing function's `# Safety` section is the contract for these raw pointers.
        if unsafe { (*srv_ctx).polling } != 0
            && req_type != OSSL_CMP_PKIBODY_POLLREQ
            && req_type != OSSL_CMP_PKIBODY_ERROR
        {
            // SAFETY: the site is a compile-time constant.
            unsafe { raise_cmp(612, c"OSSL_CMP_SRV_process_request", 104) };
            break 'srv;
        }

        match req_type {
            OSSL_CMP_PKIBODY_IR
            | OSSL_CMP_PKIBODY_CR
            | OSSL_CMP_PKIBODY_P10CR
            | OSSL_CMP_PKIBODY_KUR
            | OSSL_CMP_PKIBODY_RR
            | OSSL_CMP_PKIBODY_GENM
            | OSSL_CMP_PKIBODY_ERROR => {
                /* start of a new transaction, reset transactionID and senderNonce */
                // SAFETY: `ctx` is live.
                let ok = unsafe {
                    OSSL_CMP_CTX_set1_transactionID(ctx, ptr::null()) != 0
                        && OSSL_CMP_CTX_set1_senderNonce(ctx, ptr::null()) != 0
                };
                if !ok {
                    break 'srv;
                }
                // SAFETY: the enclosing function's `# Safety` section is the contract for these raw pointers.
                if let Some(cb) = unsafe { (*srv_ctx).clean_transaction } {
                    // SAFETY: `srv_ctx` and the NULL transaction id are valid per the callback's contract.
                    if unsafe { cb(srv_ctx, ptr::null()) } == 0 {
                        // SAFETY: the site is a compile-time constant.
                        unsafe { raise_cmp(640, c"OSSL_CMP_SRV_process_request", 158) };
                        break 'srv;
                    }
                }
            }
            _ => {
                /* transactionID should be already initialized */
                // SAFETY: the enclosing function's `# Safety` section is the contract for these raw pointers.
                if unsafe { (*ctx).transaction_id }.is_null() {
                    // SAFETY: the site is a compile-time constant.
                    unsafe { raise_cmp(649, c"OSSL_CMP_SRV_process_request", 133) };
                    break 'srv;
                }
            }
        }

        // SAFETY: `ctx`/`req` are live.
        req_verified = unsafe {
            ossl_cmp_msg_check_update(
                ctx,
                req,
                Some(unprotected_exception),
                (*srv_ctx).accept_unprotected,
            )
        };
        // SAFETY: the enclosing function's `# Safety` section is the contract for these raw pointers.
        if !unsafe { (*ctx).secret_value }.is_null()
            // SAFETY: the enclosing function's `# Safety` section is the contract for these raw pointers.
            && !unsafe { (*ctx).pkey }.is_null()
            // SAFETY: the enclosing function's `# Safety` section is the contract for these raw pointers.
            && unsafe { ossl_cmp_hdr_get_protection_nid(hdr) } != NID_id_PASSWORD_BASED_MAC
        {
            // SAFETY: `ctx` is live.
            unsafe { (*ctx).secret_value = ptr::null_mut() }; /* use MSG_SIG_ALG when protecting rsp */
        }
        if req_verified == 0 {
            break 'srv;
        }

        if req_type == OSSL_CMP_PKIBODY_POLLREQ {
            // SAFETY: the enclosing function's `# Safety` section is the contract for these raw pointers.
            if unsafe { (*srv_ctx).process_poll_req }.is_none() {
                // SAFETY: the site is a compile-time constant.
                unsafe { raise_cmp(665, c"OSSL_CMP_SRV_process_request", 101) };
            } else {
                // SAFETY: `srv_ctx`/`req` are live.
                rsp = unsafe { process_pollReq(srv_ctx, req) };
            }
        } else {
            // SAFETY: the enclosing function's `# Safety` section is the contract for these raw pointers.
            if unsafe { (*srv_ctx).delayed_delivery }.is_some() {
                // SAFETY: `srv_ctx`/`req` are live.
                rsp = unsafe { delayed_delivery(srv_ctx, req) };
                if !rsp.is_null() {
                    break 'srv;
                }
            }
            // SAFETY: `srv_ctx`/`req` are live.
            rsp = unsafe { process_non_polling_request(srv_ctx, req) };
        }
    }

    if rsp.is_null() {
        /* on error, try to respond with CMP error message to client */
        let mut data: *const c_char = ptr::null();
        let mut flags: c_int = 0;
        // SAFETY: `ERR_peek_error_all` writes only its out-slots.
        let err = unsafe {
            ERR_peek_error_all(
                ptr::null_mut(),
                ptr::null_mut(),
                ptr::null_mut(),
                &mut data,
                &mut flags,
            )
        };
        let fail_info = 1 << OSSL_CMP_PKIFAILUREINFO_BAD_REQUEST;
        if req_verified == 0 {
            // SAFETY: `ctx`/`hdr` are live.
            unsafe {
                if (*ctx).transaction_id.is_null() {
                    OSSL_CMP_CTX_set1_transactionID(ctx, (*hdr).transaction_id);
                }
                ossl_cmp_ctx_set1_recipNonce(ctx, (*hdr).sender_nonce);
            }
        }
        // SAFETY: the enclosing function's `# Safety` section is the contract for these raw pointers.
        if (flags & 0x02) == 0 || data.is_null() || unsafe { *data } == 0 {
            data = ptr::null();
        }
        // SAFETY: no preconditions.
        let reason = ERR_reason_error_string(err);
        // SAFETY: `reason` is NULL or NUL-terminated.
        let si =
            unsafe { OSSL_CMP_STATUSINFO_new(OSSL_CMP_PKISTATUS_REJECTION, fail_info, reason) };
        if !si.is_null() {
            // SAFETY: `ctx`/`si` are live.
            rsp = unsafe {
                ossl_cmp_error_new(
                    ctx,
                    si,
                    err as i64,
                    data,
                    (*srv_ctx).send_unprotected_errors,
                )
            };
            // SAFETY: `si` is this call's own.
            unsafe { OSSL_CMP_PKISI_free(si) };
        }
    }
    // SAFETY: `ctx` is live.
    unsafe {
        OSSL_CMP_CTX_print_errors(ctx);
        (*ctx).secret_value = backup_secret;
    }

    // SAFETY: `rsp` is NULL or live.
    let rsp_type = if !rsp.is_null() {
        // SAFETY: the enclosing function's `# Safety` section is the contract for these raw pointers.
        unsafe { OSSL_CMP_MSG_get_bodytype(rsp) }
    } else {
        OSSL_CMP_PKIBODY_ERROR
    };
    // SAFETY: `ctx` is live.
    unsafe {
        if !rsp.is_null() {
            ossl_cmp_log_str(
                OSSL_CMP_LOG_DEBUG,
                ctx,
                c"OSSL_CMP_SRV_process_request",
                FILE,
                714,
                format_args!(
                    "sending {}",
                    std::ffi::CStr::from_ptr(ossl_cmp_bodytype_to_string(rsp_type))
                        .to_string_lossy()
                ),
            );
        } else {
            ossl_cmp_log0(
                OSSL_CMP_LOG_ERR,
                ctx,
                c"OSSL_CMP_SRV_process_request",
                717,
                c"cannot send proper CMP response",
            );
        }
    }

    /* determine whether to keep the transaction open or not */
    // SAFETY: `ctx` is live.
    unsafe { (*ctx).status = OSSL_CMP_PKISTATUS_TRANS };
    // SAFETY: the enclosing function's `# Safety` section is the contract for these raw pointers.
    let waiting = !rsp.is_null() && unsafe { ossl_cmp_is_error_with_waiting(rsp) } != 0;
    let close = match rsp_type {
        OSSL_CMP_PKIBODY_IP | OSSL_CMP_PKIBODY_CP | OSSL_CMP_PKIBODY_KUP => {
            // SAFETY: `ctx` is live.
            (unsafe { OSSL_CMP_CTX_get_option(ctx, OSSL_CMP_OPT_IMPLICIT_CONFIRM) }) != 0
                && !waiting
        }
        OSSL_CMP_PKIBODY_ERROR => !waiting,
        OSSL_CMP_PKIBODY_RP | OSSL_CMP_PKIBODY_PKICONF | OSSL_CMP_PKIBODY_GENP => true,
        _ => false,
    };
    if close {
        // SAFETY: `srv_ctx`/`ctx` are live.
        unsafe {
            (*srv_ctx).cert_req_id = OSSL_CMP_CERTREQID_INVALID;
            if let Some(cb) = (*srv_ctx).clean_transaction {
                cb(srv_ctx, (*ctx).transaction_id);
            }
            OSSL_CMP_CTX_set1_transactionID(ctx, ptr::null());
            OSSL_CMP_CTX_set1_senderNonce(ctx, ptr::null());
            (*ctx).status = OSSL_CMP_PKISTATUS_UNSPECIFIED;
        }
    }
    rsp
}

/// `OSSL_CMP_MSG *OSSL_CMP_CTX_server_perform(OSSL_CMP_CTX *client_ctx, const OSSL_CMP_MSG *req)`
/// — `cmp_server.c:758-774`.
///
/// # Safety
/// `client_ctx`/`req` are NULL or live.
#[no_mangle]
pub unsafe extern "C" fn OSSL_CMP_CTX_server_perform(
    client_ctx: *mut OsslCmpCtx,
    req: *const CmpMsg,
) -> *mut CmpMsg {
    if client_ctx.is_null() || req.is_null() {
        // SAFETY: the site is a compile-time constant.
        unsafe { raise_cmp(764, c"OSSL_CMP_CTX_server_perform", CMP_R_NULL_ARGUMENT) };
        return ptr::null_mut();
    }
    // SAFETY: `client_ctx` is live.
    let srv_ctx = unsafe { OSSL_CMP_CTX_get_transfer_cb_arg(client_ctx) }.cast::<OsslCmpSrvCtx>();
    if srv_ctx.is_null() {
        // SAFETY: the site is a compile-time constant.
        unsafe { raise_cmp(769, c"OSSL_CMP_CTX_server_perform", 159) };
        return ptr::null_mut();
    }
    // SAFETY: `srv_ctx`/`req` are live.
    unsafe { OSSL_CMP_SRV_process_request(srv_ctx, req) }
}
