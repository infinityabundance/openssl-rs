//! `crypto/cmp/cmp_client.c` — the CMP client state machine. Phase 12.4.
//!
//! This unit lands the default certificate-confirmation callback, `OSSL_CMP_certConf_cb`, which is
//! self-contained: it validates the newly enrolled certificate through the `X509` chain/verify
//! surface (`X509_build_chain`, `X509_STORE_CTX_*`) and refuses with a `PKIFailureInfo` bit. The
//! four exchange entry points (`OSSL_CMP_try_certreq`, `OSSL_CMP_exec_certreq`,
//! `OSSL_CMP_exec_RR_ses`, `OSSL_CMP_exec_GENM_ses`) are left open: each drives
//! `ossl_cmp_exchange_*`, whose request/response messages are protected through the
//! `cmp_protect.c` engine, and the PasswordBasedMAC arm of that engine needs the `crmf_pbm.c`
//! public surface the plan lands in 12.7.
//!
//! SPDX-License-Identifier: Apache-2.0
#![allow(dead_code, non_snake_case)]
#![allow(private_interfaces)]
#![allow(unused_assignments)]

use core::ffi::{c_char, c_int, c_ulong};
use core::ptr;

use crate::asn1::prim::{ASN1_INTEGER_cmp, ASN1_INTEGER_get_int64};
use crate::asn1::string::{ossl_sk_ASN1_UTF8STRING2text, ASN1_STRING_dup, ASN1_UTF8STRING_free};
use crate::cmp::cmp_asn::*;
use crate::cmp::cmp_ctx::{
    ossl_cmp_ctx_get0_newPubkey, ossl_cmp_ctx_set0_newCert, ossl_cmp_ctx_set1_caPubs,
    ossl_cmp_ctx_set1_extraCertsIn, ossl_cmp_ctx_set1_first_senderNonce,
    ossl_cmp_ctx_set1_newChain, ossl_cmp_print_log, OSSL_CMP_CTX_get1_extraCertsIn,
    OSSL_CMP_CTX_get_certConf_cb_arg, OSSL_CMP_CTX_set0_statusString, OSSL_CMP_certConf_cb_t,
    OSSL_CMP_transfer_cb_t, OsslCmpCtx,
};
use crate::cmp::cmp_hdr::ossl_cmp_hdr_has_implicitConfirm;
use crate::cmp::cmp_http::OSSL_CMP_MSG_http_perform;
use crate::cmp::cmp_msg::*;
use crate::cmp::cmp_status::{
    ossl_cmp_pkisi_get_pkifailureinfo, ossl_cmp_pkisi_get_status, OSSL_CMP_PKISTATUS_accepted,
    OSSL_CMP_PKISTATUS_checking_response, OSSL_CMP_PKISTATUS_grantedWithMods,
    OSSL_CMP_PKISTATUS_keyUpdateWarning, OSSL_CMP_PKISTATUS_rejected_by_client,
    OSSL_CMP_PKISTATUS_rejection, OSSL_CMP_PKISTATUS_request,
    OSSL_CMP_PKISTATUS_revocationNotification, OSSL_CMP_PKISTATUS_revocationWarning,
    OSSL_CMP_PKISTATUS_trans, OSSL_CMP_PKISTATUS_waiting, OSSL_CMP_STATUSINFO_new,
};
use crate::cmp::cmp_util::{
    ossl_cmp_log0, ossl_cmp_log_str, OSSL_CMP_LOG_DEBUG, OSSL_CMP_LOG_ERR, OSSL_CMP_LOG_INFO,
    OSSL_CMP_LOG_WARNING,
};
use crate::cmp::cmp_vfy::ossl_cmp_msg_check_update;
use crate::crmf::crmf_asn::CrmfMsg;
use crate::crmf::crmf_lib::{
    OSSL_CRMF_CERTID_get0_issuer, OSSL_CRMF_CERTID_get0_serialNumber,
    OSSL_CRMF_CERTTEMPLATE_get0_issuer, OSSL_CRMF_CERTTEMPLATE_get0_serialNumber,
};
use crate::runtime::err::err_sites::ErrSite;
use crate::runtime::err::raise_site;
use crate::runtime::stack::{
    OPENSSL_sk_free, OPENSSL_sk_num, OPENSSL_sk_shift, OPENSSL_sk_value, OpenSslStack,
};
use crate::runtime::thread::OSSL_sleep;
use crate::x509::t_x509::OSSL_STACK_OF_X509_free;
use crate::x509::x509_cmp::{
    ossl_x509_add_certs_new, X509_NAME_cmp, X509_check_private_key, X509_get_subject_name,
};
use crate::x509::x509_lu::X509Store;
use crate::x509::x509_obj::X509_NAME_oneline;
use crate::x509::x509_vfy::{
    X509_STORE_CTX_free, X509_STORE_CTX_get0_chain, X509_STORE_CTX_get0_param, X509_STORE_CTX_init,
    X509_STORE_CTX_new_ex, X509_build_chain, X509_verify_cert,
};
use crate::x509::x509_vpm::X509_VERIFY_PARAM_clear_flags;
use crate::x509::x_x509::{X509_free, X509};

/// The authority translation unit for this module.
pub(crate) const FILE: &core::ffi::CStr = c"crypto/cmp/cmp_client.c";

/// `OSSL_CMP_PKIFAILUREINFO_incorrectData` — `include/openssl/cmp.h:118`.
const OSSL_CMP_PKIFAILUREINFO_INCORRECT_DATA: c_int = 7;

/// `X509_V_FLAG_USE_CHECK_TIME` — `include/openssl/x509_vfy.h.in:341`.
const X509_V_FLAG_USE_CHECK_TIME: c_ulong = 0x2;
/// `X509_V_FLAG_NO_CHECK_TIME` — `include/openssl/x509_vfy.h.in:385`.
const X509_V_FLAG_NO_CHECK_TIME: c_ulong = 0x200000;
/// `X509_V_FLAG_PARTIAL_CHAIN` — `include/openssl/x509_vfy.h.in:377`.
const X509_V_FLAG_PARTIAL_CHAIN: c_ulong = 0x80000;
/// `X509_V_FLAG_POLICY_CHECK` — `include/openssl/x509_vfy.h.in:353`.
const X509_V_FLAG_POLICY_CHECK: c_ulong = 0x80;

/// `X509_ADD_FLAG_UP_REF` — `include/openssl/x509.h:995`.
const X509_ADD_FLAG_UP_REF: c_int = 0x1;
/// `X509_ADD_FLAG_NO_DUP` — `include/openssl/x509.h:997`.
const X509_ADD_FLAG_NO_DUP: c_int = 0x4;
/// `X509_ADD_FLAG_NO_SS` — `include/openssl/x509.h:998`.
const X509_ADD_FLAG_NO_SS: c_int = 0x8;

/// One CMP log line at this unit's coordinate, through [`ossl_cmp_print_log`].
///
/// # Safety
/// `ctx` is NULL or live; `msg` is NULL or NUL-terminated.
unsafe fn cmp_log(level: c_int, ctx: *const OsslCmpCtx, line: c_int, msg: *const c_char) {
    // SAFETY: `ctx` is NULL or live; the message is the caller's static.
    unsafe {
        ossl_cmp_print_log(
            level,
            ctx,
            c"OSSL_CMP_certConf_cb".as_ptr(),
            FILE.as_ptr(),
            line,
            msg,
        )
    };
}

/// `int OSSL_CMP_certConf_cb(OSSL_CMP_CTX *ctx, X509 *cert, int fail_info, const char **text)`
/// — `cmp_client.c:584-647`.
///
/// # Safety
/// `ctx` is a live `OSSL_CMP_CTX`; `cert` is a live `X509`; `text` is unused.
#[no_mangle]
pub unsafe extern "C" fn OSSL_CMP_certConf_cb(
    ctx: *mut OsslCmpCtx,
    cert: *mut X509,
    mut fail_info: c_int,
    _text: *mut *const c_char,
) -> c_int {
    // SAFETY: `ctx` is live per the contract.
    let out_trusted = unsafe { OSSL_CMP_CTX_get_certConf_cb_arg(ctx) }.cast::<X509Store>();
    let mut chain: *mut OpenSslStack = ptr::null_mut();

    if fail_info != 0 {
        /* accept any error flagged by CMP core library */
        return fail_info;
    }

    if out_trusted.is_null() {
        // SAFETY: `ctx` is live.
        unsafe {
            cmp_log(
                OSSL_CMP_LOG_DEBUG,
                ctx,
                596,
                c"trying to build chain for newly enrolled cert".as_ptr(),
            )
        };
        // SAFETY: `cert` and `ctx` are live.
        chain = unsafe {
            X509_build_chain(
                cert,
                (*ctx).untrusted,
                out_trusted,
                0,
                (*ctx).libctx,
                (*ctx).propq,
            )
        };
    } else {
        // SAFETY: `ctx` is live.
        let csc = unsafe { X509_STORE_CTX_new_ex((*ctx).libctx, (*ctx).propq) };
        // SAFETY: `ctx` is live.
        unsafe {
            cmp_log(
                OSSL_CMP_LOG_DEBUG,
                ctx,
                602,
                c"validating newly enrolled cert".as_ptr(),
            )
        };
        if !csc.is_null() {
            // SAFETY: `csc` is live; `ctx` is live.
            let inited =
                unsafe { X509_STORE_CTX_init(csc, out_trusted, cert, (*ctx).untrusted) } != 0;
            if inited {
                /* disable any cert status/revocation checking etc. */
                // SAFETY: `csc` is live.
                unsafe {
                    X509_VERIFY_PARAM_clear_flags(
                        X509_STORE_CTX_get0_param(csc),
                        !(X509_V_FLAG_USE_CHECK_TIME
                            | X509_V_FLAG_NO_CHECK_TIME
                            | X509_V_FLAG_PARTIAL_CHAIN
                            | X509_V_FLAG_POLICY_CHECK),
                    )
                };
                // SAFETY: `csc` is live.
                if unsafe { X509_verify_cert(csc) } > 0 {
                    // SAFETY: `csc` is live and `chain` is a writable slot.
                    if unsafe {
                        ossl_x509_add_certs_new(
                            &mut chain,
                            X509_STORE_CTX_get0_chain(csc),
                            X509_ADD_FLAG_UP_REF | X509_ADD_FLAG_NO_DUP | X509_ADD_FLAG_NO_SS,
                        )
                    } == 0
                    {
                        // SAFETY: `chain` is NULL or live.
                        unsafe { OPENSSL_sk_free(chain) };
                        chain = ptr::null_mut();
                    }
                }
            }
            // SAFETY: `csc` is live.
            unsafe { X509_STORE_CTX_free(csc) };
        }
    }

    // SAFETY: `chain` is NULL or a live stack.
    if unsafe { OPENSSL_sk_num(chain) } > 0 {
        /* remove leaf (EE) cert */
        // SAFETY: the stack holds at least one `X509`.
        unsafe { X509_free(OPENSSL_sk_shift(chain).cast::<X509>()) };
    }
    if !out_trusted.is_null() {
        if chain.is_null() {
            // SAFETY: `ctx` is live.
            unsafe {
                cmp_log(
                    OSSL_CMP_LOG_ERR,
                    ctx,
                    630,
                    c"failed to validate newly enrolled cert".as_ptr(),
                )
            };
            fail_info = 1 << OSSL_CMP_PKIFAILUREINFO_INCORRECT_DATA;
        } else {
            // SAFETY: `ctx` is live.
            unsafe {
                cmp_log(
                    OSSL_CMP_LOG_DEBUG,
                    ctx,
                    633,
                    c"success validating newly enrolled cert".as_ptr(),
                )
            };
        }
    } else if chain.is_null() {
        // SAFETY: `ctx` is live.
        unsafe {
            cmp_log(
                OSSL_CMP_LOG_WARNING,
                ctx,
                637,
                c"could not build approximate chain for newly enrolled cert, resorting to received extraCerts".as_ptr(),
            )
        };
        // SAFETY: `ctx` is live.
        chain = unsafe { OSSL_CMP_CTX_get1_extraCertsIn(ctx) };
    } else {
        // SAFETY: `ctx` is live.
        unsafe {
            cmp_log(
                OSSL_CMP_LOG_DEBUG,
                ctx,
                641,
                c"success building approximate chain for newly enrolled cert".as_ptr(),
            )
        };
    }
    // SAFETY: `ctx` is live; `chain` is NULL or live.
    let _ = unsafe { ossl_cmp_ctx_set1_newChain(ctx, chain) };
    // SAFETY: `chain` is NULL or a live stack.
    unsafe { OSSL_STACK_OF_X509_free(chain) };

    fail_info
}

// ---------------------------------------------------------------------------------------------
// The client exchange state machine — `cmp_client.c:14-1059`
// ---------------------------------------------------------------------------------------------

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
const OSSL_CMP_PKIBODY_POLLREP: c_int = 26;
/// `OSSL_CMP_CERTREQID`/`_NONE` — `cmp_local.h:932-933`.
const OSSL_CMP_CERTREQID: c_int = 0;
const OSSL_CMP_CERTREQID_NONE: c_int = -1;
/// `OSSL_CMP_REVREQSID` — `cmp_local.h:936`.
const OSSL_CMP_REVREQSID: c_int = 0;
/// `OSSL_CMP_CTX_FAILINFO_badRequest` — `include/openssl/cmp.h.in:149`.
const OSSL_CMP_CTX_FAILINFO_BAD_REQUEST: c_int = 1 << 2;
/// `OSSL_CMP_EXPECTED_RESP_TIME` — `cmp_local.h:1008`.
const OSSL_CMP_EXPECTED_RESP_TIME: c_int = 2;
/// `OSSL_CMP_PKISI_BUFLEN` — `include/openssl/cmp.h.in:455`.
const OSSL_CMP_PKISI_BUFLEN: usize = 1024;

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
            lib: 58,
            reason,
            dynamic_reason: false,
        })
    };
}
/// `IS_CREP(t)` — `cmp_client.c:14-15`.
const fn is_crep(t: c_int) -> bool {
    t == OSSL_CMP_PKIBODY_IP || t == OSSL_CMP_PKIBODY_CP || t == OSSL_CMP_PKIBODY_KUP
}

/// `static int unprotected_exception(...)` — `cmp_client.c:22-73`.
///
/// # Safety
/// `ctx`/`rep` are live.
unsafe extern "C" fn unprotected_exception(
    ctx: *const OsslCmpCtx,
    rep: *const CmpMsg,
    invalid_protection: c_int,
    _expected_type: c_int,
) -> c_int {
    // SAFETY: `rep` is NULL or live.
    let rcvd_type = unsafe { OSSL_CMP_MSG_get_bodytype(rep) };
    if ctx.is_null() || rep.is_null() {
        return -1;
    }
    // SAFETY: `ctx` is live.
    if unsafe { (*ctx).unprotected_errors } == 0 {
        return 0;
    }
    let mut msg_type: *const c_char = ptr::null();
    match rcvd_type {
        OSSL_CMP_PKIBODY_ERROR => msg_type = c"error response".as_ptr(),
        OSSL_CMP_PKIBODY_RP => {
            // SAFETY: `rep` is live.
            let si = unsafe {
                ossl_cmp_revrepcontent_get_pkisi((*(*rep).body).value.rp, OSSL_CMP_REVREQSID)
            };
            if si.is_null() {
                return -1;
            }
            // SAFETY: `si` is live.
            if unsafe { ossl_cmp_pkisi_get_status(si) } == OSSL_CMP_PKISTATUS_rejection {
                msg_type = c"revocation response message with rejection status".as_ptr();
            }
        }
        OSSL_CMP_PKIBODY_PKICONF => msg_type = c"PKI Confirmation message".as_ptr(),
        _ => {
            if is_crep(rcvd_type) {
                // SAFETY: `rep` is live.
                let crepmsg = unsafe { (*(*rep).body).value.ip };
                // SAFETY: `crepmsg` is live.
                let crep = unsafe {
                    ossl_cmp_certrepmessage_get0_certresponse(crepmsg, OSSL_CMP_CERTREQID_NONE)
                };
                // SAFETY: `crepmsg`'s response stack is live.
                if unsafe { crate::runtime::stack::OPENSSL_sk_num((*crepmsg).response) } > 1 {
                    return -1;
                }
                if crep.is_null() {
                    return -1;
                }
                // SAFETY: `crep` is live.
                if unsafe { ossl_cmp_pkisi_get_status((*crep).status) }
                    == OSSL_CMP_PKISTATUS_rejection
                {
                    msg_type = c"CertRepMessage with rejection status".as_ptr();
                }
            }
        }
    }
    if msg_type.is_null() {
        return 0;
    }
    // SAFETY: `ctx` is live; `msg_type` is static.
    unsafe {
        crate::cmp::cmp_util::ossl_cmp_log_str(
            OSSL_CMP_LOG_WARNING,
            ctx,
            c"unprotected_exception",
            FILE,
            70,
            format_args!(
                "ignoring {} protection of {}",
                if invalid_protection != 0 {
                    "invalid"
                } else {
                    "missing"
                },
                std::ffi::CStr::from_ptr(msg_type).to_string_lossy(),
            ),
        )
    };
    1
}

/// `static int save_statusInfo(OSSL_CMP_CTX *ctx, OSSL_CMP_PKISI *si)` — `cmp_client.c:76-105`.
///
/// # Safety
/// `ctx`/`si` are live.
unsafe fn save_statusInfo(ctx: *mut OsslCmpCtx, si: *mut CmpPkisi) -> c_int {
    if ctx.is_null() || si.is_null() {
        return 0;
    }
    // SAFETY: `si` is live.
    let status = unsafe { ossl_cmp_pkisi_get_status(si) };
    // SAFETY: `ctx` is live.
    unsafe { (*ctx).status = status };
    if status < OSSL_CMP_PKISTATUS_accepted {
        return 0;
    }
    // SAFETY: `ctx`/`si` are live.
    unsafe {
        (*ctx).fail_info_code = ossl_cmp_pkisi_get_pkifailureinfo(si);
    }
    // SAFETY: `ctx` is live.
    if unsafe {
        OSSL_CMP_CTX_set0_statusString(ctx, crate::runtime::stack::OPENSSL_sk_new_null().cast())
    } == 0
        // SAFETY: the enclosing function's `# Safety` section is the contract for these raw pointers.
        || unsafe { (*ctx).status_string }.is_null()
    {
        return 0;
    }
    // SAFETY: `si` is live.
    let ss = unsafe { (*si).status_string };
    // SAFETY: `ss` is NULL or a live stack.
    let n = unsafe { crate::runtime::stack::OPENSSL_sk_num(ss) };
    let mut i = 0;
    while i < n {
        // SAFETY: `i` is in range.
        let s = unsafe { crate::runtime::stack::OPENSSL_sk_value(ss, i) };
        // SAFETY: `s` is a live UTF8 string.
        let dup = unsafe { ASN1_STRING_dup(s.cast()) };
        // SAFETY: `ctx`'s status string stack is live; `dup` is live.
        if dup.is_null()
            // SAFETY: the enclosing function's `# Safety` section is the contract for these raw pointers.
            || unsafe { crate::runtime::stack::OPENSSL_sk_push((*ctx).status_string, dup.cast()) }
                == 0
        {
            // SAFETY: `dup` is NULL or this call's own.
            unsafe { ASN1_UTF8STRING_free(dup) };
            return 0;
        }
        i += 1;
    }
    1
}

/// `static int is_crep_with_waiting(const OSSL_CMP_MSG *resp, int rid)` — `cmp_client.c:107-122`.
///
/// # Safety
/// `resp` is live.
unsafe fn is_crep_with_waiting(resp: *const CmpMsg, rid: c_int) -> c_int {
    // SAFETY: `resp` is live.
    let bt = unsafe { OSSL_CMP_MSG_get_bodytype(resp) };
    if !is_crep(bt) {
        return 0;
    }
    // SAFETY: `resp` is live.
    let crepmsg = unsafe { (*(*resp).body).value.ip };
    // SAFETY: `crepmsg` is live.
    let crep = unsafe { ossl_cmp_certrepmessage_get0_certresponse(crepmsg, rid) };
    // SAFETY: `crep` is NULL or live.
    c_int::from(
        !crep.is_null()
            && unsafe { ossl_cmp_pkisi_get_status((*crep).status) } == OSSL_CMP_PKISTATUS_waiting,
    )
}

/// `static int send_receive_check(...)` — `cmp_client.c:130-252`.
///
/// # Safety
/// `ctx`/`req` are live; `rep` is a writable slot.
unsafe fn send_receive_check(
    ctx: *mut OsslCmpCtx,
    req: *const CmpMsg,
    rep: *mut *mut CmpMsg,
    expected_type: c_int,
) -> c_int {
    let begin_transaction =
        expected_type != OSSL_CMP_PKIBODY_POLLREP && expected_type != OSSL_CMP_PKIBODY_PKICONF;
    // SAFETY: `req` is live.
    let req_type_str = unsafe { ossl_cmp_bodytype_to_string(OSSL_CMP_MSG_get_bodytype(req)) };
    // SAFETY: no preconditions.
    let expected_type_str = unsafe { ossl_cmp_bodytype_to_string(expected_type) };
    // SAFETY: `ctx` is live.
    let bak_msg_timeout = unsafe { (*ctx).msg_timeout };

    // SAFETY: `ctx` is live.
    unsafe { (*ctx).status = OSSL_CMP_PKISTATUS_trans };
    // SAFETY: the enclosing function's `# Safety` section is the contract for these raw pointers.
    let transfer_cb: OSSL_CMP_transfer_cb_t = if unsafe { (*ctx).transfer_cb }.is_null() {
        Some(OSSL_CMP_MSG_http_perform)
    } else {
        // SAFETY: the stored callback was installed at the matching signature.
        Some(unsafe {
            core::mem::transmute::<
                *mut core::ffi::c_void,
                unsafe extern "C" fn(*mut OsslCmpCtx, *const CmpMsg) -> *mut CmpMsg,
            >((*ctx).transfer_cb)
        })
    };
    // SAFETY: `rep` is a writable slot.
    unsafe { *rep = ptr::null_mut() };

    // SAFETY: `ctx` is live.
    if unsafe { (*ctx).total_timeout } != 0 {
        // SAFETY: `time` is the C library's.
        let now = unsafe { crate::runtime::bio::sys::time(ptr::null_mut()) };
        if begin_transaction {
            // SAFETY: `ctx` is live.
            unsafe { (*ctx).end_time = now + (*ctx).total_timeout as i64 };
        }
        // SAFETY: `ctx` is live.
        if now >= unsafe { (*ctx).end_time } {
            // SAFETY: the site is a compile-time constant.
            unsafe { raise_cmp(154, c"send_receive_check", 184) };
            return 0;
        }
        // SAFETY: `ctx` is live.
        let time_left = unsafe { (*ctx).end_time - now } as c_int;
        // SAFETY: `ctx` is live.
        if unsafe { (*ctx).msg_timeout } == 0 || time_left < unsafe { (*ctx).msg_timeout } {
            // SAFETY: `ctx` is live.
            unsafe { (*ctx).msg_timeout = time_left };
        }
    }

    /* should print error queue since transfer_cb may call ERR_clear_error() */
    // SAFETY: `ctx` is live.
    unsafe { crate::cmp::cmp_ctx::OSSL_CMP_CTX_print_errors(ctx) };

    // SAFETY: `ctx` is live.
    if !unsafe { (*ctx).server }.is_null() || !unsafe { (*ctx).transfer_cb }.is_null() {
        // SAFETY: `ctx`/`req_type_str` are live.
        unsafe {
            ossl_cmp_log_str(
                OSSL_CMP_LOG_INFO,
                ctx,
                c"send_receive_check",
                FILE,
                171,
                format_args!(
                    "sending {}",
                    std::ffi::CStr::from_ptr(req_type_str).to_string_lossy()
                ),
            )
        };
    }

    // SAFETY: `ctx`/`req` are live; both arms above set `transfer_cb` to `Some`.
    let cb = transfer_cb.unwrap_or(OSSL_CMP_MSG_http_perform);
    // SAFETY: `ctx`/`req` are live per the callback's contract.
    unsafe { *rep = cb(ctx, req) };
    // SAFETY: `ctx` is live.
    unsafe { (*ctx).msg_timeout = bak_msg_timeout };

    // SAFETY: `*rep` is NULL or live.
    if unsafe { *rep }.is_null() {
        // SAFETY: the site is a compile-time constant.
        unsafe {
            raise_cmp(
                178,
                c"send_receive_check",
                if (*ctx).total_timeout != 0
                    && crate::runtime::bio::sys::time(ptr::null_mut()) >= (*ctx).end_time
                {
                    184
                } else {
                    159
                },
            )
        };
        return 0;
    }

    // SAFETY: `ctx` is live.
    unsafe { (*ctx).status = OSSL_CMP_PKISTATUS_checking_response };
    // SAFETY: `*rep` is live.
    let bt = unsafe { OSSL_CMP_MSG_get_bodytype(*rep) };
    // SAFETY: `ctx` is live; the strings are static.
    unsafe {
        ossl_cmp_log_str(
            OSSL_CMP_LOG_INFO,
            ctx,
            c"send_receive_check",
            FILE,
            191,
            format_args!(
                "received {}{}",
                std::ffi::CStr::from_ptr(ossl_cmp_bodytype_to_string(bt)).to_string_lossy(),
                if ossl_cmp_is_error_with_waiting(*rep) != 0 {
                    " (waiting)"
                } else {
                    ""
                },
            ),
        )
    };

    /* copy received extraCerts to ctx->extraCertsIn so they can be retrieved */
    if bt != OSSL_CMP_PKIBODY_POLLREP
        && bt != OSSL_CMP_PKIBODY_PKICONF
        // SAFETY: `ctx`/`*rep` are live.
        && unsafe { ossl_cmp_ctx_set1_extraCertsIn(ctx, (**rep).extra_certs) } == 0
    {
        return 0;
    }

    // SAFETY: `ctx`/`*rep` are live; the callback is installed.
    if unsafe { ossl_cmp_msg_check_update(ctx, *rep, Some(unprotected_exception), expected_type) }
        == 0
    {
        return 0;
    }

    if bt == expected_type
        || (if expected_type == OSSL_CMP_PKIBODY_POLLREP {
            bt != OSSL_CMP_PKIBODY_ERROR
        } else {
            // SAFETY: `*rep` is live.
            (unsafe { ossl_cmp_is_error_with_waiting(*rep) }) != 0
        })
    {
        return 1;
    }

    // SAFETY: the site is a compile-time constant.
    unsafe {
        raise_cmp(
            217,
            c"send_receive_check",
            if bt == OSSL_CMP_PKIBODY_ERROR {
                180
            } else {
                133
            },
        )
    };

    if bt == OSSL_CMP_PKIBODY_ERROR {
        // SAFETY: `*rep` is live.
        let emc = unsafe { (*(**rep).body).value.error };
        // SAFETY: `emc` is live.
        let si = unsafe { (*emc).pki_status_info };
        // SAFETY: `ctx`/`si` are live.
        unsafe {
            save_statusInfo(ctx, si);
        }
        // SAFETY: `emc` is live.
        if !unsafe { (*emc).error_details }.is_null() {
            // SAFETY: `emc`'s error details are a live stack.
            let text = unsafe {
                ossl_sk_ASN1_UTF8STRING2text(
                    (*emc).error_details,
                    c", ".as_ptr(),
                    OSSL_CMP_PKISI_BUFLEN - 1,
                )
            };
            // SAFETY: `text` is NULL or this call's own.
            unsafe { crate::runtime::mem::CRYPTO_free(text.cast(), FILE.as_ptr(), 243) };
        }
        // SAFETY: `ctx` is live.
        if unsafe { (*ctx).status } != OSSL_CMP_PKISTATUS_rejection {
            // SAFETY: the site is a compile-time constant.
            unsafe { raise_cmp(246, c"send_receive_check", 185) };
            // SAFETY: `ctx` is live.
            if unsafe { (*ctx).status } == OSSL_CMP_PKISTATUS_waiting {
                // SAFETY: `ctx` is live.
                unsafe { (*ctx).status = OSSL_CMP_PKISTATUS_rejection };
            }
        }
    }
    let _ = expected_type_str;
    0
}

/// `static int poll_for_response(...)` — `cmp_client.c:270-392`.
///
/// # Safety
/// `ctx` is live; `rep`/`check_after` are writable slots.
unsafe fn poll_for_response(
    ctx: *mut OsslCmpCtx,
    sleep: c_int,
    rid: c_int,
    rep: *mut *mut CmpMsg,
    check_after_out: *mut c_int,
) -> c_int {
    let mut preq: *mut CmpMsg = ptr::null_mut();
    let mut prep: *mut CmpMsg = ptr::null_mut();
    // SAFETY: `ctx` is live.
    unsafe {
        ossl_cmp_log0(
            OSSL_CMP_LOG_INFO,
            ctx,
            c"poll_for_response",
            276,
            c"received 'waiting' PKIStatus, starting to poll for response",
        )
    };
    // SAFETY: `rep` is a writable slot.
    unsafe { *rep = ptr::null_mut() };

    let mut res: c_int = 0;
    'outer: loop {
        // SAFETY: `ctx` is live.
        let bak = unsafe { (*ctx).status };
        // SAFETY: `ctx` is live.
        unsafe { (*ctx).status = OSSL_CMP_PKISTATUS_request };
        // SAFETY: `ctx` is live.
        preq = unsafe { ossl_cmp_pollReq_new(ctx, rid) };
        if preq.is_null() {
            break 'outer;
        }
        // SAFETY: `ctx`/`preq` are live; `prep` is a writable slot.
        if unsafe { send_receive_check(ctx, preq, &mut prep, OSSL_CMP_PKIBODY_POLLREP) } == 0 {
            break 'outer;
        }
        // SAFETY: `ctx` is live.
        unsafe { (*ctx).status = bak };

        /* handle potential pollRep */
        // SAFETY: `prep` is live.
        if unsafe { OSSL_CMP_MSG_get_bodytype(prep) } == OSSL_CMP_PKIBODY_POLLREP {
            // SAFETY: `prep` is live.
            let prc = unsafe { (*(*prep).body).value.poll_rep };
            // SAFETY: `prc` is live.
            if unsafe { crate::runtime::stack::OPENSSL_sk_num(prc) } > 1 {
                // SAFETY: the site is a compile-time constant.
                unsafe { raise_cmp(299, c"poll_for_response", 170) };
                break 'outer;
            }
            // SAFETY: `prc` is live.
            let poll_rep = unsafe { ossl_cmp_pollrepcontent_get0_pollrep(prc, rid) };
            if poll_rep.is_null() {
                break 'outer;
            }
            let mut check_after: i64 = 0;
            // SAFETY: `poll_rep` is live.
            if unsafe { ASN1_INTEGER_get_int64(&mut check_after, (*poll_rep).check_after) } == 0 {
                // SAFETY: the site is a compile-time constant.
                unsafe { raise_cmp(307, c"poll_for_response", 167) };
                break 'outer;
            }
            let bound = if sleep != 0 {
                u64::MAX / 1000
            } else {
                c_int::MAX as u64
            };
            if check_after < 0 || (check_after as u64) > bound {
                // SAFETY: the site is a compile-time constant.
                unsafe { raise_cmp(311, c"poll_for_response", 181) };
                break 'outer;
            }
            // SAFETY: `ctx` is live.
            if unsafe { (*ctx).total_timeout } != 0 {
                // SAFETY: `time` is the C library's.
                let now = unsafe { crate::runtime::bio::sys::time(ptr::null_mut()) } as i64;
                // SAFETY: `ctx` is live.
                let time_left =
                    unsafe { (*ctx).end_time } - OSSL_CMP_EXPECTED_RESP_TIME as i64 - now;
                if time_left <= 0 {
                    // SAFETY: `ctx` is live.
                    unsafe { (*ctx).status = OSSL_CMP_PKISTATUS_trans };
                    // SAFETY: the site is a compile-time constant.
                    unsafe { raise_cmp(345, c"poll_for_response", 184) };
                    break 'outer;
                }
                if time_left < check_after {
                    check_after = time_left;
                }
            }

            // SAFETY: `preq`/`prep` are NULL or live.
            unsafe {
                OSSL_CMP_MSG_free(preq);
                preq = ptr::null_mut();
                OSSL_CMP_MSG_free(prep);
                prep = ptr::null_mut();
            }
            if sleep != 0 {
                // SAFETY: `check_after` is non-negative and bounded.
                OSSL_sleep((1000 * check_after) as u64);
            } else {
                if !check_after_out.is_null() {
                    // SAFETY: `check_after_out` is a writable slot.
                    unsafe { *check_after_out = check_after as c_int };
                }
                res = -1;
                break 'outer;
            }
        // SAFETY: the enclosing function's `# Safety` section is the contract for these raw pointers.
        } else if unsafe { is_crep_with_waiting(prep, rid) } != 0
            // SAFETY: the enclosing function's `# Safety` section is the contract for these raw pointers.
            || unsafe { ossl_cmp_is_error_with_waiting(prep) } != 0
        {
            /* received status must not be 'waiting' */
            // SAFETY: `ctx` is live.
            unsafe {
                ossl_cmp_exchange_error(
                    ctx,
                    OSSL_CMP_PKISTATUS_rejection,
                    OSSL_CMP_CTX_FAILINFO_BAD_REQUEST,
                    c"polling already started".as_ptr(),
                    0,
                    ptr::null(),
                )
            };
            // SAFETY: the site is a compile-time constant.
            unsafe { raise_cmp(371, c"poll_for_response", 185) };
            break 'outer;
        } else {
            // SAFETY: `ctx` is live.
            unsafe {
                ossl_cmp_log0(
                    OSSL_CMP_LOG_INFO,
                    ctx,
                    c"poll_for_response",
                    374,
                    c"received final response after polling",
                )
            };
            // SAFETY: `ctx` is live.
            if unsafe { ossl_cmp_ctx_set1_first_senderNonce(ctx, ptr::null()) } == 0 {
                break 'outer;
            }
            if prep.is_null() {
                break 'outer;
            }
            // SAFETY: `preq` is NULL or live.
            unsafe { OSSL_CMP_MSG_free(preq) };
            preq = ptr::null_mut();
            // SAFETY: `rep` is a writable slot.
            unsafe { *rep = prep };
            prep = ptr::null_mut();
            return 1;
        }
    }

    // SAFETY: `ctx` is live.
    unsafe { ossl_cmp_ctx_set1_first_senderNonce(ctx, ptr::null()) };
    // SAFETY: `preq`/`prep` are NULL or live.
    unsafe {
        OSSL_CMP_MSG_free(preq);
        OSSL_CMP_MSG_free(prep);
    }
    res
}

/// `static int save_senderNonce_if_waiting(...)` — `cmp_client.c:394-408`.
///
/// # Safety
/// `ctx`/`rep` are live.
unsafe fn save_senderNonce_if_waiting(
    ctx: *mut OsslCmpCtx,
    rep: *const CmpMsg,
    rid: c_int,
) -> c_int {
    // SAFETY: `rep` is live.
    if (unsafe { is_crep_with_waiting(rep, rid) } != 0
        // SAFETY: the enclosing function's `# Safety` section is the contract for these raw pointers.
        || unsafe { ossl_cmp_is_error_with_waiting(rep) } != 0)
        // SAFETY: `ctx` is live.
        && unsafe { ossl_cmp_ctx_set1_first_senderNonce(ctx, (*ctx).sender_nonce) } == 0
    {
        return 0;
    }
    1
}

/// `static int send_receive_also_delayed(...)` — `cmp_client.c:414-445`.
///
/// # Safety
/// `ctx`/`req` are live; `rep` is a writable slot.
unsafe fn send_receive_also_delayed(
    ctx: *mut OsslCmpCtx,
    req: *const CmpMsg,
    rep: *mut *mut CmpMsg,
    expected_type: c_int,
) -> c_int {
    // SAFETY: `ctx`/`req` are live.
    if unsafe { send_receive_check(ctx, req, rep, expected_type) } == 0 {
        return 0;
    }
    // SAFETY: `*rep` is live.
    if unsafe { ossl_cmp_is_error_with_waiting(*rep) } != 0 {
        // SAFETY: `ctx`/`*rep` are live.
        if unsafe { save_senderNonce_if_waiting(ctx, *rep, OSSL_CMP_CERTREQID_NONE) } == 0 {
            return 0;
        }
        if expected_type != OSSL_CMP_PKIBODY_PKICONF {
            // SAFETY: `*rep` is live and is an error message here.
            let emc = unsafe { (*(**rep).body).value.error };
            // SAFETY: `ctx`/`emc` are live.
            if unsafe { save_statusInfo(ctx, (*emc).pki_status_info) } == 0 {
                return 0;
            }
        }
        // SAFETY: `*rep` is NULL or live.
        unsafe {
            OSSL_CMP_MSG_free(*rep);
            *rep = ptr::null_mut();
        }
        // SAFETY: `ctx` is live; `rep` is a writable slot.
        if unsafe { poll_for_response(ctx, 1, OSSL_CMP_CERTREQID_NONE, rep, ptr::null_mut()) } <= 0
        {
            // SAFETY: the site is a compile-time constant.
            unsafe { raise_cmp(435, c"send_receive_also_delayed", 172) };
            return 0;
        }
    }
    // SAFETY: `*rep` is live.
    if unsafe { OSSL_CMP_MSG_get_bodytype(*rep) } != expected_type {
        // SAFETY: the site is a compile-time constant.
        unsafe { raise_cmp(440, c"send_receive_also_delayed", 133) };
        return 0;
    }
    1
}

/// `int ossl_cmp_exchange_certConf(OSSL_CMP_CTX *ctx, int certReqId, int fail_info, const char`
/// `*txt)` — `cmp_client.c:450-474`. Internal.
///
/// # Safety
/// `ctx` is live; `txt` is NULL or NUL-terminated.
pub(crate) unsafe fn ossl_cmp_exchange_certConf(
    ctx: *mut OsslCmpCtx,
    cert_req_id: c_int,
    fail_info: c_int,
    txt: *const c_char,
) -> c_int {
    let mut res = 0;
    let mut pki_conf: *mut CmpMsg = ptr::null_mut();
    // SAFETY: `ctx` is live.
    let bak = unsafe { (*ctx).status };
    // SAFETY: `ctx` is live.
    unsafe { (*ctx).status = OSSL_CMP_PKISTATUS_request };
    // SAFETY: `ctx` is live; `txt` is NULL or NUL-terminated.
    let cert_conf = unsafe { ossl_cmp_certConf_new(ctx, cert_req_id, fail_info, txt) };
    if cert_conf.is_null() {
        return 0;
    }
    // SAFETY: `ctx`/`cert_conf` are live.
    res = unsafe {
        send_receive_also_delayed(ctx, cert_conf, &mut pki_conf, OSSL_CMP_PKIBODY_PKICONF)
    };
    if res != 0 {
        // SAFETY: `ctx` is live.
        unsafe { (*ctx).status = bak };
    }
    // SAFETY: both are NULL or live.
    unsafe {
        OSSL_CMP_MSG_free(cert_conf);
        OSSL_CMP_MSG_free(pki_conf);
    }
    res
}

/// `int ossl_cmp_exchange_error(OSSL_CMP_CTX *ctx, int status, int fail_info, const char *txt,`
/// `int errorCode, const char *details)` — `cmp_client.c:477-502`. Internal.
///
/// # Safety
/// `ctx` is live; `txt`/`details` are NULL or NUL-terminated.
pub(crate) unsafe fn ossl_cmp_exchange_error(
    ctx: *mut OsslCmpCtx,
    status: c_int,
    fail_info: c_int,
    txt: *const c_char,
    error_code: c_int,
    details: *const c_char,
) -> c_int {
    let mut res = 0;
    // SAFETY: `ctx` is live.
    unsafe { (*ctx).status = OSSL_CMP_PKISTATUS_request };
    // SAFETY: `txt` is NULL or NUL-terminated.
    let si = unsafe { OSSL_CMP_STATUSINFO_new(status, fail_info, txt) };
    if si.is_null() {
        return 0;
    }
    // SAFETY: `ctx`/`si` are live; `details` is NULL or NUL-terminated.
    let error = unsafe { ossl_cmp_error_new(ctx, si, error_code as i64, details, 0) };
    if error.is_null() {
        // SAFETY: `si` is this call's own.
        unsafe { OSSL_CMP_PKISI_free(si) };
        return 0;
    }
    let mut pki_conf: *mut CmpMsg = ptr::null_mut();
    // SAFETY: `ctx`/`error` are live.
    res = unsafe { send_receive_also_delayed(ctx, error, &mut pki_conf, OSSL_CMP_PKIBODY_PKICONF) };
    // SAFETY: `ctx` is live.
    unsafe { (*ctx).status = OSSL_CMP_PKISTATUS_rejected_by_client };
    // SAFETY: all three are NULL or live.
    unsafe {
        OSSL_CMP_MSG_free(error);
        OSSL_CMP_PKISI_free(si);
        OSSL_CMP_MSG_free(pki_conf);
    }
    res
}

/// `static X509 *get1_cert_status(OSSL_CMP_CTX *ctx, int bodytype, OSSL_CMP_CERTRESPONSE *crep)` —
/// `cmp_client.c:509-565`.
///
/// # Safety
/// `ctx`/`crep` are live.
unsafe fn get1_cert_status(
    ctx: *mut OsslCmpCtx,
    bodytype: c_int,
    crep: *mut CmpCertResponse,
) -> *mut X509 {
    if ctx.is_null() || crep.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: `crep` is live.
    match unsafe { ossl_cmp_pkisi_get_status((*crep).status) } {
        OSSL_CMP_PKISTATUS_waiting => {
            // SAFETY: `ctx` is live.
            unsafe {
                ossl_cmp_log0(
                    OSSL_CMP_LOG_ERR,
                    ctx,
                    c"get1_cert_status",
                    520,
                    c"received \"waiting\" status for cert when actually aiming to extract cert",
                );
                raise_cmp(522, c"get1_cert_status", 162);
            }
        }
        OSSL_CMP_PKISTATUS_grantedWithMods => {}
        OSSL_CMP_PKISTATUS_accepted => {}
        OSSL_CMP_PKISTATUS_rejection => {
            // SAFETY: `ctx` is live.
            unsafe {
                ossl_cmp_log0(
                    OSSL_CMP_LOG_ERR,
                    ctx,
                    c"get1_cert_status",
                    531,
                    c"received \"rejection\" status rather than cert",
                );
                raise_cmp(532, c"get1_cert_status", 182);
            }
        }
        OSSL_CMP_PKISTATUS_revocationWarning | OSSL_CMP_PKISTATUS_revocationNotification => {}
        OSSL_CMP_PKISTATUS_keyUpdateWarning => {
            if bodytype != OSSL_CMP_PKIBODY_KUR {
                // SAFETY: the site is a compile-time constant.
                unsafe { raise_cmp(544, c"get1_cert_status", 176) };
            }
        }
        _ => {
            // SAFETY: the site is a compile-time constant.
            unsafe { raise_cmp(552, c"get1_cert_status", 186) };
        }
    }
    // SAFETY: `ctx`/`crep` are live.
    let crt = unsafe { ossl_cmp_certresponse_get1_cert(ctx, crep) };
    if crt.is_null() {
        // SAFETY: the site is a compile-time constant.
        unsafe { raise_cmp(557, c"get1_cert_status", 112) };
    }
    crt
}

/// `static int cert_response(...)` — `cmp_client.c:657-803`.
///
/// # Safety
/// `ctx` is live; `resp`/`check_after` are writable slots.
#[allow(clippy::too_many_arguments)]
unsafe fn cert_response(
    ctx: *mut OsslCmpCtx,
    sleep: c_int,
    mut rid: c_int,
    resp: *mut *mut CmpMsg,
    check_after: *mut c_int,
    _req_type: c_int,
    expected_type: c_int,
) -> c_int {
    if ctx.is_null() {
        return 0;
    }
    let mut crepmsg: *mut CmpCertRepMessage = ptr::null_mut();
    let mut crep: *mut CmpCertResponse = ptr::null_mut();
    loop {
        // SAFETY: `*resp` is NULL or live.
        let rcvd_type = unsafe { OSSL_CMP_MSG_get_bodytype(*resp) };
        let si: *mut CmpPkisi;
        if is_crep(rcvd_type) {
            // SAFETY: `*resp` is live.
            crepmsg = unsafe { (*(**resp).body).value.ip };
            // SAFETY: `crepmsg` is live.
            if unsafe { crate::runtime::stack::OPENSSL_sk_num((*crepmsg).response) } > 1 {
                // SAFETY: the site is a compile-time constant.
                unsafe { raise_cmp(682, c"cert_response", 170) };
                return 0;
            }
            // SAFETY: `crepmsg` is live.
            crep = unsafe { ossl_cmp_certrepmessage_get0_certresponse(crepmsg, rid) };
            if crep.is_null() {
                return 0;
            }
            // SAFETY: `crep` is live.
            si = unsafe { (*crep).status };
            if rid == OSSL_CMP_CERTREQID_NONE {
                // SAFETY: `crep` is live.
                rid = unsafe { ossl_cmp_asn1_get_int((*crep).cert_req_id) };
                if rid < OSSL_CMP_CERTREQID_NONE {
                    // SAFETY: the site is a compile-time constant.
                    unsafe { raise_cmp(694, c"cert_response", 108) };
                    return 0;
                }
            }
        } else if rcvd_type == OSSL_CMP_PKIBODY_ERROR {
            // SAFETY: `*resp` is live.
            si = unsafe { (*(*(**resp).body).value.error).pki_status_info };
        } else {
            // SAFETY: the site is a compile-time constant.
            unsafe { raise_cmp(701, c"cert_response", 133) };
            return 0;
        }

        // SAFETY: `ctx`/`si` are live.
        if unsafe { save_statusInfo(ctx, si) } == 0 {
            return 0;
        }

        // SAFETY: `si` is live.
        if unsafe { ossl_cmp_pkisi_get_status(si) } == OSSL_CMP_PKISTATUS_waiting {
            // SAFETY: `*resp` is NULL or live.
            unsafe {
                OSSL_CMP_MSG_free(*resp);
                *resp = ptr::null_mut();
            }
            // SAFETY: `ctx` is live; `resp`/`check_after` are writable slots.
            let ret = unsafe { poll_for_response(ctx, sleep, rid, resp, check_after) };
            if ret != 0 {
                if ret == -1 {
                    return ret; /* waiting */
                }
                continue; /* got some response other than pollRep */
            } else {
                // SAFETY: the site is a compile-time constant.
                unsafe { raise_cmp(721, c"cert_response", 172) };
                return 0;
            }
        }

        if rcvd_type == OSSL_CMP_PKIBODY_ERROR {
            // SAFETY: the site is a compile-time constant.
            unsafe { raise_cmp(728, c"cert_response", 180) };
            return 0;
        }
        if rcvd_type != expected_type {
            // SAFETY: the site is a compile-time constant.
            unsafe { raise_cmp(733, c"cert_response", 133) };
            return 0;
        }

        // SAFETY: `ctx`/`crep` are live.
        let cert = unsafe { get1_cert_status(ctx, (*(**resp).body).type_, crep) };
        if cert.is_null() {
            return 0;
        }
        // SAFETY: `ctx` is live; ownership of `cert` moves in.
        if unsafe { ossl_cmp_ctx_set0_newCert(ctx, cert.cast()) } == 0 {
            // SAFETY: `cert` is live and owned here.
            unsafe { X509_free(cert) };
            return 0;
        }

        /* copy caPubs to the context if present */
        // SAFETY: `ctx`/`crepmsg` are live.
        if !crepmsg.is_null()
            // SAFETY: the enclosing function's `# Safety` section is the contract for these raw pointers.
            && !unsafe { (*crepmsg).ca_pubs }.is_null()
            // SAFETY: the enclosing function's `# Safety` section is the contract for these raw pointers.
            && unsafe { ossl_cmp_ctx_set1_caPubs(ctx, (*crepmsg).ca_pubs) } == 0
        {
            return 0;
        }

        // SAFETY: `ctx` is live.
        let subj = unsafe {
            X509_NAME_oneline(X509_get_subject_name((*ctx).new_cert), ptr::null_mut(), 0)
        };
        // SAFETY: `ctx` is live.
        let rkey = unsafe { ossl_cmp_ctx_get0_newPubkey(ctx) };
        let mut fail_info = 0;
        let mut txt: *const c_char = ptr::null();
        // SAFETY: `ctx` is live; `rkey` and the new cert are live.
        if !rkey.is_null() && unsafe { X509_check_private_key((*ctx).new_cert, rkey.cast()) } == 0 {
            fail_info = 1 << OSSL_CMP_PKIFAILUREINFO_INCORRECT_DATA;
            txt = c"public key in new certificate does not match our enrollment key".as_ptr();
        }

        /* execute the certification checking callback */
        // SAFETY: `ctx` is live.
        let cb: OSSL_CMP_certConf_cb_t = if unsafe { (*ctx).cert_conf_cb }.is_null() {
            Some(crate::cmp::cmp_client::OSSL_CMP_certConf_cb)
        } else {
            // SAFETY: the stored callback was installed at the matching signature.
            Some(unsafe {
                core::mem::transmute::<
                    *mut core::ffi::c_void,
                    unsafe extern "C" fn(
                        *mut OsslCmpCtx,
                        *mut X509,
                        c_int,
                        *mut *const c_char,
                    ) -> c_int,
                >((*ctx).cert_conf_cb)
            })
        };
        // SAFETY: `ctx`'s new cert and `txt` are live.
        fail_info = unsafe {
            cb.unwrap_or(OSSL_CMP_certConf_cb)(ctx, (*ctx).new_cert, fail_info, &mut txt)
        };
        if fail_info != 0 && txt.is_null() {
            txt = c"CMP client did not accept it".as_ptr();
        }

        // SAFETY: the enclosing function's `# Safety` section is the contract for these raw pointers.
        if unsafe { (*ctx).disable_confirm } == 0
            // SAFETY: the enclosing function's `# Safety` section is the contract for these raw pointers.
            && unsafe { ossl_cmp_hdr_has_implicitConfirm((**resp).header) } == 0
        {
            // SAFETY: `ctx` is live; `txt` is NULL or NUL-terminated.
            if unsafe { ossl_cmp_exchange_certConf(ctx, rid, fail_info, txt) } == 0 {
                // ret = 0
                // SAFETY: `subj` is NULL or this call's own.
                unsafe { crate::runtime::mem::CRYPTO_free(subj.cast(), FILE.as_ptr(), 801) };
                return 0;
            }
        }

        if fail_info != 0 {
            // SAFETY: `ctx` is live.
            unsafe { (*ctx).status = OSSL_CMP_PKISTATUS_rejected_by_client };
            // SAFETY: `subj` is NULL or this call's own.
            unsafe { crate::runtime::mem::CRYPTO_free(subj.cast(), FILE.as_ptr(), 801) };
            return 0;
        }
        // SAFETY: `subj` is NULL or this call's own.
        unsafe { crate::runtime::mem::CRYPTO_free(subj.cast(), FILE.as_ptr(), 801) };
        return 1;
    }
}

/// `static int initial_certreq(...)` — `cmp_client.c:805-823`.
///
/// # Safety
/// `ctx` is live; `crm` is NULL or live; `p_rep` is a writable slot.
unsafe fn initial_certreq(
    ctx: *mut OsslCmpCtx,
    req_type: c_int,
    crm: *const CrmfMsg,
    p_rep: *mut *mut CmpMsg,
    rep_type: c_int,
) -> c_int {
    // SAFETY: `ctx` is live.
    unsafe { (*ctx).status = OSSL_CMP_PKISTATUS_request };
    // SAFETY: `ctx` is live.
    if unsafe { ossl_cmp_ctx_set0_newCert(ctx, ptr::null_mut()) } == 0 {
        return 0;
    }
    // SAFETY: `ctx` is live; `crm` is NULL or live.
    let req = unsafe { ossl_cmp_certreq_new(ctx, req_type, crm) };
    if req.is_null() {
        return 0;
    }
    // SAFETY: `ctx`/`req` are live.
    let res = unsafe { send_receive_check(ctx, req, p_rep, rep_type) };
    // SAFETY: `req` is live and owned here.
    unsafe { OSSL_CMP_MSG_free(req) };
    res
}

/// `int OSSL_CMP_try_certreq(OSSL_CMP_CTX *ctx, int req_type, const OSSL_CRMF_MSG *crm, int`
/// `*checkAfter)` — `cmp_client.c:825-860`.
///
/// # Safety
/// `ctx` is NULL or live; `crm` NULL or live; `check_after` NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn OSSL_CMP_try_certreq(
    ctx: *mut OsslCmpCtx,
    req_type: c_int,
    crm: *const CrmfMsg,
    check_after: *mut c_int,
) -> c_int {
    if ctx.is_null() {
        // SAFETY: the site is a compile-time constant.
        unsafe { raise_cmp(835, c"OSSL_CMP_try_certreq", 103) };
        return 0;
    }
    let mut rep: *mut CmpMsg = ptr::null_mut();
    let is_p10 = req_type == OSSL_CMP_PKIBODY_P10CR;
    let rid = if is_p10 {
        OSSL_CMP_CERTREQID_NONE
    } else {
        OSSL_CMP_CERTREQID
    };
    let rep_type = if is_p10 {
        OSSL_CMP_PKIBODY_CP
    } else {
        req_type + 1
    };

    // SAFETY: `ctx` is live.
    if unsafe { (*ctx).status } != OSSL_CMP_PKISTATUS_waiting {
        // SAFETY: `ctx` is live; `crm` is NULL or live.
        if unsafe { initial_certreq(ctx, req_type, crm, &mut rep, rep_type) } == 0 {
            // SAFETY: `rep` is NULL or live.
            unsafe { OSSL_CMP_MSG_free(rep) };
            return 0;
        }
        // SAFETY: `ctx`/`rep` are live.
        if unsafe { save_senderNonce_if_waiting(ctx, rep, rid) } == 0 {
            // SAFETY: `rep` is NULL or live.
            unsafe { OSSL_CMP_MSG_free(rep) };
            return 0;
        }
    } else {
        if req_type < 0 {
            // SAFETY: `ctx` is live.
            return unsafe {
                ossl_cmp_exchange_error(
                    ctx,
                    OSSL_CMP_PKISTATUS_rejection,
                    0,
                    c"polling aborted".as_ptr(),
                    0,
                    c"by application".as_ptr(),
                )
            };
        }
        // SAFETY: `ctx` is live; `check_after` is NULL or writable.
        let res = unsafe { poll_for_response(ctx, 0, rid, &mut rep, check_after) };
        if res <= 0 {
            return res;
        }
    }
    // SAFETY: `ctx` is live; `rep` is a live slot.
    let res = unsafe { cert_response(ctx, 0, rid, &mut rep, check_after, req_type, rep_type) };
    // SAFETY: `rep` is NULL or live.
    unsafe { OSSL_CMP_MSG_free(rep) };
    res
}

/// `X509 *OSSL_CMP_exec_certreq(OSSL_CMP_CTX *ctx, int req_type, const OSSL_CRMF_MSG *crm)` —
/// `cmp_client.c:869-897`.
///
/// # Safety
/// `ctx` is NULL or live; `crm` NULL or live.
#[no_mangle]
pub unsafe extern "C" fn OSSL_CMP_exec_certreq(
    ctx: *mut OsslCmpCtx,
    req_type: c_int,
    crm: *const CrmfMsg,
) -> *mut X509 {
    if ctx.is_null() {
        // SAFETY: the site is a compile-time constant.
        unsafe { raise_cmp(879, c"OSSL_CMP_exec_certreq", 103) };
        return ptr::null_mut();
    }
    let mut rep: *mut CmpMsg = ptr::null_mut();
    let is_p10 = req_type == OSSL_CMP_PKIBODY_P10CR;
    let rid = if is_p10 {
        OSSL_CMP_CERTREQID_NONE
    } else {
        OSSL_CMP_CERTREQID
    };
    let rep_type = if is_p10 {
        OSSL_CMP_PKIBODY_CP
    } else {
        req_type + 1
    };

    // SAFETY: `ctx` is live; `crm` is NULL or live.
    if unsafe { initial_certreq(ctx, req_type, crm, &mut rep, rep_type) } == 0 {
        // SAFETY: `rep` is NULL or live.
        unsafe { OSSL_CMP_MSG_free(rep) };
        return ptr::null_mut();
    }
    // SAFETY: `ctx`/`rep` are live.
    if unsafe { save_senderNonce_if_waiting(ctx, rep, rid) } == 0 {
        // SAFETY: `rep` is NULL or live.
        unsafe { OSSL_CMP_MSG_free(rep) };
        return ptr::null_mut();
    }
    // SAFETY: `ctx` is live; `rep` is a live slot.
    if unsafe { cert_response(ctx, 1, rid, &mut rep, ptr::null_mut(), req_type, rep_type) } <= 0 {
        // SAFETY: `rep` is NULL or live.
        unsafe { OSSL_CMP_MSG_free(rep) };
        return ptr::null_mut();
    }
    // SAFETY: `rep` is NULL or live.
    unsafe { OSSL_CMP_MSG_free(rep) };
    // SAFETY: `ctx` is live.
    unsafe { (*ctx).new_cert }
}

/// `int OSSL_CMP_exec_RR_ses(OSSL_CMP_CTX *ctx)` — `cmp_client.c:899-1027`.
///
/// # Safety
/// `ctx` is NULL or live.
#[no_mangle]
pub unsafe extern "C" fn OSSL_CMP_exec_RR_ses(ctx: *mut OsslCmpCtx) -> c_int {
    if ctx.is_null() {
        // SAFETY: the site is a compile-time constant.
        unsafe { raise_cmp(911, c"OSSL_CMP_exec_RR_ses", 100) };
        return 0;
    }
    let num_rev_details = 1;
    let rsid = OSSL_CMP_REVREQSID;
    // SAFETY: `ctx` is live.
    unsafe { (*ctx).status = OSSL_CMP_PKISTATUS_request };
    // SAFETY: `ctx` is live.
    if unsafe { (*ctx).old_cert }.is_null()
        // SAFETY: the enclosing function's `# Safety` section is the contract for these raw pointers.
        && unsafe { (*ctx).p10_csr }.is_null()
        // SAFETY: the enclosing function's `# Safety` section is the contract for these raw pointers.
        && (unsafe { (*ctx).serial_number }.is_null() || unsafe { (*ctx).issuer }.is_null())
    {
        // SAFETY: the site is a compile-time constant.
        unsafe { raise_cmp(917, c"OSSL_CMP_exec_RR_ses", 168) };
        return 0;
    }

    let mut ret = 0;
    // SAFETY: `ctx` is live.
    let rr = unsafe { ossl_cmp_rr_new(ctx) };
    if rr.is_null() {
        return 0;
    }
    let mut rp: *mut CmpMsg = ptr::null_mut();
    // SAFETY: `ctx`/`rr` are live.
    if unsafe { send_receive_also_delayed(ctx, rr, &mut rp, OSSL_CMP_PKIBODY_RP) } == 0 {
        // SAFETY: both are NULL or live.
        unsafe {
            OSSL_CMP_MSG_free(rr);
            OSSL_CMP_MSG_free(rp);
        }
        return 0;
    }
    // SAFETY: `rp` is live.
    let rrep = unsafe { (*(*rp).body).value.rp };
    // SAFETY: `rrep` is live.
    if unsafe { crate::runtime::stack::OPENSSL_sk_num((*rrep).status) } != num_rev_details {
        // SAFETY: the site is a compile-time constant.
        unsafe { raise_cmp(931, c"OSSL_CMP_exec_RR_ses", 188) };
        // SAFETY: both are NULL or live.
        unsafe {
            OSSL_CMP_MSG_free(rr);
            OSSL_CMP_MSG_free(rp);
        }
        return 0;
    }
    // SAFETY: `rrep` is live.
    let si = unsafe { ossl_cmp_revrepcontent_get_pkisi(rrep, rsid) };
    // SAFETY: `ctx`/`si` are live.
    if unsafe { save_statusInfo(ctx, si) } == 0 {
        ret = 0;
    } else {
        // SAFETY: `si` is live.
        match unsafe { ossl_cmp_pkisi_get_status(si) } {
            OSSL_CMP_PKISTATUS_accepted
            | OSSL_CMP_PKISTATUS_grantedWithMods
            | OSSL_CMP_PKISTATUS_revocationWarning
            | OSSL_CMP_PKISTATUS_revocationNotification => ret = 1,
            OSSL_CMP_PKISTATUS_rejection => {
                // SAFETY: the site is a compile-time constant.
                unsafe { raise_cmp(955, c"OSSL_CMP_exec_RR_ses", 182) };
                ret = 0;
            }
            _ => {
                // SAFETY: the site is a compile-time constant.
                unsafe { raise_cmp(972, c"OSSL_CMP_exec_RR_ses", 186) };
                ret = 0;
            }
        }
    }

    /* check any present CertId in optional revCerts field */
    // SAFETY: `rrep` is live.
    if unsafe { OPENSSL_sk_num((*rrep).rev_certs) } >= 1 {
        // SAFETY: `rr` is live.
        let rd = unsafe { OPENSSL_sk_value((*(*rr).body).value.rr, rsid).cast::<CmpRevDetails>() };
        // SAFETY: `rd` is live.
        let tmpl = unsafe { (*rd).cert_details };
        // SAFETY: `tmpl` is live.
        let issuer = unsafe { OSSL_CRMF_CERTTEMPLATE_get0_issuer(tmpl) };
        // SAFETY: `tmpl` is live.
        let serial = unsafe { OSSL_CRMF_CERTTEMPLATE_get0_serialNumber(tmpl) };
        // SAFETY: the enclosing function's `# Safety` section is the contract for these raw pointers.
        if unsafe { OPENSSL_sk_num((*rrep).rev_certs) } != num_rev_details {
            // SAFETY: the site is a compile-time constant.
            unsafe { raise_cmp(984, c"OSSL_CMP_exec_RR_ses", 188) };
            ret = 0;
        } else {
            // SAFETY: `rrep` is live.
            let cid = unsafe { ossl_cmp_revrepcontent_get_CertId(rrep, rsid) };
            if cid.is_null() {
                // SAFETY: the site is a compile-time constant.
                unsafe { raise_cmp(989, c"OSSL_CMP_exec_RR_ses", 165) };
                ret = 0;
            } else {
                // SAFETY: `issuer`/`cid` are live.
                if unsafe { X509_NAME_cmp(issuer, OSSL_CRMF_CERTID_get0_issuer(cid)) } != 0 {
                    // SAFETY: the site is a compile-time constant.
                    unsafe { raise_cmp(995, c"OSSL_CMP_exec_RR_ses", 187) };
                    ret = 0;
                }
                // SAFETY: `serial`/`cid` are live.
                if unsafe { ASN1_INTEGER_cmp(serial, OSSL_CRMF_CERTID_get0_serialNumber(cid)) } != 0
                {
                    // SAFETY: the site is a compile-time constant.
                    unsafe { raise_cmp(1003, c"OSSL_CMP_exec_RR_ses", 173) };
                    ret = 0;
                }
            }
        }
    }

    /* check number of any optionally present crls */
    // SAFETY: `rrep` is live.
    if !unsafe { (*rrep).crls }.is_null()
        // SAFETY: the enclosing function's `# Safety` section is the contract for these raw pointers.
        && unsafe { crate::runtime::stack::OPENSSL_sk_num((*rrep).crls) } != num_rev_details
    {
        // SAFETY: the site is a compile-time constant.
        unsafe { raise_cmp(1013, c"OSSL_CMP_exec_RR_ses", 188) };
        ret = 0;
    }
    // SAFETY: both are NULL or live.
    unsafe {
        OSSL_CMP_MSG_free(rr);
        OSSL_CMP_MSG_free(rp);
    }
    ret
}

/// `STACK_OF(OSSL_CMP_ITAV) *OSSL_CMP_exec_GENM_ses(OSSL_CMP_CTX *ctx)` — `cmp_client.c:1029-1059`.
///
/// # Safety
/// `ctx` is NULL or live.
#[no_mangle]
pub unsafe extern "C" fn OSSL_CMP_exec_GENM_ses(ctx: *mut OsslCmpCtx) -> *mut OpenSslStack {
    if ctx.is_null() {
        // SAFETY: the site is a compile-time constant.
        unsafe { raise_cmp(1036, c"OSSL_CMP_exec_GENM_ses", 100) };
        return ptr::null_mut();
    }
    // SAFETY: `ctx` is live.
    unsafe { (*ctx).status = OSSL_CMP_PKISTATUS_request };
    // SAFETY: `ctx` is live.
    let genm = unsafe { ossl_cmp_genm_new(ctx) };
    if genm.is_null() {
        return ptr::null_mut();
    }
    let mut genp: *mut CmpMsg = ptr::null_mut();
    // SAFETY: `ctx`/`genm` are live.
    if unsafe { send_receive_also_delayed(ctx, genm, &mut genp, OSSL_CMP_PKIBODY_GENP) } == 0 {
        // SAFETY: both are NULL or live.
        unsafe {
            OSSL_CMP_MSG_free(genm);
            OSSL_CMP_MSG_free(genp);
        }
        return ptr::null_mut();
    }
    // SAFETY: `ctx` is live.
    unsafe { (*ctx).status = OSSL_CMP_PKISTATUS_accepted };
    // SAFETY: `genp` is live.
    let mut itavs = unsafe { (*(*genp).body).value.genp };
    if itavs.is_null() {
        itavs = crate::runtime::stack::OPENSSL_sk_new_null();
    }
    /* received stack of itavs not to be freed with the genp */
    // SAFETY: `genp` is live.
    unsafe { (*(*genp).body).value.genp = ptr::null_mut() };
    // SAFETY: both are NULL or live.
    unsafe {
        OSSL_CMP_MSG_free(genm);
        OSSL_CMP_MSG_free(genp);
    }
    itavs
}
