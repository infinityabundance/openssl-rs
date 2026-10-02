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

use core::ffi::{c_char, c_int, c_ulong};
use core::ptr;

use crate::cmp::cmp_ctx::{
    ossl_cmp_ctx_set1_newChain, ossl_cmp_print_log, OSSL_CMP_CTX_get1_extraCertsIn,
    OSSL_CMP_CTX_get_certConf_cb_arg, OsslCmpCtx,
};
use crate::cmp::cmp_util::{OSSL_CMP_LOG_DEBUG, OSSL_CMP_LOG_ERR, OSSL_CMP_LOG_WARNING};
use crate::runtime::stack::{OPENSSL_sk_free, OPENSSL_sk_num, OPENSSL_sk_shift, OpenSslStack};
use crate::x509::t_x509::OSSL_STACK_OF_X509_free;
use crate::x509::x509_cmp::ossl_x509_add_certs_new;
use crate::x509::x509_lu::X509Store;
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
