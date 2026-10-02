//! `crypto/cmp/cmp_vfy.c` — CMP message and certificate-path verification. Phase 12.4.
//!
//! This unit lands `OSSL_CMP_validate_cert_path`, the self-contained path validator over
//! `X509_STORE_CTX`/`X509_verify_cert`. `OSSL_CMP_validate_msg` is left open: it is the message
//! verifier, and every one of its arms reaches the `cmp_protect.c` protection engine
//! (`ossl_cmp_calc_protection`), which in the PasswordBasedMAC arm needs the `crmf_pbm.c`
//! `OSSL_CRMF_pbm_new`/`OSSL_CRMF_pbmp_new` public surface the plan lands in 12.7. That is a
//! non-`cmp/` facility, so it is not pulled forward here.
//!
//! SPDX-License-Identifier: Apache-2.0
#![allow(dead_code, non_snake_case)]
#![allow(private_interfaces)]

use core::ffi::{c_int, c_ulong};

use crate::cmp::cmp_ctx::{OSSL_CMP_CTX_print_errors, OsslCmpCtx};
use crate::runtime::err::err_sites::ErrSite;
use crate::runtime::err::{raise_site, ERR_peek_last_error};
use crate::x509::x509_lu::X509Store;
use crate::x509::x509_vfy::{X509_STORE_CTX_free, X509_STORE_CTX_init};
use crate::x509::x509_vfy::{X509_STORE_CTX_new_ex, X509_verify_cert};
use crate::x509::x_x509::X509;

/// The authority translation unit for this module.
pub(crate) const FILE: &core::ffi::CStr = c"crypto/cmp/cmp_vfy.c";

/// `ERR_LIB_CMP`.
const ERR_LIB_CMP: c_int = 58;
/// `CMP_R_NULL_ARGUMENT` — `include/openssl/cmperr.h:91`.
const CMP_R_NULL_ARGUMENT: c_int = 103;
/// `CMP_R_MISSING_TRUST_STORE` — `include/openssl/cmperr.h:85`.
const CMP_R_MISSING_TRUST_STORE: c_int = 144;
/// `CMP_R_POTENTIALLY_INVALID_CERTIFICATE` — `include/openssl/cmperr.h:95`.
const CMP_R_POTENTIALLY_INVALID_CERTIFICATE: c_int = 147;
/// `ERR_REASON_MASK` — `include/openssl/err.h`.
const ERR_REASON_MASK: c_ulong = 0x007F_FFFF;

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

/// `ERR_GET_REASON(e)` — `(int)(e & ERR_REASON_MASK)`.
const fn err_get_reason(e: c_ulong) -> c_int {
    (e & ERR_REASON_MASK) as c_int
}

/// `int OSSL_CMP_validate_cert_path(const OSSL_CMP_CTX *ctx, X509_STORE *trusted_store, X509 *cert)`
/// — `cmp_vfy.c:102-136`.
///
/// # Safety
/// `ctx` is NULL or a live `OSSL_CMP_CTX`; `trusted_store` and `cert` are NULL or live objects.
#[no_mangle]
pub unsafe extern "C" fn OSSL_CMP_validate_cert_path(
    ctx: *const OsslCmpCtx,
    trusted_store: *mut X509Store,
    cert: *mut X509,
) -> c_int {
    if ctx.is_null() || cert.is_null() {
        // SAFETY: the site is a compile-time constant.
        unsafe { raise_cmp(110, c"OSSL_CMP_validate_cert_path", CMP_R_NULL_ARGUMENT) };
        return 0;
    }

    if trusted_store.is_null() {
        // SAFETY: the site is a compile-time constant.
        unsafe {
            raise_cmp(
                115,
                c"OSSL_CMP_validate_cert_path",
                CMP_R_MISSING_TRUST_STORE,
            )
        };
        return 0;
    }

    // SAFETY: `ctx` is live; the callees obey their own contracts.
    let csc = unsafe {
        let csc = X509_STORE_CTX_new_ex((*ctx).libctx, (*ctx).propq);
        if csc.is_null() || X509_STORE_CTX_init(csc, trusted_store, cert, (*ctx).untrusted) == 0 {
            // SAFETY: `csc` is NULL or live.
            X509_STORE_CTX_free(csc);
            // SAFETY: `ctx` is live.
            OSSL_CMP_CTX_print_errors(ctx);
            return 0;
        }
        csc
    };

    // SAFETY: `csc` is live and initialised.
    let valid: c_int = c_int::from(unsafe { X509_verify_cert(csc) } > 0);

    /* make sure suitable error is queued even if callback did not do */
    let err = ERR_peek_last_error();
    if valid == 0 && err_get_reason(err) != CMP_R_POTENTIALLY_INVALID_CERTIFICATE {
        // SAFETY: the site is a compile-time constant.
        unsafe {
            raise_cmp(
                129,
                c"OSSL_CMP_validate_cert_path",
                CMP_R_POTENTIALLY_INVALID_CERTIFICATE,
            )
        };
    }

    /* directly output any fresh errors, needed for check_msg_find_cert() */
    // SAFETY: `ctx` is live; `csc` is live.
    unsafe {
        OSSL_CMP_CTX_print_errors(ctx);
        X509_STORE_CTX_free(csc);
    }
    valid
}
