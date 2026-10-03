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
use core::ptr;

use crate::asn1::a_verify::ASN1_item_verify_ex;
use crate::asn1::layout::Asn1String;
use crate::asn1::string::ASN1_OCTET_STRING_cmp;
use crate::cmp::cmp_asn::{cmp_protectedpart_it, CmpMsg, CmpProtectedPart};
use crate::cmp::cmp_ctx::{
    ossl_cmp_ctx_set1_recipNonce, ossl_cmp_ctx_set1_validatedSrvCert, OSSL_CMP_CTX_print_errors,
    OSSL_CMP_CTX_set1_transactionID, OsslCmpCtx,
};
use crate::cmp::cmp_hdr::{ossl_cmp_hdr_get_protection_nid, ossl_cmp_hdr_get_pvno};
use crate::cmp::cmp_msg::{
    ossl_cmp_certrepmessage_get0_certresponse, ossl_cmp_certresponse_get1_cert,
    OSSL_CMP_MSG_get_bodytype,
};
use crate::cmp::cmp_protect::ossl_cmp_calc_protection;
use crate::cmp::cmp_util::{
    ossl_cmp_X509_STORE_add1_certs, ossl_cmp_log0, ossl_cmp_log_str, OSSL_CMP_LOG_DEBUG,
    OSSL_CMP_LOG_INFO, OSSL_CMP_LOG_WARNING,
};
use crate::crmf::crmf_lib::OSSL_CRMF_MSGS_verify_popo;
use crate::evp::pkey::EVP_PKEY_free;
use crate::runtime::bio::bss_mem::BIO_s_mem;
use crate::runtime::bio::{BIO_free, BIO_new};
use crate::runtime::err::err_sites::ErrSite;
use crate::runtime::err::{
    raise_site, ERR_add_error_mem_bio, ERR_add_error_txt, ERR_clear_last_mark, ERR_peek_last_error,
    ERR_pop_to_mark, ERR_set_mark,
};
use crate::runtime::mem::CRYPTO_free;
use crate::runtime::stack::{OPENSSL_sk_num, OPENSSL_sk_value, OpenSslStack};
use crate::x509::t_x509::{ossl_x509_print_ex_brief, OSSL_STACK_OF_X509_free};
use crate::x509::v3_genn::{GeneralName, GEN_DIRNAME};
use crate::x509::v3_purp::{
    ossl_x509v3_cache_extensions, X509_check_issued, X509_get0_subject_key_id, X509_get_key_usage,
};
use crate::x509::v3_skid::i2s_ASN1_OCTET_STRING;
use crate::x509::x509_cmp::{
    ossl_x509_add_certs_new, X509_NAME_cmp, X509_cmp, X509_get_issuer_name, X509_get_pubkey,
    X509_get_subject_name,
};
use crate::x509::x509_lu::{
    X509Store, X509_STORE_free, X509_STORE_get0_param, X509_STORE_get1_all_certs,
    X509_STORE_get_verify_cb, X509_STORE_new,
};
use crate::x509::x509_obj::X509_NAME_oneline;
use crate::x509::x509_req::X509_REQ_get0_pubkey;
use crate::x509::x509_set::{X509_get0_notAfter, X509_get0_notBefore};
use crate::x509::x509_vfy::{
    X509_STORE_CTX_free, X509_STORE_CTX_init, X509_STORE_CTX_new, X509_STORE_CTX_new_ex,
    X509_STORE_CTX_set_current_cert, X509_STORE_CTX_set_error, X509_cmp_timeframe,
    X509_verify_cert,
};
use crate::x509::x_all::X509_REQ_verify_ex;
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

// ---------------------------------------------------------------------------------------------
// The message verifier — `cmp_vfy.c:16-908`
// ---------------------------------------------------------------------------------------------

/// `X509v3_KU_DIGITAL_SIGNATURE` — `include/openssl/x509v3.h`.
const X509V3_KU_DIGITAL_SIGNATURE: c_ulong = 0x0080;
/// `X509_FLAG_NO_EXTENSIONS` — `include/openssl/x509.h.in:146`.
const X509_FLAG_NO_EXTENSIONS: c_ulong = 1 << 8;
/// `X509_V_OK` — `include/openssl/x509_vfy.h.in:215`.
const X509_V_OK: c_int = 0;
/// `X509_V_ERR_CERT_NOT_YET_VALID` — `include/openssl/x509_vfy.h.in:224`.
const X509_V_ERR_CERT_NOT_YET_VALID: c_int = 9;
/// `X509_V_ERR_CERT_HAS_EXPIRED` — `include/openssl/x509_vfy.h.in:225`.
const X509_V_ERR_CERT_HAS_EXPIRED: c_int = 10;
/// `NID_id_PasswordBasedMAC`/`NID_id_DHBasedMac` — `include/openssl/obj_mac.h`.
const NID_id_PASSWORD_BASED_MAC: c_int = 782;
const NID_id_DH_BASED_MAC: c_int = 783;
/// `OSSL_CMP_PVNO_2`/`_3` — `include/openssl/cmp.h.in:41-42`.
const OSSL_CMP_PVNO_2: c_int = 2;
const OSSL_CMP_PVNO_3: c_int = 3;
/// `OSSL_CMP_PKIBODY_*` selectors — `cmp_local.h:903-931`.
const OSSL_CMP_PKIBODY_IR: c_int = 0;
const OSSL_CMP_PKIBODY_IP: c_int = 1;
const OSSL_CMP_PKIBODY_CR: c_int = 2;
const OSSL_CMP_PKIBODY_CP: c_int = 3;
const OSSL_CMP_PKIBODY_P10CR: c_int = 4;
const OSSL_CMP_PKIBODY_KUR: c_int = 7;
const OSSL_CMP_PKIBODY_KUP: c_int = 8;
const OSSL_CMP_PKIBODY_CCP: c_int = 14;
const OSSL_CMP_PKIBODY_POLLREP: c_int = 26;
/// `OSSL_CMP_CERTREQID` — `cmp_local.h:932`.
const OSSL_CMP_CERTREQID: c_int = 0;
/// `X509_ADD_FLAG_*` — `include/openssl/x509.h.in:801-804`.
const X509_ADD_FLAG_UP_REF: c_int = 0x1;
const X509_ADD_FLAG_PREPEND: c_int = 0x2;
const X509_ADD_FLAG_NO_DUP: c_int = 0x4;

/// A CMP allow-unprotected callback — `cmp_local.h:996-998`.
pub type OsslCmpAllowUnprotectedCb =
    Option<unsafe extern "C" fn(*const OsslCmpCtx, *const CmpMsg, c_int, c_int) -> c_int>;

/// `static int verify_signature(const OSSL_CMP_CTX *cmp_ctx, const OSSL_CMP_MSG *msg, X509`
/// `*cert)` — `cmp_vfy.c:17-70`.
///
/// # Safety
/// `cmp_ctx`/`msg`/`cert` are live.
unsafe fn verify_signature(
    cmp_ctx: *const OsslCmpCtx,
    msg: *const CmpMsg,
    cert: *mut X509,
) -> c_int {
    if cmp_ctx.is_null() || msg.is_null() || cert.is_null() {
        return 0;
    }
    // SAFETY: `BIO_s_mem` answers a static method.
    let bio = unsafe { BIO_new(BIO_s_mem()) };
    if bio.is_null() {
        return 0;
    }
    let mut pubkey: *mut crate::evp::pkey::EvpPkey = ptr::null_mut();
    let mut ok = false;
    // SAFETY: `cmp_ctx`/`cert` are live.
    if unsafe { (*cmp_ctx).ignore_keyusage } != 0
        // SAFETY: the enclosing function's `# Safety` section is the contract for these raw pointers.
        || (unsafe { X509_get_key_usage(cert) } as c_ulong & X509V3_KU_DIGITAL_SIGNATURE) != 0
    {
        // SAFETY: `cert` is live.
        pubkey = unsafe { X509_get_pubkey(cert) };
        if pubkey.is_null() {
            // SAFETY: the site is a compile-time constant.
            unsafe { raise_cmp(40, c"verify_signature", 141) };
        } else {
            // SAFETY: `msg` is live.
            let prot_part = CmpProtectedPart {
                // SAFETY: the enclosing function's `# Safety` section is the contract for these raw pointers.
                header: unsafe { (*msg).header },
                // SAFETY: the enclosing function's `# Safety` section is the contract for these raw pointers.
                body: unsafe { (*msg).body },
            };
            // SAFETY: `msg`/`cmp_ctx` are live; `pubkey` is live.
            if unsafe {
                ASN1_item_verify_ex(
                    cmp_protectedpart_it(),
                    (*(*msg).header).protection_alg,
                    (*msg).protection,
                    ptr::addr_of!(prot_part).cast(),
                    ptr::null(),
                    pubkey,
                    (*cmp_ctx).libctx,
                    (*cmp_ctx).propq,
                )
            } > 0
            {
                ok = true;
            }
        }
    } else {
        // SAFETY: the site is a compile-time constant.
        unsafe { raise_cmp(34, c"verify_signature", 142) };
    }

    let res = if ok {
        1
    } else {
        // SAFETY: `bio`/`cert` are live.
        let r = unsafe { ossl_x509_print_ex_brief(bio, cert, X509_FLAG_NO_EXTENSIONS) };
        // SAFETY: the site is a compile-time constant.
        unsafe { raise_cmp(58, c"verify_signature", 171) };
        if r != 0 {
            // SAFETY: the separator/detail are NULL or live.
            unsafe {
                ERR_add_error_txt(ptr::null(), c"\n".as_ptr());
                ERR_add_error_mem_bio(ptr::null(), bio);
            }
        }
        0
    };
    // SAFETY: `pubkey` is NULL or this call's own; `bio` is live.
    unsafe {
        EVP_PKEY_free(pubkey);
        BIO_free(bio);
    }
    res
}

/// `static int verify_PBMAC(OSSL_CMP_CTX *ctx, const OSSL_CMP_MSG *msg)` — `cmp_vfy.c:73-93`.
///
/// # Safety
/// `ctx`/`msg` are live.
unsafe fn verify_PBMAC(ctx: *mut OsslCmpCtx, msg: *const CmpMsg) -> c_int {
    // SAFETY: `ctx`/`msg` are live.
    let protection = unsafe { ossl_cmp_calc_protection(ctx, msg) };
    if protection.is_null() {
        return 0; /* failed to generate protection string! */
    }
    // SAFETY: `msg`/`protection` are live.
    let valid = unsafe {
        !(*msg).protection.is_null()
            && (*(*msg).protection).length >= 0
            && (*(*msg).protection).type_ == (*protection).type_
            && (*(*msg).protection).length == (*protection).length
            && CRYPTO_memcmp(
                (*(*msg).protection).data,
                (*protection).data,
                (*protection).length as usize,
            ) == 0
    };
    // SAFETY: `protection` is this call's own.
    unsafe { crate::asn1::string::ASN1_BIT_STRING_free(protection) };
    if !valid {
        // SAFETY: the site is a compile-time constant.
        unsafe { raise_cmp(90, c"verify_PBMAC", 155) };
    }
    c_int::from(valid)
}

/// `int CRYPTO_memcmp(const void *, const void *, size_t)` — the constant-time comparison.
///
/// # Safety
/// Both buffers are readable for `len` bytes.
unsafe fn CRYPTO_memcmp(a: *const u8, b: *const u8, len: usize) -> c_int {
    let mut neq = 0u8;
    let mut i = 0;
    while i < len {
        // SAFETY: both buffers are readable for `len` bytes.
        neq |= unsafe { *a.add(i) } ^ unsafe { *b.add(i) };
        i += 1;
    }
    c_int::from(neq != 0)
}

/// `static int verify_cb_cert(X509_STORE *ts, X509 *cert, int err)` — `cmp_vfy.c:138-154`.
///
/// # Safety
/// `ts` is NULL or live; `cert` is live.
unsafe fn verify_cb_cert(ts: *mut X509Store, cert: *mut X509, err: c_int) -> c_int {
    // SAFETY: `ts` is NULL or live.
    let verify_cb = unsafe { X509_STORE_get_verify_cb(ts) };
    if ts.is_null() || verify_cb.is_none() {
        return 0;
    }
    let mut ok = 0;
    // SAFETY: no preconditions.
    let csc = X509_STORE_CTX_new();
    // SAFETY: `csc` is NULL or live; `ts`/`cert` are live.
    if !csc.is_null() && unsafe { X509_STORE_CTX_init(csc, ts, cert, ptr::null_mut()) } != 0 {
        // SAFETY: `csc` is live.
        unsafe {
            X509_STORE_CTX_set_error(csc, err);
            X509_STORE_CTX_set_current_cert(csc, cert);
        }
        // SAFETY: the callback is the store's own.
        if let Some(cb) = verify_cb {
            // SAFETY: `cb`/`csc` are live with the store's callback contract.
            ok = unsafe { cb(0, csc.cast()) };
        }
    }
    // SAFETY: `csc` is NULL or this call's own.
    unsafe { X509_STORE_CTX_free(csc) };
    ok
}

/// `static int check_name(...)` — `cmp_vfy.c:157-187`.
///
/// # Safety
/// `ctx` is live; the two names are NULL or live.
unsafe fn check_name(
    ctx: *const OsslCmpCtx,
    log_success: c_int,
    actual_desc: &'static core::ffi::CStr,
    actual_name: *const crate::x509::x_name::X509Name,
    expect_desc: &'static core::ffi::CStr,
    expect_name: *const crate::x509::x_name::X509Name,
) -> c_int {
    if expect_name.is_null() {
        return 1; /* no expectation, thus trivially fulfilled */
    }
    if actual_name.is_null() {
        // SAFETY: `ctx` is live.
        unsafe {
            ossl_cmp_log_str(
                OSSL_CMP_LOG_WARNING,
                ctx,
                c"check_name",
                FILE,
                169,
                format_args!("missing {}", actual_desc.to_string_lossy()),
            )
        };
        return 0;
    }
    // SAFETY: `actual_name` is live.
    let str_ = unsafe { X509_NAME_oneline(actual_name, ptr::null_mut(), 0) };
    // SAFETY: both names are live.
    if unsafe { X509_NAME_cmp(actual_name, expect_name) } == 0 {
        if log_success != 0 && !str_.is_null() {
            // SAFETY: `ctx` is live; `str_` is NUL-terminated.
            unsafe {
                ossl_cmp_log_str(
                    OSSL_CMP_LOG_INFO,
                    ctx,
                    c"check_name",
                    FILE,
                    174,
                    format_args!(
                        " {} matches {}: {}",
                        actual_desc.to_string_lossy(),
                        expect_desc.to_string_lossy(),
                        std::ffi::CStr::from_ptr(str_).to_string_lossy(),
                    ),
                )
            };
        }
        // SAFETY: `str_` is NULL or this call's own.
        unsafe { CRYPTO_free(str_.cast(), FILE.as_ptr(), 176) };
        return 1;
    }
    if !str_.is_null() {
        // SAFETY: `ctx` is live; `str_` is NUL-terminated.
        unsafe {
            ossl_cmp_log_str(
                OSSL_CMP_LOG_INFO,
                ctx,
                c"check_name",
                FILE,
                181,
                format_args!(
                    " actual name in {} = {}",
                    actual_desc.to_string_lossy(),
                    std::ffi::CStr::from_ptr(str_).to_string_lossy(),
                ),
            )
        };
    }
    // SAFETY: `str_` is NULL or this call's own.
    unsafe { CRYPTO_free(str_.cast(), FILE.as_ptr(), 182) };
    // SAFETY: `expect_name` is live.
    let str2 = unsafe { X509_NAME_oneline(expect_name, ptr::null_mut(), 0) };
    if !str2.is_null() {
        // SAFETY: `ctx` is live; `str2` is NUL-terminated.
        unsafe {
            ossl_cmp_log_str(
                OSSL_CMP_LOG_INFO,
                ctx,
                c"check_name",
                FILE,
                184,
                format_args!(
                    " does not match {} = {}",
                    expect_desc.to_string_lossy(),
                    std::ffi::CStr::from_ptr(str2).to_string_lossy(),
                ),
            )
        };
    }
    // SAFETY: `str2` is NULL or this call's own.
    unsafe { CRYPTO_free(str2.cast(), FILE.as_ptr(), 185) };
    0
}

/// `static int check_kid(const OSSL_CMP_CTX *ctx, const ASN1_OCTET_STRING *ckid, const`
/// `ASN1_OCTET_STRING *skid)` — `cmp_vfy.c:190-219`.
///
/// # Safety
/// `ctx` is live; the two octet strings are NULL or live.
unsafe fn check_kid(
    ctx: *const OsslCmpCtx,
    ckid: *const Asn1String,
    skid: *const Asn1String,
) -> c_int {
    if skid.is_null() {
        return 1; /* no expectation, thus trivially fulfilled */
    }
    if ckid.is_null() {
        // SAFETY: `ctx` is live.
        unsafe {
            ossl_cmp_log0(
                OSSL_CMP_LOG_WARNING,
                ctx,
                c"check_kid",
                201,
                c"missing Subject Key Identifier in certificate",
            )
        };
        return 0;
    }
    // SAFETY: `ckid` is live.
    let str_ = unsafe { i2s_ASN1_OCTET_STRING(ptr::null_mut(), ckid) };
    // SAFETY: both are live.
    if unsafe { ASN1_OCTET_STRING_cmp(ckid, skid) } == 0 {
        if !str_.is_null() {
            // SAFETY: `ctx` is live; `str_` is NUL-terminated.
            unsafe {
                ossl_cmp_log_str(
                    OSSL_CMP_LOG_INFO,
                    ctx,
                    c"check_kid",
                    FILE,
                    207,
                    format_args!(
                        " subjectKID matches senderKID: {}",
                        std::ffi::CStr::from_ptr(str_).to_string_lossy(),
                    ),
                )
            };
        }
        // SAFETY: `str_` is NULL or this call's own.
        unsafe { CRYPTO_free(str_.cast(), FILE.as_ptr(), 208) };
        return 1;
    }
    if !str_.is_null() {
        // SAFETY: `ctx` is live; `str_` is NUL-terminated.
        unsafe {
            ossl_cmp_log_str(
                OSSL_CMP_LOG_INFO,
                ctx,
                c"check_kid",
                FILE,
                213,
                format_args!(
                    " cert Subject Key Identifier = {}",
                    std::ffi::CStr::from_ptr(str_).to_string_lossy(),
                ),
            )
        };
    }
    // SAFETY: `str_` is NULL or this call's own.
    unsafe { CRYPTO_free(str_.cast(), FILE.as_ptr(), 214) };
    // SAFETY: `skid` is live.
    let str2 = unsafe { i2s_ASN1_OCTET_STRING(ptr::null_mut(), skid) };
    if !str2.is_null() {
        // SAFETY: `ctx` is live; `str2` is NUL-terminated.
        unsafe {
            ossl_cmp_log_str(
                OSSL_CMP_LOG_INFO,
                ctx,
                c"check_kid",
                FILE,
                216,
                format_args!(
                    " does not match senderKID    = {}",
                    std::ffi::CStr::from_ptr(str2).to_string_lossy(),
                ),
            )
        };
    }
    // SAFETY: `str2` is NULL or this call's own.
    unsafe { CRYPTO_free(str2.cast(), FILE.as_ptr(), 217) };
    0
}

/// `static int already_checked(const X509 *cert, const STACK_OF(X509) *already_checked)` —
/// `cmp_vfy.c:221-230`.
///
/// # Safety
/// `cert` is live; `already` is NULL or a live stack.
unsafe fn already_checked(cert: *const X509, already: *const OpenSslStack) -> c_int {
    // SAFETY: `already` is NULL or a live stack.
    let mut i = unsafe { OPENSSL_sk_num(already as *mut OpenSslStack) };
    while i > 0 {
        // SAFETY: `i - 1` is in range.
        let other = unsafe { OPENSSL_sk_value(already as *mut OpenSslStack, i - 1) }.cast::<X509>();
        // SAFETY: `other`/`cert` are live.
        if unsafe { X509_cmp(other, cert) } == 0 {
            return 1;
        }
        i -= 1;
    }
    0
}

/// `static int cert_acceptable(...)` — `cmp_vfy.c:240-301`.
///
/// # Safety
/// `ctx`/`cert`/`msg` are live; the two stacks are NULL or live.
#[allow(clippy::too_many_arguments)]
unsafe fn cert_acceptable(
    ctx: *const OsslCmpCtx,
    desc1: &'static core::ffi::CStr,
    desc2: &'static core::ffi::CStr,
    cert: *mut X509,
    already1: *const OpenSslStack,
    already2: *const OpenSslStack,
    msg: *const CmpMsg,
) -> c_int {
    // SAFETY: `ctx` is live.
    let ts = unsafe { (*ctx).trusted };
    // SAFETY: `cert` is live.
    let self_issued = unsafe { X509_check_issued(cert, cert) } == X509_V_OK;
    // SAFETY: `ts` is NULL or live.
    let vpm = if ts.is_null() {
        ptr::null_mut()
    } else {
        // SAFETY: the enclosing function's `# Safety` section is the contract for these raw pointers.
        unsafe { X509_STORE_get0_param(ts) }
    };
    // SAFETY: `ctx` is live.
    unsafe {
        ossl_cmp_log_str(
            OSSL_CMP_LOG_INFO,
            ctx,
            c"cert_acceptable",
            FILE,
            252,
            format_args!(
                " considering {}{} {} with..",
                if self_issued { "self-issued " } else { "" },
                desc1.to_string_lossy(),
                desc2.to_string_lossy(),
            ),
        )
    };
    // SAFETY: `cert` is live.
    let sname = unsafe { X509_NAME_oneline(X509_get_subject_name(cert), ptr::null_mut(), 0) };
    if !sname.is_null() {
        // SAFETY: `ctx` is live; `sname` is NUL-terminated.
        unsafe {
            ossl_cmp_log_str(
                OSSL_CMP_LOG_INFO,
                ctx,
                c"cert_acceptable",
                FILE,
                255,
                format_args!(
                    "  subject = {}",
                    std::ffi::CStr::from_ptr(sname).to_string_lossy()
                ),
            )
        };
    }
    // SAFETY: `sname` is NULL or this call's own.
    unsafe { CRYPTO_free(sname.cast(), FILE.as_ptr(), 256) };
    if !self_issued {
        // SAFETY: `cert` is live.
        let iname = unsafe { X509_NAME_oneline(X509_get_issuer_name(cert), ptr::null_mut(), 0) };
        if !iname.is_null() {
            // SAFETY: `ctx` is live; `iname` is NUL-terminated.
            unsafe {
                ossl_cmp_log_str(
                    OSSL_CMP_LOG_INFO,
                    ctx,
                    c"cert_acceptable",
                    FILE,
                    260,
                    format_args!(
                        "  issuer  = {}",
                        std::ffi::CStr::from_ptr(iname).to_string_lossy()
                    ),
                )
            };
        }
        // SAFETY: `iname` is NULL or this call's own.
        unsafe { CRYPTO_free(iname.cast(), FILE.as_ptr(), 261) };
    }

    // SAFETY: `cert` is live; the two stacks are NULL or live.
    if unsafe { already_checked(cert, already1) } != 0
        // SAFETY: the enclosing function's `# Safety` section is the contract for these raw pointers.
        || unsafe { already_checked(cert, already2) } != 0
    {
        // SAFETY: `ctx` is live.
        unsafe {
            ossl_cmp_log0(
                OSSL_CMP_LOG_INFO,
                ctx,
                c"cert_acceptable",
                266,
                c" cert has already been checked",
            )
        };
        return 0;
    }

    // SAFETY: `vpm` is NULL or live; the cert's times are live.
    let time_cmp =
        unsafe { X509_cmp_timeframe(vpm, X509_get0_notBefore(cert), X509_get0_notAfter(cert)) };
    if time_cmp != 0 {
        let err = if time_cmp > 0 {
            X509_V_ERR_CERT_HAS_EXPIRED
        } else {
            X509_V_ERR_CERT_NOT_YET_VALID
        };
        // SAFETY: `ctx` is live.
        unsafe {
            ossl_cmp_log0(
                OSSL_CMP_LOG_WARNING,
                ctx,
                c"cert_acceptable",
                276,
                if time_cmp > 0 {
                    c"cert has expired"
                } else {
                    c"cert is not yet valid"
                },
            )
        };
        // SAFETY: `ctx`/`ts`/`cert` are live.
        if unsafe { (*ctx).log_cb }.is_some() && unsafe { verify_cb_cert(ts, cert, err) } <= 0 {
            return 0;
        }
    }

    // SAFETY: `ctx`/`cert`/`msg` are live.
    let sender_name = unsafe {
        (*(*msg).header)
            .sender
            .cast::<GeneralName>()
            .as_ref()
            .map(|g| g.d.directoryName)
    };
    // SAFETY: `ctx`/`cert` are live; the sender name is NULL or live.
    if unsafe {
        check_name(
            ctx,
            1,
            c"cert subject",
            X509_get_subject_name(cert),
            c"sender field",
            sender_name.unwrap_or(ptr::null_mut()),
        )
    } == 0
    {
        return 0;
    }

    // SAFETY: `ctx`/`cert`/`msg` are live.
    if unsafe {
        check_kid(
            ctx,
            X509_get0_subject_key_id(cert),
            (*(*msg).header).sender_kid,
        )
    } == 0
    {
        return 0;
    }
    /* prevent misleading error later in case x509v3_cache_extensions() fails */
    // SAFETY: `cert` is live.
    if unsafe { ossl_x509v3_cache_extensions(cert) } == 0 {
        // SAFETY: `ctx` is live.
        unsafe {
            ossl_cmp_log0(
                OSSL_CMP_LOG_WARNING,
                ctx,
                c"cert_acceptable",
                291,
                c"cert appears to be invalid",
            )
        };
        return 0;
    }
    // SAFETY: `ctx`/`msg`/`cert` are live.
    if unsafe { verify_signature(ctx, msg, cert) } == 0 {
        // SAFETY: `ctx` is live.
        unsafe {
            ossl_cmp_log0(
                OSSL_CMP_LOG_WARNING,
                ctx,
                c"cert_acceptable",
                295,
                c"msg signature verification failed",
            )
        };
        return 0;
    }
    // SAFETY: `ctx` is live.
    unsafe {
        ossl_cmp_log0(
            OSSL_CMP_LOG_INFO,
            ctx,
            c"cert_acceptable",
            299,
            c" cert seems acceptable",
        )
    };
    1
}

/// `static int check_cert_path(const OSSL_CMP_CTX *ctx, X509_STORE *store, X509 *scrt)` —
/// `cmp_vfy.c:303-312`.
///
/// # Safety
/// `ctx`/`scrt` are live; `store` is NULL or live.
unsafe fn check_cert_path(ctx: *const OsslCmpCtx, store: *mut X509Store, scrt: *mut X509) -> c_int {
    // SAFETY: `ctx`/`store`/`scrt` are live or NULL as required.
    if unsafe { OSSL_CMP_validate_cert_path(ctx, store, scrt) } != 0 {
        return 1;
    }
    // SAFETY: `ctx` is live.
    unsafe {
        ossl_cmp_log0(
            OSSL_CMP_LOG_WARNING,
            ctx,
            c"check_cert_path",
            309,
            c"msg signature validates but cert path validation failed",
        )
    };
    0
}

/// `static int check_cert_path_3gpp(const OSSL_CMP_CTX *ctx, const OSSL_CMP_MSG *msg, X509`
/// `*scrt)` — `cmp_vfy.c:321-358`.
///
/// # Safety
/// `ctx`/`msg`/`scrt` are live.
unsafe fn check_cert_path_3gpp(
    ctx: *const OsslCmpCtx,
    msg: *const CmpMsg,
    scrt: *mut X509,
) -> c_int {
    // SAFETY: `ctx` is live.
    if unsafe { (*ctx).permit_ta_in_extra_certs_for_ir } == 0 {
        return 0;
    }
    // SAFETY: `X509_STORE_new` returns a fresh store or NULL.
    let store = unsafe { X509_STORE_new() };
    // SAFETY: `store` is NULL or live; `msg`'s extra certs are NULL or live.
    if store.is_null()
        // SAFETY: the enclosing function's `# Safety` section is the contract for these raw pointers.
        || unsafe { ossl_cmp_X509_STORE_add1_certs(store, (*msg).extra_certs, 1) } == 0
    {
        // SAFETY: `store` is NULL or this call's own.
        unsafe { X509_STORE_free(store) };
        return 0;
    }
    // SAFETY: `ctx`/`store`/`scrt` are live.
    let mut valid = unsafe { OSSL_CMP_validate_cert_path(ctx, store, scrt) };
    if valid == 0 {
        // SAFETY: `ctx` is live.
        unsafe {
            ossl_cmp_log0(
                OSSL_CMP_LOG_WARNING,
                ctx,
                c"check_cert_path_3gpp",
                339,
                c"also exceptional 3GPP mode cert path validation failed",
            )
        };
    // SAFETY: the enclosing function's `# Safety` section is the contract for these raw pointers.
    } else if unsafe { OSSL_CMP_MSG_get_bodytype(msg) } == OSSL_CMP_PKIBODY_IP {
        // SAFETY: `msg` is live.
        let crep = unsafe {
            ossl_cmp_certrepmessage_get0_certresponse((*(*msg).body).value.ip, OSSL_CMP_CERTREQID)
        };
        let mut newcrt: *mut X509 = ptr::null_mut();
        let newcrt_ok = if crep.is_null() {
            false
        } else {
            // SAFETY: `ctx`/`crep` are live.
            newcrt = unsafe { ossl_cmp_certresponse_get1_cert(ctx, crep) };
            // SAFETY: the enclosing function's `# Safety` section is the contract for these raw pointers.
            !newcrt.is_null() && unsafe { OSSL_CMP_validate_cert_path(ctx, store, newcrt) } != 0
        };
        valid = c_int::from(newcrt_ok);
        // SAFETY: `newcrt` is NULL or this call's own.
        unsafe { crate::x509::x_x509::X509_free(newcrt) };
    }
    // SAFETY: `store` is this call's own.
    unsafe { X509_STORE_free(store) };
    valid
}

/// `static int check_msg_given_cert(const OSSL_CMP_CTX *ctx, X509 *cert, const OSSL_CMP_MSG`
/// `*msg)` — `cmp_vfy.c:361-366`.
///
/// # Safety
/// `ctx`/`cert`/`msg` are live.
unsafe fn check_msg_given_cert(
    ctx: *const OsslCmpCtx,
    cert: *mut X509,
    msg: *const CmpMsg,
) -> c_int {
    // SAFETY: `ctx`/`cert`/`msg` are live.
    unsafe {
        cert_acceptable(
            ctx,
            c"previously validated",
            c"sender cert",
            cert,
            ptr::null(),
            ptr::null(),
            msg,
        )
    }
}

/// `static int check_msg_with_certs(OSSL_CMP_CTX *ctx, const STACK_OF(X509) *certs, const char`
/// `*desc, ...)` — `cmp_vfy.c:373-406`.
///
/// # Safety
/// `ctx`/`msg` are live; `certs` is NULL or live; the two checked stacks are NULL or live.
#[allow(clippy::too_many_arguments)]
unsafe fn check_msg_with_certs(
    ctx: *mut OsslCmpCtx,
    certs: *const OpenSslStack,
    desc: &'static core::ffi::CStr,
    already1: *const OpenSslStack,
    already2: *const OpenSslStack,
    msg: *const CmpMsg,
    mode_3gpp: c_int,
) -> c_int {
    let in_extra_certs = already1.is_null();
    let mut n_acceptable = 0;
    // SAFETY: `certs` is NULL or a live stack.
    let num = unsafe { OPENSSL_sk_num(certs as *mut OpenSslStack) };
    if num <= 0 {
        // SAFETY: `ctx` is live.
        unsafe {
            ossl_cmp_log_str(
                OSSL_CMP_LOG_INFO,
                ctx,
                c"check_msg_with_certs",
                FILE,
                384,
                format_args!("no {}", desc.to_string_lossy()),
            )
        };
        return 0;
    }
    let mut i = 0;
    while i < num {
        // SAFETY: `i` is in range.
        let cert = unsafe { OPENSSL_sk_value(certs as *mut OpenSslStack, i) }.cast::<X509>();
        if cert.is_null() {
            return 0;
        }
        // SAFETY: `ctx`/`cert`/`msg` are live.
        if unsafe { cert_acceptable(ctx, c"cert from", desc, cert, already1, already2, msg) } == 0 {
            i += 1;
            continue;
        }
        n_acceptable += 1;
        // SAFETY: `ctx`/`msg`/`cert` are live.
        let ok = if mode_3gpp != 0 {
            // SAFETY: the enclosing function's `# Safety` section is the contract for these raw pointers.
            unsafe { check_cert_path_3gpp(ctx, msg, cert) }
        } else {
            // SAFETY: `ctx` is live.
            unsafe { check_cert_path(ctx, (*ctx).trusted, cert) }
        };
        if ok != 0 {
            /* store successful sender cert for further msgs in transaction */
            // SAFETY: `ctx`/`cert` are live.
            return unsafe { ossl_cmp_ctx_set1_validatedSrvCert(ctx, cert) };
        }
        i += 1;
    }
    if in_extra_certs && n_acceptable == 0 {
        // SAFETY: `ctx` is live.
        unsafe {
            ossl_cmp_log_str(
                OSSL_CMP_LOG_WARNING,
                ctx,
                c"check_msg_with_certs",
                FILE,
                404,
                format_args!("no acceptable {}", desc.to_string_lossy()),
            )
        };
    }
    0
}

/// `static int check_msg_all_certs(OSSL_CMP_CTX *ctx, const OSSL_CMP_MSG *msg, int mode_3gpp)`
/// — `cmp_vfy.c:413-444`.
///
/// # Safety
/// `ctx`/`msg` are live.
unsafe fn check_msg_all_certs(ctx: *mut OsslCmpCtx, msg: *const CmpMsg, mode_3gpp: c_int) -> c_int {
    // SAFETY: `ctx`/`msg` are live.
    if unsafe { (*ctx).permit_ta_in_extra_certs_for_ir } != 0
        // SAFETY: the enclosing function's `# Safety` section is the contract for these raw pointers.
        && unsafe { OSSL_CMP_MSG_get_bodytype(msg) } == OSSL_CMP_PKIBODY_IP
    {
        // SAFETY: `ctx` is live.
        unsafe {
            ossl_cmp_log0(
                OSSL_CMP_LOG_INFO,
                ctx,
                c"check_msg_all_certs",
                420,
                if mode_3gpp != 0 {
                    c"normal mode failed; trying now 3GPP mode trusting extraCerts"
                } else {
                    c"trying first normal mode using trust store"
                },
            )
        };
    } else if mode_3gpp != 0 {
        return 0;
    }

    // SAFETY: `ctx`/`msg` are live.
    if unsafe {
        check_msg_with_certs(
            ctx,
            (*msg).extra_certs,
            c"extraCerts",
            ptr::null(),
            ptr::null(),
            msg,
            mode_3gpp,
        )
    } != 0
    {
        return 1;
    }
    // SAFETY: `ctx`/`msg` are live.
    if unsafe {
        check_msg_with_certs(
            ctx,
            (*ctx).untrusted,
            c"untrusted certs",
            (*msg).extra_certs,
            ptr::null(),
            msg,
            mode_3gpp,
        )
    } != 0
    {
        return 1;
    }

    // SAFETY: `ctx` is live.
    if unsafe { (*ctx).trusted }.is_null() {
        // SAFETY: `ctx` is live.
        unsafe {
            ossl_cmp_log0(
                OSSL_CMP_LOG_WARNING,
                ctx,
                c"check_msg_all_certs",
                432,
                if mode_3gpp != 0 {
                    c"no self-issued extraCerts"
                } else {
                    c"no trusted store"
                },
            )
        };
        return 0;
    }
    // SAFETY: `ctx`'s store is live.
    let trusted = unsafe { X509_STORE_get1_all_certs((*ctx).trusted) };
    // SAFETY: `ctx`/`msg` are live; the stacks are NULL or live.
    let ret = unsafe {
        check_msg_with_certs(
            ctx,
            trusted,
            if mode_3gpp != 0 {
                c"self-issued extraCerts"
            } else {
                c"certs in trusted store"
            },
            (*msg).extra_certs,
            (*ctx).untrusted,
            msg,
            mode_3gpp,
        )
    };
    // SAFETY: `trusted` is NULL or this call's own.
    unsafe { OSSL_STACK_OF_X509_free(trusted) };
    ret
}

/// `static int check_msg_find_cert(OSSL_CMP_CTX *ctx, const OSSL_CMP_MSG *msg)` —
/// `cmp_vfy.c:450-537`.
///
/// # Safety
/// `ctx`/`msg` are live.
unsafe fn check_msg_find_cert(ctx: *mut OsslCmpCtx, msg: *const CmpMsg) -> c_int {
    // SAFETY: `ctx` is live.
    let mut scrt = unsafe { (*ctx).validated_srv_cert };
    // SAFETY: `msg` is live.
    let sender = unsafe { (*(*msg).header).sender }.cast::<GeneralName>();
    // SAFETY: `msg` is live.
    let skid = unsafe { (*(*msg).header).sender_kid };
    // SAFETY: `ctx` is live.
    let backup_log_cb = unsafe { (*ctx).log_cb };

    // SAFETY: the enclosing function's `# Safety` section is the contract for these raw pointers.
    if sender.is_null() || unsafe { (*msg).body }.is_null() {
        return 0;
    }
    // SAFETY: `sender` is live.
    if unsafe { (*sender).type_ } != GEN_DIRNAME {
        // SAFETY: the site is a compile-time constant.
        unsafe { raise_cmp(464, c"check_msg_find_cert", 150) };
        return 0;
    }

    /* dump any hitherto errors to avoid confusion when printing further ones */
    // SAFETY: `ctx` is live.
    unsafe { OSSL_CMP_CTX_print_errors(ctx) };
    /* enable clearing irrelevant errors in attempts to validate sender certs */
    // SAFETY: no preconditions.
    unsafe {
        ERR_set_mark();
        (*ctx).log_cb = None; /* temporarily disable logging */
    }

    if !scrt.is_null() {
        // SAFETY: `ctx`/`scrt`/`msg` are live.
        if unsafe { check_msg_given_cert(ctx, scrt, msg) } != 0 {
            // SAFETY: `ctx` is live.
            unsafe {
                (*ctx).log_cb = backup_log_cb;
                ERR_pop_to_mark();
            }
            return 1;
        }
        /* cached sender cert has shown to be no more successfully usable */
        /* re-do the above check (just) for adding diagnostic information */
        // SAFETY: `ctx` is live.
        unsafe {
            ossl_cmp_log0(
                OSSL_CMP_LOG_INFO,
                ctx,
                c"check_msg_find_cert",
                490,
                c"trying to verify msg signature with previously validated cert",
            );
            (*ctx).log_cb = backup_log_cb;
            check_msg_given_cert(ctx, scrt, msg);
            (*ctx).log_cb = None;
            ossl_cmp_ctx_set1_validatedSrvCert(ctx, ptr::null_mut());
        }
        scrt = ptr::null_mut();
    }

    // SAFETY: `ctx`/`msg` are live.
    let res = unsafe { check_msg_all_certs(ctx, msg, 0) } != 0
        || unsafe { check_msg_all_certs(ctx, msg, 1) } != 0;

    // SAFETY: `ctx` is live.
    unsafe {
        (*ctx).log_cb = backup_log_cb;
        ERR_pop_to_mark();
    }

    if res {
        return 1;
    }
    /* failed finding a sender cert that verifies the message signature */
    let _ = scrt;
    // SAFETY: the enclosing function's `# Safety` section is the contract for these raw pointers.
    let sname = unsafe { X509_NAME_oneline((*sender).d.directoryName, ptr::null_mut(), 0) };
    let skid_str = if skid.is_null() {
        ptr::null_mut()
    } else {
        // SAFETY: `skid` is live.
        unsafe { i2s_ASN1_OCTET_STRING(ptr::null_mut(), skid) }
    };
    // SAFETY: `ctx` is live.
    if unsafe { (*ctx).log_cb }.is_some() {
        // SAFETY: `ctx` is live.
        unsafe {
            ossl_cmp_log0(
                OSSL_CMP_LOG_INFO,
                ctx,
                c"check_msg_find_cert",
                511,
                c"trying to verify msg signature with a valid cert that..",
            );
        }
        if !sname.is_null() {
            // SAFETY: `ctx`/`sname` are live.
            unsafe {
                ossl_cmp_log_str(
                    OSSL_CMP_LOG_INFO,
                    ctx,
                    c"check_msg_find_cert",
                    FILE,
                    513,
                    format_args!(
                        "matches msg sender    = {}",
                        std::ffi::CStr::from_ptr(sname).to_string_lossy()
                    ),
                )
            };
        }
        if !skid_str.is_null() {
            // SAFETY: `ctx`/`skid_str` are live.
            unsafe {
                ossl_cmp_log_str(
                    OSSL_CMP_LOG_INFO,
                    ctx,
                    c"check_msg_find_cert",
                    FILE,
                    515,
                    format_args!(
                        "matches msg senderKID = {}",
                        std::ffi::CStr::from_ptr(skid_str).to_string_lossy()
                    ),
                )
            };
        } else {
            // SAFETY: `ctx` is live.
            unsafe {
                ossl_cmp_log0(
                    OSSL_CMP_LOG_INFO,
                    ctx,
                    c"check_msg_find_cert",
                    517,
                    c"while msg header does not contain senderKID",
                )
            };
        }
        /* re-do the above checks (just) for adding diagnostic information */
        // SAFETY: `ctx`/`msg` are live.
        unsafe {
            check_msg_all_certs(ctx, msg, 0);
            check_msg_all_certs(ctx, msg, 1);
        }
    }

    // SAFETY: the site is a compile-time constant.
    unsafe { raise_cmp(523, c"check_msg_find_cert", 145) };
    if !sname.is_null() {
        // SAFETY: `sname` is NUL-terminated.
        unsafe {
            ERR_add_error_txt(ptr::null(), c"for msg sender name = ".as_ptr());
            ERR_add_error_txt(ptr::null(), sname);
        }
    }
    if !skid_str.is_null() {
        // SAFETY: `skid_str` is NUL-terminated.
        unsafe {
            ERR_add_error_txt(c" and ".as_ptr(), c"for msg senderKID = ".as_ptr());
            ERR_add_error_txt(ptr::null(), skid_str);
        }
    }
    // SAFETY: both are NULL or this call's own.
    unsafe {
        CRYPTO_free(sname.cast(), FILE.as_ptr(), 534);
        CRYPTO_free(skid_str.cast(), FILE.as_ptr(), 535);
    }
    0
}

/// `int OSSL_CMP_validate_msg(OSSL_CMP_CTX *ctx, const OSSL_CMP_MSG *msg)` — `cmp_vfy.c:555-651`.
///
/// # Safety
/// `ctx`/`msg` are NULL or live.
#[no_mangle]
pub unsafe extern "C" fn OSSL_CMP_validate_msg(ctx: *mut OsslCmpCtx, msg: *const CmpMsg) -> c_int {
    // SAFETY: `ctx` is NULL or live.
    unsafe {
        ossl_cmp_log0(
            OSSL_CMP_LOG_DEBUG,
            ctx,
            c"OSSL_CMP_validate_msg",
            559,
            c"validating CMP message",
        )
    };
    if ctx.is_null()
        || msg.is_null()
        // SAFETY: the enclosing function's `# Safety` section is the contract for these raw pointers.
        || unsafe { (*msg).header }.is_null()
        // SAFETY: the enclosing function's `# Safety` section is the contract for these raw pointers.
        || unsafe { (*msg).body }.is_null()
    {
        // SAFETY: the site is a compile-time constant.
        unsafe { raise_cmp(562, c"OSSL_CMP_validate_msg", CMP_R_NULL_ARGUMENT) };
        return 0;
    }
    // SAFETY: `msg` is live.
    if unsafe { (*(*msg).header).protection_alg }.is_null()
        // SAFETY: the enclosing function's `# Safety` section is the contract for these raw pointers.
        || unsafe { (*msg).protection }.is_null()
        // SAFETY: the enclosing function's `# Safety` section is the contract for these raw pointers.
        || unsafe { (*(*msg).protection).data }.is_null()
    {
        // SAFETY: the site is a compile-time constant.
        unsafe { raise_cmp(568, c"OSSL_CMP_validate_msg", 143) };
        return 0;
    }

    // SAFETY: `msg`'s header is live.
    match unsafe { ossl_cmp_hdr_get_protection_nid((*msg).header) } {
        NID_id_PASSWORD_BASED_MAC => {
            // SAFETY: `ctx` is live.
            if unsafe { (*ctx).secret_value }.is_null() {
                // SAFETY: `ctx` is live.
                unsafe {
                    ossl_cmp_log0(
                        OSSL_CMP_LOG_INFO,
                        ctx,
                        c"OSSL_CMP_validate_msg",
                        576,
                        c"no secret available for verifying PBM-based CMP message protection",
                    )
                };
                // SAFETY: the site is a compile-time constant.
                unsafe { raise_cmp(577, c"OSSL_CMP_validate_msg", 178) };
                return 0;
            }
            // SAFETY: `ctx`/`msg` are live.
            if unsafe { verify_PBMAC(ctx, msg) } != 0 {
                // SAFETY: `ctx` is live.
                let trusted = unsafe { (*ctx).trusted };
                // SAFETY: `msg` is live.
                match unsafe { OSSL_CMP_MSG_get_bodytype(msg) } {
                    -1 => return 0,
                    OSSL_CMP_PKIBODY_IP | OSSL_CMP_PKIBODY_CP | OSSL_CMP_PKIBODY_KUP
                    | OSSL_CMP_PKIBODY_CCP
                        if !trusted.is_null() =>
                    {
                        // SAFETY: `msg` is live.
                        let certs = unsafe { (*(*msg).body).value.ip };
                        // SAFETY: `certs` is live; `ctx`'s store is live.
                        if unsafe { ossl_cmp_X509_STORE_add1_certs(trusted, (*certs).ca_pubs, 0) }
                            == 0
                        {
                            return 0;
                        }
                    }
                    _ => {}
                }
                // SAFETY: `ctx` is live.
                unsafe {
                    ossl_cmp_log0(
                        OSSL_CMP_LOG_DEBUG,
                        ctx,
                        c"OSSL_CMP_validate_msg",
                        607,
                        c"successfully validated PBM-based CMP message protection",
                    )
                };
                return 1;
            }
            // SAFETY: `ctx` is live.
            unsafe {
                ossl_cmp_log0(
                    OSSL_CMP_LOG_WARNING,
                    ctx,
                    c"OSSL_CMP_validate_msg",
                    610,
                    c"verifying PBM-based CMP message protection failed",
                )
            };
        }
        NID_id_DH_BASED_MAC => {
            // SAFETY: the site is a compile-time constant.
            unsafe { raise_cmp(618, c"OSSL_CMP_validate_msg", 154) };
        }
        _ => {
            // SAFETY: `ctx` is live.
            let mut scrt = unsafe { (*ctx).srv_cert };
            if scrt.is_null() {
                // SAFETY: `ctx` is live.
                if unsafe { (*ctx).trusted }.is_null() && !unsafe { (*ctx).secret_value }.is_null()
                {
                    // SAFETY: `ctx` is live.
                    unsafe {
                        ossl_cmp_log0(
                            OSSL_CMP_LOG_INFO,
                            ctx,
                            c"OSSL_CMP_validate_msg",
                            628,
                            c"no trust store nor pinned sender cert available for verifying signature-based CMP message protection",
                        )
                    };
                    // SAFETY: the site is a compile-time constant.
                    unsafe { raise_cmp(629, c"OSSL_CMP_validate_msg", 179) };
                    return 0;
                }
                // SAFETY: `ctx`/`msg` are live.
                if unsafe { check_msg_find_cert(ctx, msg) } != 0 {
                    // SAFETY: `ctx` is live.
                    unsafe {
                        ossl_cmp_log_str(
                            OSSL_CMP_LOG_DEBUG,
                            ctx,
                            c"OSSL_CMP_validate_msg",
                            FILE,
                            634,
                            format_args!(
                                "successfully validated signature-based CMP message protection using trust store{}",
                                if (*ctx).permit_ta_in_extra_certs_for_ir != 0 {
                                    " or 3GPP mode"
                                } else {
                                    ""
                                },
                            ),
                        )
                    };
                    return 1;
                }
            } else {
                /* use ctx->srvCert for signature check even if not acceptable */
                // SAFETY: `ctx`/`msg`/`scrt` are live.
                if unsafe { verify_signature(ctx, msg, scrt) } != 0 {
                    // SAFETY: `ctx` is live.
                    unsafe {
                        ossl_cmp_log0(
                            OSSL_CMP_LOG_DEBUG,
                            ctx,
                            c"OSSL_CMP_validate_msg",
                            642,
                            c"successfully validated signature-based CMP message protection using pinned sender cert",
                        )
                    };
                    // SAFETY: `ctx`/`scrt` are live.
                    return unsafe { ossl_cmp_ctx_set1_validatedSrvCert(ctx, scrt) };
                }
                // SAFETY: `ctx` is live.
                unsafe {
                    ossl_cmp_log0(
                        OSSL_CMP_LOG_WARNING,
                        ctx,
                        c"OSSL_CMP_validate_msg",
                        645,
                        c"CMP message signature verification failed",
                    )
                };
                // SAFETY: the site is a compile-time constant.
                unsafe { raise_cmp(646, c"OSSL_CMP_validate_msg", 151) };
            }
            let _ = scrt;
            scrt = ptr::null_mut();
            let _ = scrt;
        }
    }
    0
}

/// `static int check_transactionID_or_nonce(ASN1_OCTET_STRING *expected, ASN1_OCTET_STRING`
/// `*actual, int reason)` — `cmp_vfy.c:653-674`.
///
/// # Safety
/// `expected`/`actual` are NULL or live.
unsafe fn check_transactionID_or_nonce(
    expected: *const Asn1String,
    actual: *const Asn1String,
    _reason: c_int,
) -> c_int {
    if !expected.is_null()
        // SAFETY: the enclosing function's `# Safety` section is the contract for these raw pointers.
        && (actual.is_null() || unsafe { ASN1_OCTET_STRING_cmp(expected, actual) } != 0)
    {
        /* the authority raises with the two hex strings as error data */
        // SAFETY: `expected` is live.
        let expected_str = unsafe { i2s_ASN1_OCTET_STRING(ptr::null_mut(), expected) };
        let actual_str = if actual.is_null() {
            ptr::null_mut()
        } else {
            // SAFETY: `actual` is live.
            unsafe { i2s_ASN1_OCTET_STRING(ptr::null_mut(), actual) }
        };
        // SAFETY: the strings are NULL or this call's own.
        unsafe {
            CRYPTO_free(expected_str.cast(), FILE.as_ptr(), 668);
            CRYPTO_free(actual_str.cast(), FILE.as_ptr(), 669);
        }
        return 0;
    }
    1
}

/// `int ossl_cmp_msg_check_update(OSSL_CMP_CTX *ctx, const OSSL_CMP_MSG *msg,`
/// `ossl_cmp_allow_unprotected_cb_t cb, int cb_arg)` — `cmp_vfy.c:696-872`. Internal.
///
/// # Safety
/// `ctx`/`msg` are live; `cb` is NULL or a valid callback.
pub(crate) unsafe fn ossl_cmp_msg_check_update(
    ctx: *mut OsslCmpCtx,
    msg: *const CmpMsg,
    cb: OsslCmpAllowUnprotectedCb,
    cb_arg: c_int,
) -> c_int {
    // SAFETY: the enclosing function's `# Safety` section is the contract for these raw pointers.
    if ctx.is_null() || msg.is_null() || unsafe { (*msg).header }.is_null() {
        return 0;
    }
    // SAFETY: `msg` is live.
    let hdr = unsafe { (*msg).header };

    /* If expected_sender is given, validate sender name of received msg */
    // SAFETY: `ctx` is live.
    let mut expected_sender = unsafe { (*ctx).expected_sender };
    // SAFETY: `ctx` is live.
    if expected_sender.is_null() && !unsafe { (*ctx).srv_cert }.is_null() {
        // SAFETY: `ctx`'s srv cert is live.
        expected_sender = unsafe { X509_get_subject_name((*ctx).srv_cert) };
    }
    if !expected_sender.is_null() {
        // SAFETY: `hdr` is live.
        let actual_sender = unsafe { (*hdr).sender }.cast::<GeneralName>();
        // SAFETY: `actual_sender` is live.
        if unsafe { (*actual_sender).type_ } != GEN_DIRNAME {
            // SAFETY: the site is a compile-time constant.
            unsafe { raise_cmp(716, c"ossl_cmp_msg_check_update", 150) };
            return 0;
        }
        // SAFETY: `actual_sender` is live.
        let dname = unsafe { (*actual_sender).d.directoryName };
        // SAFETY: `ctx`/`dname` are live.
        if unsafe {
            check_name(
                ctx,
                0,
                c"sender DN field",
                dname,
                c"expected sender",
                expected_sender,
            )
        } == 0
        {
            // SAFETY: `dname` is live.
            let str_ = unsafe { X509_NAME_oneline(dname, ptr::null_mut(), 0) };
            // SAFETY: `str_` is NULL or this call's own.
            unsafe { CRYPTO_free(str_.cast(), FILE.as_ptr(), 730) };
            // SAFETY: the site is a compile-time constant.
            unsafe { raise_cmp(728, c"ossl_cmp_msg_check_update", 106) };
            return 0;
        }
    }

    // SAFETY: `msg` is live.
    let num_added = unsafe { OPENSSL_sk_num((*msg).extra_certs) };
    if num_added > 10 {
        // SAFETY: `ctx` is live.
        unsafe {
            ossl_cmp_log_str(
                OSSL_CMP_LOG_WARNING,
                ctx,
                c"ossl_cmp_msg_check_update",
                FILE,
                738,
                format_args!("received CMP message contains {} extraCerts", num_added),
            )
        };
    }
    // SAFETY: `ctx` is live.
    let num_untrusted = unsafe {
        if (*ctx).untrusted.is_null() {
            0
        } else {
            OPENSSL_sk_num((*ctx).untrusted)
        }
    };
    // SAFETY: `ctx`/`msg` are live.
    let res = unsafe {
        ossl_x509_add_certs_new(
            ptr::addr_of_mut!((*ctx).untrusted),
            (*msg).extra_certs,
            X509_ADD_FLAG_UP_REF | X509_ADD_FLAG_NO_DUP | X509_ADD_FLAG_PREPEND,
        )
    };
    // SAFETY: `ctx` is live.
    let num_added = unsafe {
        (if (*ctx).untrusted.is_null() {
            0
        } else {
            OPENSSL_sk_num((*ctx).untrusted)
        }) - num_untrusted
    };
    if res == 0 {
        let mut left = num_added;
        while left > 0 {
            // SAFETY: `ctx`'s stack is live.
            let x = unsafe { crate::runtime::stack::OPENSSL_sk_shift((*ctx).untrusted) };
            // SAFETY: `x` is a live X509.
            unsafe { crate::x509::x_x509::X509_free(x.cast()) };
            left -= 1;
        }
        return 0;
    }

    // SAFETY: `hdr` is live.
    let protection_alg = unsafe { (*hdr).protection_alg };
    let res = if !protection_alg.is_null() {
        // SAFETY: `ctx`/`msg` are live.
        let validated = unsafe { OSSL_CMP_validate_msg(ctx, msg) } != 0;
        let excepted = match cb {
            // SAFETY: `ctx`/`msg`/`cb_arg` are live per the callback's contract.
            Some(cb) => (unsafe { cb(ctx, msg, 1, cb_arg) }) > 0,
            None => false,
        };
        validated || excepted
    } else {
        match cb {
            // SAFETY: `ctx`/`msg`/`cb_arg` are live per the callback's contract.
            Some(cb) => (unsafe { cb(ctx, msg, 0, cb_arg) }) > 0,
            None => false,
        }
    };

    // SAFETY: `ctx` is live.
    if unsafe { (*ctx).no_cache_extra_certs } != 0 || !res {
        let mut left = num_added;
        while left > 0 {
            // SAFETY: `ctx`'s stack is live.
            let x = unsafe { crate::runtime::stack::OPENSSL_sk_shift((*ctx).untrusted) };
            // SAFETY: `x` is a live X509.
            unsafe { crate::x509::x_x509::X509_free(x.cast()) };
            left -= 1;
        }
    }

    if !res {
        // SAFETY: `hdr` is live.
        if !unsafe { (*hdr).protection_alg }.is_null() {
            // SAFETY: the site is a compile-time constant.
            unsafe { raise_cmp(785, c"ossl_cmp_msg_check_update", 140) };
        } else {
            // SAFETY: the site is a compile-time constant.
            unsafe { raise_cmp(787, c"ossl_cmp_msg_check_update", 143) };
        }
        return 0;
    }

    /* check CMP version number in header */
    // SAFETY: `hdr` is live.
    let pvno = unsafe { ossl_cmp_hdr_get_pvno(hdr) };
    if pvno != OSSL_CMP_PVNO_2 && pvno != OSSL_CMP_PVNO_3 {
        // SAFETY: the site is a compile-time constant.
        unsafe { raise_cmp(795, c"ossl_cmp_msg_check_update", 153) };
        return 0;
    }

    // SAFETY: `msg` is live.
    if unsafe { OSSL_CMP_MSG_get_bodytype(msg) } < 0 {
        // SAFETY: the site is a compile-time constant.
        unsafe { raise_cmp(802, c"ossl_cmp_msg_check_update", 146) };
        return 0;
    }

    /* compare received transactionID with the expected one in previous msg */
    // SAFETY: `ctx`/`hdr` are live.
    if unsafe { check_transactionID_or_nonce((*ctx).transaction_id, (*hdr).transaction_id, 152) }
        == 0
    {
        return 0;
    }

    /* enable clearing irrelevant errors in attempts to validate recipient nonce */
    ERR_set_mark();
    /* compare received nonce with the one we sent */
    // SAFETY: `ctx`/`hdr` are live.
    if unsafe { check_transactionID_or_nonce((*ctx).sender_nonce, (*hdr).recip_nonce, 148) } == 0 {
        /* check if we are polling and received final response */
        // SAFETY: `ctx`/`hdr`/`msg` are live.
        let first_null = unsafe { (*ctx).first_sender_nonce }.is_null();
        // SAFETY: `msg` is live.
        let is_pollrep = unsafe { OSSL_CMP_MSG_get_bodytype(msg) } == OSSL_CMP_PKIBODY_POLLREP;
        let matched = !first_null
            && !is_pollrep
            // SAFETY: the enclosing function's `# Safety` section is the contract for these raw pointers.
            && unsafe {
                check_transactionID_or_nonce((*ctx).first_sender_nonce, (*hdr).recip_nonce, 148)
            } != 0;
        if !matched {
            ERR_clear_last_mark();
            return 0;
        }
    }
    ERR_pop_to_mark();

    /* if not yet present, learn transactionID */
    // SAFETY: `ctx`/`hdr` are live.
    if unsafe { (*ctx).transaction_id }.is_null()
        // SAFETY: the enclosing function's `# Safety` section is the contract for these raw pointers.
        && unsafe { OSSL_CMP_CTX_set1_transactionID(ctx, (*hdr).transaction_id) } == 0
    {
        return 0;
    }

    /* the recipNonce is copied from the senderNonce of the previous message */
    // SAFETY: `ctx`/`hdr` are live.
    if unsafe { ossl_cmp_ctx_set1_recipNonce(ctx, (*hdr).sender_nonce) } == 0 {
        return 0;
    }

    // SAFETY: `hdr` is live.
    if unsafe { ossl_cmp_hdr_get_protection_nid(hdr) } == NID_id_PASSWORD_BASED_MAC {
        // SAFETY: `ctx` is live.
        let trusted = unsafe { (*ctx).trusted };
        // SAFETY: `msg` is live.
        match unsafe { OSSL_CMP_MSG_get_bodytype(msg) } {
            OSSL_CMP_PKIBODY_IP | OSSL_CMP_PKIBODY_CP | OSSL_CMP_PKIBODY_KUP
            | OSSL_CMP_PKIBODY_CCP
                if !trusted.is_null() =>
            {
                // SAFETY: `msg` is live.
                let certs = unsafe { (*(*msg).body).value.ip };
                // SAFETY: `ctx`'s store and `certs` are live.
                if unsafe { ossl_cmp_X509_STORE_add1_certs(trusted, (*certs).ca_pubs, 0) } == 0 {
                    return 0;
                }
            }
            _ => {}
        }
    }
    1
}

/// `int ossl_cmp_verify_popo(const OSSL_CMP_CTX *ctx, const OSSL_CMP_MSG *msg, int`
/// `acceptRAVerified)` — `cmp_vfy.c:874-908`. Internal.
///
/// # Safety
/// `msg` is live; `ctx` is live when the CRMF arm is reached.
pub(crate) unsafe fn ossl_cmp_verify_popo(
    ctx: *const OsslCmpCtx,
    msg: *const CmpMsg,
    accept_raverified: c_int,
) -> c_int {
    // SAFETY: the enclosing function's `# Safety` section is the contract for these raw pointers.
    if msg.is_null() || unsafe { (*msg).body }.is_null() {
        return 0;
    }
    // SAFETY: `msg` is live.
    match unsafe { (*(*msg).body).type_ } {
        OSSL_CMP_PKIBODY_P10CR => {
            // SAFETY: `msg` is live.
            let req =
                unsafe { (*(*msg).body).value.p10cr }.cast::<crate::x509::x509_req::X509Req>();
            // SAFETY: `ctx`/`req` are live.
            if unsafe {
                X509_REQ_verify_ex(req, X509_REQ_get0_pubkey(req), (*ctx).libctx, (*ctx).propq)
            } <= 0
            {
                // SAFETY: the site is a compile-time constant.
                unsafe { raise_cmp(887, c"ossl_cmp_verify_popo", 149) };
                return 0;
            }
        }
        OSSL_CMP_PKIBODY_IR | OSSL_CMP_PKIBODY_CR | OSSL_CMP_PKIBODY_KUR => {
            // SAFETY: `msg` is live.
            let msgs = unsafe { (*(*msg).body).value.ir };
            // SAFETY: `ctx` is live; `msgs` is live.
            if unsafe {
                OSSL_CRMF_MSGS_verify_popo(
                    msgs,
                    OSSL_CMP_CERTREQID,
                    accept_raverified,
                    (*ctx).libctx,
                    (*ctx).propq,
                )
            } == 0
            {
                return 0;
            }
        }
        _ => {
            // SAFETY: the site is a compile-time constant.
            unsafe { raise_cmp(904, c"ossl_cmp_verify_popo", 146) };
            return 0;
        }
    }
    1
}
