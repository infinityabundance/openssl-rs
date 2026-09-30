//! `crypto/ct/ct_vfy.c` — SCT signature verification. Phase 10.14.15's CT layer.
//!
//! `crypto/ct/ct_vfy.c` is 138 lines and transcribes whole: the `SCT_SIGNATURE_TYPE` enum, the
//! `static` `sct_ctx_update` that rebuilds the signed `DigitallySigned` input, and `SCT_CTX_verify`.
//! `SCT_CTX_verify` is declared in `crypto/ct/ct_local.h:178`, **not** in `include/openssl/ct.h`, so
//! it carries `pub(crate)` and **no** `#[no_mangle]`; `ct_sct.c`'s `SCT_validate` reaches it by Rust
//! path.
//!
//! The three network-order writes (`l2n8`, `s2n`, `l2n3`) come from `ct_oct.c`'s shared macros, not
//! a second copy.
//!
//! ## The raise sites
//!
//! `crypto/ct/ct_vfy.c` is not an entry in `gen_err_raise_sites.py`, so its five coordinates are
//! **declared locally**, their reason values read from `include/openssl/cterr.h`.
//!
//! SPDX-License-Identifier: Apache-2.0

#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]

use core::ffi::{c_int, c_uchar, c_void, CStr};
use core::ptr;

use crate::ct::ct_oct::{l2n3, l2n8, s2n};
use crate::ct::ct_sct::{
    SCT_is_complete, Sct, CT_LOG_ENTRY_TYPE_NOT_SET, CT_LOG_ENTRY_TYPE_PRECERT,
    CT_LOG_ENTRY_TYPE_X509, SCT_VERSION_V1,
};
use crate::ct::ct_sct_ctx::SctCtx;
use crate::evp::digest::{
    EVP_DigestUpdate, EVP_DigestVerifyFinal, EVP_DigestVerifyInit_ex, EVP_MD_CTX_free,
    EVP_MD_CTX_new, EvpMdCtx,
};
use crate::runtime::bio::sys;
use crate::runtime::err::err_reasons::{
    CT_R_SCT_FUTURE_TIMESTAMP, CT_R_SCT_INVALID_SIGNATURE, CT_R_SCT_LOG_ID_MISMATCH,
    CT_R_SCT_NOT_SET, CT_R_SCT_UNSUPPORTED_VERSION,
};
use crate::runtime::err::err_sites::ErrSite;
use crate::runtime::err::raise_site;

/// `ERR_LIB_CT` — `include/openssl/err.h.in:115`.
const ERR_LIB_CT: c_int = 50;

/// One `ct_vfy.c` raise coordinate, declared locally (see the module doc).
const fn ct_vfy_site(line: c_int, func: &'static CStr, reason: c_int) -> ErrSite {
    ErrSite {
        file: c"../../src/openssl-3.6.4/crypto/ct/ct_vfy.c",
        line,
        func,
        lib: ERR_LIB_CT,
        reason,
        dynamic_reason: false,
    }
}

/// `SCT_CTX_verify` at `crypto/ct/ct_vfy.c:102`.
const CT_VFY_102: ErrSite = ct_vfy_site(102, c"SCT_CTX_verify", CT_R_SCT_NOT_SET);
/// `SCT_CTX_verify` at `crypto/ct/ct_vfy.c:106`.
const CT_VFY_106: ErrSite = ct_vfy_site(106, c"SCT_CTX_verify", CT_R_SCT_UNSUPPORTED_VERSION);
/// `SCT_CTX_verify` at `crypto/ct/ct_vfy.c:110`.
const CT_VFY_110: ErrSite = ct_vfy_site(110, c"SCT_CTX_verify", CT_R_SCT_LOG_ID_MISMATCH);
/// `SCT_CTX_verify` at `crypto/ct/ct_vfy.c:114`.
const CT_VFY_114: ErrSite = ct_vfy_site(114, c"SCT_CTX_verify", CT_R_SCT_FUTURE_TIMESTAMP);
/// `SCT_CTX_verify` at `crypto/ct/ct_vfy.c:133`.
const CT_VFY_133: ErrSite = ct_vfy_site(133, c"SCT_CTX_verify", CT_R_SCT_INVALID_SIGNATURE);

/// `typedef enum sct_signature_type_t { ... } SCT_SIGNATURE_TYPE` — `crypto/ct/ct_vfy.c:19-23`.
///
/// Only `SIGNATURE_TYPE_CERT_TIMESTAMP` is written by `sct_ctx_update`; the other two are named for
/// the enum's completeness.
#[allow(dead_code)]
const SIGNATURE_TYPE_NOT_SET: c_int = -1;
/// `SIGNATURE_TYPE_CERT_TIMESTAMP` — `crypto/ct/ct_vfy.c:21`.
const SIGNATURE_TYPE_CERT_TIMESTAMP: c_int = 0;
/// `SIGNATURE_TYPE_TREE_HASH` — `crypto/ct/ct_vfy.c:22`.
#[allow(dead_code)]
const SIGNATURE_TYPE_TREE_HASH: c_int = 1;

/// `static int sct_ctx_update(EVP_MD_CTX *ctx, const SCT_CTX *sctx, const SCT *sct)` —
/// `crypto/ct/ct_vfy.c:29-94`.
///
/// # Safety
///
/// `ctx` is a live `EVP_MD_CTX`; `sctx` is a live `SCT_CTX`; `sct` is a live `SCT` whose DER
/// encoding (its own, or `sctx`'s) is present for the entry type selected.
unsafe fn sct_ctx_update(ctx: *mut EvpMdCtx, sctx: *const SctCtx, sct: *const Sct) -> c_int {
    let mut tmpbuf = [0 as c_uchar; 12];

    // SAFETY: `sct` is live per the contract.
    let entry_type = unsafe { (*sct).entry_type };
    if entry_type == CT_LOG_ENTRY_TYPE_NOT_SET {
        return 0;
    }
    // SAFETY: `sctx` and `sct` are live per the contract.
    if entry_type == CT_LOG_ENTRY_TYPE_PRECERT && unsafe { (*sctx).ihash.is_null() } {
        return 0;
    }

    let mut p: *mut c_uchar = tmpbuf.as_mut_ptr();
    // SAFETY: `tmpbuf` has twelve writable bytes; the writes below stay within it.
    unsafe {
        *p = (*sct).version as c_uchar;
        p = p.add(1);
        *p = SIGNATURE_TYPE_CERT_TIMESTAMP as c_uchar;
        p = p.add(1);
        l2n8((*sct).timestamp, &mut p);
        s2n(entry_type as u64, &mut p);
    }

    // SAFETY: `ctx` is live; `tmpbuf` is readable for the `p - tmpbuf` bytes written.
    if unsafe {
        EVP_DigestUpdate(
            ctx,
            tmpbuf.as_ptr().cast::<c_void>(),
            p.offset_from(tmpbuf.as_ptr()) as usize,
        )
    } == 0
    {
        return 0;
    }

    // SAFETY: `sctx` and `sct` are live per the contract.
    let (der, derlen) = unsafe {
        if entry_type == CT_LOG_ENTRY_TYPE_X509 {
            ((*sctx).certder, (*sctx).certderlen)
        } else {
            // The issuer hash precedes the pre-certificate encoding.
            if EVP_DigestUpdate(ctx, (*sctx).ihash.cast::<c_void>(), (*sctx).ihashlen) == 0 {
                return 0;
            }
            ((*sctx).preder, (*sctx).prederlen)
        }
    };

    // If no encoding available, fatal error.
    if der.is_null() {
        return 0;
    }

    // Include the length first.
    let mut p: *mut c_uchar = tmpbuf.as_mut_ptr();
    // SAFETY: `tmpbuf` has twelve writable bytes; `l2n3` writes three.
    unsafe { l2n3(derlen as u64, &mut p) };

    // SAFETY: `ctx` is live; `tmpbuf` is readable for three bytes.
    if unsafe { EVP_DigestUpdate(ctx, tmpbuf.as_ptr().cast::<c_void>(), 3) } == 0 {
        return 0;
    }
    // SAFETY: `ctx` is live; `der` is readable for `derlen` bytes.
    if unsafe { EVP_DigestUpdate(ctx, der.cast::<c_void>(), derlen) } == 0 {
        return 0;
    }

    // Add any extensions.
    let mut p: *mut c_uchar = tmpbuf.as_mut_ptr();
    // SAFETY: `tmpbuf` has twelve writable bytes; `s2n` writes two.
    unsafe { s2n((*sct).ext_len as u64, &mut p) };

    // SAFETY: `ctx` is live; `tmpbuf` is readable for two bytes.
    if unsafe { EVP_DigestUpdate(ctx, tmpbuf.as_ptr().cast::<c_void>(), 2) } == 0 {
        return 0;
    }

    // SAFETY: `sct` is live; when `ext_len` is non-zero `ext` is readable for that many bytes.
    unsafe {
        if (*sct).ext_len != 0
            && EVP_DigestUpdate(ctx, (*sct).ext.cast::<c_void>(), (*sct).ext_len) == 0
        {
            return 0;
        }
    }

    1
}

/// `int SCT_CTX_verify(const SCT_CTX *sctx, const SCT *sct)` — `crypto/ct/ct_vfy.c:96-137`.
///
/// Declared in `crypto/ct/ct_local.h:178`, so it is **not** an export.
///
/// # Safety
///
/// `sctx` and `sct` are live.
pub(crate) unsafe fn SCT_CTX_verify(sctx: *const SctCtx, sct: *const Sct) -> c_int {
    let mut ret: c_int = 0;

    // SAFETY: `sctx` and `sct` are live per the contract.
    let incomplete = unsafe {
        SCT_is_complete(sct) == 0
            || (*sctx).pkey.is_null()
            || (*sct).entry_type == CT_LOG_ENTRY_TYPE_NOT_SET
            || ((*sct).entry_type == CT_LOG_ENTRY_TYPE_PRECERT && (*sctx).ihash.is_null())
    };
    if incomplete {
        // SAFETY: the site is a compiled-in constant.
        unsafe { raise_site(&CT_VFY_102) };
        return 0;
    }
    // SAFETY: `sct` is live per the contract.
    if unsafe { (*sct).version } != SCT_VERSION_V1 {
        // SAFETY: the site is a compiled-in constant.
        unsafe { raise_site(&CT_VFY_106) };
        return 0;
    }
    // SAFETY: `sctx` and `sct` are live per the contract.
    if unsafe {
        (*sct).log_id_len != (*sctx).pkeyhashlen
            || sys::memcmp(
                (*sct).log_id.cast::<c_void>(),
                (*sctx).pkeyhash.cast::<c_void>(),
                (*sctx).pkeyhashlen,
            ) != 0
    } {
        // SAFETY: the site is a compiled-in constant.
        unsafe { raise_site(&CT_VFY_110) };
        return 0;
    }
    // SAFETY: `sctx` and `sct` are live per the contract.
    if unsafe { (*sct).timestamp > (*sctx).epoch_time_in_ms } {
        // SAFETY: the site is a compiled-in constant.
        unsafe { raise_site(&CT_VFY_114) };
        return 0;
    }

    // SAFETY: no preconditions; the constructor answers NULL or a live context.
    let ctx = EVP_MD_CTX_new();
    if ctx.is_null() {
        return ret;
    }

    // SAFETY: `ctx` is live; `sctx` and `sct` are live per the contract.
    if unsafe {
        EVP_DigestVerifyInit_ex(
            ctx,
            ptr::null_mut(),
            c"SHA2-256".as_ptr(),
            (*sctx).libctx,
            (*sctx).propq,
            (*sctx).pkey,
            ptr::null(),
        )
    } == 0
    {
        // SAFETY: `ctx` is live.
        unsafe { EVP_MD_CTX_free(ctx) };
        return ret;
    }

    // SAFETY: `ctx`, `sctx` and `sct` are live per the contract.
    if unsafe { sct_ctx_update(ctx, sctx, sct) } == 0 {
        // SAFETY: `ctx` is live.
        unsafe { EVP_MD_CTX_free(ctx) };
        return ret;
    }

    // Verify the signature.
    // SAFETY: `ctx` is live after the digest init; `sct->sig` is readable for `sig_len` bytes.
    ret = unsafe { EVP_DigestVerifyFinal(ctx, (*sct).sig, (*sct).sig_len) };
    // If ret < 0 some other error: fall through without setting error.
    if ret == 0 {
        // SAFETY: the site is a compiled-in constant.
        unsafe { raise_site(&CT_VFY_133) };
    }

    // SAFETY: `ctx` is live.
    unsafe { EVP_MD_CTX_free(ctx) };
    ret
}
