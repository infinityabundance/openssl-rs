//! `crypto/ts/ts_verify_ctx.c` — the verification context. Phase 12.5.
//!
//! The context's allocation, flags, the four deprecated *borrowing* setters and their four
//! *taking* `set0_*` twins, `TS_VERIFY_CTX_cleanup`, and `TS_REQ_to_TS_VERIFY_CTX`, which fills a
//! context from a request's imprint, policy and nonce. The struct is `ts_local.h:131-152`.
//!
//! SPDX-License-Identifier: Apache-2.0
#![allow(non_snake_case)]

use core::ffi::{c_int, c_long, c_uchar};
use core::ptr;

use crate::asn1::layout::Asn1String;
use crate::asn1::prim::{ASN1_INTEGER_dup, ASN1_OBJECT_free};
use crate::asn1::string::{ASN1_INTEGER_free, ASN1_STRING_get0_data, ASN1_STRING_length};
use crate::asn1::x_algor::{X509Algor, X509_ALGOR_dup, X509_ALGOR_free};
use crate::runtime::bio::{BIO_free_all, Bio};
use crate::runtime::mem::{CRYPTO_free, CRYPTO_malloc, CRYPTO_zalloc};
use crate::runtime::obj::{Asn1Object, OBJ_dup};
use crate::runtime::stack::OpenSslStack;
use crate::x509::t_x509::OSSL_STACK_OF_X509_free;
use crate::x509::v3_genn::{GENERAL_NAME_free, GeneralName};
use crate::x509::x509_lu::{X509Store, X509_STORE_free};

use super::ts_asn1::{TsMsgImprint, TsReq};

/// The authority translation unit for this module.
pub(crate) const FILE: &core::ffi::CStr = c"crypto/ts/ts_verify_ctx.c";

/// `TS_VFY_SIGNATURE` — `include/openssl/ts.h:367`.
const TS_VFY_SIGNATURE: u32 = 1 << 0;
/// `TS_VFY_VERSION` — `include/openssl/ts.h:369`.
const TS_VFY_VERSION: u32 = 1 << 1;
/// `TS_VFY_POLICY` — `include/openssl/ts.h:371`.
const TS_VFY_POLICY: u32 = 1 << 2;
/// `TS_VFY_IMPRINT` — `include/openssl/ts.h:376`.
const TS_VFY_IMPRINT: u32 = 1 << 3;
/// `TS_VFY_DATA` — `include/openssl/ts.h:382`. Named for completeness; the verify entry points that
/// read it are withheld on the ESS item group, so no landed arm consults it yet.
#[allow(dead_code)]
const TS_VFY_DATA: u32 = 1 << 4;
/// `TS_VFY_NONCE` — `include/openssl/ts.h:384`.
const TS_VFY_NONCE: u32 = 1 << 5;
/// `TS_VFY_SIGNER` — `include/openssl/ts.h:386`.
const TS_VFY_SIGNER: u32 = 1 << 6;
/// `TS_VFY_TSA_NAME` — `include/openssl/ts.h:388`.
const TS_VFY_TSA_NAME: u32 = 1 << 7;

/// `TS_VFY_ALL_IMPRINT` — `include/openssl/ts.h:391-397`.
const TS_VFY_ALL_IMPRINT: u32 = TS_VFY_SIGNATURE
    | TS_VFY_VERSION
    | TS_VFY_POLICY
    | TS_VFY_IMPRINT
    | TS_VFY_NONCE
    | TS_VFY_SIGNER
    | TS_VFY_TSA_NAME;

/// `TS_VERIFY_CTX` — `ts_local.h:131-152`.
#[repr(C)]
pub(crate) struct TsVerifyCtx {
    pub(crate) flags: u32,
    pub(crate) store: *mut X509Store,
    pub(crate) certs: *mut OpenSslStack,
    pub(crate) policy: *mut Asn1Object,
    pub(crate) md_alg: *mut X509Algor,
    pub(crate) imprint: *mut c_uchar,
    pub(crate) imprint_len: u32,
    pub(crate) data: *mut Bio,
    pub(crate) nonce: *mut Asn1String,
    pub(crate) tsa_name: *mut GeneralName,
}

/// `TS_VERIFY_CTX *TS_VERIFY_CTX_new(void)` — `ts_verify_ctx.c:15-20`.
///
/// # Safety
/// The returned pointer must be released with [`TS_VERIFY_CTX_free`].
#[no_mangle]
pub(crate) unsafe extern "C" fn TS_VERIFY_CTX_new() -> *mut TsVerifyCtx {
    // SAFETY: `OPENSSL_zalloc` on a positive size; the two arguments are the authority's
    // `OPENSSL_FILE`/`OPENSSL_LINE`.
    CRYPTO_zalloc(core::mem::size_of::<TsVerifyCtx>(), FILE.as_ptr(), 17).cast()
}

/// `void TS_VERIFY_CTX_init(TS_VERIFY_CTX *ctx)` — `ts_verify_ctx.c:22-26`.
///
/// # Safety
/// `ctx` is a live, writable context.
#[no_mangle]
pub(crate) unsafe extern "C" fn TS_VERIFY_CTX_init(ctx: *mut TsVerifyCtx) {
    // `OPENSSL_assert(ctx != NULL)` guards the authority's `memset`; a null context is a
    // programming error whose abort the crate does not model across the FFI boundary.
    if ctx.is_null() {
        return;
    }
    // SAFETY: `ctx` is a live, writable context.
    unsafe { ptr::write_bytes(ctx, 0, 1) };
}

/// `void TS_VERIFY_CTX_free(TS_VERIFY_CTX *ctx)` — `ts_verify_ctx.c:28-35`.
///
/// # Safety
/// `ctx` is NULL or a value [`TS_VERIFY_CTX_new`] returned.
#[no_mangle]
pub(crate) unsafe extern "C" fn TS_VERIFY_CTX_free(ctx: *mut TsVerifyCtx) {
    if ctx.is_null() {
        return;
    }
    // SAFETY: `ctx` is live.
    unsafe { TS_VERIFY_CTX_cleanup(ctx) };
    // SAFETY: `ctx` is an `OPENSSL_zalloc` allocation; this is `OPENSSL_free(ctx)` at `:34`.
    unsafe { CRYPTO_free(ctx.cast(), FILE.as_ptr(), 34) };
}

/// `int TS_VERIFY_CTX_add_flags(TS_VERIFY_CTX *ctx, int f)` — `ts_verify_ctx.c:37-41`.
///
/// # Safety
/// `ctx` is live.
#[no_mangle]
pub(crate) unsafe extern "C" fn TS_VERIFY_CTX_add_flags(ctx: *mut TsVerifyCtx, f: c_int) -> c_int {
    // SAFETY: `ctx` is live.
    unsafe { (*ctx).flags |= f as u32 };
    // SAFETY: `ctx` is live.
    unsafe { (*ctx).flags as c_int }
}

/// `int TS_VERIFY_CTX_set_flags(TS_VERIFY_CTX *ctx, int f)` — `ts_verify_ctx.c:43-47`.
///
/// # Safety
/// `ctx` is live.
#[no_mangle]
pub(crate) unsafe extern "C" fn TS_VERIFY_CTX_set_flags(ctx: *mut TsVerifyCtx, f: c_int) -> c_int {
    // SAFETY: `ctx` is live.
    unsafe { (*ctx).flags = f as u32 };
    // SAFETY: `ctx` is live.
    unsafe { (*ctx).flags as c_int }
}

/// `BIO *TS_VERIFY_CTX_set_data(TS_VERIFY_CTX *ctx, BIO *b)` — `ts_verify_ctx.c:50-54`.
///
/// # Safety
/// `ctx` is live; `b` is NULL or live.
#[no_mangle]
pub(crate) unsafe extern "C" fn TS_VERIFY_CTX_set_data(
    ctx: *mut TsVerifyCtx,
    b: *mut Bio,
) -> *mut Bio {
    // SAFETY: `ctx` is live.
    unsafe { (*ctx).data = b };
    // SAFETY: `ctx` is live.
    unsafe { (*ctx).data }
}

/// `int TS_VERIFY_CTX_set0_data(TS_VERIFY_CTX *ctx, BIO *b)` — `ts_verify_ctx.c:57-62`.
///
/// # Safety
/// `ctx` is live; `b` is NULL or owned.
#[no_mangle]
pub(crate) unsafe extern "C" fn TS_VERIFY_CTX_set0_data(
    ctx: *mut TsVerifyCtx,
    b: *mut Bio,
) -> c_int {
    // SAFETY: `ctx` is live.
    unsafe {
        BIO_free_all((*ctx).data);
        (*ctx).data = b;
    }
    1
}

/// `X509_STORE *TS_VERIFY_CTX_set_store(TS_VERIFY_CTX *ctx, X509_STORE *s)` —
/// `ts_verify_ctx.c:65-69`.
///
/// # Safety
/// `ctx` is live; `s` is NULL or live.
#[no_mangle]
pub(crate) unsafe extern "C" fn TS_VERIFY_CTX_set_store(
    ctx: *mut TsVerifyCtx,
    s: *mut X509Store,
) -> *mut X509Store {
    // SAFETY: `ctx` is live.
    unsafe { (*ctx).store = s };
    // SAFETY: `ctx` is live.
    unsafe { (*ctx).store }
}

/// `int TS_VERIFY_CTX_set0_store(TS_VERIFY_CTX *ctx, X509_STORE *s)` — `ts_verify_ctx.c:72-77`.
///
/// # Safety
/// `ctx` is live; `s` is NULL or owned.
#[no_mangle]
pub(crate) unsafe extern "C" fn TS_VERIFY_CTX_set0_store(
    ctx: *mut TsVerifyCtx,
    s: *mut X509Store,
) -> c_int {
    // SAFETY: `ctx` is live.
    unsafe {
        X509_STORE_free((*ctx).store);
        (*ctx).store = s;
    }
    1
}

/// `STACK_OF(X509) *TS_VERIFY_CTX_set_certs(TS_VERIFY_CTX *ctx, STACK_OF(X509) *certs)` —
/// `ts_verify_ctx.c:80-85`.
///
/// # Safety
/// `ctx` is live; `certs` is NULL or live.
#[no_mangle]
pub(crate) unsafe extern "C" fn TS_VERIFY_CTX_set_certs(
    ctx: *mut TsVerifyCtx,
    certs: *mut OpenSslStack,
) -> *mut OpenSslStack {
    // SAFETY: `ctx` is live.
    unsafe { (*ctx).certs = certs };
    // SAFETY: `ctx` is live.
    unsafe { (*ctx).certs }
}

/// `int TS_VERIFY_CTX_set0_certs(TS_VERIFY_CTX *ctx, STACK_OF(X509) *certs)` —
/// `ts_verify_ctx.c:88-93`.
///
/// # Safety
/// `ctx` is live; `certs` is NULL or owned.
#[no_mangle]
pub(crate) unsafe extern "C" fn TS_VERIFY_CTX_set0_certs(
    ctx: *mut TsVerifyCtx,
    certs: *mut OpenSslStack,
) -> c_int {
    // SAFETY: `ctx` is live.
    unsafe {
        OSSL_STACK_OF_X509_free((*ctx).certs);
        (*ctx).certs = certs;
    }
    1
}

/// `unsigned char *TS_VERIFY_CTX_set_imprint(TS_VERIFY_CTX *ctx, unsigned char *hexstr, long len)`
/// — `ts_verify_ctx.c:96-103`.
///
/// # Safety
/// `ctx` is live; `hexstr` is NULL or an `OPENSSL_malloc` allocation of `len` bytes.
#[no_mangle]
pub(crate) unsafe extern "C" fn TS_VERIFY_CTX_set_imprint(
    ctx: *mut TsVerifyCtx,
    hexstr: *mut c_uchar,
    len: c_long,
) -> *mut c_uchar {
    // SAFETY: `ctx` is live.
    unsafe {
        CRYPTO_free((*ctx).imprint.cast(), FILE.as_ptr(), 99);
        (*ctx).imprint = hexstr;
        (*ctx).imprint_len = len as u32;
        (*ctx).imprint
    }
}

/// `int TS_VERIFY_CTX_set0_imprint(TS_VERIFY_CTX *ctx, unsigned char *hexstr, long len)` —
/// `ts_verify_ctx.c:106-113`.
///
/// # Safety
/// `ctx` is live; `hexstr` is NULL or owned.
#[no_mangle]
pub(crate) unsafe extern "C" fn TS_VERIFY_CTX_set0_imprint(
    ctx: *mut TsVerifyCtx,
    hexstr: *mut c_uchar,
    len: c_long,
) -> c_int {
    // SAFETY: `ctx` is live.
    unsafe {
        CRYPTO_free((*ctx).imprint.cast(), FILE.as_ptr(), 110);
        (*ctx).imprint = hexstr;
        (*ctx).imprint_len = len as u32;
    }
    1
}

/// `void TS_VERIFY_CTX_cleanup(TS_VERIFY_CTX *ctx)` — `ts_verify_ctx.c:115-135`.
///
/// # Safety
/// `ctx` is NULL or a live context.
#[no_mangle]
pub(crate) unsafe extern "C" fn TS_VERIFY_CTX_cleanup(ctx: *mut TsVerifyCtx) {
    if ctx.is_null() {
        return;
    }
    // SAFETY: `ctx` is live; every member is NULL or owned by the context.
    unsafe {
        X509_STORE_free((*ctx).store);
        OSSL_STACK_OF_X509_free((*ctx).certs);
        ASN1_OBJECT_free((*ctx).policy);
        X509_ALGOR_free((*ctx).md_alg);
        CRYPTO_free((*ctx).imprint.cast(), FILE.as_ptr(), 126);
        BIO_free_all((*ctx).data);
        ASN1_INTEGER_free((*ctx).nonce);
        GENERAL_NAME_free((*ctx).tsa_name);
    }
    // SAFETY: `ctx` is live.
    unsafe { TS_VERIFY_CTX_init(ctx) };
}

/// `TS_VERIFY_CTX *TS_REQ_to_TS_VERIFY_CTX(TS_REQ *req, TS_VERIFY_CTX *ctx)` —
/// `ts_verify_ctx.c:137-185`.
///
/// # Safety
/// `req` is live; `ctx` is NULL or a live context whose cleanup the call performs first.
#[no_mangle]
pub(crate) unsafe extern "C" fn TS_REQ_to_TS_VERIFY_CTX(
    req: *mut TsReq,
    ctx: *mut TsVerifyCtx,
) -> *mut TsVerifyCtx {
    let mut ret = ctx;

    if !ret.is_null() {
        // SAFETY: `ret` is live.
        unsafe { TS_VERIFY_CTX_cleanup(ret) };
    } else {
        // SAFETY: no preconditions.
        ret = unsafe { TS_VERIFY_CTX_new() };
        if ret.is_null() {
            return ptr::null_mut();
        }
    }

    // SAFETY: `ret` is live.
    unsafe { (*ret).flags = TS_VFY_ALL_IMPRINT & !(TS_VFY_TSA_NAME | TS_VFY_SIGNATURE) };

    // SAFETY: `req` is live.
    let policy = unsafe { (*req).policy_id };
    if !policy.is_null() {
        // SAFETY: `policy` is live.
        let dup = unsafe { OBJ_dup(policy) };
        if dup.is_null() {
            // SAFETY: the err: arm releases the context per the authority.
            return unsafe { ts_req_to_ctx_err(ctx, ret) };
        }
        // SAFETY: `ret` is live.
        unsafe { (*ret).policy = dup };
    } else {
        // SAFETY: `ret` is live.
        unsafe { (*ret).flags &= !TS_VFY_POLICY };
    }

    // SAFETY: `req` is live.
    let imprint: *mut TsMsgImprint = unsafe { (*req).msg_imprint };
    // SAFETY: `imprint` is live.
    let md_alg = unsafe { (*imprint).hash_algo };
    // SAFETY: `md_alg` is live.
    let dup_alg = unsafe { X509_ALGOR_dup(md_alg) };
    if dup_alg.is_null() {
        // SAFETY: the err: arm releases the context per the authority.
        return unsafe { ts_req_to_ctx_err(ctx, ret) };
    }
    // SAFETY: `ret` is live.
    unsafe { (*ret).md_alg = dup_alg };
    // SAFETY: `imprint` is live.
    let msg = unsafe { (*imprint).hashed_msg };
    // SAFETY: `msg` is live.
    let len = unsafe { ASN1_STRING_length(msg) };
    // SAFETY: `ret` is live.
    unsafe { (*ret).imprint_len = len as u32 };
    if len <= 0 {
        // SAFETY: the err: arm releases the context per the authority.
        return unsafe { ts_req_to_ctx_err(ctx, ret) };
    }
    // SAFETY: `len` is positive.
    let buf: *mut c_uchar = CRYPTO_malloc(len as usize, FILE.as_ptr(), 168).cast();
    if buf.is_null() {
        // SAFETY: the err: arm releases the context per the authority.
        return unsafe { ts_req_to_ctx_err(ctx, ret) };
    }
    // SAFETY: `buf` holds `len` bytes and `msg` holds `len` bytes.
    unsafe {
        ptr::copy_nonoverlapping(ASN1_STRING_get0_data(msg), buf, len as usize);
        (*ret).imprint = buf;
    }

    // SAFETY: `req` is live.
    let nonce = unsafe { (*req).nonce };
    if !nonce.is_null() {
        // SAFETY: `nonce` is live.
        let dup_nonce = unsafe { ASN1_INTEGER_dup(nonce) };
        if dup_nonce.is_null() {
            // SAFETY: the err: arm releases the context per the authority.
            return unsafe { ts_req_to_ctx_err(ctx, ret) };
        }
        // SAFETY: `ret` is live.
        unsafe { (*ret).nonce = dup_nonce };
    } else {
        // SAFETY: `ret` is live.
        unsafe { (*ret).flags &= !TS_VFY_NONCE };
    }

    ret
}

/// The `err:` arm of [`TS_REQ_to_TS_VERIFY_CTX`] — `ts_verify_ctx.c:179-184`.
///
/// # Safety
/// `ctx` is NULL or live; `ret` is live.
unsafe fn ts_req_to_ctx_err(ctx: *mut TsVerifyCtx, ret: *mut TsVerifyCtx) -> *mut TsVerifyCtx {
    if !ctx.is_null() {
        // SAFETY: `ctx` is live.
        unsafe { TS_VERIFY_CTX_cleanup(ctx) };
    } else {
        // SAFETY: `ret` is live.
        unsafe { TS_VERIFY_CTX_free(ret) };
    }
    ptr::null_mut()
}
