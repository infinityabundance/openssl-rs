//! `crypto/ts/ts_rsp_sign.c` — the response-generation context. Phase 12.5.
//!
//! The `TS_RESP_CTX` object model: its allocation and release, the signer certificate/key/digest
//! and certificate-chain setters, the acceptable-policy and acceptable-digest stacks, the accuracy
//! triple and the clock-precision control, the three callbacks and their default implementations,
//! the flags, and the status/failure mutators.
//!
//! **What this unit does not land, and why.** `TS_RESP_create_response` and its private helpers
//! (`ts_RESP_sign`, `ossl_ess_add1_signing_cert*`, `ts_TST_INFO_content_new`,
//! `TS_RESP_set_genTime_with_precision`, `ts_RESP_check_request`, `ts_RESP_get_policy`,
//! `ts_RESP_create_tst_info`, `ts_RESP_process_extensions`) reach the ESS item group and the
//! `OSSL_ESS_*` helpers through the `SigningCertificate` signed attribute, and those are Phase
//! 12.7's by their `ess.h` declaration. They are not ts-local, so the entry point waits for 12.7
//! rather than reaching across the subphase boundary. Everything the rest of `ts_conf.c` and a
//! caller can reach *without* a signed token lands here.
//!
//! SPDX-License-Identifier: Apache-2.0
#![allow(non_snake_case)]

use core::ffi::{c_int, c_long, c_void};
use core::ptr;

use crate::asn1::bitstr::ASN1_BIT_STRING_set_bit;
use crate::asn1::layout::Asn1String;
use crate::asn1::prim::{ASN1_INTEGER_get, ASN1_INTEGER_set, ASN1_OBJECT_free};
use crate::asn1::string::{
    ASN1_BIT_STRING_new, ASN1_INTEGER_free, ASN1_INTEGER_new, ASN1_STRING_set,
    ASN1_UTF8STRING_free, ASN1_UTF8STRING_new,
};
use crate::evp::digest::EvpMd;
use crate::evp::pkey::{EVP_PKEY_free, EVP_PKEY_up_ref, EvpPkey};
use crate::runtime::bio::sys::{gettimeofday, Timeval};
use crate::runtime::mem::{CRYPTO_free, CRYPTO_strdup, CRYPTO_zalloc};
use crate::runtime::obj::{Asn1Object, OBJ_dup};
use crate::runtime::stack::{
    OPENSSL_sk_free, OPENSSL_sk_new_null, OPENSSL_sk_pop_free, OPENSSL_sk_push, OpenSslStack,
};
use crate::x509::t_x509::OSSL_STACK_OF_X509_free;
use crate::x509::v3_purp::X509_check_purpose;
use crate::x509::x509_cmp::X509_chain_up_ref;
use crate::x509::x509_set::X509_up_ref;
use crate::x509::x_exten::X509Extension;
use crate::x509::x_x509::{X509_free, X509};

use super::ts_asn1::{TS_STATUS_INFO_free, TsReq, TsResp, TsTstInfo};
use super::ts_rsp_utils::TS_RESP_set_status_info;
use super::{raise_ts, ERR_R_ASN1_LIB, ERR_R_CRYPTO_LIB, ERR_R_OBJ_LIB, ERR_R_TS_LIB};

/// The authority translation unit for this module.
pub(crate) const FILE: &core::ffi::CStr = c"crypto/ts/ts_rsp_sign.c";

/// `X509_PURPOSE_TIMESTAMP_SIGN` — `include/openssl/x509v3.h`.
const X509_PURPOSE_TIMESTAMP_SIGN: c_int = 9;

/// `TS_MAX_CLOCK_PRECISION_DIGITS` — `include/openssl/ts.h:312`.
const TS_MAX_CLOCK_PRECISION_DIGITS: u32 = 6;
/// `TS_STATUS_GRANTED` — `include/openssl/ts.h:48`.
const TS_STATUS_GRANTED: c_int = 0;
/// `TS_STATUS_REJECTION` — `include/openssl/ts.h:50`.
const TS_STATUS_REJECTION: c_int = 2;
/// `TS_INFO_TIME_NOT_AVAILABLE` — `include/openssl/ts.h:59`.
const TS_INFO_TIME_NOT_AVAILABLE: c_int = 14;
/// `TS_INFO_UNACCEPTED_EXTENSION` — `include/openssl/ts.h:61`.
const TS_INFO_UNACCEPTED_EXTENSION: c_int = 16;

/// `TS_R_TIME_SYSCALL_ERROR` — `include/openssl/tserr.h`.
const TS_R_TIME_SYSCALL_ERROR: c_int = 122;
/// `TS_R_INVALID_SIGNER_CERTIFICATE_PURPOSE` — `include/openssl/tserr.h`.
const TS_R_INVALID_SIGNER_CERTIFICATE_PURPOSE: c_int = 117;

/// `TS_serial_cb` — `include/openssl/ts.h:248`.
pub(crate) type TsSerialCb = unsafe extern "C" fn(*mut TsRespCtx, *mut c_void) -> *mut Asn1String;
/// `TS_time_cb` — `include/openssl/ts.h:255-256`.
pub(crate) type TsTimeCb =
    unsafe extern "C" fn(*mut TsRespCtx, *mut c_void, *mut c_long, *mut c_long) -> c_int;
/// `TS_extension_cb` — `include/openssl/ts.h:263-264`.
pub(crate) type TsExtensionCb =
    unsafe extern "C" fn(*mut TsRespCtx, *mut X509Extension, *mut c_void) -> c_int;

/// `TS_resp_ctx` — `ts_local.h:101-129`.
#[repr(C)]
pub(crate) struct TsRespCtx {
    pub(crate) signer_cert: *mut X509,
    pub(crate) signer_key: *mut EvpPkey,
    pub(crate) signer_md: *const EvpMd,
    pub(crate) ess_cert_id_digest: *const EvpMd,
    pub(crate) certs: *mut OpenSslStack,
    pub(crate) policies: *mut OpenSslStack,
    pub(crate) default_policy: *mut Asn1Object,
    pub(crate) mds: *mut OpenSslStack,
    pub(crate) seconds: *mut Asn1String,
    pub(crate) millis: *mut Asn1String,
    pub(crate) micros: *mut Asn1String,
    pub(crate) clock_precision_digits: u32,
    pub(crate) flags: u32,
    pub(crate) serial_cb: Option<TsSerialCb>,
    pub(crate) serial_cb_data: *mut c_void,
    pub(crate) time_cb: Option<TsTimeCb>,
    pub(crate) time_cb_data: *mut c_void,
    pub(crate) extension_cb: Option<TsExtensionCb>,
    pub(crate) extension_cb_data: *mut c_void,
    pub(crate) request: *mut TsReq,
    pub(crate) response: *mut TsResp,
    pub(crate) tst_info: *mut TsTstInfo,
    pub(crate) libctx: *mut c_void,
    pub(crate) propq: *mut core::ffi::c_char,
}

/// The `void (*)(void *)` shape `OPENSSL_sk_pop_free` takes for `ASN1_OBJECT_free`.
///
/// # Safety
/// `p` is an `ASN1_OBJECT` per the stack's element type.
unsafe extern "C" fn asn1_object_free_void(p: *mut c_void) {
    // SAFETY: per this function's contract.
    unsafe { ASN1_OBJECT_free(p.cast()) };
}

// ---------------------------------------------------------------------------------------------
// The default callbacks
// ---------------------------------------------------------------------------------------------

/// `def_serial_cb(struct TS_resp_ctx *ctx, void *data)` — `ts_rsp_sign.c:43-59`.
///
/// # Safety
/// `ctx` is live; `_data` is unused.
unsafe extern "C" fn def_serial_cb(ctx: *mut TsRespCtx, _data: *mut c_void) -> *mut Asn1String {
    // SAFETY: no preconditions.
    let serial = ASN1_INTEGER_new();
    if serial.is_null() {
        // SAFETY: the err: arm releases the serial per the authority.
        return unsafe { def_serial_err(ctx, serial) };
    }
    // SAFETY: `serial` is live.
    if unsafe { ASN1_INTEGER_set(serial, 1) } == 0 {
        // SAFETY: the err: arm releases the serial per the authority.
        return unsafe { def_serial_err(ctx, serial) };
    }
    serial
}

/// The `err:` arm shared by `def_serial_cb`'s two failure paths.
///
/// # Safety
/// `ctx` is live; `serial` is NULL or live.
unsafe fn def_serial_err(ctx: *mut TsRespCtx, serial: *mut Asn1String) -> *mut Asn1String {
    // SAFETY: a compile-time coordinate.
    unsafe { raise_ts(FILE, 54, c"def_serial_cb", ERR_R_ASN1_LIB) };
    // SAFETY: `ctx` is live.
    unsafe {
        TS_RESP_CTX_set_status_info(
            ctx,
            TS_STATUS_REJECTION,
            c"Error during serial number generation.".as_ptr(),
        )
    };
    // SAFETY: `serial` is NULL or live.
    unsafe { ASN1_INTEGER_free(serial) };
    ptr::null_mut()
}

/// `OSSL_TIME` — `internal/time.h:26-28`. Nanoseconds since the epoch.
#[repr(transparent)]
struct OsslTime(u64);

/// `OSSL_TIME_US` — `internal/time.h:37`.
const OSSL_TIME_US: u64 = 1000;

/// `ossl_time_now()` — `crypto/time.c:15-48`, the non-Windows arm. Private to this unit because
/// `crypto/time.c` is not a landed stratum file; `ct_policy.rs` and `bss_dgram.rs` carry their own
/// copies of the same shape.
fn ossl_time_now() -> OsslTime {
    let mut tv = Timeval {
        tv_sec: 0,
        tv_usec: 0,
    };
    // SAFETY: `tv` is a live local and the timezone argument is NULL.
    if unsafe { gettimeofday(&mut tv, ptr::null_mut()) } < 0 {
        return OsslTime(0);
    }
    if tv.tv_sec <= 0 {
        return if tv.tv_usec <= 0 {
            OsslTime(0)
        } else {
            OsslTime((tv.tv_usec as u64).wrapping_mul(OSSL_TIME_US))
        };
    }
    OsslTime(
        ((tv.tv_sec as u64)
            .wrapping_mul(1_000_000)
            .wrapping_add(tv.tv_usec as u64))
        .wrapping_mul(OSSL_TIME_US),
    )
}

/// `ossl_time_to_timeval(OSSL_TIME t)` — `internal/time.h:90-110`.
fn ossl_time_to_timeval(t: OsslTime) -> Timeval {
    let rounded = t.0.saturating_add(OSSL_TIME_US - 1);
    Timeval {
        tv_sec: (rounded / 1_000_000_000) as c_long,
        tv_usec: ((rounded % 1_000_000_000) / OSSL_TIME_US) as c_long,
    }
}

/// `def_time_cb(struct TS_resp_ctx *ctx, void *data, long *sec, long *usec)` —
/// `ts_rsp_sign.c:61-80`.
///
/// # Safety
/// `ctx` is live; `sec`/`usec` are writable.
unsafe extern "C" fn def_time_cb(
    ctx: *mut TsRespCtx,
    _data: *mut c_void,
    sec: *mut c_long,
    usec: *mut c_long,
) -> c_int {
    let t = ossl_time_now();
    if t.0 == 0 {
        // SAFETY: a compile-time coordinate.
        unsafe { raise_ts(FILE, 69, c"def_time_cb", TS_R_TIME_SYSCALL_ERROR) };
        // SAFETY: `ctx` is live.
        unsafe {
            TS_RESP_CTX_set_status_info(
                ctx,
                TS_STATUS_REJECTION,
                c"Time is not available.".as_ptr(),
            )
        };
        // SAFETY: `ctx` is live.
        unsafe { TS_RESP_CTX_add_failure_info(ctx, TS_INFO_TIME_NOT_AVAILABLE) };
        return 0;
    }
    let tv = ossl_time_to_timeval(t);
    // SAFETY: `sec`/`usec` are writable per the contract.
    unsafe {
        *sec = tv.tv_sec;
        *usec = tv.tv_usec;
    }
    1
}

/// `def_extension_cb(struct TS_resp_ctx *ctx, X509_EXTENSION *ext, void *data)` —
/// `ts_rsp_sign.c:82-89`.
///
/// # Safety
/// `ctx` is live; `_ext`/`_data` are unused.
unsafe extern "C" fn def_extension_cb(
    ctx: *mut TsRespCtx,
    _ext: *mut X509Extension,
    _data: *mut c_void,
) -> c_int {
    // SAFETY: `ctx` is live.
    unsafe {
        TS_RESP_CTX_set_status_info(ctx, TS_STATUS_REJECTION, c"Unsupported extension.".as_ptr())
    };
    // SAFETY: `ctx` is live.
    unsafe { TS_RESP_CTX_add_failure_info(ctx, TS_INFO_UNACCEPTED_EXTENSION) };
    0
}

// ---------------------------------------------------------------------------------------------
// TS_RESP_CTX management
// ---------------------------------------------------------------------------------------------

/// `TS_RESP_CTX *TS_RESP_CTX_new_ex(OSSL_LIB_CTX *libctx, const char *propq)` —
/// `ts_rsp_sign.c:93-113`.
///
/// # Safety
/// `_libctx` is NULL or live; `propq` is NULL or NUL-terminated.
#[no_mangle]
pub(crate) unsafe extern "C" fn TS_RESP_CTX_new_ex(
    _libctx: *mut c_void,
    propq: *const core::ffi::c_char,
) -> *mut TsRespCtx {
    // SAFETY: `OPENSSL_zalloc` on a positive size.
    let ctx: *mut TsRespCtx =
        CRYPTO_zalloc(core::mem::size_of::<TsRespCtx>(), FILE.as_ptr(), 97).cast();
    if ctx.is_null() {
        return ptr::null_mut();
    }

    if !propq.is_null() {
        // SAFETY: `propq` is NUL-terminated.
        let dup = unsafe { CRYPTO_strdup(propq, FILE.as_ptr(), 101) };
        if dup.is_null() {
            // SAFETY: `ctx` is an `OPENSSL_zalloc` allocation.
            unsafe { CRYPTO_free(ctx.cast(), FILE.as_ptr(), 103) };
            return ptr::null_mut();
        }
        // SAFETY: `ctx` is live.
        unsafe { (*ctx).propq = dup };
    }
    // SAFETY: `ctx` is live.
    unsafe {
        (*ctx).libctx = _libctx;
        (*ctx).serial_cb = Some(def_serial_cb);
        (*ctx).time_cb = Some(def_time_cb);
        (*ctx).extension_cb = Some(def_extension_cb);
    }

    ctx
}

/// `TS_RESP_CTX *TS_RESP_CTX_new(void)` — `ts_rsp_sign.c:115-118`.
///
/// # Safety
/// The returned pointer must be released with [`TS_RESP_CTX_free`].
#[no_mangle]
pub(crate) unsafe extern "C" fn TS_RESP_CTX_new() -> *mut TsRespCtx {
    // SAFETY: no preconditions.
    unsafe { TS_RESP_CTX_new_ex(ptr::null_mut(), ptr::null()) }
}

/// `void TS_RESP_CTX_free(TS_RESP_CTX *ctx)` — `ts_rsp_sign.c:120-136`.
///
/// # Safety
/// `ctx` is NULL or a value [`TS_RESP_CTX_new`] returned.
#[no_mangle]
pub(crate) unsafe extern "C" fn TS_RESP_CTX_free(ctx: *mut TsRespCtx) {
    if ctx.is_null() {
        return;
    }
    // SAFETY: `ctx` is live; every member is NULL or owned by the context.
    unsafe {
        CRYPTO_free((*ctx).propq.cast(), FILE.as_ptr(), 125);
        X509_free((*ctx).signer_cert);
        EVP_PKEY_free((*ctx).signer_key);
        OSSL_STACK_OF_X509_free((*ctx).certs);
        OPENSSL_sk_pop_free((*ctx).policies, Some(asn1_object_free_void));
        ASN1_OBJECT_free((*ctx).default_policy);
        OPENSSL_sk_free((*ctx).mds);
        ASN1_INTEGER_free((*ctx).seconds);
        ASN1_INTEGER_free((*ctx).millis);
        ASN1_INTEGER_free((*ctx).micros);
        CRYPTO_free(ctx.cast(), FILE.as_ptr(), 135);
    }
}

/// `int TS_RESP_CTX_set_signer_cert(TS_RESP_CTX *ctx, X509 *signer)` — `ts_rsp_sign.c:138-151`.
///
/// # Safety
/// `ctx` is live; `signer` is live.
#[no_mangle]
pub(crate) unsafe extern "C" fn TS_RESP_CTX_set_signer_cert(
    ctx: *mut TsRespCtx,
    signer: *mut X509,
) -> c_int {
    // SAFETY: `signer` is live.
    if unsafe { X509_check_purpose(signer, X509_PURPOSE_TIMESTAMP_SIGN, 0) } != 1 {
        // SAFETY: a compile-time coordinate.
        unsafe {
            raise_ts(
                FILE,
                141,
                c"TS_RESP_CTX_set_signer_cert",
                TS_R_INVALID_SIGNER_CERTIFICATE_PURPOSE,
            )
        };
        return 0;
    }
    // SAFETY: `signer` is live.
    if unsafe { X509_up_ref(signer) } == 0 {
        return 0;
    }

    // SAFETY: `ctx` is live.
    unsafe {
        X509_free((*ctx).signer_cert);
        (*ctx).signer_cert = signer;
    }
    1
}

/// `int TS_RESP_CTX_set_signer_key(TS_RESP_CTX *ctx, EVP_PKEY *key)` — `ts_rsp_sign.c:153-162`.
///
/// # Safety
/// `ctx` is live; `key` is live.
#[no_mangle]
pub(crate) unsafe extern "C" fn TS_RESP_CTX_set_signer_key(
    ctx: *mut TsRespCtx,
    key: *mut EvpPkey,
) -> c_int {
    // SAFETY: `key` is live.
    if unsafe { EVP_PKEY_up_ref(key) } == 0 {
        return 0;
    }
    // SAFETY: `ctx` is live.
    unsafe {
        EVP_PKEY_free((*ctx).signer_key);
        (*ctx).signer_key = key;
    }
    1
}

/// `int TS_RESP_CTX_set_signer_digest(TS_RESP_CTX *ctx, const EVP_MD *md)` —
/// `ts_rsp_sign.c:164-168`.
///
/// # Safety
/// `ctx` is live; `md` is NULL or live.
#[no_mangle]
pub(crate) unsafe extern "C" fn TS_RESP_CTX_set_signer_digest(
    ctx: *mut TsRespCtx,
    md: *const EvpMd,
) -> c_int {
    // SAFETY: `ctx` is live.
    unsafe { (*ctx).signer_md = md };
    1
}

/// `int TS_RESP_CTX_set_def_policy(TS_RESP_CTX *ctx, const ASN1_OBJECT *def_policy)` —
/// `ts_rsp_sign.c:170-179`.
///
/// # Safety
/// `ctx` is live; `def_policy` is live.
#[no_mangle]
pub(crate) unsafe extern "C" fn TS_RESP_CTX_set_def_policy(
    ctx: *mut TsRespCtx,
    def_policy: *const Asn1Object,
) -> c_int {
    // SAFETY: `ctx` is live.
    unsafe { ASN1_OBJECT_free((*ctx).default_policy) };
    // SAFETY: `def_policy` is live.
    let dup = unsafe { OBJ_dup(def_policy) };
    // SAFETY: `ctx` is live.
    unsafe { (*ctx).default_policy = dup };
    if dup.is_null() {
        // SAFETY: a compile-time coordinate.
        unsafe { raise_ts(FILE, 177, c"TS_RESP_CTX_set_def_policy", ERR_R_OBJ_LIB) };
        return 0;
    }
    1
}

/// `int TS_RESP_CTX_set_certs(TS_RESP_CTX *ctx, STACK_OF(X509) *certs)` — `ts_rsp_sign.c:181-187`.
///
/// # Safety
/// `ctx` is live; `certs` is NULL or live.
#[no_mangle]
pub(crate) unsafe extern "C" fn TS_RESP_CTX_set_certs(
    ctx: *mut TsRespCtx,
    certs: *mut OpenSslStack,
) -> c_int {
    // SAFETY: `ctx` is live.
    unsafe {
        OSSL_STACK_OF_X509_free((*ctx).certs);
        (*ctx).certs = ptr::null_mut();
    }

    if certs.is_null() {
        return 1;
    }
    // SAFETY: `certs` is live.
    let dup = unsafe { X509_chain_up_ref(certs) };
    // SAFETY: `ctx` is live.
    unsafe { (*ctx).certs = dup };
    (!dup.is_null()) as c_int
}

/// `int TS_RESP_CTX_add_policy(TS_RESP_CTX *ctx, const ASN1_OBJECT *policy)` —
/// `ts_rsp_sign.c:189-211`.
///
/// # Safety
/// `ctx` is live; `policy` is live.
#[no_mangle]
pub(crate) unsafe extern "C" fn TS_RESP_CTX_add_policy(
    ctx: *mut TsRespCtx,
    policy: *const Asn1Object,
) -> c_int {
    // SAFETY: `ctx` is live.
    if unsafe { (*ctx).policies }.is_null() {
        // SAFETY: no preconditions.
        let fresh = OPENSSL_sk_new_null();
        // SAFETY: `ctx` is live.
        unsafe { (*ctx).policies = fresh };
        if fresh.is_null() {
            // SAFETY: a compile-time coordinate.
            unsafe { raise_ts(FILE, 195, c"TS_RESP_CTX_add_policy", ERR_R_CRYPTO_LIB) };
            return 0;
        }
    }
    // SAFETY: `policy` is live.
    let copy = unsafe { OBJ_dup(policy) };
    if copy.is_null() {
        // SAFETY: a compile-time coordinate.
        unsafe { raise_ts(FILE, 199, c"TS_RESP_CTX_add_policy", ERR_R_OBJ_LIB) };
        return 0;
    }
    // SAFETY: `ctx` is live; `copy` is owned.
    if unsafe { OPENSSL_sk_push((*ctx).policies, copy.cast()) } == 0 {
        // SAFETY: a compile-time coordinate.
        unsafe { raise_ts(FILE, 203, c"TS_RESP_CTX_add_policy", ERR_R_CRYPTO_LIB) };
        // SAFETY: `copy` is live.
        unsafe { ASN1_OBJECT_free(copy) };
        return 0;
    }
    1
}

/// `int TS_RESP_CTX_add_md(TS_RESP_CTX *ctx, const EVP_MD *md)` — `ts_rsp_sign.c:213-225`.
///
/// # Safety
/// `ctx` is live; `md` is NULL or live.
#[no_mangle]
pub(crate) unsafe extern "C" fn TS_RESP_CTX_add_md(ctx: *mut TsRespCtx, md: *const EvpMd) -> c_int {
    // SAFETY: `ctx` is live.
    if unsafe { (*ctx).mds }.is_null() {
        // SAFETY: no preconditions.
        let fresh = OPENSSL_sk_new_null();
        // SAFETY: `ctx` is live.
        unsafe { (*ctx).mds = fresh };
        if fresh.is_null() {
            // SAFETY: a compile-time coordinate.
            unsafe { raise_ts(FILE, 217, c"TS_RESP_CTX_add_md", ERR_R_CRYPTO_LIB) };
            return 0;
        }
    }
    // SAFETY: `ctx` is live; `md` is copied by pointer, exactly as the comment records.
    if unsafe { OPENSSL_sk_push((*ctx).mds, md.cast()) } == 0 {
        // SAFETY: a compile-time coordinate.
        unsafe { raise_ts(FILE, 219, c"TS_RESP_CTX_add_md", ERR_R_CRYPTO_LIB) };
        return 0;
    }
    1
}

/// The `TS_RESP_CTX_accuracy_free(ctx)` macro — `ts_rsp_sign.c:227-233`.
///
/// # Safety
/// `ctx` is live.
unsafe fn ts_resp_ctx_accuracy_free(ctx: *mut TsRespCtx) {
    // SAFETY: `ctx` is live.
    unsafe {
        ASN1_INTEGER_free((*ctx).seconds);
        (*ctx).seconds = ptr::null_mut();
        ASN1_INTEGER_free((*ctx).millis);
        (*ctx).millis = ptr::null_mut();
        ASN1_INTEGER_free((*ctx).micros);
        (*ctx).micros = ptr::null_mut();
    }
}

/// `int TS_RESP_CTX_set_accuracy(TS_RESP_CTX *ctx, int secs, int millis, int micros)` —
/// `ts_rsp_sign.c:235-258`.
///
/// # Safety
/// `ctx` is live.
#[no_mangle]
pub(crate) unsafe extern "C" fn TS_RESP_CTX_set_accuracy(
    ctx: *mut TsRespCtx,
    secs: c_int,
    millis: c_int,
    micros: c_int,
) -> c_int {
    // SAFETY: `ctx` is live.
    unsafe { ts_resp_ctx_accuracy_free(ctx) };

    if secs != 0 {
        // SAFETY: no preconditions.
        let s = ASN1_INTEGER_new();
        // SAFETY: `ctx` is live.
        unsafe { (*ctx).seconds = s };
        let mut ok = !s.is_null();
        if ok {
            // SAFETY: `s` is live.
            ok = unsafe { ASN1_INTEGER_set(s, secs as c_long) } != 0;
        }
        if !ok {
            // SAFETY: the err: arm releases the accuracy triple per the authority.
            return unsafe { ts_resp_ctx_accuracy_err(ctx) };
        }
    }
    if millis != 0 {
        // SAFETY: no preconditions.
        let m = ASN1_INTEGER_new();
        // SAFETY: `ctx` is live.
        unsafe { (*ctx).millis = m };
        let mut ok = !m.is_null();
        if ok {
            // SAFETY: `m` is live.
            ok = unsafe { ASN1_INTEGER_set(m, millis as c_long) } != 0;
        }
        if !ok {
            // SAFETY: the err: arm releases the accuracy triple per the authority.
            return unsafe { ts_resp_ctx_accuracy_err(ctx) };
        }
    }
    if micros != 0 {
        // SAFETY: no preconditions.
        let u = ASN1_INTEGER_new();
        // SAFETY: `ctx` is live.
        unsafe { (*ctx).micros = u };
        let mut ok = !u.is_null();
        if ok {
            // SAFETY: `u` is live.
            ok = unsafe { ASN1_INTEGER_set(u, micros as c_long) } != 0;
        }
        if !ok {
            // SAFETY: the err: arm releases the accuracy triple per the authority.
            return unsafe { ts_resp_ctx_accuracy_err(ctx) };
        }
    }

    1
}

/// The `err:` arm of [`TS_RESP_CTX_set_accuracy`] — `ts_rsp_sign.c:254-257`.
///
/// # Safety
/// `ctx` is live.
unsafe fn ts_resp_ctx_accuracy_err(ctx: *mut TsRespCtx) -> c_int {
    // SAFETY: `ctx` is live.
    unsafe { ts_resp_ctx_accuracy_free(ctx) };
    // SAFETY: a compile-time coordinate.
    unsafe { raise_ts(FILE, 256, c"TS_RESP_CTX_set_accuracy", ERR_R_ASN1_LIB) };
    0
}

/// `void TS_RESP_CTX_add_flags(TS_RESP_CTX *ctx, int flags)` — `ts_rsp_sign.c:260-263`.
///
/// # Safety
/// `ctx` is live.
#[no_mangle]
pub(crate) unsafe extern "C" fn TS_RESP_CTX_add_flags(ctx: *mut TsRespCtx, flags: c_int) {
    // SAFETY: `ctx` is live.
    unsafe { (*ctx).flags |= flags as u32 };
}

/// `void TS_RESP_CTX_set_serial_cb(TS_RESP_CTX *ctx, TS_serial_cb cb, void *data)` —
/// `ts_rsp_sign.c:265-269`.
///
/// # Safety
/// `ctx` is live.
#[no_mangle]
pub(crate) unsafe extern "C" fn TS_RESP_CTX_set_serial_cb(
    ctx: *mut TsRespCtx,
    cb: Option<TsSerialCb>,
    data: *mut c_void,
) {
    // SAFETY: `ctx` is live.
    unsafe {
        (*ctx).serial_cb = cb;
        (*ctx).serial_cb_data = data;
    }
}

/// `void TS_RESP_CTX_set_time_cb(TS_RESP_CTX *ctx, TS_time_cb cb, void *data)` —
/// `ts_rsp_sign.c:271-275`.
///
/// # Safety
/// `ctx` is live.
#[no_mangle]
pub(crate) unsafe extern "C" fn TS_RESP_CTX_set_time_cb(
    ctx: *mut TsRespCtx,
    cb: Option<TsTimeCb>,
    data: *mut c_void,
) {
    // SAFETY: `ctx` is live.
    unsafe {
        (*ctx).time_cb = cb;
        (*ctx).time_cb_data = data;
    }
}

/// `void TS_RESP_CTX_set_extension_cb(TS_RESP_CTX *ctx, TS_extension_cb cb, void *data)` —
/// `ts_rsp_sign.c:277-282`.
///
/// # Safety
/// `ctx` is live.
#[no_mangle]
pub(crate) unsafe extern "C" fn TS_RESP_CTX_set_extension_cb(
    ctx: *mut TsRespCtx,
    cb: Option<TsExtensionCb>,
    data: *mut c_void,
) {
    // SAFETY: `ctx` is live.
    unsafe {
        (*ctx).extension_cb = cb;
        (*ctx).extension_cb_data = data;
    }
}

/// `int TS_RESP_CTX_set_status_info(TS_RESP_CTX *ctx, int status, const char *text)` —
/// `ts_rsp_sign.c:284-325`.
///
/// # Safety
/// `ctx` is live and its `response` is live; `text` is NULL or NUL-terminated.
#[no_mangle]
pub(crate) unsafe extern "C" fn TS_RESP_CTX_set_status_info(
    ctx: *mut TsRespCtx,
    status: c_int,
    text: *const core::ffi::c_char,
) -> c_int {
    // SAFETY: no preconditions.
    let si = unsafe { super::ts_asn1::TS_STATUS_INFO_new() };
    let mut utf8_text: *mut Asn1String = ptr::null_mut();
    let mut ret = 0;
    if si.is_null() {
        // SAFETY: a compile-time coordinate.
        unsafe { raise_ts(FILE, 292, c"TS_RESP_CTX_set_status_info", ERR_R_TS_LIB) };
        // SAFETY: `si` is NULL, `utf8_text` is NULL.
        unsafe { TS_STATUS_INFO_free(si) };
        return ret;
    }
    // SAFETY: `si` is live.
    if unsafe { ASN1_INTEGER_set((*si).status, status as c_long) } == 0 {
        // SAFETY: a compile-time coordinate.
        unsafe { raise_ts(FILE, 296, c"TS_RESP_CTX_set_status_info", ERR_R_ASN1_LIB) };
        // SAFETY: `si` is live.
        unsafe { TS_STATUS_INFO_free(si) };
        return ret;
    }
    if !text.is_null() {
        // SAFETY: no preconditions.
        utf8_text = ASN1_UTF8STRING_new();
        // SAFETY: `text` is NUL-terminated.
        let text_len = unsafe { core::ffi::CStr::from_ptr(text) }.to_bytes().len() as c_int;
        let mut set_failed = utf8_text.is_null();
        if !set_failed {
            // SAFETY: `utf8_text` is live.
            set_failed = unsafe { ASN1_STRING_set(utf8_text, text.cast(), text_len) } == 0;
        }
        if set_failed {
            // SAFETY: a compile-time coordinate.
            unsafe { raise_ts(FILE, 302, c"TS_RESP_CTX_set_status_info", ERR_R_ASN1_LIB) };
            // SAFETY: `si` is live, `utf8_text` is NULL or live.
            unsafe {
                TS_STATUS_INFO_free(si);
                ASN1_UTF8STRING_free(utf8_text);
            }
            return ret;
        }
        // SAFETY: `si` is live.
        if unsafe { (*si).text }.is_null() {
            // SAFETY: no preconditions.
            let fresh = OPENSSL_sk_new_null();
            // SAFETY: `si` is live.
            unsafe { (*si).text = fresh };
            if fresh.is_null() {
                // SAFETY: a compile-time coordinate.
                unsafe { raise_ts(FILE, 307, c"TS_RESP_CTX_set_status_info", ERR_R_CRYPTO_LIB) };
                // SAFETY: `si` is live, `utf8_text` is live.
                unsafe {
                    TS_STATUS_INFO_free(si);
                    ASN1_UTF8STRING_free(utf8_text);
                }
                return ret;
            }
        }
        // SAFETY: `si` is live; the push takes ownership of `utf8_text`.
        if unsafe { OPENSSL_sk_push((*si).text, utf8_text.cast()) } == 0 {
            // SAFETY: a compile-time coordinate.
            unsafe { raise_ts(FILE, 311, c"TS_RESP_CTX_set_status_info", ERR_R_CRYPTO_LIB) };
            // SAFETY: `si` is live, `utf8_text` is live.
            unsafe {
                TS_STATUS_INFO_free(si);
                ASN1_UTF8STRING_free(utf8_text);
            }
            return ret;
        }
        utf8_text = ptr::null_mut(); /* Ownership is lost. */
    }
    // SAFETY: `ctx` is live and its response is live.
    if unsafe { TS_RESP_set_status_info((*ctx).response, si) } == 0 {
        // SAFETY: a compile-time coordinate.
        unsafe { raise_ts(FILE, 317, c"TS_RESP_CTX_set_status_info", ERR_R_TS_LIB) };
        // SAFETY: `si` is live, `utf8_text` is NULL.
        unsafe {
            TS_STATUS_INFO_free(si);
            ASN1_UTF8STRING_free(utf8_text);
        }
        return ret;
    }
    ret = 1;
    // SAFETY: `si` is live and now either owned by the response or freed.
    unsafe {
        TS_STATUS_INFO_free(si);
        ASN1_UTF8STRING_free(utf8_text);
    }
    ret
}

/// `int TS_RESP_CTX_set_status_info_cond(TS_RESP_CTX *ctx, int status, const char *text)` —
/// `ts_rsp_sign.c:327-337`.
///
/// # Safety
/// `ctx` is live and its `response` is live; `text` is NULL or NUL-terminated.
#[no_mangle]
pub(crate) unsafe extern "C" fn TS_RESP_CTX_set_status_info_cond(
    ctx: *mut TsRespCtx,
    status: c_int,
    text: *const core::ffi::c_char,
) -> c_int {
    // SAFETY: `ctx` is live and its response is live.
    let si = unsafe { (*(*ctx).response).status_info };
    // SAFETY: `si` is live.
    if unsafe { ASN1_INTEGER_get((*si).status) } == TS_STATUS_GRANTED as c_long {
        // SAFETY: `ctx` is live; `text` is the caller's.
        return unsafe { TS_RESP_CTX_set_status_info(ctx, status, text) };
    }
    1
}

/// `int TS_RESP_CTX_add_failure_info(TS_RESP_CTX *ctx, int failure)` — `ts_rsp_sign.c:339-351`.
///
/// # Safety
/// `ctx` is live and its `response` is live.
#[no_mangle]
pub(crate) unsafe extern "C" fn TS_RESP_CTX_add_failure_info(
    ctx: *mut TsRespCtx,
    failure: c_int,
) -> c_int {
    // SAFETY: `ctx` is live and its response is live.
    let si = unsafe { (*(*ctx).response).status_info };
    // SAFETY: `si` is live.
    if unsafe { (*si).failure_info }.is_null() {
        // SAFETY: no preconditions.
        let fresh = ASN1_BIT_STRING_new();
        // SAFETY: `si` is live.
        unsafe { (*si).failure_info = fresh };
        if fresh.is_null() {
            // SAFETY: a compile-time coordinate.
            unsafe { raise_ts(FILE, 349, c"TS_RESP_CTX_add_failure_info", ERR_R_ASN1_LIB) };
            return 0;
        }
    }
    // SAFETY: `si` is live and `failure_info` is live.
    if unsafe { ASN1_BIT_STRING_set_bit((*si).failure_info, failure, 1) } == 0 {
        // SAFETY: a compile-time coordinate.
        unsafe { raise_ts(FILE, 349, c"TS_RESP_CTX_add_failure_info", ERR_R_ASN1_LIB) };
        return 0;
    }
    1
}

/// `TS_REQ *TS_RESP_CTX_get_request(TS_RESP_CTX *ctx)` — `ts_rsp_sign.c:353-356`.
///
/// # Safety
/// `ctx` is live.
#[no_mangle]
pub(crate) unsafe extern "C" fn TS_RESP_CTX_get_request(ctx: *mut TsRespCtx) -> *mut TsReq {
    // SAFETY: `ctx` is live.
    unsafe { (*ctx).request }
}

/// `TS_TST_INFO *TS_RESP_CTX_get_tst_info(TS_RESP_CTX *ctx)` — `ts_rsp_sign.c:358-361`.
///
/// # Safety
/// `ctx` is live.
#[no_mangle]
pub(crate) unsafe extern "C" fn TS_RESP_CTX_get_tst_info(ctx: *mut TsRespCtx) -> *mut TsTstInfo {
    // SAFETY: `ctx` is live.
    unsafe { (*ctx).tst_info }
}

/// `int TS_RESP_CTX_set_clock_precision_digits(TS_RESP_CTX *ctx, unsigned precision)` —
/// `ts_rsp_sign.c:363-370`.
///
/// # Safety
/// `ctx` is live.
#[no_mangle]
pub(crate) unsafe extern "C" fn TS_RESP_CTX_set_clock_precision_digits(
    ctx: *mut TsRespCtx,
    precision: u32,
) -> c_int {
    if precision > TS_MAX_CLOCK_PRECISION_DIGITS {
        return 0;
    }
    // SAFETY: `ctx` is live.
    unsafe { (*ctx).clock_precision_digits = precision };
    1
}

/// `int TS_RESP_CTX_set_ess_cert_id_digest(TS_RESP_CTX *ctx, const EVP_MD *md)` —
/// `ts_rsp_sign.c:898-902`.
///
/// # Safety
/// `ctx` is live; `md` is NULL or live.
#[no_mangle]
pub(crate) unsafe extern "C" fn TS_RESP_CTX_set_ess_cert_id_digest(
    ctx: *mut TsRespCtx,
    md: *const EvpMd,
) -> c_int {
    // SAFETY: `ctx` is live.
    unsafe { (*ctx).ess_cert_id_digest = md };
    1
}
