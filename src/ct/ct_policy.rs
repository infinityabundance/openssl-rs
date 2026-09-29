//! `crypto/ct/ct_policy.c` — the CT policy-evaluation context. Phase 10.14.15's CT layer.
//!
//! `crypto/ct/ct_policy.c` is 113 lines and transcribes whole. It owns the `CT_POLICY_EVAL_CTX`
//! structure (`crypto/ct/ct_local.h:110-119`) and its lifecycle, setters and getters, all declared
//! in `include/openssl/ct.h.in:88-140`, so every one is an export with `#[no_mangle]`.
//!
//! ## The clock
//!
//! `CT_POLICY_EVAL_CTX_new_ex` seeds `epoch_time_in_ms` from
//! `ossl_time2ms(ossl_time_add(ossl_time_now(), ossl_seconds2time(300)))` (`:46-48`). The crate has
//! no landed `ossl_time_*` helper, so this unit reconstructs the four the expression needs from
//! `include/internal/time.h` exactly: `ossl_time_now` (`tv_sec * OSSL_TIME_SECOND +
//! tv_usec * OSSL_TIME_US` over `gettimeofday`, zero on failure or a negative `tv_sec`), the
//! saturating `ossl_time_add`, `ossl_seconds2time` and `ossl_time2ms`. The helper is private to this
//! unit because nothing else in the crate's landed surface reads the wall clock for CT.
//!
//! **Withheld by name**: none. The unit raises nothing, so it declares no coordinates.
//!
//! SPDX-License-Identifier: Apache-2.0

#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]

use core::ffi::{c_char, c_int, c_void};
use core::ptr;

use crate::ct::ct_log::CtlogStore;
use crate::runtime::bio::sys;
use crate::runtime::mem::{CRYPTO_free, CRYPTO_strdup, CRYPTO_zalloc};
use crate::x509::x509_set::X509_up_ref;
use crate::x509::x_x509::X509_free;
use crate::x509::x_x509::X509;

/// `OSS_L_TIME_SECOND` — `include/internal/time.h:31`, one second in ticks.
const OSSL_TIME_SECOND: u64 = 1_000_000_000;
/// `OSSL_TIME_MS` — `include/internal/time.h:34`, one millisecond in ticks.
const OSSL_TIME_MS: u64 = OSSL_TIME_SECOND / 1000;
/// `OSSL_TIME_US` — `include/internal/time.h:37`, one microsecond in ticks.
const OSSL_TIME_US: u64 = OSSL_TIME_MS / 1000;

/// `static const time_t SCT_CLOCK_DRIFT_TOLERANCE` — `crypto/ct/ct_policy.c:26`, 300 seconds.
const SCT_CLOCK_DRIFT_TOLERANCE: c_int = 300;

/// `ossl_time_now()` — `crypto/time.c:15-30`, the non-Windows non-DJGPP arm.
///
/// Nanoseconds since the epoch, or zero when `gettimeofday` fails or `tv_sec` is negative (the
/// same `ossl_time_zero()` fallback the authority's `ossl_time_from_timeval` makes).
fn ossl_time_now() -> u64 {
    let mut tv = sys::Timeval {
        tv_sec: 0,
        tv_usec: 0,
    };
    // SAFETY: `tv` is a live local and the timezone argument is NULL.
    if unsafe { sys::gettimeofday(&mut tv, ptr::null_mut()) } < 0 {
        return 0;
    }
    if tv.tv_sec < 0 {
        return 0;
    }
    // `tv_sec * OSSL_TIME_SECOND + tv_usec * OSSL_TIME_US`, wrapping as the authority's unsigned
    // 64-bit arithmetic does.
    (tv.tv_sec as u64)
        .wrapping_mul(OSSL_TIME_SECOND)
        .wrapping_add((tv.tv_usec as u64).wrapping_mul(OSSL_TIME_US))
}

/// `ossl_seconds2time(s)` — `include/internal/time.h:42`.
fn ossl_seconds2time(s: u64) -> u64 {
    s.wrapping_mul(OSSL_TIME_SECOND)
}

/// `ossl_time_add(a, b)` — `include/internal/time.h:168-175`, saturating at `ossl_time_infinite()`.
fn ossl_time_add(a: u64, b: u64) -> u64 {
    a.saturating_add(b)
}

/// `ossl_time2ms(t)` — `include/internal/time.h:45`.
fn ossl_time2ms(t: u64) -> u64 {
    t / OSSL_TIME_MS
}

/// `struct ct_policy_eval_ctx_st` — `CT_POLICY_EVAL_CTX`, from `crypto/ct/ct_local.h:110-119`.
#[repr(C)]
pub struct CtPolicyEvalCtx {
    /// `X509 *cert`.
    pub(crate) cert: *mut X509,
    /// `X509 *issuer`.
    pub(crate) issuer: *mut X509,
    /// `CTLOG_STORE *log_store`.
    pub(crate) log_store: *mut CtlogStore,
    /// `uint64_t epoch_time_in_ms`.
    pub(crate) epoch_time_in_ms: u64,
    /// `OSSL_LIB_CTX *libctx`.
    pub(crate) libctx: *mut c_void,
    /// `char *propq`.
    pub(crate) propq: *mut c_char,
}

const _: () = {
    assert!(core::mem::size_of::<CtPolicyEvalCtx>() == 48);
    assert!(core::mem::offset_of!(CtPolicyEvalCtx, cert) == 0);
    assert!(core::mem::offset_of!(CtPolicyEvalCtx, issuer) == 8);
    assert!(core::mem::offset_of!(CtPolicyEvalCtx, log_store) == 16);
    assert!(core::mem::offset_of!(CtPolicyEvalCtx, epoch_time_in_ms) == 24);
    assert!(core::mem::offset_of!(CtPolicyEvalCtx, libctx) == 32);
    assert!(core::mem::offset_of!(CtPolicyEvalCtx, propq) == 40);
};

/// `CT_POLICY_EVAL_CTX *CT_POLICY_EVAL_CTX_new_ex(OSSL_LIB_CTX *libctx, const char *propq)` —
/// `crypto/ct/ct_policy.c:28-51`.
///
/// # Safety
///
/// `libctx` is NULL or a live library context; `propq` is NULL or NUL-terminated.
#[no_mangle]
pub unsafe extern "C" fn CT_POLICY_EVAL_CTX_new_ex(
    libctx: *mut c_void,
    propq: *const c_char,
) -> *mut CtPolicyEvalCtx {
    let ctx = CRYPTO_zalloc(core::mem::size_of::<CtPolicyEvalCtx>(), ptr::null(), 0)
        .cast::<CtPolicyEvalCtx>();
    if ctx.is_null() {
        return ptr::null_mut();
    }

    // SAFETY: `ctx` is a fresh zeroed allocation; `libctx` is a pointer value.
    unsafe { (*ctx).libctx = libctx };
    if !propq.is_null() {
        // SAFETY: `propq` is NUL-terminated per the contract.
        let propq_copy = unsafe { CRYPTO_strdup(propq, ptr::null(), 0) };
        if propq_copy.is_null() {
            // SAFETY: `ctx` is the allocation this call owns.
            unsafe { CRYPTO_free(ctx.cast::<c_void>(), ptr::null(), 0) };
            return ptr::null_mut();
        }
        // SAFETY: `ctx` is live; `propq_copy` is the copy this call owns.
        unsafe { (*ctx).propq = propq_copy };
    }

    let now = ossl_time_add(
        ossl_time_now(),
        ossl_seconds2time(SCT_CLOCK_DRIFT_TOLERANCE as u64),
    );
    // SAFETY: `ctx` is live.
    unsafe { (*ctx).epoch_time_in_ms = ossl_time2ms(now) };

    ctx
}

/// `CT_POLICY_EVAL_CTX *CT_POLICY_EVAL_CTX_new(void)` — `crypto/ct/ct_policy.c:53-56`.
#[no_mangle]
pub extern "C" fn CT_POLICY_EVAL_CTX_new() -> *mut CtPolicyEvalCtx {
    // SAFETY: both arguments are NULL, which the constructor accepts.
    unsafe { CT_POLICY_EVAL_CTX_new_ex(ptr::null_mut(), ptr::null()) }
}

/// `void CT_POLICY_EVAL_CTX_free(CT_POLICY_EVAL_CTX *ctx)` — `crypto/ct/ct_policy.c:58-66`.
///
/// # Safety
///
/// `ctx` is NULL or a live `CT_POLICY_EVAL_CTX` this crate owns and that is not used afterwards.
#[no_mangle]
pub unsafe extern "C" fn CT_POLICY_EVAL_CTX_free(ctx: *mut CtPolicyEvalCtx) {
    if ctx.is_null() {
        return;
    }
    // SAFETY: `ctx` is live per the contract; each field is NULL or owned.
    unsafe {
        X509_free((*ctx).cert);
        X509_free((*ctx).issuer);
        CRYPTO_free((*ctx).propq.cast::<c_void>(), ptr::null(), 0);
        CRYPTO_free(ctx.cast::<c_void>(), ptr::null(), 0);
    }
}

/// `int CT_POLICY_EVAL_CTX_set1_cert(CT_POLICY_EVAL_CTX *ctx, X509 *cert)` —
/// `crypto/ct/ct_policy.c:68-74`.
///
/// # Safety
///
/// `ctx` is a live `CT_POLICY_EVAL_CTX`; `cert` is a live `X509`.
#[no_mangle]
pub unsafe extern "C" fn CT_POLICY_EVAL_CTX_set1_cert(
    ctx: *mut CtPolicyEvalCtx,
    cert: *mut X509,
) -> c_int {
    // SAFETY: `cert` is live per the contract.
    if unsafe { X509_up_ref(cert) } == 0 {
        return 0;
    }
    // SAFETY: `ctx` is live per the contract.
    unsafe { (*ctx).cert = cert };
    1
}

/// `int CT_POLICY_EVAL_CTX_set1_issuer(CT_POLICY_EVAL_CTX *ctx, X509 *issuer)` —
/// `crypto/ct/ct_policy.c:76-82`.
///
/// # Safety
///
/// `ctx` is a live `CT_POLICY_EVAL_CTX`; `issuer` is a live `X509`.
#[no_mangle]
pub unsafe extern "C" fn CT_POLICY_EVAL_CTX_set1_issuer(
    ctx: *mut CtPolicyEvalCtx,
    issuer: *mut X509,
) -> c_int {
    // SAFETY: `issuer` is live per the contract.
    if unsafe { X509_up_ref(issuer) } == 0 {
        return 0;
    }
    // SAFETY: `ctx` is live per the contract.
    unsafe { (*ctx).issuer = issuer };
    1
}

/// `void CT_POLICY_EVAL_CTX_set_shared_CTLOG_STORE(CT_POLICY_EVAL_CTX *ctx, CTLOG_STORE *log_store)`
/// — `crypto/ct/ct_policy.c:84-88`.
///
/// # Safety
///
/// `ctx` is a live `CT_POLICY_EVAL_CTX`; `log_store` is NULL or a live `CTLOG_STORE`.
#[no_mangle]
pub unsafe extern "C" fn CT_POLICY_EVAL_CTX_set_shared_CTLOG_STORE(
    ctx: *mut CtPolicyEvalCtx,
    log_store: *mut CtlogStore,
) {
    // SAFETY: `ctx` is live per the contract.
    unsafe { (*ctx).log_store = log_store };
}

/// `void CT_POLICY_EVAL_CTX_set_time(CT_POLICY_EVAL_CTX *ctx, uint64_t time_in_ms)` —
/// `crypto/ct/ct_policy.c:90-93`.
///
/// # Safety
///
/// `ctx` is a live `CT_POLICY_EVAL_CTX`.
#[no_mangle]
pub unsafe extern "C" fn CT_POLICY_EVAL_CTX_set_time(ctx: *mut CtPolicyEvalCtx, time_in_ms: u64) {
    // SAFETY: `ctx` is live per the contract.
    unsafe { (*ctx).epoch_time_in_ms = time_in_ms };
}

/// `X509 *CT_POLICY_EVAL_CTX_get0_cert(const CT_POLICY_EVAL_CTX *ctx)` —
/// `crypto/ct/ct_policy.c:95-98`.
///
/// # Safety
///
/// `ctx` is a live `CT_POLICY_EVAL_CTX`.
#[no_mangle]
pub unsafe extern "C" fn CT_POLICY_EVAL_CTX_get0_cert(ctx: *const CtPolicyEvalCtx) -> *mut X509 {
    // SAFETY: `ctx` is live per the contract.
    unsafe { (*ctx).cert }
}

/// `X509 *CT_POLICY_EVAL_CTX_get0_issuer(const CT_POLICY_EVAL_CTX *ctx)` —
/// `crypto/ct/ct_policy.c:100-103`.
///
/// # Safety
///
/// `ctx` is a live `CT_POLICY_EVAL_CTX`.
#[no_mangle]
pub unsafe extern "C" fn CT_POLICY_EVAL_CTX_get0_issuer(ctx: *const CtPolicyEvalCtx) -> *mut X509 {
    // SAFETY: `ctx` is live per the contract.
    unsafe { (*ctx).issuer }
}

/// `const CTLOG_STORE *CT_POLICY_EVAL_CTX_get0_log_store(const CT_POLICY_EVAL_CTX *ctx)` —
/// `crypto/ct/ct_policy.c:105-108`.
///
/// # Safety
///
/// `ctx` is a live `CT_POLICY_EVAL_CTX`.
#[no_mangle]
pub unsafe extern "C" fn CT_POLICY_EVAL_CTX_get0_log_store(
    ctx: *const CtPolicyEvalCtx,
) -> *const CtlogStore {
    // SAFETY: `ctx` is live per the contract.
    unsafe { (*ctx).log_store }
}

/// `uint64_t CT_POLICY_EVAL_CTX_get_time(const CT_POLICY_EVAL_CTX *ctx)` —
/// `crypto/ct/ct_policy.c:110-113`.
///
/// # Safety
///
/// `ctx` is a live `CT_POLICY_EVAL_CTX`.
#[no_mangle]
pub unsafe extern "C" fn CT_POLICY_EVAL_CTX_get_time(ctx: *const CtPolicyEvalCtx) -> u64 {
    // SAFETY: `ctx` is live per the contract.
    unsafe { (*ctx).epoch_time_in_ms }
}
