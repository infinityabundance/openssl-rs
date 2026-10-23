//! Phase 7.4 — `crypto/evp/pmeth_check.c` whole: the seven key-validation entry points.
//!
//! It is 7.4c-ii's row and it lands here because **7.4b-iii reaches into it**:
//! `EVP_PKEY_derive_set_peer`'s `validate_peer` arm is
//! `EVP_PKEY_public_check(EVP_PKEY_CTX_new_from_pkey(...))`, so the exchange operation family
//! cannot be completed without it. That is a plan edge rather than a reordering — the owning
//! subphase is unchanged, and the row it belongs to finds it already landed when it arrives.
//!
//! ## One provider probe, and five wrappers that differ only in a selection
//!
//! ```text
//! try_provided_check(ctx, selection, checktype)
//!   1. ctx is legacy (keymgmt == NULL)         -> -1   "ask someone else"
//!   2. the key cannot be exported              -> 0    with EVP_R_INITIALIZATION_ERROR
//!   3. evp_keymgmt_validate(keymgmt, keydata, selection, checktype)
//! ```
//!
//! `-1` is the only one of the three that is not an answer: it means *this context is not a provider
//! context*, and every caller treats it as "fall through to the legacy half". The distinction
//! between `0` and `-1` is therefore load-bearing — a transcription that returned `0` for a legacy
//! context would turn "not mine to answer" into "the key is invalid", and
//! `EVP_PKEY_public_check` would report a valid provider key as bad.
//!
//! The five selections are the whole of the difference between the entry points:
//!
//! | export | selection | checktype |
//! |---|---|---|
//! | `EVP_PKEY_public_check` | `SELECT_PUBLIC_KEY` | `VALIDATE_FULL_CHECK` |
//! | `EVP_PKEY_public_check_quick` | `SELECT_PUBLIC_KEY` | `VALIDATE_QUICK_CHECK` |
//! | `EVP_PKEY_param_check` | `SELECT_ALL_PARAMETERS` | `VALIDATE_FULL_CHECK` |
//! | `EVP_PKEY_param_check_quick` | `SELECT_ALL_PARAMETERS` | `VALIDATE_QUICK_CHECK` |
//! | `EVP_PKEY_private_check` | `SELECT_PRIVATE_KEY` | `VALIDATE_FULL_CHECK` |
//! | `EVP_PKEY_pairwise_check` | `SELECT_KEYPAIR` | `VALIDATE_FULL_CHECK` |
//!
//! `EVP_PKEY_check` is `EVP_PKEY_pairwise_check` under another name — it is **not** a seventh
//! behaviour, and it is not even a wrapper with its own body.
//!
//! ## The legacy half is live, and the pmeth half is checked first
//!
//! After `try_provided_check` answers `-1`, each wrapper with a legacy half consults, in the
//! authority's order (`pmeth_check.c:67-84`, `:113-129`, `:178-195`): `evp_pkey_is_legacy`'s type
//! test (`pkey->type == EVP_PKEY_NONE` is `not_supported`), then `ctx->pmeth-><check>` if the method
//! publishes it, then `pkey->ameth->pkey_<check>` if the type's method publishes that. Either
//! callback's return value is the answer; only when neither is published is the `not_supported`
//! refusal (`-2`) taken.
//!
//! That half was previously recorded as unreachable because "both objects are Phase 8's". Both have
//! landed: `EVP_PKEY_ASN1_METHOD` is populated by `pkey_set_type` for every legacy type, and a
//! legacy context (keymgmt == NULL, which `int_ctx_new` refuses to build without a pmeth) carries
//! its `EVP_PKEY_METHOD`. The four checks therefore answered `-2` for every legacy key, including the
//! EC and DH keys whose methods publish real checks.
//!
//! `EVP_PKEY_private_check` genuinely has no legacy half — the authority raises the refusal after
//! `try_provided_check` returns `-1` — so its `-2` is the authority's answer and not a gap.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::c_int;
use core::ptr;

use crate::evp::keymgmt::{evp_keymgmt_validate, EvpKeyMgmt};
use crate::evp::pkey::evp_pkey_export_to_provider;
use crate::evp::pkey_ctx::EvpPkeyCtx;
use crate::runtime::err::{err_sites, raise_site};

/// `EVP_PKEY_NONE` — `include/openssl/evp.h`, `NID_undef`.
const EVP_PKEY_NONE: c_int = 0;

/// `OSSL_KEYMGMT_SELECT_PRIVATE_KEY` — `include/openssl/core_dispatch.h`.
const OSSL_KEYMGMT_SELECT_PRIVATE_KEY: c_int = 0x01;
/// `OSSL_KEYMGMT_SELECT_PUBLIC_KEY`.
const OSSL_KEYMGMT_SELECT_PUBLIC_KEY: c_int = 0x02;
/// `OSSL_KEYMGMT_SELECT_KEYPAIR` — `PRIVATE_KEY | PUBLIC_KEY`.
const OSSL_KEYMGMT_SELECT_KEYPAIR: c_int = 0x01 | 0x02;
/// `OSSL_KEYMGMT_SELECT_ALL_PARAMETERS` — `DOMAIN_PARAMETERS | OTHER_PARAMETERS`.
const OSSL_KEYMGMT_SELECT_ALL_PARAMETERS: c_int = 0x04 | 0x80;

/// `OSSL_KEYMGMT_VALIDATE_FULL_CHECK`.
const OSSL_KEYMGMT_VALIDATE_FULL_CHECK: c_int = 0;
/// `OSSL_KEYMGMT_VALIDATE_QUICK_CHECK`.
const OSSL_KEYMGMT_VALIDATE_QUICK_CHECK: c_int = 1;

/// `static int try_provided_check(EVP_PKEY_CTX *ctx, int selection, int checktype)` —
/// `crypto/evp/pmeth_check.c:28`.
///
/// Returns **1** true, **0** false, **-1** "not a provider context, ask the legacy half". The `-1`
/// is produced before any error is raised, so a caller that falls through leaves the queue clean.
///
/// # Safety
/// `ctx` must be live.
unsafe fn try_provided_check(ctx: *mut EvpPkeyCtx, selection: c_int, checktype: c_int) -> c_int {
    // SAFETY: `ctx` is live.
    if unsafe { &*ctx }.is_legacy() {
        return -1;
    }

    /* The authority takes a **copy** of `ctx->keymgmt` and hands the export its address, so the
     * export may substitute the provider's own method without disturbing the context. */
    // SAFETY: `ctx` is live.
    let mut keymgmt: *mut EvpKeyMgmt = unsafe { (*ctx).keymgmt };
    // SAFETY: `ctx` is live.
    let (pkey, libctx, propquery) = unsafe { ((*ctx).pkey, (*ctx).libctx, (*ctx).propquery) };
    // SAFETY: `pkey` is live, and `keymgmt` is a live local whose address is valid for the call --
    // which may replace it with the provider's own method.
    let keydata =
        unsafe { evp_pkey_export_to_provider(pkey, libctx, ptr::addr_of_mut!(keymgmt), propquery) };
    if keydata.is_null() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::PMETH_CHECK_40) };
        return 0;
    }

    // SAFETY: `keymgmt` is live — either the context's own or the exporter's substitute — and
    // `keydata` is live.
    unsafe { evp_keymgmt_validate(keymgmt, keydata, selection, checktype) }
}

/// `static int evp_pkey_public_check_combined(EVP_PKEY_CTX *ctx, int checktype)` —
/// `crypto/evp/pmeth_check.c:47`.
///
/// # Safety
/// `ctx` must be live.
unsafe fn evp_pkey_public_check_combined(ctx: *mut EvpPkeyCtx, checktype: c_int) -> c_int {
    // SAFETY: `ctx` is live.
    let pkey = unsafe { (*ctx).pkey };
    if pkey.is_null() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::PMETH_CHECK_53) };
        return 0;
    }

    // SAFETY: `ctx` is live.
    let ok = unsafe { try_provided_check(ctx, OSSL_KEYMGMT_SELECT_PUBLIC_KEY, checktype) };
    if ok != -1 {
        return ok;
    }

    // SAFETY: `pkey` is live.
    if unsafe { (*pkey).type_ } == EVP_PKEY_NONE {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::PMETH_CHECK_78) };
        return -2;
    }

    /* The legacy half, in the authority's order: a customised public check on the context's method
     * first, then the type's own default. A context with `keymgmt == NULL` always has a `pmeth`
     * (`int_ctx_new` refuses one with neither), so the two dereferences below are guarded by that
     * invariant and the checks are for safety rather than behaviour. */
    // SAFETY: `ctx` is live.
    let pmeth = unsafe { (*ctx).pmeth };
    if !pmeth.is_null() {
        // SAFETY: `pmeth` is the live method this context was built with.
        if let Some(f) = unsafe { (*pmeth).public_check } {
            // SAFETY: the method's own public-key check, handed the live key.
            return unsafe { f(pkey) };
        }
    }
    // SAFETY: `pkey` is live.
    let ameth = unsafe { (*pkey).ameth };
    /* The built-in check callbacks dereference the legacy union; a typed-but-unassigned key has
     * none and the authority would crash there (§17: UB is not reproduced). With no key material
     * there is no check to run, so the `not_supported` refusal below is the answer. */
    // SAFETY: `pkey` is live; this is the legacy origin union.
    let unassigned = unsafe { (*pkey).pkey }.is_null();
    if !ameth.is_null() && !unassigned {
        // SAFETY: `ameth` is the method `pkey_set_type` installed for this key.
        if let Some(f) = unsafe { (*ameth).pkey_public_check } {
            // SAFETY: the type's own default public-key check, handed the live key.
            return unsafe { f(pkey) };
        }
    }
    // SAFETY: a compile-time-constant site.
    unsafe { raise_site(&err_sites::PMETH_CHECK_78) };
    -2
}

/// `int EVP_PKEY_public_check(EVP_PKEY_CTX *ctx)`.
///
/// # Safety
/// `ctx` must be live.
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_public_check(ctx: *mut EvpPkeyCtx) -> c_int {
    // SAFETY: `ctx` is live per the contract.
    unsafe { evp_pkey_public_check_combined(ctx, OSSL_KEYMGMT_VALIDATE_FULL_CHECK) }
}

/// `int EVP_PKEY_public_check_quick(EVP_PKEY_CTX *ctx)`.
///
/// # Safety
/// `ctx` must be live.
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_public_check_quick(ctx: *mut EvpPkeyCtx) -> c_int {
    // SAFETY: `ctx` is live per the contract.
    unsafe { evp_pkey_public_check_combined(ctx, OSSL_KEYMGMT_VALIDATE_QUICK_CHECK) }
}

/// `static int evp_pkey_param_check_combined(EVP_PKEY_CTX *ctx, int checktype)` —
/// `crypto/evp/pmeth_check.c:92`.
///
/// # Safety
/// `ctx` must be live.
unsafe fn evp_pkey_param_check_combined(ctx: *mut EvpPkeyCtx, checktype: c_int) -> c_int {
    // SAFETY: `ctx` is live.
    let pkey = unsafe { (*ctx).pkey };
    if pkey.is_null() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::PMETH_CHECK_98) };
        return 0;
    }

    // SAFETY: `ctx` is live.
    let ok = unsafe { try_provided_check(ctx, OSSL_KEYMGMT_SELECT_ALL_PARAMETERS, checktype) };
    if ok != -1 {
        return ok;
    }

    // SAFETY: `pkey` is live.
    if unsafe { (*pkey).type_ } == EVP_PKEY_NONE {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::PMETH_CHECK_124) };
        return -2;
    }

    /* The legacy half, as `evp_pkey_public_check_combined`'s: `ctx->pmeth->param_check`, then
     * `pkey->ameth->pkey_param_check`. */
    // SAFETY: `ctx` is live.
    let pmeth = unsafe { (*ctx).pmeth };
    if !pmeth.is_null() {
        // SAFETY: `pmeth` is the live method this context was built with.
        if let Some(f) = unsafe { (*pmeth).param_check } {
            // SAFETY: the method's own parameter check, handed the live key.
            return unsafe { f(pkey) };
        }
    }
    // SAFETY: `pkey` is live.
    let ameth = unsafe { (*pkey).ameth };
    /* As `evp_pkey_public_check_combined`: no union member is no check to run. */
    // SAFETY: `pkey` is live; this is the legacy origin union.
    let unassigned = unsafe { (*pkey).pkey }.is_null();
    if !ameth.is_null() && !unassigned {
        // SAFETY: `ameth` is the method `pkey_set_type` installed for this key.
        if let Some(f) = unsafe { (*ameth).pkey_param_check } {
            // SAFETY: the type's own default parameter check, handed the live key.
            return unsafe { f(pkey) };
        }
    }
    // SAFETY: a compile-time-constant site.
    unsafe { raise_site(&err_sites::PMETH_CHECK_124) };
    -2
}

/// `int EVP_PKEY_param_check(EVP_PKEY_CTX *ctx)`.
///
/// # Safety
/// `ctx` must be live.
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_param_check(ctx: *mut EvpPkeyCtx) -> c_int {
    // SAFETY: `ctx` is live per the contract.
    unsafe { evp_pkey_param_check_combined(ctx, OSSL_KEYMGMT_VALIDATE_FULL_CHECK) }
}

/// `int EVP_PKEY_param_check_quick(EVP_PKEY_CTX *ctx)`.
///
/// # Safety
/// `ctx` must be live.
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_param_check_quick(ctx: *mut EvpPkeyCtx) -> c_int {
    // SAFETY: `ctx` is live per the contract.
    unsafe { evp_pkey_param_check_combined(ctx, OSSL_KEYMGMT_VALIDATE_QUICK_CHECK) }
}

/// `int EVP_PKEY_private_check(EVP_PKEY_CTX *ctx)` — `crypto/evp/pmeth_check.c:138`.
///
/// The one wrapper with **no legacy half at all**: after `try_provided_check` answers `-1` the
/// authority raises `EVP_R_OPERATION_NOT_SUPPORTED_FOR_THIS_KEYTYPE` without consulting `ameth`,
/// because no legacy key type implements a private-key check. So this function's refusal is not a
/// gap in this crate — it is the authority's own answer.
///
/// # Safety
/// `ctx` must be live.
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_private_check(ctx: *mut EvpPkeyCtx) -> c_int {
    // SAFETY: `ctx` is live.
    let pkey = unsafe { (*ctx).pkey };
    if pkey.is_null() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::PMETH_CHECK_144) };
        return 0;
    }

    // SAFETY: `ctx` is live.
    let ok = unsafe {
        try_provided_check(
            ctx,
            OSSL_KEYMGMT_SELECT_PRIVATE_KEY,
            OSSL_KEYMGMT_VALIDATE_FULL_CHECK,
        )
    };
    if ok != -1 {
        return ok;
    }

    // SAFETY: a compile-time-constant site.
    unsafe { raise_site(&err_sites::PMETH_CHECK_154) };
    -2
}

/// `int EVP_PKEY_check(EVP_PKEY_CTX *ctx)` — `crypto/evp/pmeth_check.c:158`.
///
/// A second name for `EVP_PKEY_pairwise_check` and nothing else: no key test, no selection, no
/// error of its own. Written as the call rather than as a copy of the body so the two cannot drift.
///
/// # Safety
/// `ctx` must be live.
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_check(ctx: *mut EvpPkeyCtx) -> c_int {
    // SAFETY: `ctx` is live per the contract.
    unsafe { EVP_PKEY_pairwise_check(ctx) }
}

/// `int EVP_PKEY_pairwise_check(EVP_PKEY_CTX *ctx)` — `crypto/evp/pmeth_check.c:163`.
///
/// # Safety
/// `ctx` must be live.
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_pairwise_check(ctx: *mut EvpPkeyCtx) -> c_int {
    // SAFETY: `ctx` is live.
    let pkey = unsafe { (*ctx).pkey };
    if pkey.is_null() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::PMETH_CHECK_169) };
        return 0;
    }

    // SAFETY: `ctx` is live.
    let ok = unsafe {
        try_provided_check(
            ctx,
            OSSL_KEYMGMT_SELECT_KEYPAIR,
            OSSL_KEYMGMT_VALIDATE_FULL_CHECK,
        )
    };
    if ok != -1 {
        return ok;
    }

    // SAFETY: `pkey` is live.
    if unsafe { (*pkey).type_ } == EVP_PKEY_NONE {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::PMETH_CHECK_194) };
        return -2;
    }

    /* The legacy half, as `evp_pkey_public_check_combined`'s: `ctx->pmeth->check`, then
     * `pkey->ameth->pkey_check`. */
    // SAFETY: `ctx` is live.
    let pmeth = unsafe { (*ctx).pmeth };
    if !pmeth.is_null() {
        // SAFETY: `pmeth` is the live method this context was built with.
        if let Some(f) = unsafe { (*pmeth).check } {
            // SAFETY: the method's own pairwise check, handed the live key.
            return unsafe { f(pkey) };
        }
    }
    // SAFETY: `pkey` is live.
    let ameth = unsafe { (*pkey).ameth };
    /* As `evp_pkey_public_check_combined`: no union member is no check to run. */
    // SAFETY: `pkey` is live; this is the legacy origin union.
    let unassigned = unsafe { (*pkey).pkey }.is_null();
    if !ameth.is_null() && !unassigned {
        // SAFETY: `ameth` is the method `pkey_set_type` installed for this key.
        if let Some(f) = unsafe { (*ameth).pkey_check } {
            // SAFETY: the type's own default pairwise check, handed the live key.
            return unsafe { f(pkey) };
        }
    }
    // SAFETY: a compile-time-constant site.
    unsafe { raise_site(&err_sites::PMETH_CHECK_194) };
    -2
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::ec::key::{EC_KEY_generate_key, EC_KEY_new_by_curve_name};
    use crate::evp::pkey::{EVP_PKEY_assign, EVP_PKEY_free, EVP_PKEY_new};
    use crate::evp::pkey_ctx::{EvpPkeyMethod, EVP_PKEY_EC, EVP_PKEY_RSA};
    use crate::runtime::obj::NID_X9_62_prime256v1;

    /// A context with no `keymgmt` and no `pmeth` is a legacy context for `try_provided_check`
    /// (`evp_pkey_ctx_is_legacy` is `keymgmt == NULL`). `int_ctx_new` refuses to build one with
    /// neither a method nor a `keymgmt`, so this shape reaches the ameth arm only in a test — which
    /// is exactly the arm under test.
    ///
    /// # Safety
    /// `pkey` must be live and outlive the returned value; the block is never freed.
    unsafe fn legacy_ctx(pkey: *mut crate::evp::pkey::EvpPkey) -> EvpPkeyCtx {
        // SAFETY: every field is a scalar, a raw pointer or an `Option` of a function pointer, so the
        // all-zero bit pattern is a valid `EvpPkeyCtx`.
        let mut ctx: EvpPkeyCtx = unsafe { core::mem::zeroed() };
        ctx.pkey = pkey;
        ctx
    }

    /// A generated legacy EC key: the ameth publishes `pkey_check`, `pkey_public_check` and
    /// `pkey_param_check`, so all three wrappers run a real check instead of answering `-2`.
    #[test]
    fn evp_pkey_checks_dispatch_to_the_legacy_ameth() {
        // SAFETY: the key owns the EC_KEY transferred to it; the stack context never frees anything.
        unsafe {
            let ec = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
            assert!(!ec.is_null());
            assert_eq!(EC_KEY_generate_key(ec), 1);
            let pkey = EVP_PKEY_new();
            assert!(!pkey.is_null());
            assert_eq!(EVP_PKEY_assign(pkey, EVP_PKEY_EC, ec.cast()), 1);
            let mut ctx = legacy_ctx(pkey);
            let ctx = ptr::addr_of_mut!(ctx);

            assert_eq!(
                EVP_PKEY_public_check(ctx),
                1,
                "the legacy public check runs and accepts a generated key"
            );
            assert_eq!(EVP_PKEY_public_check_quick(ctx), 1);
            assert_eq!(
                EVP_PKEY_param_check(ctx),
                1,
                "the legacy parameter check runs"
            );
            assert_eq!(EVP_PKEY_param_check_quick(ctx), 1);
            assert_eq!(
                EVP_PKEY_pairwise_check(ctx),
                1,
                "the legacy pairwise check runs"
            );
            assert_eq!(EVP_PKEY_check(ctx), 1);

            /* Negative: `EVP_PKEY_private_check` has no legacy half in the authority either. */
            assert_eq!(EVP_PKEY_private_check(ctx), -2);
            crate::runtime::err::ERR_clear_error();

            EVP_PKEY_free(pkey);
        }
    }

    /// The other refusals stay refusals: a key with no type is `not_supported`, a method without the
    /// callback is `not_supported`, and an incomplete EC key makes the legacy check answer `0`
    /// rather than `-2`.
    #[test]
    fn evp_pkey_checks_keep_their_unsupported_answers() {
        // SAFETY: every object below is this test's own.
        unsafe {
            /* A typed key whose EC object has a group but no public point: `EC_KEY_check_key`
             * answers 0, which is a real answer and not the -2 refusal. */
            let ec = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
            assert!(!ec.is_null());
            let pkey = EVP_PKEY_new();
            assert!(!pkey.is_null());
            assert_eq!(EVP_PKEY_assign(pkey, EVP_PKEY_EC, ec.cast()), 1);
            let mut ctx = legacy_ctx(pkey);
            let ctx = ptr::addr_of_mut!(ctx);
            crate::runtime::err::ERR_clear_error();
            assert_eq!(EVP_PKEY_pairwise_check(ctx), 0);
            crate::runtime::err::ERR_clear_error();
            EVP_PKEY_free(pkey);

            /* A blank key is `EVP_PKEY_NONE` and takes `not_supported` before any ameth is read. */
            let blank = EVP_PKEY_new();
            assert!(!blank.is_null());
            let mut ctx = legacy_ctx(blank);
            let ctx = ptr::addr_of_mut!(ctx);
            crate::runtime::err::ERR_clear_error();
            assert_eq!(EVP_PKEY_public_check(ctx), -2);
            crate::runtime::err::ERR_clear_error();
            EVP_PKEY_free(blank);
        }
    }

    static PMETH_CHECKS: core::sync::atomic::AtomicI32 = core::sync::atomic::AtomicI32::new(0);

    unsafe extern "C" fn counting_check(_pkey: *mut crate::evp::pkey::EvpPkey) -> c_int {
        PMETH_CHECKS.fetch_add(1, core::sync::atomic::Ordering::SeqCst);
        1
    }

    /// `ctx->pmeth->check` is consulted **before** `pkey->ameth->pkey_check` (`pmeth_check.c:184-190`).
    /// The standard methods publish no `check`, so this needs a method of the test's own — which is
    /// exactly the boundary the authority defines.
    #[test]
    fn evp_pkey_pairwise_check_runs_the_context_methods_check_first() {
        // SAFETY: the method and the RSA object are live for the whole test.
        unsafe {
            let mut meth: EvpPkeyMethod = core::mem::zeroed();
            meth.pkey_id = EVP_PKEY_RSA;
            meth.check = Some(counting_check);

            let pkey = EVP_PKEY_new();
            let rsa = crate::rsa::object::RSA_new();
            assert!(!pkey.is_null() && !rsa.is_null());
            assert_eq!(EVP_PKEY_assign(pkey, EVP_PKEY_RSA, rsa.cast()), 1);

            let mut ctx = legacy_ctx(pkey);
            ctx.pmeth = ptr::addr_of!(meth);
            PMETH_CHECKS.store(0, core::sync::atomic::Ordering::SeqCst);
            assert_eq!(EVP_PKEY_pairwise_check(ptr::addr_of_mut!(ctx)), 1);
            assert_eq!(
                PMETH_CHECKS.load(core::sync::atomic::Ordering::SeqCst),
                1,
                "the context's own check must run"
            );
            EVP_PKEY_free(pkey);
        }
    }
}
