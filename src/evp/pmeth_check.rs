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
//! ## The legacy half is unreachable here, and saying why is the point
//!
//! After `try_provided_check` answers `-1`, each wrapper consults `pkey->ameth` and `ctx->pmeth`.
//! In this crate both are absent — `EVP_PKEY_ASN1_METHOD` and `EVP_PKEY_METHOD` are Phase 8's
//! (D163, D165) — so the legacy arm cannot be taken. The two refusals that remain are transcribed
//! at their own recorded sites: `EVP_R_NO_KEY_SET` when the context has no key, and
//! `EVP_R_OPERATION_NOT_SUPPORTED_FOR_THIS_KEYTYPE` from the `not_supported` label.
//!
//! The `pkey->type == EVP_PKEY_NONE` test *is* written, because it is what distinguishes a key that
//! was never typed from one that has a legacy method — and a provider key is typed
//! `EVP_PKEY_KEYMGMT`, so the test is false for it. Reading it as dead because "there are no legacy
//! keys here" would be the same mistake D168 records from the other direction.
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

    /* The legacy half: `ctx->pmeth->public_check` and then `pkey->ameth->pkey_public_check`. Both
     * objects are Phase 8's, and a context that agreed to the legacy half would be one whose
     * `keymgmt` is NULL — which is exactly the case that returned -1 above and cannot be built in
     * this crate. So this arm is unreachable here and answers as the `not_supported` label does. */
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

    /* The legacy half, unreachable for the reason given on `evp_pkey_public_check_combined`. */
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

    /* The legacy half: `ctx->pmeth->check` then `pkey->ameth->pkey_check`, unreachable for the
     * reason given on `evp_pkey_public_check_combined`. */
    // SAFETY: a compile-time-constant site.
    unsafe { raise_site(&err_sites::PMETH_CHECK_194) };
    -2
}
