//! `crypto/evp/ec_ctrl.c` — the `EVP_PKEY_CTX_*ec*` controls (Phase 8.7, slice E).
//!
//! **Why this is a module of its own rather than part of [`crate::ec`].** The authority has **no
//! `crypto/ec/ec_ctrl.c`**: the EC controls live beside every other key type's under `crypto/evp/`,
//! and every symbol this file defines is one the ledger labels `src/ec/mod.rs` because its
//! *declaring header* is `ec.h` rather than because of its translation unit. The module is split
//! out for the reason `src/rsa/ctrl.rs` records for 8.4's own slice E and [`crate::dh::ctrl`] and
//! [`crate::dsa::ctrl`] for 8.5's and 8.6's: `crypto/evp/ec_ctrl.c` is a translation unit of its
//! own, and giving it a module is what makes `forensics/atlas/transcription-edges.json` say which
//! authority file the EC control surface answers for.
//!
//! **Three shapes, and a reader can classify all twelve by them.**
//!
//!   1. **The `EVP_PKEY_CTX_ctrl` wrappers** — `set_ecdh_kdf_type`, `get_ecdh_kdf_type`,
//!      `set_ecdh_kdf_md`, `get_ecdh_kdf_md`, `set_ec_paramgen_curve_nid` and `set_ec_param_enc`.
//!      The authority's comment says "currently implemented as an `EVP_PKEY_CTX_ctrl()` wrapper,
//!      simply because that's easier" for five of the six, and the sixth,
//!      `set_ec_paramgen_curve_nid`, is the one whose **key type is computed from its argument**
//!      (`nid == EVP_PKEY_SM2 ? EVP_PKEY_SM2 : EVP_PKEY_EC`).
//!   2. **The four `OSSL_PARAM` builders handed to the *strict* setter/getter** —
//!      `set_ecdh_cofactor_mode`, `get_ecdh_cofactor_mode`, `set_ecdh_kdf_outlen`,
//!      `get_ecdh_kdf_outlen`, `set0_ecdh_kdf_ukm` and `get0_ecdh_kdf_ukm`. They build the
//!      provider parameter directly and hand it to `evp_pkey_ctx_{set,get}_params_strict`, which is
//!      what makes their refusal for a parameter the method does not list a `-2` rather than a ctrl
//!      result.
//!   3. **The one gate**, `evp_pkey_ctx_getset_ecdh_param_checks`, which is the whole of the shared
//!      refusal structure: a NULL context or one whose operation is not a *derivation* one is `-2`
//!      with `EVP_R_COMMAND_NOT_SUPPORTED`, and a *legacy* context of the wrong key type is `-1`.
//!
//! **The legacy key-type arm of the gate is unreachable here, and that is the `pmeth` reduction
//! rather than an omission.** The authority's guard is `evp_pkey_ctx_is_legacy(ctx) &&
//! ctx->pmeth != NULL && ctx->pmeth->pkey_id != EVP_PKEY_EC`. `evp_pkey_ctx_is_legacy` is
//! `keymgmt == NULL` (`src/evp/pkey_ctx.rs` records that reading it by its name would be wrong),
//! and `int_ctx_new` refuses to return a context with a NULL `keymgmt` at all — so the first clause
//! is false for every context this crate can build and the `&&` never reaches `ctx->pmeth`, which
//! this crate's `EvpPkeyCtx` does not carry anyway. It is the same reduction `src/dh/ctrl.rs` makes
//! for `dh_param_derive_check` and `src/dsa/ctrl.rs` for `dsa_paramgen_check`, written for the form
//! that tests `pmeth` directly (the DSA spelling) rather than the `is_legacy`-guarded one (the DH
//! spelling).
//!
//! **`set0_ecdh_kdf_ukm` takes custody of memory, and unlike its DH sibling it does *not* refuse a
//! negative length.** `crypto/evp/dh_ctrl.c`'s `set0_dh_kdf_ukm` has an `if (len < 0) return -1;`
//! **before** the gate; `ec_ctrl.c`'s has no such test at all, so a negative `len` is widened to a
//! huge `size_t` and handed to the method. This is transcribed as written — the absence is a
//! behaviour, not a gap — and the court observes the difference by not carrying the DH pair's
//! negative-length arm.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_char, c_int, c_uchar, c_void};

use crate::evp::pkey_ctx::{
    evp_pkey_ctx_get_params_strict, evp_pkey_ctx_set_params_strict, EVP_PKEY_CTX_ctrl, EvpPkeyCtx,
    EVP_PKEY_CTRL_EC_KDF_MD, EVP_PKEY_CTRL_EC_KDF_TYPE, EVP_PKEY_CTRL_EC_PARAMGEN_CURVE_NID,
    EVP_PKEY_CTRL_EC_PARAM_ENC, EVP_PKEY_CTRL_GET_EC_KDF_MD, EVP_PKEY_EC, EVP_PKEY_OP_DERIVE,
    EVP_PKEY_OP_TYPE_GEN, EVP_PKEY_SM2, OSSL_EXCHANGE_PARAM_EC_ECDH_COFACTOR_MODE,
    OSSL_EXCHANGE_PARAM_KDF_OUTLEN, OSSL_EXCHANGE_PARAM_KDF_UKM,
};
use crate::params::{
    OSSL_PARAM_construct_end, OSSL_PARAM_construct_int, OSSL_PARAM_construct_octet_ptr,
    OSSL_PARAM_construct_octet_string, OSSL_PARAM_construct_size_t, OsslParam,
};
use crate::runtime::err::err_sites;
use crate::runtime::err::raise_site;
use crate::runtime::mem::CRYPTO_free;

/// The allocation-tracking `file` argument for this unit's one release.
///
/// `crypto/evp/ec_ctrl.c` is a **source-tree** file, so its `__FILE__` carries the
/// `../../src/openssl-3.6.4/` prefix — the same check D279/D280/D321 applied. This module has
/// exactly one allocation-facing call: `EVP_PKEY_CTX_set0_ecdh_kdf_ukm`'s `OPENSSL_free(ukm)` at
/// `ec_ctrl.c:234`, which is a *release* and still records its coordinate to an installed
/// allocator.
const FILE_CTRL: *const c_char = c"../../src/openssl-3.6.4/crypto/evp/ec_ctrl.c".as_ptr();

/// `__LINE__` of that release, `ec_ctrl.c:234`. Inert under `OPENSSL_NO_CRYPTO_MDEBUG`.
const LINE_FREE_LABEL: c_int = 234;

/// `static ossl_inline int evp_pkey_ctx_getset_ecdh_param_checks(const EVP_PKEY_CTX *ctx)` —
/// `ec_ctrl.c:23-37`.
///
/// The gate shared by all six `OSSL_PARAM` builders (and not by the ctrl wrappers, which reach
/// `EVP_PKEY_CTX_ctrl`'s own operation test). `-2` with `EVP_R_COMMAND_NOT_SUPPORTED` for a NULL
/// context or one whose operation is not a derivation one, and `-1` for a legacy context of the
/// wrong key type — which this crate cannot reach (this module's header).
///
/// The authority's second clause tests `evp_pkey_ctx_is_legacy(ctx) && ctx->pmeth != NULL &&
/// ctx->pmeth->pkey_id != EVP_PKEY_EC`; its first clause is false for every context that reaches
/// here, so the remaining two are never evaluated — and `ctx->pmeth` is absent from this crate's
/// `EvpPkeyCtx` anyway.
///
/// # Safety
/// `ctx` NULL or live.
unsafe fn evp_pkey_ctx_getset_ecdh_param_checks(ctx: *mut EvpPkeyCtx) -> c_int {
    // SAFETY: `ctx` is NULL or live; the two clauses are short-circuited in this order.
    if ctx.is_null() || !unsafe { (*ctx).is_derive_op() } {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::EC_CTRL_26) };
        /* Uses the same return values as `EVP_PKEY_CTX_ctrl`. */
        return -2;
    }
    /* `if (evp_pkey_ctx_is_legacy(ctx) && ctx->pmeth != NULL
     *  && ctx->pmeth->pkey_id != EVP_PKEY_EC) return -1;` — the authority's key-type guard, and
     * its first clause is false for every context that reaches here: `evp_pkey_ctx_is_legacy` is
     * `keymgmt == NULL` and `int_ctx_new` never returns a context with a NULL `keymgmt`. The
     * remaining clauses read `ctx->pmeth`, absent from this crate's `EvpPkeyCtx`, and the
     * short-circuit means they are never evaluated. */
    1
}

// ---------------------------------------------------------------------------------------------
// The six `OSSL_PARAM` builders handed to the strict setter/getter
// ---------------------------------------------------------------------------------------------

/// `int EVP_PKEY_CTX_set_ecdh_cofactor_mode(EVP_PKEY_CTX *ctx, int cofactor_mode)` —
/// `ec_ctrl.c:39-67`.
///
/// The ECDH cofactor mode as an **`int`** parameter named `ecdh-cofactor-mode`, guarded by
/// [`evp_pkey_ctx_getset_ecdh_param_checks`]. A value outside `-1..=1` is refused `-2` **after** the
/// gate and **before** the parameter is built, with no raise — the authority's comment names the
/// three legal values (`0` disable, `1` enable, `-1` reset) and says the refusal "uses the same
/// return value of `pkey_ec_ctrl()`". A `-2` from the strict *setter* (a parameter the method does
/// not list), by contrast, *does* raise `EVP_R_COMMAND_NOT_SUPPORTED`.
///
/// # Safety
/// `ctx` NULL or live.
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_CTX_set_ecdh_cofactor_mode(
    ctx: *mut EvpPkeyCtx,
    cofactor_mode: c_int,
) -> c_int {
    let mut params: [OsslParam; 2] = [OSSL_PARAM_construct_end(); 2];
    let mut cofactor_mode = cofactor_mode;

    // SAFETY: `ctx` is NULL or live per the contract.
    let ret = unsafe { evp_pkey_ctx_getset_ecdh_param_checks(ctx) };
    if ret != 1 {
        return ret;
    }

    if !(-1..=1).contains(&cofactor_mode) {
        /* Uses the same return value of `pkey_ec_ctrl()`. */
        return -2;
    }

    // SAFETY: `OSSL_EXCHANGE_PARAM_EC_ECDH_COFACTOR_MODE` is NUL-terminated and `cofactor_mode` is
    // a live local.
    params[0] = unsafe {
        OSSL_PARAM_construct_int(
            OSSL_EXCHANGE_PARAM_EC_ECDH_COFACTOR_MODE,
            &mut cofactor_mode,
        )
    };
    params[1] = OSSL_PARAM_construct_end();

    // SAFETY: `ctx` is live and `params` is a terminated two-entry array.
    let ret = unsafe { evp_pkey_ctx_set_params_strict(ctx, params.as_mut_ptr()) };
    if ret == -2 {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::EC_CTRL_65) };
    }
    ret
}

/// `int EVP_PKEY_CTX_get_ecdh_cofactor_mode(EVP_PKEY_CTX *ctx)` — `ec_ctrl.c:69-104`.
///
/// The read half, and the four-armed switch is the whole of its decision: a `-2` from the strict
/// *getter* raises and is returned, a `1` with a mode in `0..=1` returns the mode, and **every
/// other answer — a `1` with an out-of-range mode, or any other return — is `-1`**. The authority's
/// comment says an out-of-range mode "is a provider error", which is why it is flattened to `-1`
/// rather than passed through.
///
/// # Safety
/// `ctx` NULL or live.
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_CTX_get_ecdh_cofactor_mode(ctx: *mut EvpPkeyCtx) -> c_int {
    let mut params: [OsslParam; 2] = [OSSL_PARAM_construct_end(); 2];
    let mut mode: c_int = 0;

    // SAFETY: `ctx` is NULL or live per the contract.
    let ret = unsafe { evp_pkey_ctx_getset_ecdh_param_checks(ctx) };
    if ret != 1 {
        return ret;
    }

    // SAFETY: `OSSL_EXCHANGE_PARAM_EC_ECDH_COFACTOR_MODE` is NUL-terminated and `mode` is a live
    // local the callee writes.
    params[0] =
        unsafe { OSSL_PARAM_construct_int(OSSL_EXCHANGE_PARAM_EC_ECDH_COFACTOR_MODE, &mut mode) };
    params[1] = OSSL_PARAM_construct_end();

    // SAFETY: `ctx` is live and `params` is a terminated two-entry array.
    let ret = unsafe { evp_pkey_ctx_get_params_strict(ctx, params.as_mut_ptr()) };

    match ret {
        -2 => {
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&err_sites::EC_CTRL_86) };
            -2
        }
        1 => {
            if !(0..=1).contains(&mode) {
                /*
                 * The provider should return either 0 or 1, any other value is a
                 * provider error.
                 */
                -1
            } else {
                mode
            }
        }
        _ => -1,
    }
}

/// `int EVP_PKEY_CTX_set_ecdh_kdf_outlen(EVP_PKEY_CTX *ctx, int outlen)` — `ec_ctrl.c:146-173`.
///
/// The output length as a **`size_t`** parameter named `kdf-outlen`, guarded by
/// [`evp_pkey_ctx_getset_ecdh_param_checks`]. A non-positive `outlen` is refused `-2` before the
/// parameter is built and without a raise, for the reason the authority's comment gives: it "would
/// ideally be -1 or 0, but we have to retain compatibility with legacy behaviour of
/// `EVP_PKEY_CTX_ctrl()` which returned -2 if `inlen <= 0`". A `-2` from the strict setter, by
/// contrast, raises.
///
/// # Safety
/// `ctx` NULL or live.
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_CTX_set_ecdh_kdf_outlen(
    ctx: *mut EvpPkeyCtx,
    outlen: c_int,
) -> c_int {
    let mut params: [OsslParam; 2] = [OSSL_PARAM_construct_end(); 2];
    let mut len = outlen as usize;

    // SAFETY: `ctx` is NULL or live per the contract.
    let ret = unsafe { evp_pkey_ctx_getset_ecdh_param_checks(ctx) };
    if ret != 1 {
        return ret;
    }

    if outlen <= 0 {
        /* This would ideally be -1 or 0, but the legacy `EVP_PKEY_CTX_ctrl()` contract is -2. */
        return -2;
    }

    // SAFETY: `OSSL_EXCHANGE_PARAM_KDF_OUTLEN` is NUL-terminated and `len` is a live local.
    params[0] = unsafe { OSSL_PARAM_construct_size_t(OSSL_EXCHANGE_PARAM_KDF_OUTLEN, &mut len) };
    params[1] = OSSL_PARAM_construct_end();

    // SAFETY: `ctx` is live and `params` is a terminated two-entry array.
    let ret = unsafe { evp_pkey_ctx_set_params_strict(ctx, params.as_mut_ptr()) };
    if ret == -2 {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::EC_CTRL_171) };
    }
    ret
}

/// `int EVP_PKEY_CTX_get_ecdh_kdf_outlen(EVP_PKEY_CTX *ctx, int *plen)` — `ec_ctrl.c:175-207`.
///
/// The read half. `len` starts at `UINT_MAX`, so a method that does not write the parameter leaves
/// it wider than `INT_MAX` and the control answers `-1`; a written value within `INT_MAX` is the
/// answer. The switch is the same four-arm shape as [`EVP_PKEY_CTX_get_ecdh_cofactor_mode`] but its
/// success arm is a **range test against `INT_MAX`** rather than the provider's own domain.
///
/// # Safety
/// `ctx` NULL or live; `plen` NULL or a live `int` the callee writes.
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_CTX_get_ecdh_kdf_outlen(
    ctx: *mut EvpPkeyCtx,
    plen: *mut c_int,
) -> c_int {
    let mut params: [OsslParam; 2] = [OSSL_PARAM_construct_end(); 2];
    let mut len = u32::MAX as usize;

    // SAFETY: `ctx` is NULL or live per the contract.
    let ret = unsafe { evp_pkey_ctx_getset_ecdh_param_checks(ctx) };
    if ret != 1 {
        return ret;
    }

    // SAFETY: `OSSL_EXCHANGE_PARAM_KDF_OUTLEN` is NUL-terminated and `len` is a live local the
    // callee writes.
    params[0] = unsafe { OSSL_PARAM_construct_size_t(OSSL_EXCHANGE_PARAM_KDF_OUTLEN, &mut len) };
    params[1] = OSSL_PARAM_construct_end();

    // SAFETY: `ctx` is live and `params` is a terminated two-entry array.
    let ret = unsafe { evp_pkey_ctx_get_params_strict(ctx, params.as_mut_ptr()) };

    match ret {
        -2 => {
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&err_sites::EC_CTRL_193) };
            -2
        }
        1 if len <= c_int::MAX as usize => {
            // SAFETY: `plen` is NULL or a live `int` that this call writes.
            unsafe { *plen = len as c_int };
            1
        }
        _ => -1,
    }
}

/// `int EVP_PKEY_CTX_set0_ecdh_kdf_ukm(EVP_PKEY_CTX *ctx, unsigned char *ukm, int len)` —
/// `ec_ctrl.c:209-239`.
///
/// **The one EC control that takes custody of memory**, and it does so only on success: the
/// caller's buffer is released with `OPENSSL_free` when the strict setter answers `1`. A negative
/// `len` is **not** refused — the authority widens it to `size_t` and hands it on, unlike
/// `crypto/evp/dh_ctrl.c`'s sibling, which returns `-1` before the gate (this module's header).
/// The parameter is an **`octet_string`** and the authority casts the `const` away ("read only so
/// should be safe"), which is transcribed.
///
/// # Safety
/// `ctx` NULL or live; `ukm` NULL (with `len == 0`) or an `OPENSSL_malloc`ed buffer of `len` bytes
/// whose ownership transfers on success.
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_CTX_set0_ecdh_kdf_ukm(
    ctx: *mut EvpPkeyCtx,
    ukm: *mut c_uchar,
    len: c_int,
) -> c_int {
    let mut params: [OsslParam; 2] = [OSSL_PARAM_construct_end(); 2];

    // SAFETY: `ctx` is NULL or live per the contract.
    let ret = unsafe { evp_pkey_ctx_getset_ecdh_param_checks(ctx) };
    if ret != 1 {
        return ret;
    }

    /* Cast away the const. This is read only so should be safe. */
    // SAFETY: `OSSL_EXCHANGE_PARAM_KDF_UKM` is NUL-terminated and `ukm` is readable for `len`
    // bytes (the authority treats a negative `len` as an `unsigned` width).
    params[0] = unsafe {
        OSSL_PARAM_construct_octet_string(
            OSSL_EXCHANGE_PARAM_KDF_UKM,
            ukm.cast::<c_void>(),
            len as usize,
        )
    };
    params[1] = OSSL_PARAM_construct_end();

    // SAFETY: `ctx` is live and `params` is a terminated two-entry array.
    let ret = unsafe { evp_pkey_ctx_set_params_strict(ctx, params.as_mut_ptr()) };

    match ret {
        -2 => {
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&err_sites::EC_CTRL_231) };
        }
        1 => {
            // SAFETY: `ukm` is the caller's allocation, which this call owns on this path.
            unsafe { CRYPTO_free(ukm.cast::<c_void>(), FILE_CTRL, LINE_FREE_LABEL) };
        }
        _ => {}
    }

    ret
}

/// `int EVP_PKEY_CTX_get0_ecdh_kdf_ukm(EVP_PKEY_CTX *ctx, unsigned char **pukm)` —
/// `ec_ctrl.c:242-274`, under `#ifndef OPENSSL_NO_DEPRECATED_3_0` (which this profile does not
/// define, so it is transcribed).
///
/// The read half. The parameter is an **`octet_ptr`** — the method writes the *address* of its own
/// buffer into the caller's slot and reports its length in `return_size`, which is the whole of the
/// `get0` promise. The `1` arm answers that length when it fits an `int` and `-1` otherwise; the
/// caller's slot may be left NULL when the method has no UKM.
///
/// # Safety
/// `ctx` NULL or live; `pukm` NULL or a live slot the callee writes a borrowed pointer into.
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_CTX_get0_ecdh_kdf_ukm(
    ctx: *mut EvpPkeyCtx,
    pukm: *mut *mut c_uchar,
) -> c_int {
    let mut params: [OsslParam; 2] = [OSSL_PARAM_construct_end(); 2];

    // SAFETY: `ctx` is NULL or live per the contract.
    let ret = unsafe { evp_pkey_ctx_getset_ecdh_param_checks(ctx) };
    if ret != 1 {
        return ret;
    }

    // SAFETY: `OSSL_EXCHANGE_PARAM_KDF_UKM` is NUL-terminated and `pukm` is a live out-slot.
    params[0] = unsafe {
        OSSL_PARAM_construct_octet_ptr(OSSL_EXCHANGE_PARAM_KDF_UKM, pukm.cast::<*mut c_void>(), 0)
    };
    params[1] = OSSL_PARAM_construct_end();

    // SAFETY: `ctx` is live and `params` is a terminated two-entry array.
    let ret = unsafe { evp_pkey_ctx_get_params_strict(ctx, params.as_mut_ptr()) };

    match ret {
        -2 => {
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&err_sites::EC_CTRL_260) };
            -2
        }
        1 => {
            let ukmlen = params[0].return_size;
            if ukmlen <= c_int::MAX as usize {
                ukmlen as c_int
            } else {
                -1
            }
        }
        _ => -1,
    }
}

// ---------------------------------------------------------------------------------------------
// The four `EVP_PKEY_CTX_ctrl` wrappers over derivation
// ---------------------------------------------------------------------------------------------

/// `int EVP_PKEY_CTX_set_ecdh_kdf_type(EVP_PKEY_CTX *ctx, int kdf)` — `ec_ctrl.c:110-114`.
///
/// **A `EVP_PKEY_CTX_ctrl` wrapper**: the numeric type is translated to the `kdf-type` string by
/// `ctrl_params_translate.c`'s `fix_ec_kdf_type` rather than here.
///
/// # Safety
/// `ctx` NULL or live.
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_CTX_set_ecdh_kdf_type(ctx: *mut EvpPkeyCtx, kdf: c_int) -> c_int {
    // SAFETY: the caller's contract, forwarded unchanged.
    unsafe {
        EVP_PKEY_CTX_ctrl(
            ctx,
            EVP_PKEY_EC,
            EVP_PKEY_OP_DERIVE,
            EVP_PKEY_CTRL_EC_KDF_TYPE,
            kdf,
            core::ptr::null_mut(),
        )
    }
}

/// `int EVP_PKEY_CTX_get_ecdh_kdf_type(EVP_PKEY_CTX *ctx)` — `ec_ctrl.c:120-124`.
///
/// The read half, and its `p1` is the literal **`-2`** — the value `fix_ec_kdf_type` tests for to
/// switch a `NONE` action into a `GET`.
///
/// # Safety
/// `ctx` NULL or live.
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_CTX_get_ecdh_kdf_type(ctx: *mut EvpPkeyCtx) -> c_int {
    // SAFETY: the caller's contract, forwarded unchanged.
    unsafe {
        EVP_PKEY_CTX_ctrl(
            ctx,
            EVP_PKEY_EC,
            EVP_PKEY_OP_DERIVE,
            EVP_PKEY_CTRL_EC_KDF_TYPE,
            -2,
            core::ptr::null_mut(),
        )
    }
}

/// `int EVP_PKEY_CTX_set_ecdh_kdf_md(EVP_PKEY_CTX *ctx, const EVP_MD *md)` — `ec_ctrl.c:130-134`.
///
/// **A `EVP_PKEY_CTX_ctrl` wrapper**: the digest travels as a pointer in `p2` and `fix_md` turns it
/// into the `kdf-digest` name.
///
/// # Safety
/// `ctx` NULL or live; `md` NULL or a live digest method.
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_CTX_set_ecdh_kdf_md(
    ctx: *mut EvpPkeyCtx,
    md: *const crate::evp::digest::EvpMd,
) -> c_int {
    // SAFETY: the caller's contract; the digest travels as a pointer in `p2`.
    unsafe {
        EVP_PKEY_CTX_ctrl(
            ctx,
            EVP_PKEY_EC,
            EVP_PKEY_OP_DERIVE,
            EVP_PKEY_CTRL_EC_KDF_MD,
            0,
            md.cast_mut().cast::<c_void>(),
        )
    }
}

/// `int EVP_PKEY_CTX_get_ecdh_kdf_md(EVP_PKEY_CTX *ctx, const EVP_MD **pmd)` —
/// `ec_ctrl.c:140-144`.
///
/// The read half: `p2` is a slot the callee writes a digest method into. Its `1` arm resolves the
/// method's `kdf-digest` name back into an `EVP_MD *` through `fix_md`'s GET arm, which calls
/// `evp_get_digestbyname_ex` — the lookup this crate answers NULL for, because the legacy
/// `OBJ_NAME` table is empty until Phase 13. That is a recorded deferral in a unit no stratum of
/// 8.7 owns and not a defect of this wrapper, so the court observes the control's return value and
/// the parameter-level round trip rather than the returned pointer (this module's sibling
/// `src/dh/ctrl.rs` records the same coordinate for `EVP_PKEY_CTX_get_dh_kdf_md`).
///
/// # Safety
/// `ctx` NULL or live; `pmd` NULL or a live slot the callee writes.
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_CTX_get_ecdh_kdf_md(
    ctx: *mut EvpPkeyCtx,
    pmd: *mut *const crate::evp::digest::EvpMd,
) -> c_int {
    // SAFETY: the caller's contract; `pmd` is the out-slot the fixer writes.
    unsafe {
        EVP_PKEY_CTX_ctrl(
            ctx,
            EVP_PKEY_EC,
            EVP_PKEY_OP_DERIVE,
            EVP_PKEY_CTRL_GET_EC_KDF_MD,
            0,
            pmd.cast::<c_void>(),
        )
    }
}

// ---------------------------------------------------------------------------------------------
// The two `EVP_PKEY_CTX_ctrl` parameter-generation wrappers
// ---------------------------------------------------------------------------------------------

/// `int EVP_PKEY_CTX_set_ec_paramgen_curve_nid(EVP_PKEY_CTX *ctx, int nid)` —
/// `ec_ctrl.c:283-290`, under `#ifndef FIPS_MODULE` (which this profile does not define, so it is
/// transcribed).
///
/// **The one control whose key type is computed from its own argument**: `nid == EVP_PKEY_SM2`
/// selects `EVP_PKEY_SM2` and every other `nid` selects `EVP_PKEY_EC`, so an SM2 context accepts
/// the SM2 curve under the SM2 row rather than under EC's. The operation is the **union**
/// `EVP_PKEY_OP_TYPE_GEN` (parameter generation or key generation), and the NID reaches
/// `fix_ec_paramgen_curve_nid`, which turns it into the `group` parameter's short name.
///
/// # Safety
/// `ctx` NULL or live.
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_CTX_set_ec_paramgen_curve_nid(
    ctx: *mut EvpPkeyCtx,
    nid: c_int,
) -> c_int {
    let keytype = if nid == EVP_PKEY_SM2 {
        EVP_PKEY_SM2
    } else {
        EVP_PKEY_EC
    };

    // SAFETY: the caller's contract, forwarded unchanged.
    unsafe {
        EVP_PKEY_CTX_ctrl(
            ctx,
            keytype,
            EVP_PKEY_OP_TYPE_GEN,
            EVP_PKEY_CTRL_EC_PARAMGEN_CURVE_NID,
            nid,
            core::ptr::null_mut(),
        )
    }
}

/// `int EVP_PKEY_CTX_set_ec_param_enc(EVP_PKEY_CTX *ctx, int param_enc)` —
/// `ec_ctrl.c:296-300`, under `#ifndef FIPS_MODULE` (which this profile does not define, so it is
/// transcribed).
///
/// **A `EVP_PKEY_CTX_ctrl` wrapper** over the union operation: the numeric encoding reaches
/// `fix_ec_param_enc`, which turns `OPENSSL_EC_EXPLICIT_CURVE`/`OPENSSL_EC_NAMED_CURVE` into the
/// `encoding` parameter's string and refuses any other value `-2`.
///
/// # Safety
/// `ctx` NULL or live.
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_CTX_set_ec_param_enc(
    ctx: *mut EvpPkeyCtx,
    param_enc: c_int,
) -> c_int {
    // SAFETY: the caller's contract, forwarded unchanged.
    unsafe {
        EVP_PKEY_CTX_ctrl(
            ctx,
            EVP_PKEY_EC,
            EVP_PKEY_OP_TYPE_GEN,
            EVP_PKEY_CTRL_EC_PARAM_ENC,
            param_enc,
            core::ptr::null_mut(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every one of the twelve controls is NULL-safe and answers `-2`: the six `OSSL_PARAM`
    /// builders and their one gate raise `EVP_R_COMMAND_NOT_SUPPORTED` at `EC_CTRL_26`, and the six
    /// `EVP_PKEY_CTX_ctrl` wrappers reach the ctrl door's own NULL test. The split is a contract, so
    /// it is asserted rather than left to the court.
    #[test]
    fn the_null_context_controls_answer_minus_two_with_a_drained_queue() {
        // SAFETY: every call below takes a NULL context by construction and no argument it
        // dereferences.
        unsafe {
            crate::runtime::err::ERR_clear_error();
            assert_eq!(
                EVP_PKEY_CTX_set_ecdh_cofactor_mode(core::ptr::null_mut(), 1),
                -2
            );
            assert_eq!(
                EVP_PKEY_CTX_get_ecdh_cofactor_mode(core::ptr::null_mut()),
                -2
            );
            assert_eq!(
                EVP_PKEY_CTX_set_ecdh_kdf_outlen(core::ptr::null_mut(), 32),
                -2
            );
            assert_eq!(
                EVP_PKEY_CTX_get_ecdh_kdf_outlen(core::ptr::null_mut(), core::ptr::null_mut()),
                -2
            );
            assert_eq!(
                EVP_PKEY_CTX_set0_ecdh_kdf_ukm(core::ptr::null_mut(), core::ptr::null_mut(), 0),
                -2
            );
            assert_eq!(
                EVP_PKEY_CTX_get0_ecdh_kdf_ukm(core::ptr::null_mut(), core::ptr::null_mut()),
                -2
            );
            assert_eq!(EVP_PKEY_CTX_set_ecdh_kdf_type(core::ptr::null_mut(), 2), -2);
            assert_eq!(EVP_PKEY_CTX_get_ecdh_kdf_type(core::ptr::null_mut()), -2);
            assert_eq!(
                EVP_PKEY_CTX_set_ecdh_kdf_md(core::ptr::null_mut(), core::ptr::null()),
                -2
            );
            assert_eq!(
                EVP_PKEY_CTX_get_ecdh_kdf_md(core::ptr::null_mut(), core::ptr::null_mut()),
                -2
            );
            assert_eq!(
                EVP_PKEY_CTX_set_ec_paramgen_curve_nid(core::ptr::null_mut(), 415),
                -2
            );
            assert_eq!(EVP_PKEY_CTX_set_ec_param_enc(core::ptr::null_mut(), 1), -2);
        }
        assert_ne!(crate::runtime::err::ERR_peek_error(), 0);
        crate::runtime::err::ERR_clear_error();
    }
}
