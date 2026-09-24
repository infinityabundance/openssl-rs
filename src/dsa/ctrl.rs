//! `crypto/evp/dsa_ctrl.c` — the `EVP_PKEY_CTX_set_dsa_paramgen_*` controls (Phase 8.6, slice E).
//!
//! **Why this is a module of its own rather than part of [`crate::dsa`].** There is **no
//! `crypto/dsa/dsa_ctrl.c` in the authority**: the `EVP_PKEY_CTX_*dsa*` controls live beside the
//! other key types' under `crypto/evp/`, and every symbol this file defines is one the ledger labels
//! `src/dsa/mod.rs` because its *declaring header* is `dsa.h`. The module is split out for the
//! reason `src/rsa/ctrl.rs` records for 8.4's own slice E and [`crate::dh::ctrl`] for 8.5's:
//! `crypto/evp/dsa_ctrl.c` is a translation unit of its own, and giving it a module is what makes
//! `forensics/atlas/transcription-edges.json` say which authority file the DSA control surface
//! answers for.
//!
//! **One static gate and seven `OSSL_PARAM` builders.** [`dsa_paramgen_check`] is the shared
//! refusal structure — a NULL context or a context whose operation is not a generation one is `-2`
//! with `EVP_R_COMMAND_NOT_SUPPORTED` — and six of the seven exports build a provider parameter and
//! hand it to [`EVP_PKEY_CTX_set_params`] (the **non-strict** spelling, unlike the DH controls'
//! `evp_pkey_ctx_set_params_strict`). The seventh, `set_dsa_paramgen_md`, is an
//! `EVP_PKEY_CTX_ctrl` wrapper and the authority's own comment says so.
//!
//! **The key-type arm of the gate is unreachable here, and it reads `pmeth` rather than
//! `legacy_keytype`.** The authority's guard is `ctx->pmeth != NULL && ctx->pmeth->pkey_id !=
//! EVP_PKEY_DSA` — note that it is **not** gated on `evp_pkey_ctx_is_legacy`, unlike the DH pair.
//! This crate's `EvpPkeyCtx` does not carry `pmeth` at all, so the first clause is false for every
//! context and the guard refuses nothing — the reduction `src/rsa/ctrl.rs` records for
//! `RSA_pkey_ctx_ctrl`'s own `pmeth`-shaped guard, applied to the form that tests `pmeth` directly.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_char, c_int, c_uchar};

use crate::evp::pkey_ctx::{
    EVP_PKEY_CTX_ctrl, EVP_PKEY_CTX_set_params, EvpPkeyCtx, EVP_PKEY_CTRL_DSA_PARAMGEN_MD,
    EVP_PKEY_DSA, EVP_PKEY_OP_PARAMGEN, OSSL_PKEY_PARAM_FFC_DIGEST,
    OSSL_PKEY_PARAM_FFC_DIGEST_PROPS, OSSL_PKEY_PARAM_FFC_GINDEX, OSSL_PKEY_PARAM_FFC_PBITS,
    OSSL_PKEY_PARAM_FFC_QBITS, OSSL_PKEY_PARAM_FFC_SEED, OSSL_PKEY_PARAM_FFC_TYPE,
};
use crate::params::{
    OSSL_PARAM_construct_end, OSSL_PARAM_construct_int, OSSL_PARAM_construct_octet_string,
    OSSL_PARAM_construct_size_t, OSSL_PARAM_construct_utf8_string, OsslParam,
};
use crate::runtime::err::err_sites;
use crate::runtime::err::raise_site;

/// `static int dsa_paramgen_check(EVP_PKEY_CTX *ctx)` — `dsa_ctrl.c:17-23`.
///
/// The parameter-generation gate shared by all seven controls. `-2` with
/// `EVP_R_COMMAND_NOT_SUPPORTED` for a NULL context or one whose operation is not a generation one.
/// The authority's second clause tests `ctx->pmeth` **directly** rather than through
/// `evp_pkey_ctx_is_legacy`, and this crate's `EvpPkeyCtx` has no `pmeth` — so it is always NULL and
/// the `!= NULL` clause is false, which is why the key-type refusal is not written (this module's
/// header).
///
/// # Safety
/// `ctx` NULL or live.
unsafe fn dsa_paramgen_check(ctx: *mut EvpPkeyCtx) -> c_int {
    // SAFETY: `ctx` is NULL or live; the two clauses are short-circuited in this order.
    if ctx.is_null() || !unsafe { (*ctx).is_gen_op() } {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::DSA_CTRL_20) };
        /* Uses the same return values as `EVP_PKEY_CTX_ctrl`. */
        return -2;
    }
    /* `if (ctx->pmeth != NULL && ctx->pmeth->pkey_id != EVP_PKEY_DSA) return -1;` — unreachable:
     * `ctx->pmeth` is absent from this crate's `EvpPkeyCtx`, so the first clause is false for every
     * context and the `&&` never evaluates the `pkey_id` test. */
    1
}

/// `int EVP_PKEY_CTX_set_dsa_paramgen_type(EVP_PKEY_CTX *ctx, const char *name)` —
/// `dsa_ctrl.c:30-43`.
///
/// The generation type as a **`utf8_string`** parameter named `type`, guarded by
/// [`dsa_paramgen_check`]. The authority casts `const` away; the callee reads only.
///
/// # Safety
/// `ctx` NULL or live; `name` NULL or NUL-terminated.
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_CTX_set_dsa_paramgen_type(
    ctx: *mut EvpPkeyCtx,
    name: *const c_char,
) -> c_int {
    let mut params: [OsslParam; 2] = [OSSL_PARAM_construct_end(); 2];

    // SAFETY: `ctx` is NULL or live per the contract.
    let ret = unsafe { dsa_paramgen_check(ctx) };
    if ret <= 0 {
        return ret;
    }

    // SAFETY: `OSSL_PKEY_PARAM_FFC_TYPE` is NUL-terminated and `name` is NUL-terminated.
    params[0] =
        unsafe { OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAM_FFC_TYPE, name.cast_mut(), 0) };
    params[1] = OSSL_PARAM_construct_end();

    // SAFETY: `ctx` is live and `params` is a terminated two-entry array.
    unsafe { EVP_PKEY_CTX_set_params(ctx, params.as_ptr()) }
}

/// `int EVP_PKEY_CTX_set_dsa_paramgen_gindex(EVP_PKEY_CTX *ctx, int gindex)` — `dsa_ctrl.c:45-57`.
///
/// The FFC index as an **`int`** parameter named `gindex`, guarded by [`dsa_paramgen_check`].
///
/// # Safety
/// `ctx` NULL or live.
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_CTX_set_dsa_paramgen_gindex(
    ctx: *mut EvpPkeyCtx,
    gindex: c_int,
) -> c_int {
    let mut params: [OsslParam; 2] = [OSSL_PARAM_construct_end(); 2];
    let mut gindex = gindex;

    // SAFETY: `ctx` is NULL or live per the contract.
    let ret = unsafe { dsa_paramgen_check(ctx) };
    if ret <= 0 {
        return ret;
    }

    // SAFETY: `OSSL_PKEY_PARAM_FFC_GINDEX` is NUL-terminated and `gindex` is a live local.
    params[0] = unsafe { OSSL_PARAM_construct_int(OSSL_PKEY_PARAM_FFC_GINDEX, &mut gindex) };
    params[1] = OSSL_PARAM_construct_end();

    // SAFETY: `ctx` is live; `params[0]`'s `data` points at the local `gindex`, which outlives the
    // call, and the array is terminated.
    unsafe { EVP_PKEY_CTX_set_params(ctx, params.as_ptr()) }
}

/// `int EVP_PKEY_CTX_set_dsa_paramgen_seed(EVP_PKEY_CTX *ctx, const unsigned char *seed,`
/// `size_t seedlen)` — `dsa_ctrl.c:59-74`.
///
/// The verifiable-generation seed as an **`octet_string`**, guarded by [`dsa_paramgen_check`].
///
/// # Safety
/// `ctx` NULL or live; `seed` NULL or readable for `seedlen` bytes.
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_CTX_set_dsa_paramgen_seed(
    ctx: *mut EvpPkeyCtx,
    seed: *const c_uchar,
    seedlen: usize,
) -> c_int {
    let mut params: [OsslParam; 2] = [OSSL_PARAM_construct_end(); 2];

    // SAFETY: `ctx` is NULL or live per the contract.
    let ret = unsafe { dsa_paramgen_check(ctx) };
    if ret <= 0 {
        return ret;
    }

    // SAFETY: `OSSL_PKEY_PARAM_FFC_SEED` is NUL-terminated and `seed` is readable for `seedlen`.
    params[0] = unsafe {
        OSSL_PARAM_construct_octet_string(
            OSSL_PKEY_PARAM_FFC_SEED,
            seed.cast_mut().cast::<core::ffi::c_void>(),
            seedlen,
        )
    };
    params[1] = OSSL_PARAM_construct_end();

    // SAFETY: `ctx` is live and `params` is a terminated two-entry array.
    unsafe { EVP_PKEY_CTX_set_params(ctx, params.as_ptr()) }
}

/// `int EVP_PKEY_CTX_set_dsa_paramgen_bits(EVP_PKEY_CTX *ctx, int nbits)` — `dsa_ctrl.c:76-89`.
///
/// The prime width as a **`size_t`** parameter named `pbits`, guarded by [`dsa_paramgen_check`].
///
/// # Safety
/// `ctx` NULL or live.
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_CTX_set_dsa_paramgen_bits(
    ctx: *mut EvpPkeyCtx,
    nbits: c_int,
) -> c_int {
    let mut params: [OsslParam; 2] = [OSSL_PARAM_construct_end(); 2];
    let mut bits = nbits as usize;

    // SAFETY: `ctx` is NULL or live per the contract.
    let ret = unsafe { dsa_paramgen_check(ctx) };
    if ret <= 0 {
        return ret;
    }

    // SAFETY: `OSSL_PKEY_PARAM_FFC_PBITS` is NUL-terminated and `bits` is a live local.
    params[0] = unsafe { OSSL_PARAM_construct_size_t(OSSL_PKEY_PARAM_FFC_PBITS, &mut bits) };
    params[1] = OSSL_PARAM_construct_end();

    // SAFETY: `ctx` is live; `params[0]`'s `data` points at the local `bits`, which outlives the
    // call, and the array is terminated.
    unsafe { EVP_PKEY_CTX_set_params(ctx, params.as_ptr()) }
}

/// `int EVP_PKEY_CTX_set_dsa_paramgen_q_bits(EVP_PKEY_CTX *ctx, int qbits)` — `dsa_ctrl.c:91-104`.
///
/// The subprime width as a **`size_t`** parameter named `qbits`, guarded by [`dsa_paramgen_check`].
///
/// # Safety
/// `ctx` NULL or live.
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_CTX_set_dsa_paramgen_q_bits(
    ctx: *mut EvpPkeyCtx,
    qbits: c_int,
) -> c_int {
    let mut params: [OsslParam; 2] = [OSSL_PARAM_construct_end(); 2];
    let mut bits2 = qbits as usize;

    // SAFETY: `ctx` is NULL or live per the contract.
    let ret = unsafe { dsa_paramgen_check(ctx) };
    if ret <= 0 {
        return ret;
    }

    // SAFETY: `OSSL_PKEY_PARAM_FFC_QBITS` is NUL-terminated and `bits2` is a live local.
    params[0] = unsafe { OSSL_PARAM_construct_size_t(OSSL_PKEY_PARAM_FFC_QBITS, &mut bits2) };
    params[1] = OSSL_PARAM_construct_end();

    // SAFETY: `ctx` is live; `params[0]`'s `data` points at the local `bits2`, which outlives the
    // call, and the array is terminated.
    unsafe { EVP_PKEY_CTX_set_params(ctx, params.as_ptr()) }
}

/// `int EVP_PKEY_CTX_set_dsa_paramgen_md_props(EVP_PKEY_CTX *ctx, const char *md_name,`
/// `const char *md_properties)` — `dsa_ctrl.c:106-124`.
///
/// The one control that builds **two** parameters: the digest `name` always, and the property query
/// only when `md_properties` is non-NULL — which is why the array is three entries and the
/// authority walks a `p` cursor rather than indexing. A NULL property string is therefore an
/// *omitted* parameter and not an empty one, which the court observes through the method that
/// receives it.
///
/// # Safety
/// `ctx` NULL or live; `md_name` NULL or NUL-terminated; `md_properties` NULL or NUL-terminated.
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_CTX_set_dsa_paramgen_md_props(
    ctx: *mut EvpPkeyCtx,
    md_name: *const c_char,
    md_properties: *const c_char,
) -> c_int {
    let mut params: [OsslParam; 3] = [OSSL_PARAM_construct_end(); 3];
    let mut p = 0usize;

    // SAFETY: `ctx` is NULL or live per the contract.
    let ret = unsafe { dsa_paramgen_check(ctx) };
    if ret <= 0 {
        return ret;
    }

    // SAFETY: `OSSL_PKEY_PARAM_FFC_DIGEST` is NUL-terminated and `md_name` is NUL-terminated.
    params[p] = unsafe {
        OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAM_FFC_DIGEST, md_name.cast_mut(), 0)
    };
    p += 1;
    if !md_properties.is_null() {
        // SAFETY: `OSSL_PKEY_PARAM_FFC_DIGEST_PROPS` is NUL-terminated and `md_properties` is
        // NUL-terminated. The array has room for the second parameter plus the terminator.
        params[p] = unsafe {
            OSSL_PARAM_construct_utf8_string(
                OSSL_PKEY_PARAM_FFC_DIGEST_PROPS,
                md_properties.cast_mut(),
                0,
            )
        };
        p += 1;
    }
    params[p] = OSSL_PARAM_construct_end();

    // SAFETY: `ctx` is live and `params` is a terminated array of `p + 1` entries.
    unsafe { EVP_PKEY_CTX_set_params(ctx, params.as_ptr()) }
}

/// `int EVP_PKEY_CTX_set_dsa_paramgen_md(EVP_PKEY_CTX *ctx, const EVP_MD *md)` —
/// `dsa_ctrl.c:127-131`, under `#if !defined(FIPS_MODULE)` (which this profile does not define, so
/// it is transcribed).
///
/// **An `EVP_PKEY_CTX_ctrl` wrapper**: the digest travels as a pointer in `p2` and the translation
/// table's `fix_md` turns it into the `digest` name.
///
/// # Safety
/// `ctx` NULL or live; `md` NULL or a live digest method.
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_CTX_set_dsa_paramgen_md(
    ctx: *mut EvpPkeyCtx,
    md: *const crate::evp::digest::EvpMd,
) -> c_int {
    // SAFETY: the caller's contract; the digest travels as a pointer in `p2`.
    unsafe {
        EVP_PKEY_CTX_ctrl(
            ctx,
            EVP_PKEY_DSA,
            EVP_PKEY_OP_PARAMGEN,
            EVP_PKEY_CTRL_DSA_PARAMGEN_MD,
            0,
            md.cast_mut().cast::<core::ffi::c_void>(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// All seven controls are NULL-safe and answer `-2`: six raise the gate's
    /// `EVP_R_COMMAND_NOT_SUPPORTED` at `dsa_ctrl.c:20`, and `set_dsa_paramgen_md` reaches the ctrl
    /// door's own NULL test. The split is a contract, so it is asserted rather than left to the
    /// court.
    #[test]
    fn the_null_context_controls_answer_minus_two_with_a_drained_queue() {
        // SAFETY: every call below takes a NULL context by construction and no argument it
        // dereferences.
        unsafe {
            crate::runtime::err::ERR_clear_error();
            assert_eq!(
                EVP_PKEY_CTX_set_dsa_paramgen_type(core::ptr::null_mut(), core::ptr::null()),
                -2
            );
            assert_eq!(
                EVP_PKEY_CTX_set_dsa_paramgen_gindex(core::ptr::null_mut(), 5),
                -2
            );
            assert_eq!(
                EVP_PKEY_CTX_set_dsa_paramgen_seed(core::ptr::null_mut(), core::ptr::null(), 0),
                -2
            );
            assert_eq!(
                EVP_PKEY_CTX_set_dsa_paramgen_bits(core::ptr::null_mut(), 2048),
                -2
            );
            assert_eq!(
                EVP_PKEY_CTX_set_dsa_paramgen_q_bits(core::ptr::null_mut(), 256),
                -2
            );
            assert_eq!(
                EVP_PKEY_CTX_set_dsa_paramgen_md_props(
                    core::ptr::null_mut(),
                    core::ptr::null(),
                    core::ptr::null()
                ),
                -2
            );
            assert_eq!(
                EVP_PKEY_CTX_set_dsa_paramgen_md(core::ptr::null_mut(), core::ptr::null()),
                -2
            );
        }
        assert_ne!(crate::runtime::err::ERR_peek_error(), 0);
        crate::runtime::err::ERR_clear_error();
    }
}
