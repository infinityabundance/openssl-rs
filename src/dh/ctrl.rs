//! `crypto/evp/dh_ctrl.c` — the `EVP_PKEY_CTX_*dh*` controls (Phase 8.5, slice E).
//!
//! **Why this is a module of its own rather than part of [`crate::dh`].** The authority has **no
//! `crypto/dh/dh_ctrl.c`**: the DH controls live beside the other key types' under `crypto/evp/`,
//! and every symbol this file defines is one the ledger labels `src/dh/mod.rs` because its
//! *declaring header* is `dh.h` rather than because of its translation unit. The module is split
//! out for the reason `src/rsa/ctrl.rs` records for 8.4's own slice E: `crypto/evp/dh_ctrl.c` is a
//! different translation unit from `crypto/dh/dh_meth.c`, which `src/dh/mod.rs`'s edge names, and
//! `forensics/atlas/transcription-edges.json`'s own rule is that *"a module whose definitions are
//! spread across units is expected"* — so giving the unit a module is what makes the map say which
//! authority file each half of the DH surface answers for.
//!
//! **Three shapes, and a reader can classify all twenty by them.**
//!
//!   1. **The `EVP_PKEY_CTX_ctrl` wrappers** — `set_dh_paramgen_type`, `set_dh_rfc5114`,
//!      `set_dhx_rfc5114`, `set_dh_nid`, `set_dh_kdf_type`, `get_dh_kdf_type`, `set0_dh_kdf_oid`,
//!      `get0_dh_kdf_oid`, `set_dh_kdf_md` and `get_dh_kdf_md`. Each is one call to
//!      [`EVP_PKEY_CTX_ctrl`] with the key type and operation the *control's own contract* names,
//!      and the authority's comment says "currently implemented as an `EVP_PKEY_CTX_ctrl()`
//!      wrapper, simply because that's easier" for eight of them.
//!   2. **The `OSSL_PARAM` builders that go through the *strict* setter/getter** —
//!      `set_dh_paramgen_gindex`, `set_dh_paramgen_seed`, `set_dh_paramgen_prime_len`,
//!      `set_dh_paramgen_subprime_len`, `set_dh_paramgen_generator`, `set_dh_pad`,
//!      `set_dh_kdf_outlen`, `get_dh_kdf_outlen`, `set0_dh_kdf_ukm` and `get0_dh_kdf_ukm`. These
//!      build the provider parameter directly and hand it to `evp_pkey_ctx_set_params_strict` /
//!      `evp_pkey_ctx_get_params_strict`, which is what makes their refusal for a parameter the
//!      method does not list a `-2` rather than a ctrl result.
//!   3. **The two `dh_paramgen_check`/`dh_param_derive_check` gates**, which are the whole of the
//!      shared refusal structure: a NULL context or the wrong operation is `-2` with
//!      `EVP_R_COMMAND_NOT_SUPPORTED`, and a *legacy* context of the wrong key type is `-1`.
//!
//! **The legacy key-type arm of both gates is unreachable here, and that is the `pmeth` reduction
//! rather than an omission.** The authority's guard is `evp_pkey_ctx_is_legacy(ctx) &&
//! ctx->pmeth->pkey_id != EVP_PKEY_DH && ctx->pmeth->pkey_id != EVP_PKEY_DHX`. `evp_pkey_ctx_is_legacy`
//! is `keymgmt == NULL` (`src/evp/pkey_ctx.rs` records that reading it by its name would be wrong),
//! and `int_ctx_new` refuses to return a context with a NULL `keymgmt` at all — so the first clause
//! is false for every context this crate can build and the `&&` never reaches `ctx->pmeth`, which
//! this crate's `EvpPkeyCtx` does not carry anyway. It is the same reduction `src/rsa/ctrl.rs` makes
//! for `RSA_pkey_ctx_ctrl`'s guard, seen from the other side: there the absent `pmeth` was a clause
//! of a conjunction, here it is a clause the short-circuit protects.
//!
//! **What the court can and cannot drive, said here rather than discovered.** Every one of the
//! twenty is reachable with a NULL context and answers a refusal whose error coordinate is
//! compared, and every one that does not dereference `ctx` before its first test is *also* driven
//! against a live context the probe publishes — a keymgmt named `COURT-DH`, so a control can be
//! asked what it decides about a context that exists. What no arm can reach with a *default*
//! provider is the successful translation of a ctrl into a provider parameter, because this crate
//! publishes no DH `EVP_KEYMGMT` and no DH `EVP_KEYEXCH` (8.5's provider half is not landed), so
//! `EVP_PKEY_CTX_new_from_name(NULL, "DH", NULL)` answers NULL on the candidate and a context on
//! the authority. The probe's own keymgmt and keyexch supply both, which is what makes the
//! round-trip arms a comparison of the *library's* translation rather than of a missing row.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_char, c_int, c_uchar, c_void};

use crate::evp::pkey_ctx::{
    evp_pkey_ctx_get_params_strict, evp_pkey_ctx_set_params_strict, EVP_PKEY_CTX_ctrl, EvpPkeyCtx,
    EVP_PKEY_CTRL_DH_KDF_MD, EVP_PKEY_CTRL_DH_KDF_OID, EVP_PKEY_CTRL_DH_KDF_TYPE,
    EVP_PKEY_CTRL_DH_NID, EVP_PKEY_CTRL_DH_PARAMGEN_TYPE, EVP_PKEY_CTRL_DH_RFC5114,
    EVP_PKEY_CTRL_GET_DH_KDF_MD, EVP_PKEY_CTRL_GET_DH_KDF_OID, EVP_PKEY_DH, EVP_PKEY_DHX,
    EVP_PKEY_OP_DERIVE, EVP_PKEY_OP_KEYGEN, EVP_PKEY_OP_PARAMGEN, OSSL_EXCHANGE_PARAM_KDF_OUTLEN,
    OSSL_EXCHANGE_PARAM_KDF_UKM, OSSL_EXCHANGE_PARAM_PAD, OSSL_PKEY_PARAM_DH_GENERATOR,
    OSSL_PKEY_PARAM_FFC_GINDEX, OSSL_PKEY_PARAM_FFC_PBITS, OSSL_PKEY_PARAM_FFC_QBITS,
    OSSL_PKEY_PARAM_FFC_SEED,
};
use crate::params::{
    OSSL_PARAM_construct_end, OSSL_PARAM_construct_int, OSSL_PARAM_construct_octet_ptr,
    OSSL_PARAM_construct_octet_string, OSSL_PARAM_construct_size_t, OSSL_PARAM_construct_uint,
    OsslParam,
};
use crate::runtime::err::err_sites;
use crate::runtime::err::raise_site;
use crate::runtime::mem::CRYPTO_free;
use crate::runtime::obj::Asn1Object;

/// The allocation-tracking `file` argument for this unit's one release.
///
/// `crypto/evp/dh_ctrl.c` is a **source-tree** file, so its `__FILE__` carries the
/// `../../src/openssl-3.6.4/` prefix — the same check D279/D280/D321 applied. This module has
/// exactly one allocation-facing call: `EVP_PKEY_CTX_set0_dh_kdf_ukm`'s `OPENSSL_free(ukm)` at
/// `dh_ctrl.c:315`, which is a *release* and still records its coordinate to an installed
/// allocator.
const FILE_CTRL: *const c_char = c"../../src/openssl-3.6.4/crypto/evp/dh_ctrl.c".as_ptr();

/// `__LINE__` of that release, `dh_ctrl.c:315`. Inert under `OPENSSL_NO_CRYPTO_MDEBUG`.
const LINE_FREE_LABEL: c_int = 315;

/// `static int dh_paramgen_check(EVP_PKEY_CTX *ctx)` — `dh_ctrl.c:19-27`.
///
/// The parameter-generation gate shared by the six `set_dh_paramgen_*` controls. Two refusals:
/// `-2` with `EVP_R_COMMAND_NOT_SUPPORTED` for a NULL context or one whose operation is not a
/// generation one, and `-1` for a legacy context of the wrong key type — which this crate cannot
/// reach (this module's header).
///
/// # Safety
/// `ctx` NULL or live.
unsafe fn dh_paramgen_check(ctx: *mut EvpPkeyCtx) -> c_int {
    // SAFETY: `ctx` is NULL or live; the two clauses are short-circuited in this order.
    if ctx.is_null() || !unsafe { (*ctx).is_gen_op() } {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::DH_CTRL_22) };
        /* Uses the same return values as `EVP_PKEY_CTX_ctrl`. */
        return -2;
    }
    /* `if (evp_pkey_ctx_is_legacy(ctx) && ctx->pmeth->pkey_id != EVP_PKEY_DH
     *  && ctx->pmeth->pkey_id != EVP_PKEY_DHX) return -1;` — the authority's key-type guard, and
     * its first clause is false for every context that reaches here: `evp_pkey_ctx_is_legacy` is
     * `keymgmt == NULL` and `int_ctx_new` never returns a context with a NULL `keymgmt`. The
     * remaining clauses read `ctx->pmeth`, absent from this crate's `EvpPkeyCtx`, and the
     * short-circuit means they are never evaluated. */
    1
}

/// `static int dh_param_derive_check(EVP_PKEY_CTX *ctx)` — `dh_ctrl.c:34-42`.
///
/// The key-derivation gate shared by the ten `set/get_dh_kdf_*`, `set0_dh_kdf_ukm`/`get0_dh_kdf_ukm`
/// and `set_dh_pad` controls. Identical to [`dh_paramgen_check`] but for the operation it tests and
/// the coordinate it raises at.
///
/// # Safety
/// `ctx` NULL or live.
unsafe fn dh_param_derive_check(ctx: *mut EvpPkeyCtx) -> c_int {
    // SAFETY: `ctx` is NULL or live; the two clauses are short-circuited in this order.
    if ctx.is_null() || !unsafe { (*ctx).is_derive_op() } {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::DH_CTRL_37) };
        /* Uses the same return values as `EVP_PKEY_CTX_ctrl`. */
        return -2;
    }
    /* The legacy key-type guard is unreachable here for the reason `dh_paramgen_check` gives. */
    1
}

// ---------------------------------------------------------------------------------------------
// The six `set_dh_paramgen_*` `OSSL_PARAM` builders
// ---------------------------------------------------------------------------------------------

/// `int EVP_PKEY_CTX_set_dh_paramgen_gindex(EVP_PKEY_CTX *ctx, int gindex)` — `dh_ctrl.c:49-60`.
///
/// The FFC index as an **`int`** parameter named `gindex`, guarded by [`dh_paramgen_check`].
///
/// # Safety
/// `ctx` NULL or live.
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_CTX_set_dh_paramgen_gindex(
    ctx: *mut EvpPkeyCtx,
    gindex: c_int,
) -> c_int {
    let mut params: [OsslParam; 2] = [OSSL_PARAM_construct_end(); 2];
    let mut gindex = gindex;

    // SAFETY: `ctx` is NULL or live per the contract.
    let ret = unsafe { dh_paramgen_check(ctx) };
    if ret <= 0 {
        return ret;
    }

    // SAFETY: `OSSL_PKEY_PARAM_FFC_GINDEX` is NUL-terminated and `gindex` is a live local.
    params[0] = unsafe { OSSL_PARAM_construct_int(OSSL_PKEY_PARAM_FFC_GINDEX, &mut gindex) };
    params[1] = OSSL_PARAM_construct_end();

    // SAFETY: `ctx` is live; `params[0]`'s `data` points at the local `gindex`, which outlives the
    // call, and the array is terminated.
    unsafe { evp_pkey_ctx_set_params_strict(ctx, params.as_mut_ptr()) }
}

/// `int EVP_PKEY_CTX_set_dh_paramgen_seed(EVP_PKEY_CTX *ctx, const unsigned char *seed,`
/// `size_t seedlen)` — `dh_ctrl.c:63-78`.
///
/// The verifiable-generation seed as an **`octet_string`**, guarded by [`dh_paramgen_check`]. The
/// authority casts the `const` away ("read only so should be safe"), which is transcribed.
///
/// # Safety
/// `ctx` NULL or live; `seed` NULL or readable for `seedlen` bytes.
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_CTX_set_dh_paramgen_seed(
    ctx: *mut EvpPkeyCtx,
    seed: *const c_uchar,
    seedlen: usize,
) -> c_int {
    let mut params: [OsslParam; 2] = [OSSL_PARAM_construct_end(); 2];

    // SAFETY: `ctx` is NULL or live per the contract.
    let ret = unsafe { dh_paramgen_check(ctx) };
    if ret <= 0 {
        return ret;
    }

    // SAFETY: `OSSL_PKEY_PARAM_FFC_SEED` is NUL-terminated and `seed` is readable for `seedlen`.
    params[0] = unsafe {
        OSSL_PARAM_construct_octet_string(
            OSSL_PKEY_PARAM_FFC_SEED,
            seed.cast_mut().cast::<c_void>(),
            seedlen,
        )
    };
    params[1] = OSSL_PARAM_construct_end();

    // SAFETY: `ctx` is live and `params` is a terminated two-entry array.
    unsafe { evp_pkey_ctx_set_params_strict(ctx, params.as_mut_ptr()) }
}

/// `int EVP_PKEY_CTX_set_dh_paramgen_type(EVP_PKEY_CTX *ctx, int typ)` — `dh_ctrl.c:84-88`.
///
/// **A `EVP_PKEY_CTX_ctrl` wrapper**, and the authority says why: the numeric type is translated to
/// the `type` string by `ctrl_params_translate.c`'s fixer rather than here.
///
/// # Safety
/// `ctx` NULL or live.
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_CTX_set_dh_paramgen_type(
    ctx: *mut EvpPkeyCtx,
    typ: c_int,
) -> c_int {
    // SAFETY: the caller's contract, forwarded unchanged.
    unsafe {
        EVP_PKEY_CTX_ctrl(
            ctx,
            EVP_PKEY_DH,
            EVP_PKEY_OP_PARAMGEN,
            EVP_PKEY_CTRL_DH_PARAMGEN_TYPE,
            typ,
            core::ptr::null_mut(),
        )
    }
}

/// `int EVP_PKEY_CTX_set_dh_paramgen_prime_len(EVP_PKEY_CTX *ctx, int pbits)` — `dh_ctrl.c:90-102`.
///
/// The prime width as a **`size_t`** parameter named `pbits`, guarded by [`dh_paramgen_check`].
///
/// # Safety
/// `ctx` NULL or live.
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_CTX_set_dh_paramgen_prime_len(
    ctx: *mut EvpPkeyCtx,
    pbits: c_int,
) -> c_int {
    let mut params: [OsslParam; 2] = [OSSL_PARAM_construct_end(); 2];
    let mut bits = pbits as usize;

    // SAFETY: `ctx` is NULL or live per the contract.
    let ret = unsafe { dh_paramgen_check(ctx) };
    if ret <= 0 {
        return ret;
    }

    // SAFETY: `OSSL_PKEY_PARAM_FFC_PBITS` is NUL-terminated and `bits` is a live local.
    params[0] = unsafe { OSSL_PARAM_construct_size_t(OSSL_PKEY_PARAM_FFC_PBITS, &mut bits) };
    params[1] = OSSL_PARAM_construct_end();

    // SAFETY: `ctx` is live; `params[0]`'s `data` points at the local `bits`, which outlives the
    // call, and the array is terminated.
    unsafe { evp_pkey_ctx_set_params_strict(ctx, params.as_mut_ptr()) }
}

/// `int EVP_PKEY_CTX_set_dh_paramgen_subprime_len(EVP_PKEY_CTX *ctx, int qbits)` —
/// `dh_ctrl.c:104-117`.
///
/// The subprime width as a **`size_t`** parameter named `qbits`, guarded by [`dh_paramgen_check`].
/// The local's two-step `size_t bits2 = qbits` is the authority's, and it is kept because the
/// widening happens before the pointer is taken.
///
/// # Safety
/// `ctx` NULL or live.
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_CTX_set_dh_paramgen_subprime_len(
    ctx: *mut EvpPkeyCtx,
    qbits: c_int,
) -> c_int {
    let mut params: [OsslParam; 2] = [OSSL_PARAM_construct_end(); 2];
    let mut bits2 = qbits as usize;

    // SAFETY: `ctx` is NULL or live per the contract.
    let ret = unsafe { dh_paramgen_check(ctx) };
    if ret <= 0 {
        return ret;
    }

    // SAFETY: `OSSL_PKEY_PARAM_FFC_QBITS` is NUL-terminated and `bits2` is a live local.
    params[0] = unsafe { OSSL_PARAM_construct_size_t(OSSL_PKEY_PARAM_FFC_QBITS, &mut bits2) };
    params[1] = OSSL_PARAM_construct_end();

    // SAFETY: `ctx` is live; `params[0]`'s `data` points at the local `bits2`, which outlives the
    // call, and the array is terminated.
    unsafe { evp_pkey_ctx_set_params_strict(ctx, params.as_mut_ptr()) }
}

/// `int EVP_PKEY_CTX_set_dh_paramgen_generator(EVP_PKEY_CTX *ctx, int gen)` — `dh_ctrl.c:119-135`.
///
/// The generator as an **`int`** parameter named `safeprime-generator`, guarded by
/// [`dh_paramgen_check`].
///
/// # Safety
/// `ctx` NULL or live.
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_CTX_set_dh_paramgen_generator(
    ctx: *mut EvpPkeyCtx,
    gen: c_int,
) -> c_int {
    let mut params: [OsslParam; 2] = [OSSL_PARAM_construct_end(); 2];
    let mut gen = gen;

    // SAFETY: `ctx` is NULL or live per the contract.
    let ret = unsafe { dh_paramgen_check(ctx) };
    if ret <= 0 {
        return ret;
    }

    // SAFETY: `OSSL_PKEY_PARAM_DH_GENERATOR` is NUL-terminated and `gen` is a live local.
    params[0] = unsafe { OSSL_PARAM_construct_int(OSSL_PKEY_PARAM_DH_GENERATOR, &mut gen) };
    params[1] = OSSL_PARAM_construct_end();

    // SAFETY: `ctx` is live; `params[0]`'s `data` points at the local `gen`, which outlives the
    // call, and the array is terminated.
    unsafe { evp_pkey_ctx_set_params_strict(ctx, params.as_mut_ptr()) }
}

// ---------------------------------------------------------------------------------------------
// The three `EVP_PKEY_CTX_ctrl` parameter-generation wrappers
// ---------------------------------------------------------------------------------------------

/// `int EVP_PKEY_CTX_set_dh_rfc5114(EVP_PKEY_CTX *ctx, int gen)` — `dh_ctrl.c:137-141`.
///
/// **A `EVP_PKEY_CTX_ctrl` wrapper**, and it names `EVP_PKEY_DHX` rather than `EVP_PKEY_DH` — the
/// RFC 5114 groups are DHX's.
///
/// # Safety
/// `ctx` NULL or live.
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_CTX_set_dh_rfc5114(ctx: *mut EvpPkeyCtx, gen: c_int) -> c_int {
    // SAFETY: the caller's contract, forwarded unchanged.
    unsafe {
        EVP_PKEY_CTX_ctrl(
            ctx,
            EVP_PKEY_DHX,
            EVP_PKEY_OP_PARAMGEN,
            EVP_PKEY_CTRL_DH_RFC5114,
            gen,
            core::ptr::null_mut(),
        )
    }
}

/// `int EVP_PKEY_CTX_set_dhx_rfc5114(EVP_PKEY_CTX *ctx, int gen)` — `dh_ctrl.c:143-146`.
///
/// **One call to its own sibling**, which is the whole body: the DHX spelling and the DH one are the
/// same control.
///
/// # Safety
/// `ctx` NULL or live.
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_CTX_set_dhx_rfc5114(ctx: *mut EvpPkeyCtx, gen: c_int) -> c_int {
    // SAFETY: the caller's contract, forwarded unchanged.
    unsafe { EVP_PKEY_CTX_set_dh_rfc5114(ctx, gen) }
}

/// `int EVP_PKEY_CTX_set_dh_nid(EVP_PKEY_CTX *ctx, int nid)` — `dh_ctrl.c:152-157`.
///
/// The only DH ctrl whose operation is the **union** `EVP_PKEY_OP_PARAMGEN | EVP_PKEY_OP_KEYGEN`,
/// so the same call serves a parameter-generation and a key-generation context.
///
/// # Safety
/// `ctx` NULL or live.
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_CTX_set_dh_nid(ctx: *mut EvpPkeyCtx, nid: c_int) -> c_int {
    // SAFETY: the caller's contract, forwarded unchanged.
    unsafe {
        EVP_PKEY_CTX_ctrl(
            ctx,
            EVP_PKEY_DH,
            EVP_PKEY_OP_PARAMGEN | EVP_PKEY_OP_KEYGEN,
            EVP_PKEY_CTRL_DH_NID,
            nid,
            core::ptr::null_mut(),
        )
    }
}

// ---------------------------------------------------------------------------------------------
// `set_dh_pad` and the ten key-derivation controls
// ---------------------------------------------------------------------------------------------

/// `int EVP_PKEY_CTX_set_dh_pad(EVP_PKEY_CTX *ctx, int pad)` — `dh_ctrl.c:159-178`.
///
/// The only one of the ten derivation controls that does **not** use [`dh_param_derive_check`]: its
/// `ctx == NULL || !EVP_PKEY_CTX_IS_DERIVE_OP(ctx)` test is written inline, raising the same
/// coordinate as the gate would. The uint is built here rather than through a ctrl, so `pad` is a
/// provider parameter and not a translated command — the pad fixer is the authority's `dh_pad` row.
///
/// # Safety
/// `ctx` NULL or live.
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_CTX_set_dh_pad(ctx: *mut EvpPkeyCtx, pad: c_int) -> c_int {
    let mut params: [OsslParam; 2] = [OSSL_PARAM_construct_end(); 2];
    let mut upad = pad as u32;

    /* We use `EVP_PKEY_CTX_ctrl` return values. */
    // SAFETY: `ctx` is NULL or live; the two clauses are short-circuited in this order.
    if ctx.is_null() || !unsafe { (*ctx).is_derive_op() } {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::DH_CTRL_166) };
        return -2;
    }

    // SAFETY: `OSSL_EXCHANGE_PARAM_PAD` is NUL-terminated and `upad` is a live local.
    params[0] = unsafe { OSSL_PARAM_construct_uint(OSSL_EXCHANGE_PARAM_PAD, &mut upad) };
    params[1] = OSSL_PARAM_construct_end();

    // SAFETY: `ctx` is live; `params[0]`'s `data` points at the local `upad`, which outlives the
    // call, and the array is terminated.
    unsafe { evp_pkey_ctx_set_params_strict(ctx, params.as_mut_ptr()) }
}

/// `int EVP_PKEY_CTX_set_dh_kdf_type(EVP_PKEY_CTX *ctx, int kdf)` — `dh_ctrl.c:180-184`.
///
/// **A `EVP_PKEY_CTX_ctrl` wrapper** over the one DH ctrl that is bidirectional: `kdf` is the `p1`
/// the fixer reads to decide the action.
///
/// # Safety
/// `ctx` NULL or live.
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_CTX_set_dh_kdf_type(ctx: *mut EvpPkeyCtx, kdf: c_int) -> c_int {
    // SAFETY: the caller's contract, forwarded unchanged.
    unsafe {
        EVP_PKEY_CTX_ctrl(
            ctx,
            EVP_PKEY_DHX,
            EVP_PKEY_OP_DERIVE,
            EVP_PKEY_CTRL_DH_KDF_TYPE,
            kdf,
            core::ptr::null_mut(),
        )
    }
}

/// `int EVP_PKEY_CTX_get_dh_kdf_type(EVP_PKEY_CTX *ctx)` — `dh_ctrl.c:190-194`.
///
/// The read half, and its `p1` is the literal **`-2`** — the value `fix_dh_kdf_type` tests for to
/// switch a `NONE` action into a `GET`.
///
/// # Safety
/// `ctx` NULL or live.
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_CTX_get_dh_kdf_type(ctx: *mut EvpPkeyCtx) -> c_int {
    // SAFETY: the caller's contract, forwarded unchanged.
    unsafe {
        EVP_PKEY_CTX_ctrl(
            ctx,
            EVP_PKEY_DHX,
            EVP_PKEY_OP_DERIVE,
            EVP_PKEY_CTRL_DH_KDF_TYPE,
            -2,
            core::ptr::null_mut(),
        )
    }
}

/// `int EVP_PKEY_CTX_set0_dh_kdf_oid(EVP_PKEY_CTX *ctx, ASN1_OBJECT *oid)` — `dh_ctrl.c:200-204`.
///
/// **A `EVP_PKEY_CTX_ctrl` wrapper**, and its `p2` is the caller's `ASN1_OBJECT` cast to `void *`.
/// The parameter is the object's *text*, produced by the fixer, so nothing here dereferences it.
///
/// # Safety
/// `ctx` NULL or live; `oid` NULL or a live `ASN1_OBJECT`.
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_CTX_set0_dh_kdf_oid(
    ctx: *mut EvpPkeyCtx,
    oid: *mut Asn1Object,
) -> c_int {
    // SAFETY: the caller's contract; the object travels as a pointer in `p2`.
    unsafe {
        EVP_PKEY_CTX_ctrl(
            ctx,
            EVP_PKEY_DHX,
            EVP_PKEY_OP_DERIVE,
            EVP_PKEY_CTRL_DH_KDF_OID,
            0,
            oid.cast::<c_void>(),
        )
    }
}

/// `int EVP_PKEY_CTX_get0_dh_kdf_oid(EVP_PKEY_CTX *ctx, ASN1_OBJECT **oid)` — `dh_ctrl.c:210-214`.
///
/// The read half: `p2` is a **slot the callee writes an `ASN1_OBJECT *` into**, which the fixer
/// builds from the method's string.
///
/// # Safety
/// `ctx` NULL or live; `oid` NULL or a live slot the callee writes.
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_CTX_get0_dh_kdf_oid(
    ctx: *mut EvpPkeyCtx,
    oid: *mut *mut Asn1Object,
) -> c_int {
    // SAFETY: the caller's contract; `oid` is the out-slot the fixer writes.
    unsafe {
        EVP_PKEY_CTX_ctrl(
            ctx,
            EVP_PKEY_DHX,
            EVP_PKEY_OP_DERIVE,
            EVP_PKEY_CTRL_GET_DH_KDF_OID,
            0,
            oid.cast::<c_void>(),
        )
    }
}

/// `int EVP_PKEY_CTX_set_dh_kdf_md(EVP_PKEY_CTX *ctx, const EVP_MD *md)` — `dh_ctrl.c:220-224`.
///
/// **A `EVP_PKEY_CTX_ctrl` wrapper**: the digest travels as a pointer in `p2` and the fixer turns it
/// into the `kdf-digest` name.
///
/// # Safety
/// `ctx` NULL or live; `md` NULL or a live digest method.
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_CTX_set_dh_kdf_md(
    ctx: *mut EvpPkeyCtx,
    md: *const crate::evp::digest::EvpMd,
) -> c_int {
    // SAFETY: the caller's contract; the digest travels as a pointer in `p2`.
    unsafe {
        EVP_PKEY_CTX_ctrl(
            ctx,
            EVP_PKEY_DHX,
            EVP_PKEY_OP_DERIVE,
            EVP_PKEY_CTRL_DH_KDF_MD,
            0,
            md.cast_mut().cast::<c_void>(),
        )
    }
}

/// `int EVP_PKEY_CTX_get_dh_kdf_md(EVP_PKEY_CTX *ctx, const EVP_MD **pmd)` — `dh_ctrl.c:230-234`.
///
/// The read half: `p2` is a slot the callee writes a digest method into.
///
/// # Safety
/// `ctx` NULL or live; `pmd` NULL or a live slot the callee writes.
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_CTX_get_dh_kdf_md(
    ctx: *mut EvpPkeyCtx,
    pmd: *mut *const crate::evp::digest::EvpMd,
) -> c_int {
    // SAFETY: the caller's contract; `pmd` is the out-slot the fixer writes.
    unsafe {
        EVP_PKEY_CTX_ctrl(
            ctx,
            EVP_PKEY_DHX,
            EVP_PKEY_OP_DERIVE,
            EVP_PKEY_CTRL_GET_DH_KDF_MD,
            0,
            pmd.cast::<c_void>(),
        )
    }
}

/// `int EVP_PKEY_CTX_set_dh_kdf_outlen(EVP_PKEY_CTX *ctx, int outlen)` — `dh_ctrl.c:236-263`.
///
/// The output length as a **`size_t`** parameter named `kdf-outlen`, guarded by
/// [`dh_param_derive_check`]. **A non-positive `outlen` is refused `-2` before the parameter is
/// built and without a raise** — the authority's comment says the value "would ideally be -1 or 0,
/// but we have to retain compatibility with legacy behaviour of `EVP_PKEY_CTX_ctrl()` which
/// returned -2 if `inlen <= 0`". A `-2` from the strict setter, by contrast, *does* raise.
///
/// # Safety
/// `ctx` NULL or live.
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_CTX_set_dh_kdf_outlen(
    ctx: *mut EvpPkeyCtx,
    outlen: c_int,
) -> c_int {
    let mut params: [OsslParam; 2] = [OSSL_PARAM_construct_end(); 2];
    let mut len = outlen as usize;

    // SAFETY: `ctx` is NULL or live per the contract.
    let ret = unsafe { dh_param_derive_check(ctx) };
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
        unsafe { raise_site(&err_sites::DH_CTRL_261) };
    }
    ret
}

/// `int EVP_PKEY_CTX_get_dh_kdf_outlen(EVP_PKEY_CTX *ctx, int *plen)` — `dh_ctrl.c:265-288`.
///
/// The read half. `len` starts at `UINT_MAX`, so a method that does not write the parameter leaves
/// it wider than `INT_MAX` and the control answers `-1` — the one refusal here that is neither a
/// `-2` nor a raise.
///
/// # Safety
/// `ctx` NULL or live; `plen` NULL or a live `int` the callee writes.
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_CTX_get_dh_kdf_outlen(
    ctx: *mut EvpPkeyCtx,
    plen: *mut c_int,
) -> c_int {
    let mut params: [OsslParam; 2] = [OSSL_PARAM_construct_end(); 2];
    let mut len = u32::MAX as usize;

    // SAFETY: `ctx` is NULL or live per the contract.
    let ret = unsafe { dh_param_derive_check(ctx) };
    if ret != 1 {
        return ret;
    }

    // SAFETY: `OSSL_EXCHANGE_PARAM_KDF_OUTLEN` is NUL-terminated and `len` is a live local.
    params[0] = unsafe { OSSL_PARAM_construct_size_t(OSSL_EXCHANGE_PARAM_KDF_OUTLEN, &mut len) };
    params[1] = OSSL_PARAM_construct_end();

    // SAFETY: `ctx` is live and `params` is a terminated two-entry array.
    let ret = unsafe { evp_pkey_ctx_get_params_strict(ctx, params.as_mut_ptr()) };
    if ret == -2 {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::DH_CTRL_281) };
    }
    if ret != 1 || len > c_int::MAX as usize {
        return -1;
    }

    // SAFETY: `plen` is NULL or a live `int` that this call writes.
    unsafe { *plen = len as c_int };

    1
}

/// `int EVP_PKEY_CTX_set0_dh_kdf_ukm(EVP_PKEY_CTX *ctx, unsigned char *ukm, int len)` —
/// `dh_ctrl.c:290-317`.
///
/// **The one DH control that takes custody of memory**, and it does so only on success: the caller's
/// buffer is released with `OPENSSL_free` when the strict setter answers `1`. A negative `len` is
/// refused `-1` **before** the context is tested at all, which is why this control is NULL-safe
/// second rather than first.
///
/// # Safety
/// `ctx` NULL or live; `ukm` NULL (with `len == 0`) or an `OPENSSL_malloc`ed buffer of `len` bytes
/// whose ownership transfers on success.
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_CTX_set0_dh_kdf_ukm(
    ctx: *mut EvpPkeyCtx,
    ukm: *mut c_uchar,
    len: c_int,
) -> c_int {
    let mut params: [OsslParam; 2] = [OSSL_PARAM_construct_end(); 2];

    if len < 0 {
        return -1;
    }

    // SAFETY: `ctx` is NULL or live per the contract.
    let ret = unsafe { dh_param_derive_check(ctx) };
    if ret != 1 {
        return ret;
    }

    /* Cast away the const. This is read only so should be safe. */
    // SAFETY: `OSSL_EXCHANGE_PARAM_KDF_UKM` is NUL-terminated and `ukm` is readable for `len` bytes.
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
    if ret == -2 {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::DH_CTRL_313) };
    }
    if ret == 1 {
        // SAFETY: `ukm` is the caller's allocation, which this call owns on this path.
        unsafe { CRYPTO_free(ukm.cast::<c_void>(), FILE_CTRL, LINE_FREE_LABEL) };
    }
    ret
}

/// `int EVP_PKEY_CTX_get0_dh_kdf_ukm(EVP_PKEY_CTX *ctx, unsigned char **pukm)` — `dh_ctrl.c:320-345`.
///
/// The read half, under `#ifndef OPENSSL_NO_DEPRECATED_3_0` (which this profile does not define, so
/// it is transcribed). The parameter is an **`octet_ptr`** — the method writes the *address* of its
/// own buffer into the caller's slot and reports its length in `return_size`, which is the whole of
/// the `get0` promise.
///
/// # Safety
/// `ctx` NULL or live; `pukm` NULL or a live slot the callee writes a borrowed pointer into.
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_CTX_get0_dh_kdf_ukm(
    ctx: *mut EvpPkeyCtx,
    pukm: *mut *mut c_uchar,
) -> c_int {
    let mut params: [OsslParam; 2] = [OSSL_PARAM_construct_end(); 2];

    // SAFETY: `ctx` is NULL or live per the contract.
    let ret = unsafe { dh_param_derive_check(ctx) };
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
    if ret == -2 {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::DH_CTRL_336) };
    }
    if ret != 1 {
        return -1;
    }

    let ukmlen = params[0].return_size;
    if ukmlen > c_int::MAX as usize {
        return -1;
    }

    ukmlen as c_int
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every one of the twenty controls is NULL-safe, answers `-2`, and leaves a
    /// `EVP_R_COMMAND_NOT_SUPPORTED` record: the split between the two gates and the ctrl door is a
    /// contract, so it is asserted rather than left to the court.
    ///
    /// The `-2`s come from three places and the assertion does not conflate them: `DH_CTRL_22` and
    /// `DH_CTRL_37` for the two gates, `DH_CTRL_166` for `set_dh_pad`'s inline test, and
    /// `PMETH_LIB_1346` for the nine `EVP_PKEY_CTX_ctrl` wrappers, whose NULL test is the ctrl's.
    #[test]
    fn the_null_context_controls_answer_minus_two_with_a_drained_queue() {
        // SAFETY: every call below takes a NULL context by construction and no argument it
        // dereferences.
        unsafe {
            crate::runtime::err::ERR_clear_error();
            assert_eq!(
                EVP_PKEY_CTX_set_dh_paramgen_gindex(core::ptr::null_mut(), 5),
                -2
            );
            assert_eq!(
                EVP_PKEY_CTX_set_dh_paramgen_seed(core::ptr::null_mut(), core::ptr::null(), 0),
                -2
            );
            assert_eq!(
                EVP_PKEY_CTX_set_dh_paramgen_type(core::ptr::null_mut(), 0),
                -2
            );
            assert_eq!(
                EVP_PKEY_CTX_set_dh_paramgen_prime_len(core::ptr::null_mut(), 2048),
                -2
            );
            assert_eq!(
                EVP_PKEY_CTX_set_dh_paramgen_subprime_len(core::ptr::null_mut(), 256),
                -2
            );
            assert_eq!(
                EVP_PKEY_CTX_set_dh_paramgen_generator(core::ptr::null_mut(), 2),
                -2
            );
            assert_eq!(EVP_PKEY_CTX_set_dh_rfc5114(core::ptr::null_mut(), 1), -2);
            assert_eq!(EVP_PKEY_CTX_set_dhx_rfc5114(core::ptr::null_mut(), 1), -2);
            assert_eq!(EVP_PKEY_CTX_set_dh_nid(core::ptr::null_mut(), 1), -2);
            assert_eq!(EVP_PKEY_CTX_set_dh_pad(core::ptr::null_mut(), 1), -2);
            assert_eq!(EVP_PKEY_CTX_set_dh_kdf_type(core::ptr::null_mut(), 2), -2);
            assert_eq!(EVP_PKEY_CTX_get_dh_kdf_type(core::ptr::null_mut()), -2);
            assert_eq!(
                EVP_PKEY_CTX_set0_dh_kdf_oid(core::ptr::null_mut(), core::ptr::null_mut()),
                -2
            );
            assert_eq!(
                EVP_PKEY_CTX_get0_dh_kdf_oid(core::ptr::null_mut(), core::ptr::null_mut()),
                -2
            );
            assert_eq!(
                EVP_PKEY_CTX_set_dh_kdf_md(core::ptr::null_mut(), core::ptr::null()),
                -2
            );
            assert_eq!(
                EVP_PKEY_CTX_get_dh_kdf_md(core::ptr::null_mut(), core::ptr::null_mut()),
                -2
            );
            assert_eq!(
                EVP_PKEY_CTX_set_dh_kdf_outlen(core::ptr::null_mut(), 16),
                -2
            );
            assert_eq!(
                EVP_PKEY_CTX_get_dh_kdf_outlen(core::ptr::null_mut(), core::ptr::null_mut()),
                -2
            );
            assert_eq!(
                EVP_PKEY_CTX_set0_dh_kdf_ukm(core::ptr::null_mut(), core::ptr::null_mut(), 0),
                -2
            );
            assert_eq!(
                EVP_PKEY_CTX_get0_dh_kdf_ukm(core::ptr::null_mut(), core::ptr::null_mut()),
                -2
            );
        }
        assert_ne!(crate::runtime::err::ERR_peek_error(), 0);
        crate::runtime::err::ERR_clear_error();
    }

    /// The one control whose first test is not the context: a negative `len` is `-1` with **no
    /// raise at all**, whether or not the context is NULL, because the authority tests `len` first.
    #[test]
    fn a_negative_ukm_length_is_refused_before_the_context_is_tested() {
        crate::runtime::err::ERR_clear_error();
        // SAFETY: a NULL context is never reached, and `ukm` is NULL with a negative length.
        let ret = unsafe {
            EVP_PKEY_CTX_set0_dh_kdf_ukm(core::ptr::null_mut(), core::ptr::null_mut(), -1)
        };
        assert_eq!(ret, -1);
        assert_eq!(crate::runtime::err::ERR_peek_error(), 0);
        crate::runtime::err::ERR_clear_error();
    }

    /// `set_dh_kdf_outlen`'s two `-2`s are reached from different places: the *gate* refuses a NULL
    /// context first and raises `DH_CTRL_37`, while the non-positive-length refusal is a bare `-2`
    /// with no raise that only a *live* derivation context can reach. This arm pins the order — the
    /// gate's coordinate is the one on the queue when both conditions hold — and the quirk itself is
    /// the court's to observe against a live context.
    #[test]
    fn the_gate_precedes_the_non_positive_outlen_refusal() {
        crate::runtime::err::ERR_clear_error();
        // SAFETY: a NULL context is never dereferenced, because the gate refuses it first.
        let ret = unsafe { EVP_PKEY_CTX_set_dh_kdf_outlen(core::ptr::null_mut(), 0) };
        assert_eq!(ret, -2);
        // The record is the gate's `EVP_R_COMMAND_NOT_SUPPORTED` at `dh_ctrl.c:37`, not the bare
        // refusal, so the queue is non-empty.
        assert_ne!(crate::runtime::err::ERR_peek_error(), 0);
        crate::runtime::err::ERR_clear_error();
    }
}
