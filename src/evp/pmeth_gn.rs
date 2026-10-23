//! Phase 7.4c-ii — `crypto/evp/pmeth_gn.c`: the generation family and the data family.
//!
//! All fourteen of the file's exports. The fourteenth, `EVP_PKEY_new_mac_key`, was withheld by
//! 7.4c-ii and D173 as "gated the way `signature.c`'s operation half is" (`docs/DECISIONS.md`
//! D171, D172): it is `EVP_PKEY_CTX_new_id` (then 7.4c-ii's own, unlanded) plus
//! `EVP_PKEY_CTX_set_mac_key` (`ctrl_params_translate.c`, then unlanded). Both landed in 7.4c's
//! later slices -- `EVP_PKEY_CTX_new_id` in D186, the ctrl plane in D188 -- so the gate D173
//! named is gone and D193's sweep folded the name into the legacy-accessor group with a reason
//! that does not hold for it (its call list is `EVP_PKEY_CTX_new_id`, `EVP_PKEY_keygen_init`,
//! `EVP_PKEY_CTX_set_mac_key`, `EVP_PKEY_keygen`, `EVP_PKEY_CTX_free` and nothing else). It lands
//! here, with its thirteen siblings, and D196 records the measurement.
//!
//! ## One init, two operations, and the two answers it can give
//!
//! `gen_init` is shared by `EVP_PKEY_paramgen_init` and `EVP_PKEY_keygen_init`, and the *only*
//! thing that distinguishes the two is the selection it hands `evp_keymgmt_gen_init`:
//! `OSSL_KEYMGMT_SELECT_ALL_PARAMETERS` for `PARAMGEN` and `OSSL_KEYMGMT_SELECT_KEYPAIR` for
//! `KEYGEN`. A transcription that passed one selection for both would produce a parameter-only
//! context that generates keys, or the reverse, and nothing else in the function would look wrong.
//!
//! The two refusals are also different answers and must not be collapsed:
//!
//! ```text
//! ctx == NULL                                    -> -2, NOT_SUPPORTED_FOR_THIS_KEYTYPE
//! keymgmt == NULL || keymgmt->gen_init == NULL   -> -2, NOT_SUPPORTED_FOR_THIS_KEYTYPE  (legacy)
//! genctx == NULL after the genter                ->  0, INITIALIZATION_ERROR
//! ```
//!
//! The middle one is the legacy arm, and in this crate it is not a thin arm but `goto legacy` ->
//! `ctx->pmeth == NULL` -> `goto not_supported`, so it lands on the same site as a NULL context
//! would if the context were not the thing being tested. Note where it is tested: **before**
//! `ctx->operation` is consulted, so a context whose method has no generator is refused for the
//! method's reason and not for the operation's.
//!
//! ## `EVP_PKEY_generate` attaches a *local* array to the context
//!
//! `ctx->keygen_info = gentmp; ctx->keygen_info_count = 2;` and then `ctx->keygen_info = NULL` after
//! the generator returns. That is deliberate and is the authority's own comment: providers are not
//! allowed to reach into the `EVP_PKEY_CTX`, so the two legacy-compatible counters a provider reports
//! progress through are given a stack array to write into, valid exactly for the duration of the
//! call. A transcription that allocated one, or that left the pointer set, would hand a later
//! `EVP_PKEY_CTX_get_keygen_info` a dangling array — which is why the clearing is a statement and
//! not a tidy-up.
//!
//! `ctx->legacy_keytype` is then written into `(*ppkey)->type` **unconditionally**, including on a
//! provider-only build where it is 0. That is the authority's line and it is observable:
//! `EVP_PKEY_get_id` on a freshly generated key reports what the *context* was told, not what the
//! method is — the same seam D-PKEY-AMETH-1 records from the other side.
//!
//! ## The data family shares one shape and differs in two places
//!
//! `EVP_PKEY_fromdata_init` does **not** have a legacy arm; it refuses a NULL `keytype` before it
//! refuses a NULL `keymgmt`, and it sets `operation` **after** the `keymgmt` test, so a refusal
//! leaves `UNDEFINED`. `EVP_PKEY_fromdata_settable` is a *call* to that init with
//! `EVP_PKEY_OP_UNDEFINED` as the operation — a context that is asked what it can accept is
//! deliberately left uninitialised, which is the one place in the file where an init is used as a
//! query.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_char, c_int, c_void};
use core::ptr;

use crate::bn::ctx::{BN_GENCB_get_arg, BN_GENCB_set, BnGencb};
use crate::evp::keymgmt::{
    evp_keymgmt_gen_init, evp_keymgmt_gen_set_template, evp_keymgmt_import_types, EvpKeyMgmt,
};
use crate::evp::keymgmt_lib::{
    evp_keymgmt_util_export, evp_keymgmt_util_fromdata, evp_keymgmt_util_gen,
};
use crate::evp::pkey::{
    evp_pkey_export_to_provider, evp_pkey_free_legacy, evp_pkey_is_legacy, EVP_PKEY_free,
    EVP_PKEY_new, EvpPkey,
};
use crate::evp::pkey_asn1::Engine;
use crate::evp::pkey_ctx::{
    evp_pkey_ctx_free_old_ops, EVP_PKEY_CTX_free, EVP_PKEY_CTX_new_id, EVP_PKEY_CTX_set_mac_key,
    EvpPkeyCtx, EvpPkeyGenCb, EVP_PKEY_OP_FROMDATA, EVP_PKEY_OP_KEYGEN, EVP_PKEY_OP_PARAMGEN,
    EVP_PKEY_OP_TYPE_GEN, EVP_PKEY_OP_UNDEFINED,
};
use crate::params::dup::OSSL_PARAM_dup;
use crate::params::{OSSL_PARAM_get_int, OSSL_PARAM_locate_const, OsslParam};
use crate::runtime::err::{err_sites, raise_site};

/// `OSSL_KEYMGMT_SELECT_ALL_PARAMETERS` — `DOMAIN_PARAMETERS | OTHER_PARAMETERS`.
const OSSL_KEYMGMT_SELECT_ALL_PARAMETERS: c_int = 0x04 | 0x80;
/// `OSSL_KEYMGMT_SELECT_KEYPAIR` — `PRIVATE_KEY | PUBLIC_KEY`.
const OSSL_KEYMGMT_SELECT_KEYPAIR: c_int = 0x01 | 0x02;

/// `OSSL_GEN_PARAM_POTENTIAL` — `include/openssl/core_names.h`, the generated one.
///
/// **Its value is not in the vendored `core_names.h.in`**: that file carries 75 `define OSSL_` lines
/// and the generated header 532, and this is one of the 457 the template does not have
/// (`docs/DECISIONS.md` D172). The value here is read from the built header.
const OSSL_GEN_PARAM_POTENTIAL: *const c_char = c"potential".as_ptr();
/// `OSSL_GEN_PARAM_ITERATION` — the same header, and the same note as above.
const OSSL_GEN_PARAM_ITERATION: *const c_char = c"iteration".as_ptr();

/// `static int gen_init(EVP_PKEY_CTX *ctx, int operation)` — `crypto/evp/pmeth_gn.c:25`.
///
/// # Safety
/// `ctx` NULL or live.
unsafe fn gen_init(ctx: *mut EvpPkeyCtx, operation: c_int) -> c_int {
    let mut ret: c_int = 0;

    if ctx.is_null() {
        /* `goto not_supported`, which reaches `end:` with `ctx == NULL` and so skips the teardown. */
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::PMETH_GN_87) };
        return -2;
    }

    // SAFETY: `ctx` is live.
    unsafe { evp_pkey_ctx_free_old_ops(ctx) };
    // SAFETY: `ctx` is live.
    unsafe { (*ctx).operation = operation };

    // SAFETY: `ctx` is live.
    let keymgmt = unsafe { (*ctx).keymgmt };
    if keymgmt.is_null() {
        // SAFETY: `ctx` is live.
        return unsafe { gen_init_legacy(ctx) };
    }
    // SAFETY: `keymgmt` is live.
    let has_gen_init = unsafe { (*keymgmt).gen_init }.is_some();
    if !has_gen_init {
        // SAFETY: `ctx` is live.
        return unsafe { gen_init_legacy(ctx) };
    }

    /* The selection is the whole of the difference between the two entry points. */
    let selection = if operation == EVP_PKEY_OP_PARAMGEN {
        OSSL_KEYMGMT_SELECT_ALL_PARAMETERS
    } else {
        OSSL_KEYMGMT_SELECT_KEYPAIR
    };
    // SAFETY: `keymgmt` is live and `params` is a literal NULL, which the callback documents.
    let genctx = unsafe { evp_keymgmt_gen_init(keymgmt, selection, ptr::null()) };
    // SAFETY: `ctx` is live.
    unsafe { (*ctx).op_keymgmt_genctx = genctx };

    if genctx.is_null() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::PMETH_GN_50) };
    } else {
        ret = 1;
    }

    if ret <= 0 {
        // SAFETY: `ctx` is live.
        unsafe { evp_pkey_ctx_free_old_ops(ctx) };
        // SAFETY: `ctx` is live.
        unsafe { (*ctx).operation = EVP_PKEY_OP_UNDEFINED };
    }
    ret
}

/// The authority's `legacy:` label reached from `gen_init` — `crypto/evp/pmeth_gn.c:55`.
///
/// `ctx->pmeth` is `EVP_PKEY_METHOD`'s and is Phase 8's (D163, D165), so both `goto legacy` entries
/// — a NULL `keymgmt` and a NULL `gen_init` — reach `goto not_supported`, and the whole legacy arm
/// collapses to the same refusal as the NULL-context entry, **from the same site**. That is why this
/// is one function and not two: the authority writes one label and two ways in, and the crate keeps
/// that shape so that the day Phase 8 lands, the arm becomes the authority's switch.
///
/// # Safety
/// `ctx` must be live.
unsafe fn gen_init_legacy(ctx: *mut EvpPkeyCtx) -> c_int {
    // SAFETY: a compile-time-constant site.
    unsafe { raise_site(&err_sites::PMETH_GN_87) };
    /* `goto end` with `ret == -2`. */
    // SAFETY: `ctx` is live.
    unsafe { evp_pkey_ctx_free_old_ops(ctx) };
    // SAFETY: `ctx` is live.
    unsafe { (*ctx).operation = EVP_PKEY_OP_UNDEFINED };
    -2
}

/// `int EVP_PKEY_paramgen_init(EVP_PKEY_CTX *ctx)`.
///
/// # Safety
/// `ctx` NULL or live.
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_paramgen_init(ctx: *mut EvpPkeyCtx) -> c_int {
    // SAFETY: `ctx` is NULL or live per the contract.
    unsafe { gen_init(ctx, EVP_PKEY_OP_PARAMGEN) }
}

/// `int EVP_PKEY_keygen_init(EVP_PKEY_CTX *ctx)`.
///
/// # Safety
/// `ctx` NULL or live.
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_keygen_init(ctx: *mut EvpPkeyCtx) -> c_int {
    // SAFETY: `ctx` is NULL or live per the contract.
    unsafe { gen_init(ctx, EVP_PKEY_OP_KEYGEN) }
}

/// `static int ossl_callback_to_pkey_gencb(const OSSL_PARAM params[], void *arg)` —
/// `crypto/evp/pmeth_gn.c:102`.
///
/// A provider reports progress by calling this with two named ints; this translates them into the
/// legacy `EVP_PKEY_gen_cb` protocol, which is a callback with **no arguments** that reads
/// `ctx->keygen_info[0]` and `[1]`. That is why `EVP_PKEY_generate` attaches `gentmp`.
///
/// Two things are contract and neither is obvious:
///
///   * **a NULL `pkey_gencb` is success, not failure** — a caller who wants no progress reporting
///     gets 1 and the provider carries on;
///   * a **missing or malformed** param is `0`, which the generator reads as a callback veto.
///
/// # Safety
/// `params` NULL or a terminated array; `arg` a live `EVP_PKEY_CTX`, which is what
/// `evp_keymgmt_util_gen` is handed.
unsafe extern "C" fn ossl_callback_to_pkey_gencb(
    params: *const OsslParam,
    arg: *mut c_void,
) -> c_int {
    let ctx = arg.cast::<EvpPkeyCtx>();
    let mut p: c_int = -1;
    let mut n: c_int = -1;

    // SAFETY: `ctx` is live per the contract.
    let Some(cb) = (unsafe { (*ctx).pkey_gencb }) else {
        return 1; /* No callback? That's fine. */
    };

    // SAFETY: `params` is NULL or a terminated array and the key is NUL-terminated.
    let Some(param) =
        (unsafe { OSSL_PARAM_locate_const(params, OSSL_GEN_PARAM_POTENTIAL).as_ref() })
    else {
        return 0;
    };
    // SAFETY: `param` is one of the array's entries and `p` is writable.
    if unsafe { OSSL_PARAM_get_int(param, ptr::addr_of_mut!(p)) } == 0 {
        return 0;
    }
    // SAFETY: as above, for the iteration count.
    let Some(param) =
        (unsafe { OSSL_PARAM_locate_const(params, OSSL_GEN_PARAM_ITERATION).as_ref() })
    else {
        return 0;
    };
    // SAFETY: as above.
    if unsafe { OSSL_PARAM_get_int(param, ptr::addr_of_mut!(n)) } == 0 {
        return 0;
    }

    /* SAFETY: `ctx` is live and `gentmp` was attached by `EVP_PKEY_generate`, which is the only
     * caller that hands this callback out; the two counters are the whole reason it exists. */
    unsafe {
        *(*ctx).keygen_info = p;
        *(*ctx).keygen_info.add(1) = n;
    }

    // SAFETY: `cb` is the caller's own callback and `ctx` is the argument it registered with.
    unsafe { cb(ctx) }
}

/// `int EVP_PKEY_generate(EVP_PKEY_CTX *ctx, EVP_PKEY **ppkey)` — `crypto/evp/pmeth_gn.c:126`.
///
/// **`ppkey == NULL` answers `-1` before `ctx` is tested at all**, so a NULL output is a caller
/// mistake rather than an unsupported operation. The four refusals are four different answers:
/// `-1` for a NULL `ppkey`, `-1` for a NULL context allocation, `-1` for an uninitialised operation
/// and `-2` for a method that cannot generate.
///
/// # Safety
/// `ctx` NULL or live; `ppkey` NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_generate(
    ctx: *mut EvpPkeyCtx,
    ppkey: *mut *mut EvpPkey,
) -> c_int {
    /* `ret` is assigned before it is read on every path, so it carries the authority's first
     * assignment as its initialiser rather than a zero that is overwritten. */
    let mut ret: c_int = 1;
    let mut allocated_pkey: *mut EvpPkey = ptr::null_mut();
    /* Legacy compatible keygen callback info, only used with provider implementations. */
    let mut gentmp: [c_int; 2] = [0; 2];

    if ppkey.is_null() {
        return -1;
    }

    if ctx.is_null() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::PMETH_GN_241) };
        return -2;
    }

    // SAFETY: `ctx` is live.
    if (unsafe { (*ctx).operation } & EVP_PKEY_OP_TYPE_GEN) == 0 {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::PMETH_GN_245) };
        return -1;
    }

    // SAFETY: `ppkey` is non-NULL per the contract.
    if unsafe { *ppkey }.is_null() {
        // SAFETY: the constructor takes no arguments.
        allocated_pkey = unsafe { EVP_PKEY_new() };
        // SAFETY: `ppkey` is writable per the contract.
        unsafe { *ppkey = allocated_pkey };
    }

    // SAFETY: `ppkey` is writable and holds the caller's pointer or the one just allocated.
    if unsafe { *ppkey }.is_null() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::PMETH_GN_146) };
        return -1;
    }

    // SAFETY: `ctx` is live.
    if unsafe { (*ctx).op_keymgmt_genctx }.is_null() {
        // SAFETY: `ctx` is live, `ppkey` is writable, and `allocated_pkey` is NULL or this call's
        // own object.
        return unsafe { generate_legacy(ctx, ppkey, allocated_pkey) };
    }

    /* The two counters are attached **for the duration of this call only**: a provider is not
     * allowed to reach into the context, so the array it reports progress through is this frame's.
     * See the module doc. */
    // SAFETY: `ctx` is live and `gentmp` is this frame's array, live for the whole call.
    unsafe {
        (*ctx).keygen_info = gentmp.as_mut_ptr();
        (*ctx).keygen_info_count = 2;
    }

    // SAFETY: `ctx` is live.
    if !unsafe { (*ctx).pkey }.is_null() {
        // SAFETY: `ctx` is live.
        let mut tmp_keymgmt: *mut EvpKeyMgmt = unsafe { (*ctx).keymgmt };
        // SAFETY: `ctx` is live and `tmp_keymgmt`'s address is valid for the call.
        let keydata = unsafe {
            evp_pkey_export_to_provider(
                (*ctx).pkey,
                (*ctx).libctx,
                ptr::addr_of_mut!(tmp_keymgmt),
                (*ctx).propquery,
            )
        };

        if tmp_keymgmt.is_null() {
            // SAFETY: `ppkey` is writable and `allocated_pkey` is NULL or this call's own object.
            return unsafe { generate_end(ppkey, allocated_pkey, -2) };
        }
        /* It is fine for `keydata` to be NULL: the backend deals with that as it sees fit. */
        // SAFETY: `ctx` is live and its method is live.
        ret = unsafe {
            evp_keymgmt_gen_set_template((*ctx).keymgmt, (*ctx).op_keymgmt_genctx, keydata)
        };
    }

    /* The generator caches the key data in `*ppkey`, so only the NULL test matters here. */
    // SAFETY: `ctx` is live, its method is live and `op_keymgmt_genctx` is its generator context.
    let generated = unsafe {
        evp_keymgmt_util_gen(
            *ppkey,
            (*ctx).keymgmt,
            (*ctx).op_keymgmt_genctx,
            Some(ossl_callback_to_pkey_gencb),
            ctx.cast::<c_void>(),
        )
    };
    ret = if ret != 0 && !generated.is_null() {
        1
    } else {
        0
    };

    // SAFETY: `ctx` is live and the array is this frame's, so the pointer must not outlive it.
    unsafe { (*ctx).keygen_info = ptr::null_mut() };

    if ret != 0 {
        /* In case `*ppkey` was originally a legacy key. The call is compiled in: this build defines
         * `NDEBUG` and no `OPENSSL_NO_DEPRECATED_*` (D172), so the `#if` around it in the authority
         * does not remove it. In this crate the function's body is empty — every statement it has is
         * `ameth` or `ENGINE` work — and it is transcribed at its own site in `pkey.rs`. */
        // SAFETY: `ppkey` holds a live key.
        unsafe { evp_pkey_free_legacy(*ppkey) };
    }

    /* Because we still have legacy keys. Unconditional, and observable — see the module doc. */
    // SAFETY: `ctx` is live and `ppkey` holds a live key.
    unsafe { (*(*ppkey)).type_ = (*ctx).legacy_keytype };

    // SAFETY: `ppkey` is writable and `allocated_pkey` is NULL or this call's own object.
    unsafe { generate_end(ppkey, allocated_pkey, ret) }
}

/// The authority's `end:` label — `crypto/evp/pmeth_gn.c:232`.
///
/// # Safety
/// `ppkey` must be writable and non-NULL; `allocated_pkey` NULL or this call's own object.
unsafe fn generate_end(
    ppkey: *mut *mut EvpPkey,
    allocated_pkey: *mut EvpPkey,
    ret: c_int,
) -> c_int {
    if ret <= 0 {
        if !allocated_pkey.is_null() {
            // SAFETY: `ppkey` is writable per the contract.
            unsafe { *ppkey = ptr::null_mut() };
        }
        // SAFETY: `allocated_pkey` is NULL or this call's own object.
        unsafe { EVP_PKEY_free(allocated_pkey) };
    }
    ret
}

/// The authority's `legacy:` label reached from `EVP_PKEY_generate` — `crypto/evp/pmeth_gn.c:205`.
///
/// `ctx->pmeth` is Phase 8's, so the `pmeth->paramgen` and `pmeth->keygen` calls are unreachable and
/// the arm is the `not_supported` refusal. Its `not_accessible` label sits beside it and is
/// **unreachable in this crate for a second reason**: its guard is
/// `ctx->pkey != NULL && !ossl_assert(!evp_pkey_is_provided(ctx->pkey))`, so it needs a key that is
/// *not* provided — and every key this crate can build is.
///
/// # Safety
/// `ctx` must be live; `ppkey` writable; `allocated_pkey` NULL or this call's own object.
unsafe fn generate_legacy(
    ctx: *mut EvpPkeyCtx,
    ppkey: *mut *mut EvpPkey,
    allocated_pkey: *mut EvpPkey,
) -> c_int {
    /* `ctx->operation` is one of the two GENERATION bits — established by the caller's mask test —
     * and the authority's `switch` has arms for `PARAMGEN` and `KEYGEN` and `goto not_supported`
     * for anything else in that mask, which cannot occur because the mask holds exactly those two.
     * Either way the legacy arm cannot be taken, so all three outcomes are the same refusal. */
    let _ = ctx;
    // SAFETY: a compile-time-constant site.
    unsafe { raise_site(&err_sites::PMETH_GN_241) };
    // SAFETY: `ppkey` is writable and `allocated_pkey` is NULL or this call's own object.
    unsafe { generate_end(ppkey, allocated_pkey, -2) }
}

/// `int EVP_PKEY_paramgen(EVP_PKEY_CTX *ctx, EVP_PKEY **ppkey)`.
///
/// Note the operation test is **before** any NULL test on `ctx`, and it dereferences it: a NULL
/// context faults the authority here rather than answering. The crate does not invent an answer.
///
/// # Safety
/// `ctx` must be live; `ppkey` NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_paramgen(
    ctx: *mut EvpPkeyCtx,
    ppkey: *mut *mut EvpPkey,
) -> c_int {
    // SAFETY: `ctx` is live per the contract.
    if unsafe { (*ctx).operation } != EVP_PKEY_OP_PARAMGEN {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::PMETH_GN_259) };
        return -1;
    }
    // SAFETY: the arguments are forwarded under this function's contract.
    unsafe { EVP_PKEY_generate(ctx, ppkey) }
}

/// `int EVP_PKEY_keygen(EVP_PKEY_CTX *ctx, EVP_PKEY **ppkey)`.
///
/// # Safety
/// `ctx` must be live; `ppkey` NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_keygen(ctx: *mut EvpPkeyCtx, ppkey: *mut *mut EvpPkey) -> c_int {
    // SAFETY: `ctx` is live per the contract.
    if unsafe { (*ctx).operation } != EVP_PKEY_OP_KEYGEN {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::PMETH_GN_268) };
        return -1;
    }
    // SAFETY: the arguments are forwarded under this function's contract.
    unsafe { EVP_PKEY_generate(ctx, ppkey) }
}

/// `void EVP_PKEY_CTX_set_cb(EVP_PKEY_CTX *ctx, EVP_PKEY_gen_cb *cb)`.
///
/// # Safety
/// `ctx` must be live.
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_CTX_set_cb(ctx: *mut EvpPkeyCtx, cb: Option<EvpPkeyGenCb>) {
    // SAFETY: `ctx` is live per the contract.
    unsafe { (*ctx).pkey_gencb = cb };
}

/// `EVP_PKEY_gen_cb *EVP_PKEY_CTX_get_cb(EVP_PKEY_CTX *ctx)`.
///
/// # Safety
/// `ctx` must be live.
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_CTX_get_cb(ctx: *mut EvpPkeyCtx) -> Option<EvpPkeyGenCb> {
    // SAFETY: `ctx` is live per the contract.
    unsafe { (*ctx).pkey_gencb }
}

/// `static int trans_cb(int a, int b, BN_GENCB *gcb)` — `crypto/evp/pmeth_gn.c:289`.
///
/// The direction opposite to `ossl_callback_to_pkey_gencb`: a legacy `BN_GENCB` callback whose two
/// arguments are copied into the context's counters before the `EVP_PKEY_gen_cb` is called, so that
/// a caller written against the old protocol sees the same two values it always did.
///
/// # Safety
/// `gcb` must be a live `BnGencb` whose argument is a live `EVP_PKEY_CTX` that has counters
/// attached — which is what `evp_pkey_set_cb_translate` establishes.
unsafe extern "C" fn trans_cb(a: c_int, b: c_int, gcb: *mut BnGencb) -> c_int {
    // SAFETY: `gcb` is live per the contract.
    let ctx = unsafe { BN_GENCB_get_arg(gcb) }.cast::<EvpPkeyCtx>();
    /* SAFETY: `ctx` is live and its counters are attached for the duration of the generation the
     * caller is inside. */
    unsafe {
        *(*ctx).keygen_info = a;
        *(*ctx).keygen_info.add(1) = b;
    }
    // SAFETY: `ctx` is live and `pkey_gencb` is the callback the caller registered; the authority
    // dereferences it without a test here, so a translation registered with no callback faults it.
    let cb = unsafe { (*ctx).pkey_gencb };
    match cb {
        // SAFETY: the caller's own callback, with the context it registered with.
        Some(cb) => unsafe { cb(ctx) },
        None => 0,
    }
}

/// `void evp_pkey_set_cb_translate(BN_GENCB *cb, EVP_PKEY_CTX *ctx)`.
///
/// # Safety
/// `cb` must be live; `ctx` must be live and outlive the encryption callback it is registered with.
#[allow(dead_code)] // first live caller is Phase 8's key generators, which register a `BN_GENCB`
pub(crate) unsafe fn evp_pkey_set_cb_translate(cb: *mut BnGencb, ctx: *mut EvpPkeyCtx) {
    // SAFETY: `cb` is live per the contract, `trans_cb` is this file's own and `ctx` is the
    // argument it will be handed back.
    unsafe { BN_GENCB_set(cb, Some(trans_cb), ctx.cast::<c_void>()) };
}

/// `int EVP_PKEY_CTX_get_keygen_info(EVP_PKEY_CTX *ctx, int idx)` — `crypto/evp/pmeth_gn.c:302`.
///
/// Two boundaries, and they are **not** the same test: `idx == -1` answers the *count*, `idx < 0`
/// answers 0 — so `-1` is a count query and every other negative is out of range, and `idx >
/// keygen_info_count` is out of range while `idx == keygen_info_count` is **not**, which reads one
/// past what the count reports.
///
/// # Safety
/// `ctx` must be live, and `keygen_info` must be attached — which it is only for the duration of an
/// `EVP_PKEY_generate` call.
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_CTX_get_keygen_info(ctx: *mut EvpPkeyCtx, idx: c_int) -> c_int {
    // SAFETY: `ctx` is live per the contract.
    let count = unsafe { (*ctx).keygen_info_count };
    if idx == -1 {
        return count;
    }
    // The authority writes `idx > count`, which reads one slot past a `count`-element array
    // and dereferences a NULL `keygen_info` before the first generation (where `count` is 0).
    // Both are UB in the C authority, so the boundary is `>=` here: an index the context does
    // not have answers 0. Valid indices (`0..count`) are unchanged.
    if idx < 0 || idx >= count {
        return 0;
    }
    // SAFETY: `idx` is in `0..=count` and the authority treats the array as that long; the caller's
    // contract is that this is called inside a generation.
    unsafe { *(*ctx).keygen_info.add(idx as usize) }
}

/// `static int fromdata_init(EVP_PKEY_CTX *ctx, int operation)` — `crypto/evp/pmeth_gn.c:336`.
///
/// Three refusals collapse into one, and the **order** is why: `ctx == NULL || keytype == NULL` is
/// tested first, then the old ops are freed, then `keymgmt == NULL`. `operation` is assigned only
/// after both tests, so every refusal leaves the context `UNDEFINED` — including the one that
/// already freed the old ops.
///
/// # Safety
/// `ctx` NULL or live.
unsafe fn fromdata_init(ctx: *mut EvpPkeyCtx, operation: c_int) -> c_int {
    if ctx.is_null() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::PMETH_GN_351) };
        return -2;
    }
    // SAFETY: `ctx` is live.
    if unsafe { (*ctx).keytype }.is_null() {
        // SAFETY: `ctx` is live.
        unsafe { (*ctx).operation = EVP_PKEY_OP_UNDEFINED };
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::PMETH_GN_351) };
        return -2;
    }

    // SAFETY: `ctx` is live.
    unsafe { evp_pkey_ctx_free_old_ops(ctx) };
    // SAFETY: `ctx` is live.
    if unsafe { (*ctx).keymgmt }.is_null() {
        // SAFETY: `ctx` is live.
        unsafe { (*ctx).operation = EVP_PKEY_OP_UNDEFINED };
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::PMETH_GN_351) };
        return -2;
    }

    // SAFETY: `ctx` is live.
    unsafe { (*ctx).operation = operation };
    1
}

/// `int EVP_PKEY_fromdata_init(EVP_PKEY_CTX *ctx)`.
///
/// # Safety
/// `ctx` NULL or live.
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_fromdata_init(ctx: *mut EvpPkeyCtx) -> c_int {
    // SAFETY: `ctx` is NULL or live per the contract.
    unsafe { fromdata_init(ctx, EVP_PKEY_OP_FROMDATA) }
}

/// `int EVP_PKEY_fromdata(EVP_PKEY_CTX *ctx, EVP_PKEY **ppkey, int selection, OSSL_PARAM params[])`.
///
/// The operation test and the NULL `ppkey` test are **both** inside one `if` in the authority and
/// answer different things: an uninitialised operation is `-2` with
/// `OPERATION_NOT_SUPPORTED_FOR_THIS_KEYTYPE`, a NULL `ppkey` is `-1` with nothing raised.
///
/// # Safety
/// `ctx` NULL or live; `ppkey` NULL or writable; `params` NULL or a terminated array.
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_fromdata(
    ctx: *mut EvpPkeyCtx,
    ppkey: *mut *mut EvpPkey,
    selection: c_int,
    params: *mut OsslParam,
) -> c_int {
    let mut allocated_pkey: *mut EvpPkey = ptr::null_mut();

    if ctx.is_null() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::PMETH_GN_367) };
        return -2;
    }
    // SAFETY: `ctx` is live.
    if (unsafe { (*ctx).operation } & EVP_PKEY_OP_FROMDATA) == 0 {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::PMETH_GN_367) };
        return -2;
    }

    if ppkey.is_null() {
        return -1;
    }

    // SAFETY: `ppkey` is non-NULL and writable per the contract.
    if unsafe { *ppkey }.is_null() {
        // SAFETY: the constructor takes no arguments.
        allocated_pkey = unsafe { EVP_PKEY_new() };
        // SAFETY: `ppkey` is writable per the contract.
        unsafe { *ppkey = allocated_pkey };
    }

    // SAFETY: `ppkey` is writable.
    if unsafe { *ppkey }.is_null() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::PMETH_GN_378) };
        return -1;
    }

    // SAFETY: `ctx` is live and `ppkey` holds a live key; `params` is NULL or terminated.
    let keydata = unsafe { evp_keymgmt_util_fromdata(*ppkey, (*ctx).keymgmt, selection, params) };
    if keydata.is_null() {
        if !allocated_pkey.is_null() {
            // SAFETY: `ppkey` is writable.
            unsafe { *ppkey = ptr::null_mut() };
            // SAFETY: `allocated_pkey` is this call's own object.
            unsafe { EVP_PKEY_free(allocated_pkey) };
        }
        return 0;
    }
    /* The key data is cached in `*ppkey`, so it is not touched again here. */
    1
}

/// `const OSSL_PARAM *EVP_PKEY_fromdata_settable(EVP_PKEY_CTX *ctx, int selection)`.
///
/// An init used as a **query**: `fromdata_init(ctx, EVP_PKEY_OP_UNDEFINED)` populates `keymgmt` and
/// deliberately leaves the operation unset, and only then is the method asked which parameters it
/// can import. A transcription that passed `EVP_PKEY_OP_FROMDATA` would leave a context that has been
/// asked a question ready to import.
///
/// # Safety
/// `ctx` NULL or live.
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_fromdata_settable(
    ctx: *mut EvpPkeyCtx,
    selection: c_int,
) -> *const OsslParam {
    // SAFETY: `ctx` is NULL or live per the contract.
    if unsafe { fromdata_init(ctx, EVP_PKEY_OP_UNDEFINED) } == 1 {
        // SAFETY: `ctx` is live — the init answered 1, so it is non-NULL and has a method.
        let keymgmt = unsafe { (*ctx).keymgmt };
        // SAFETY: `keymgmt` is live.
        return unsafe { evp_keymgmt_import_types(keymgmt, selection) };
    }
    ptr::null()
}

/// `static int ossl_pkey_todata_cb(const OSSL_PARAM params[], void *arg)` —
/// `crypto/evp/pmeth_gn.c:404`.
///
/// # Safety
/// `params` NULL or a terminated array; `arg` a writable `*mut *mut OsslParam`.
unsafe extern "C" fn ossl_pkey_todata_cb(params: *const OsslParam, arg: *mut c_void) -> c_int {
    let ret = arg.cast::<*mut OsslParam>();
    // SAFETY: `ret` is writable per the contract and `params` is NULL or terminated.
    unsafe { *ret = OSSL_PARAM_dup(params) };
    1
}

/// `int EVP_PKEY_todata(const EVP_PKEY *pkey, int selection, OSSL_PARAM **params)`.
///
/// The callback **always answers 1** even when the duplication failed and `*params` is NULL, so a
/// failed duplication is reported as success by this function and shows up only as a NULL array.
/// That is the authority's shape; it is not repaired here.
///
/// # Safety
/// `pkey` NULL or live; `params` NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_todata(
    pkey: *const EvpPkey,
    selection: c_int,
    params: *mut *mut OsslParam,
) -> c_int {
    if params.is_null() {
        return 0;
    }
    // SAFETY: `pkey` is NULL or live and the callback is this file's own.
    unsafe {
        EVP_PKEY_export(
            pkey,
            selection,
            Some(ossl_pkey_todata_cb),
            params.cast::<c_void>(),
        )
    }
}

/// `struct fake_import_data_st` — `crypto/evp/pmeth_gn.c:419-422`.
///
/// The two callbacks a legacy export hands the method's `export_to`, which the method calls back
/// through `pkey_fake_import` as if it were importing into a provider.
struct FakeImportData {
    export_cb: Option<unsafe extern "C" fn(*const OsslParam, *mut c_void) -> c_int>,
    export_cbarg: *mut c_void,
}

/// `static int pkey_fake_import(void *fake_keydata, int ignored_selection,
/// const OSSL_PARAM params[])` — `crypto/evp/pmeth_gn.c:425`.
///
/// The bridge from the method's `OSSL_FUNC_keymgmt_import_fn` shape to the caller's
/// `OSSL_CALLBACK`. The authority calls `data->export_cb(params, data->export_cbarg)` without a NULL
/// test; a NULL `export_cb` there is a call through a NULL function pointer, so this transcription
/// answers 0 instead (§17: UB in the C authority is not reproduced). No caller this crate can build
/// passes NULL — `EVP_PKEY_export`'s callers all supply a callback — so the arm is a safety repair
/// with no compatibility consequence.
///
/// # Safety
/// `fake_keydata` is the live `FakeImportData` the export handed the method; `params` is NULL or a
/// terminated array.
unsafe extern "C" fn pkey_fake_import(
    fake_keydata: *mut c_void,
    _ignored_selection: c_int,
    params: *const OsslParam,
) -> c_int {
    let data = fake_keydata.cast::<FakeImportData>();
    // SAFETY: `data` is live per the contract.
    match unsafe { (*data).export_cb } {
        // SAFETY: the caller's own callback with the caller's own argument and the method's params.
        Some(f) => unsafe { f(params, (*data).export_cbarg) },
        None => 0,
    }
}

/// `int EVP_PKEY_export(const EVP_PKEY *pkey, int selection, OSSL_CALLBACK *export_cb,
/// void *export_cbarg)` — `crypto/evp/pmeth_gn.c:435`.
///
/// `pkey == NULL` raises and answers 0. A **legacy** key (`type != EVP_PKEY_NONE && keymgmt ==
/// NULL`) is exported through its own `ameth->export_to`, with `pkey_fake_import` bridging the
/// method's importer call to the caller's callback; the authority checks that arm first. Everything
/// else is the provider export.
///
/// The legacy arm was omitted on the recorded premise that `ameth` was always NULL. The ASN.1
/// method table made it reachable, and without it `EVP_PKEY_export` (and so `EVP_PKEY_todata`)
/// answered 0 for every legacy key — the census's L07.
///
/// The authority dereferences `pkey->ameth->export_to` with no NULL test. A typed key always has an
/// `ameth`, but an application-registered method need not publish `export_to`; this transcription
/// answers 0 for that state rather than calling NULL (§17: UB in the C authority is not reproduced).
/// That is the only divergence in this function and it is a refusal, never a false success.
///
/// # Safety
/// `pkey` NULL or live; `export_cb` the caller's callback; `export_cbarg` its argument.
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_export(
    pkey: *const EvpPkey,
    selection: c_int,
    export_cb: Option<unsafe extern "C" fn(*const OsslParam, *mut c_void) -> c_int>,
    export_cbarg: *mut c_void,
) -> c_int {
    if pkey.is_null() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::PMETH_GN_439) };
        return 0;
    }
    // SAFETY: `pkey` is live per the contract.
    if unsafe { evp_pkey_is_legacy(pkey) } != 0 {
        // SAFETY: `pkey` is live.
        let ameth = unsafe { (*pkey).ameth };
        if ameth.is_null() {
            return 0;
        }
        // SAFETY: `ameth` is live.
        let Some(export_to) = (unsafe { (*ameth).export_to }) else {
            return 0;
        };
        /* Every built-in `export_to` reads the legacy union immediately, and a typed-but-unassigned
         * key has none; the authority dereferences NULL there (UB, §17). Answer 0 — there is
         * nothing to export — rather than reproducing the crash. */
        // SAFETY: `pkey` is live.
        if unsafe { (*pkey).pkey }.is_null() {
            return 0;
        }
        let mut data = FakeImportData {
            export_cb,
            export_cbarg,
        };
        // SAFETY: the method's own exporter, handed the live key, this frame's bridge record, the
        // bridge itself and the authority's NULL libctx/propq.
        return unsafe {
            export_to(
                pkey,
                ptr::addr_of_mut!(data).cast::<c_void>(),
                Some(pkey_fake_import),
                ptr::null_mut(),
                ptr::null(),
            )
        };
    }
    // SAFETY: `pkey` is live and `export_cb` is the caller's own.
    unsafe { evp_keymgmt_util_export(pkey, selection, export_cb, export_cbarg) }
}

/// `EVP_PKEY *EVP_PKEY_new_mac_key(int type, ENGINE *e, const unsigned char *key, int keylen)` —
/// `crypto/evp/pmeth_gn.c:313`.
///
/// The authority's four calls and one label: `EVP_PKEY_CTX_new_id`, then `EVP_PKEY_keygen_init`,
/// `EVP_PKEY_CTX_set_mac_key` and `EVP_PKEY_keygen`, each of which jumps to the same `merr:` -- so
/// the `EVP_PKEY_CTX_free` runs whether the chain succeeded or was abandoned, and the answer is the
/// key the last call wrote. Three of those calls are landed in `src/evp/pkey_ctx.rs` and two are
/// this file's, which is the whole of why D173 could not land it and D193's reason for withholding
/// it does not apply: there is no legacy key here, no `evp_pkey_get_legacy` and no `ameth` read.
///
/// The engine parameter is passed through to `EVP_PKEY_CTX_new_id`, which adopts it (S18): the
/// context takes the functional reference and the engine's `EVP_PKEY_METHOD`, and releases the
/// reference in `EVP_PKEY_CTX_free`. The older "reads and discards it (D186)" note is superseded.
///
/// # Safety
/// `e` NULL or a live `ENGINE`; `key` NULL or `keylen` readable bytes.
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_new_mac_key(
    type_: c_int,
    e: *mut Engine,
    key: *const u8,
    keylen: c_int,
) -> *mut EvpPkey {
    let mut mac_key: *mut EvpPkey = ptr::null_mut();
    // SAFETY: the arguments are forwarded under this function's contract.
    let mac_ctx = unsafe { EVP_PKEY_CTX_new_id(type_, e) };
    if mac_ctx.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: `mac_ctx` is live and this call's own; `key` is NULL or `keylen` readable bytes.
    unsafe {
        if EVP_PKEY_keygen_init(mac_ctx) > 0
            && EVP_PKEY_CTX_set_mac_key(mac_ctx, key, keylen) > 0
            && EVP_PKEY_keygen(mac_ctx, ptr::addr_of_mut!(mac_key)) > 0
        {
            /* The authority's `merr:` is reached on both paths; the chain above is its three
             * `goto merr` tests, short-circuited the way the labels are. */
        }
        EVP_PKEY_CTX_free(mac_ctx);
    }
    mac_key
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::evp::pkey_ctx::CachedParameters;

    fn an_unattached_ctx() -> EvpPkeyCtx {
        EvpPkeyCtx {
            operation: EVP_PKEY_OP_UNDEFINED,
            libctx: ptr::null_mut(),
            propquery: ptr::null_mut(),
            keytype: ptr::null(),
            keymgmt: ptr::null_mut(),
            op_keymgmt_genctx: ptr::null_mut(),
            op_kex_exchange: ptr::null_mut(),
            op_kex_algctx: ptr::null_mut(),
            op_sig_signature: ptr::null_mut(),
            op_sig_algctx: ptr::null_mut(),
            op_ciph_cipher: ptr::null_mut(),
            op_ciph_algctx: ptr::null_mut(),
            op_encap_kem: ptr::null_mut(),
            op_encap_algctx: ptr::null_mut(),
            cached_parameters: CachedParameters {
                dist_id_name: ptr::null_mut(),
                dist_id: ptr::null_mut(),
                dist_id_len: 0,
                dist_id_set: 0,
            },
            app_data: ptr::null_mut(),
            pkey_gencb: None,
            keygen_info: ptr::null_mut(),
            keygen_info_count: 0,
            legacy_keytype: 0,
            pmeth: ptr::null(),
            engine: ptr::null_mut(),
            pkey: ptr::null_mut(),
            peerkey: ptr::null_mut(),
            data: ptr::null_mut(),
            flag_call_digest_custom: 0,
            rsa_pubexp: ptr::null_mut(),
        }
    }

    /// The authority's `idx > count` reads the slot after the array. This pins the corrected
    /// boundary on both shapes: an attached two-slot array, and no array at all (where the
    /// authority would dereference NULL for `idx == 0`).
    #[test]
    fn keygen_info_refuses_the_index_it_does_not_have() {
        let mut info = [11 as c_int, 22 as c_int];
        let mut ctx = an_unattached_ctx();
        ctx.keygen_info = info.as_mut_ptr();
        ctx.keygen_info_count = 2;
        // SAFETY: `ctx` is this frame's own live object and `info` outlives every call.
        unsafe {
            let p = ptr::addr_of_mut!(ctx);
            assert_eq!(EVP_PKEY_CTX_get_keygen_info(p, -1), 2);
            assert_eq!(EVP_PKEY_CTX_get_keygen_info(p, 0), 11);
            assert_eq!(EVP_PKEY_CTX_get_keygen_info(p, 1), 22);
            assert_eq!(
                EVP_PKEY_CTX_get_keygen_info(p, 2),
                0,
                "one past the count is not a slot"
            );
            assert_eq!(EVP_PKEY_CTX_get_keygen_info(p, -2), 0);
        }

        let mut fresh = an_unattached_ctx();
        // SAFETY: `fresh` is this frame's own live object; `keygen_info` is NULL and `count` 0.
        unsafe {
            assert_eq!(EVP_PKEY_CTX_get_keygen_info(ptr::addr_of_mut!(fresh), 0), 0);
            assert_eq!(
                EVP_PKEY_CTX_get_keygen_info(ptr::addr_of_mut!(fresh), -1),
                0
            );
        }
    }

    /// S19 L07. `EVP_PKEY_export` sends a **legacy** key through `pkey->ameth->export_to`, with
    /// `pkey_fake_import` bridging the method's importer call to the caller's callback
    /// (`pmeth_gn.c:450-463`). A legacy EC key's method exports its domain parameters, so the
    /// callback must see a parameter array carrying `group`; a blank key is neither legacy nor
    /// provided and still answers 0.
    #[test]
    fn evp_pkey_export_exports_a_legacy_key_through_its_ameth() {
        use crate::ec::key::EC_KEY_new_by_curve_name;
        use crate::evp::pkey::EVP_PKEY_assign;
        use crate::evp::pkey_ctx::EVP_PKEY_EC;
        use crate::runtime::obj::NID_X9_62_prime256v1;

        unsafe extern "C" fn collect(params: *const OsslParam, arg: *mut c_void) -> c_int {
            let seen = arg.cast::<c_int>();
            // SAFETY: `seen` is the test's own live counter.
            unsafe { *seen += 1 };
            // SAFETY: `params` is the exporter's terminated array.
            if !unsafe { OSSL_PARAM_locate_const(params, c"group".as_ptr()) }.is_null() {
                // SAFETY: as above.
                unsafe { *seen += 10 };
            }
            1
        }

        // SAFETY: every object below is this test's own and is freed exactly once.
        unsafe {
            let pkey = EVP_PKEY_new();
            let ec = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
            assert!(!pkey.is_null() && !ec.is_null());
            assert_eq!(EVP_PKEY_assign(pkey, EVP_PKEY_EC, ec.cast()), 1);

            let mut seen: c_int = 0;
            assert_eq!(
                EVP_PKEY_export(
                    pkey,
                    0,
                    Some(collect),
                    ptr::addr_of_mut!(seen).cast::<c_void>()
                ),
                1,
                "the legacy export answers the method's own result"
            );
            assert_eq!(seen, 11, "one import carrying the group name");
            EVP_PKEY_free(pkey);

            let blank = EVP_PKEY_new();
            assert!(!blank.is_null());
            let mut seen: c_int = 0;
            assert_eq!(
                EVP_PKEY_export(
                    blank,
                    0,
                    Some(collect),
                    ptr::addr_of_mut!(seen).cast::<c_void>()
                ),
                0,
                "neither legacy nor provided is the provider export's refusal"
            );
            assert_eq!(seen, 0);
            EVP_PKEY_free(blank);
        }
    }
}
