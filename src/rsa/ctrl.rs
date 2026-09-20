//! `crypto/rsa/rsa_lib.c:741-1383` — the `EVP_PKEY_CTX` controls (Phase 8.4, slice E).
//!
//! **Twenty-five labels, and they are `rsa_lib.c`'s second half.** The file's first half is the
//! object layer, which lives in [`crate::rsa::object`]; the part transcribed here is the block the
//! atlas calls slice E -- the `RSA_pkey_ctx_ctrl` door, the two `static int_{set,get}_rsa_md_name`
//! helpers, and the twenty-three `EVP_PKEY_CTX_{get,set}_rsa_*` controls. The module is split out
//! rather than appended to `object.rs` because the two halves share nothing but a translation unit:
//! the gate's own rule is that a unit may have several modules (`forensics/atlas/transcription-edges.json`
//! says so in its `rule` field), and this half's dominant unit is `rsa_lib.c` all the same.
//!
//! **Three shapes, and a reader can classify all twenty-three by them.**
//!
//!   1. **The `RSA_pkey_ctx_ctrl` wrappers** -- `set_rsa_padding`, `get_rsa_padding`,
//!      `set_rsa_pss_saltlen`, `get_rsa_pss_saltlen`, `set_rsa_mgf1_md`, `get_rsa_mgf1_md`,
//!      `set_rsa_pss_keygen_md` and `set_rsa_pss_keygen_mgf1_md`. Each is one call with the key type
//!      the *control's own* contract names: `-1` for the four the authority's comment says "is
//!      currently implemented as an `EVP_PKEY_CTX_ctrl()` wrapper, simply because that's easier".
//!   2. **The `OSSL_PARAM` builders** -- `set_rsa_pss_keygen_saltlen`, `set_rsa_keygen_bits`,
//!      `set_rsa_keygen_primes`, `set0_rsa_oaep_label`, `get0_rsa_oaep_label` and the two
//!      `_name` pairs that go through `int_{set,get}_rsa_md_name`. These do **not** go through the
//!      ctrl translation at all: they build the provider parameter directly and hand it to
//!      `evp_pkey_ctx_set_params_strict`/`evp_pkey_ctx_get_params_strict`, which is why they answer
//!      `-2` for a parameter list the method does not list and why their behaviour is the *same*
//!      on a provider context and different on a legacy one.
//!   3. **The two `pubexp` controls**, which are the only state this file adds to a context:
//!      `set_rsa_keygen_pubexp` takes custody of the caller's `BIGNUM` on a provider context, and
//!      `set1_rsa_keygen_pubexp` duplicates it on a legacy one. The `rsa_pubexp` member of
//!      `EVP_PKEY_CTX` exists for no other purpose, and the authority's own comment says so.
//!
//! **`ctx->pmeth` is absent from this crate, and `RSA_pkey_ctx_ctrl` is where that shows.** The
//! authority's guard is `ctx != NULL && ctx->pmeth != NULL && ctx->pmeth->pkey_id != EVP_PKEY_RSA &&
//! ctx->pmeth->pkey_id != EVP_PKEY_RSA_PSS`. `EVP_PKEY_METHOD` is 7.4l's and `src/evp/pkey_ctx.rs`
//! records that `pmeth` is only ever read behind a non-NULL test, so the whole conjunction is
//! **unreachable** here and the body reduces to its last statement. The same absence is what makes
//! the guard dead rather than wrong: a context whose method answered a non-RSA `pkey_id` cannot be
//! built in this crate, because no `EVP_PKEY_CTX` can be built from a legacy method at all.
//!
//! **What the court can and cannot drive, said here rather than discovered.** Every control below is
//! reachable with a NULL context and answers a refusal whose error coordinate is compared, and every
//! one that does not dereference `ctx` before its first test is *also* driven with a live context
//! this probe publishes (`RT-RSA`'s own `COURT-RSA` keymgmt). Three of the twenty-three dereference
//! `ctx` before any test -- `set_rsa_oaep_md` and `get_rsa_oaep_md` through `EVP_PKEY_CTX_is_a`, and
//! `set1_rsa_keygen_pubexp` through `evp_pkey_ctx_is_legacy` -- so a NULL context is a **fault** on
//! both sides there and only the live-context arm is written. What no arm can reach, because the
//! crate publishes no RSA `EVP_KEYMGMT` (8.4's provider half is not landed) and the authority does,
//! is the *successful* translation of a ctrl into a provider parameter: an arm that built a real
//! RSA context would differ between the two binaries for a reason that is not this file's.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_char, c_int, c_void};

use crate::bn::bignum::{BN_dup, BN_free, BigNum};
use crate::evp::digest::EvpMd;
use crate::evp::pkey::evp_pkey_type2name;
use crate::evp::pkey_ctx::{
    evp_pkey_ctx_get_params_strict, evp_pkey_ctx_set_params_strict, evp_pkey_ctx_state,
    EVP_PKEY_CTX_ctrl, EVP_PKEY_CTX_get_params, EVP_PKEY_CTX_is_a, EvpPkeyCtx,
    EVP_PKEY_CTRL_GET_RSA_MGF1_MD, EVP_PKEY_CTRL_GET_RSA_OAEP_MD, EVP_PKEY_CTRL_GET_RSA_PADDING,
    EVP_PKEY_CTRL_GET_RSA_PSS_SALTLEN, EVP_PKEY_CTRL_MD, EVP_PKEY_CTRL_RSA_KEYGEN_PUBEXP,
    EVP_PKEY_CTRL_RSA_MGF1_MD, EVP_PKEY_CTRL_RSA_OAEP_MD, EVP_PKEY_CTRL_RSA_PADDING,
    EVP_PKEY_CTRL_RSA_PSS_SALTLEN, EVP_PKEY_OP_KEYGEN, EVP_PKEY_OP_TYPE_CRYPT,
    EVP_PKEY_OP_TYPE_SIG, EVP_PKEY_RSA, EVP_PKEY_RSA_PSS, EVP_PKEY_STATE_PROVIDER,
    OSSL_ASYM_CIPHER_PARAM_OAEP_DIGEST, OSSL_ASYM_CIPHER_PARAM_OAEP_DIGEST_PROPS,
    OSSL_ASYM_CIPHER_PARAM_OAEP_LABEL, OSSL_PKEY_PARAM_MGF1_DIGEST,
    OSSL_PKEY_PARAM_MGF1_PROPERTIES, OSSL_PKEY_PARAM_RSA_BITS, OSSL_PKEY_PARAM_RSA_DIGEST,
    OSSL_PKEY_PARAM_RSA_DIGEST_PROPS, OSSL_PKEY_PARAM_RSA_PRIMES, OSSL_SIGNATURE_PARAM_PSS_SALTLEN,
};
use crate::params::{
    OSSL_PARAM_construct_end, OSSL_PARAM_construct_int, OSSL_PARAM_construct_octet_ptr,
    OSSL_PARAM_construct_octet_string, OSSL_PARAM_construct_size_t,
    OSSL_PARAM_construct_utf8_string, OsslParam,
};
use crate::runtime::err::err_sites;
use crate::runtime::err::raise_site;

/// The allocation-tracking `file` argument for this unit's allocations and releases.
///
/// `crypto/rsa/rsa_lib.c` is a **source-tree** file, so its `__FILE__` carries the
/// `../../src/openssl-3.6.4/` prefix — the same check D279/D280/D321 applied. This module has
/// exactly one allocation-facing call: `EVP_PKEY_CTX_set0_rsa_oaep_label`'s `OPENSSL_free(label)` at
/// `rsa_lib.c:1211`, which is a *release* and still records its coordinate to an installed
/// allocator.
const FILE_LIB: *const c_char = c"../../src/openssl-3.6.4/crypto/rsa/rsa_lib.c".as_ptr();

/// `__LINE__` of that release, `rsa_lib.c:1211`. Inert under `OPENSSL_NO_CRYPTO_MDEBUG`.
const LINE_FREE_LABEL: c_int = 1211;

/// `int RSA_pkey_ctx_ctrl(EVP_PKEY_CTX *ctx, int optype, int cmd, int p1, void *p2)` —
/// `rsa_lib.c:741-749`.
///
/// **The key-type guard is the whole function, and it is dead in this crate.** The authority's body
/// is one `if` that refuses `-1` for a context whose *legacy* method is neither RSA nor RSA-PSS, and
/// then the call. `ctx->pmeth` does not exist here (this module's header says why), so the `if`'s
/// condition is a compile-time `false` and what remains is the call with the same arguments. The
/// reduction is the `src/evp/pkey_ctx.rs` one about `pmeth`, seen from its only reader in 8.4.
///
/// **`optype` reaches `EVP_PKEY_CTX_ctrl` unchanged, and `-1` is a real value.** Three of the
/// eight callers below pass `-1` -- "any operation" -- and the other five pass one of the two type
/// masks, so the operation test inside `EVP_PKEY_CTX_ctrl` is what distinguishes a signing control
/// from a key-generation one.
///
/// # Safety
/// `ctx` NULL or live; `p2` NULL or valid for the ctrl `cmd` names.
#[no_mangle]
pub unsafe extern "C" fn RSA_pkey_ctx_ctrl(
    ctx: *mut EvpPkeyCtx,
    optype: c_int,
    cmd: c_int,
    p1: c_int,
    p2: *mut c_void,
) -> c_int {
    /* The authority's `ctx != NULL && ctx->pmeth != NULL && ctx->pmeth->pkey_id != EVP_PKEY_RSA &&
     * ctx->pmeth->pkey_id != EVP_PKEY_RSA_PSS` guard, reduced: `pmeth` is absent from this crate's
     * `EvpPkeyCtx`, so the conjunction is false for every context and nothing is refused here. */
    // SAFETY: the caller's contract, forwarded unchanged. `-1` as the key type is the authority's
    // own argument at this call and means "do not test the key type again".
    unsafe { EVP_PKEY_CTX_ctrl(ctx, -1, optype, cmd, p1, p2) }
}

/// `static int int_set_rsa_md_name(EVP_PKEY_CTX *ctx, int keytype, int optype, const char *mdkey,`
/// `const char *mdname, const char *propkey, const char *mdprops)` — `rsa_lib.c:963-1000`.
///
/// The shared body of the four `_name` *setters*, and it is the one function in this file whose
/// refusals have three different reasons:
///
///   * `ctx == NULL`, `mdname == NULL`, or an operation of the wrong type is `-2` with
///     `EVP_R_COMMAND_NOT_SUPPORTED` — **the same value `EVP_PKEY_CTX_ctrl` answers**, which the
///     authority's comment says is deliberate;
///   * a key type that is not the one asked for is `-1` with **no raise at all**;
///   * otherwise the parameters go to `evp_pkey_ctx_set_params_strict`, whose `-2` (a parameter the
///     method does not list) is what makes this a *provider* control rather than a ctrl.
///
/// **The `keytype == -1` case tests two names and the default case tests one**, because `-1` means
/// "either RSA or RSA-PSS" and a named key type means exactly that type. `evp_pkey_type2name` is the
/// same resolution `EVP_PKEY_CTX_ctrl`'s translation table uses.
///
/// **The property query is added only for a provider context and only when non-NULL.** A legacy
/// context gets a one-parameter array, so a caller that passes properties to a legacy method is
/// silently ignored rather than refused — and `ctx` cannot be legacy *and* live in this crate, which
/// is why the arm is transcribed and not tested.
///
/// # Safety
/// `ctx` NULL or live; `mdname` NULL or NUL-terminated; `mdprops` NULL or NUL-terminated.
unsafe fn int_set_rsa_md_name(
    ctx: *mut EvpPkeyCtx,
    keytype: c_int,
    optype: c_int,
    mdkey: *const c_char,
    mdname: *const c_char,
    propkey: *const c_char,
    mdprops: *const c_char,
) -> c_int {
    let mut params: [OsslParam; 3] = [OSSL_PARAM_construct_end(); 3];
    let mut p = 0usize;

    /* The authority's `ctx == NULL || mdname == NULL || (ctx->operation & optype) == 0`, three
     * clauses short-circuited in that order -- which is what makes the dereference safe here. */
    // SAFETY: `ctx` is non-NULL when the third clause is reached, and live per the contract.
    if ctx.is_null() || mdname.is_null() || unsafe { (*ctx).operation } & optype == 0 {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::RSA_LIB_973) };
        /* Uses the same return values as `EVP_PKEY_CTX_ctrl`. */
        return -2;
    }

    /* If key type not RSA return error. */
    if keytype == -1 {
        // SAFETY: `ctx` is non-NULL and live; both names are NUL-terminated literals.
        if unsafe { EVP_PKEY_CTX_is_a(ctx, c"RSA".as_ptr()) } == 0
            // SAFETY: `ctx` is non-NULL and live; the name is NUL-terminated. The `&&`
            // short-circuits exactly as the authority's does.
            && unsafe { EVP_PKEY_CTX_is_a(ctx, c"RSA-PSS".as_ptr()) } == 0
        {
            return -1;
        }
    } else {
        // SAFETY: `ctx` is non-NULL and live; the callee answers a NUL-terminated name.
        if unsafe { EVP_PKEY_CTX_is_a(ctx, evp_pkey_type2name(keytype)) } == 0 {
            return -1;
        }
    }

    /* Cast away the const. This is read only so should be safe. */
    // SAFETY: `mdkey` is NUL-terminated and `mdname` is NUL-terminated per the contract.
    params[p] = unsafe { OSSL_PARAM_construct_utf8_string(mdkey, mdname.cast_mut(), 0) };
    p += 1;
    // SAFETY: `ctx` is non-NULL and live.
    if unsafe { evp_pkey_ctx_state(ctx) } == EVP_PKEY_STATE_PROVIDER && !mdprops.is_null() {
        /* Cast away the const. This is read only so should be safe. */
        // SAFETY: `propkey` and `mdprops` are NUL-terminated.
        params[p] = unsafe { OSSL_PARAM_construct_utf8_string(propkey, mdprops.cast_mut(), 0) };
        p += 1;
    }
    params[p] = OSSL_PARAM_construct_end();

    // SAFETY: `ctx` is live and `params` is a terminated array of `p + 1` entries.
    unsafe { evp_pkey_ctx_set_params_strict(ctx, params.as_mut_ptr()) }
}

/// `static int int_get_rsa_md_name(EVP_PKEY_CTX *ctx, int keytype, int optype, const char *mdkey,`
/// `char *mdname, size_t mdnamesize)` — `rsa_lib.c:1003-1036`.
///
/// The read half, and the two differences from the setter are both in the array: there is **no
/// property parameter** (a name is read out of a method, not asked for with a query) and the
/// `utf8_string` is built with a *buffer size* rather than `0`, because the callee is writing into
/// the caller's buffer and needs to know how much room it has.
///
/// # Safety
/// `ctx` NULL or live; `mdname` NULL or writable for `mdnamesize` bytes.
unsafe fn int_get_rsa_md_name(
    ctx: *mut EvpPkeyCtx,
    keytype: c_int,
    optype: c_int,
    mdkey: *const c_char,
    mdname: *mut c_char,
    mdnamesize: usize,
) -> c_int {
    let mut params: [OsslParam; 2] = [OSSL_PARAM_construct_end(); 2];

    /* The authority's `ctx == NULL || mdname == NULL || (ctx->operation & optype) == 0`, three
     * clauses short-circuited in that order -- which is what makes the dereference safe here. */
    // SAFETY: `ctx` is non-NULL when the third clause is reached, and live per the contract.
    if ctx.is_null() || mdname.is_null() || unsafe { (*ctx).operation } & optype == 0 {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::RSA_LIB_1013) };
        /* Uses the same return values as `EVP_PKEY_CTX_ctrl`. */
        return -2;
    }

    /* If key type not RSA return error. */
    if keytype == -1 {
        // SAFETY: `ctx` is non-NULL and live; both names are NUL-terminated literals.
        if unsafe { EVP_PKEY_CTX_is_a(ctx, c"RSA".as_ptr()) } == 0
            // SAFETY: `ctx` is non-NULL and live; the name is NUL-terminated. The `&&`
            // short-circuits exactly as the authority's does.
            && unsafe { EVP_PKEY_CTX_is_a(ctx, c"RSA-PSS".as_ptr()) } == 0
        {
            return -1;
        }
    } else {
        // SAFETY: `ctx` is non-NULL and live.
        if unsafe { EVP_PKEY_CTX_is_a(ctx, evp_pkey_type2name(keytype)) } == 0 {
            return -1;
        }
    }

    /* Cast away the const. This is read only so should be safe. */
    // SAFETY: `mdkey` is NUL-terminated and `mdname` is writable for `mdnamesize` bytes.
    params[0] = unsafe { OSSL_PARAM_construct_utf8_string(mdkey, mdname, mdnamesize) };
    params[1] = OSSL_PARAM_construct_end();

    // SAFETY: `ctx` is live and `params` is a terminated two-entry array.
    unsafe { evp_pkey_ctx_get_params_strict(ctx, params.as_mut_ptr()) }
}

// ---------------------------------------------------------------------------------------------
// The eight `RSA_pkey_ctx_ctrl` wrappers
// ---------------------------------------------------------------------------------------------

/// `int EVP_PKEY_CTX_set_rsa_padding(EVP_PKEY_CTX *ctx, int pad_mode)` — `rsa_lib.c:1042-1046`.
///
/// `-1` for both the key type and the operation, so this control is accepted on any RSA context in
/// any state and the *padding* value is what `pkey_rsa_ctrl` later validates.
///
/// # Safety
/// `ctx` NULL or live.
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_CTX_set_rsa_padding(
    ctx: *mut EvpPkeyCtx,
    pad_mode: c_int,
) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        RSA_pkey_ctx_ctrl(
            ctx,
            -1,
            EVP_PKEY_CTRL_RSA_PADDING,
            pad_mode,
            core::ptr::null_mut(),
        )
    }
}

/// `int EVP_PKEY_CTX_get_rsa_padding(EVP_PKEY_CTX *ctx, int *pad_mode)` — `rsa_lib.c:1052-1056`.
///
/// The read half, and its `p1` is `0` because the command itself says "GET": the answer travels in
/// `p2`. `EVP_PKEY_CTRL_GET_RSA_PADDING` is also the one RSA ctrl whose `p2` is *written* rather
/// than read, which `src/evp/pkey_ctx.rs` records at the translation table.
///
/// # Safety
/// `ctx` NULL or live; `pad_mode` NULL or a live `int` the callee writes.
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_CTX_get_rsa_padding(
    ctx: *mut EvpPkeyCtx,
    pad_mode: *mut c_int,
) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        RSA_pkey_ctx_ctrl(
            ctx,
            -1,
            EVP_PKEY_CTRL_GET_RSA_PADDING,
            0,
            pad_mode.cast::<c_void>(),
        )
    }
}

/// `int EVP_PKEY_CTX_set_rsa_pss_keygen_md(EVP_PKEY_CTX *ctx, const EVP_MD *md)` —
/// `rsa_lib.c:1062-1066`.
///
/// **The only one of the eight that names a key type and not a mask.** It is `EVP_PKEY_RSA_PSS`
/// with `EVP_PKEY_OP_KEYGEN`, so an RSA (non-PSS) key-generation context refuses it — and that
/// refusal comes from `EVP_PKEY_CTX_ctrl`'s key-type test in the legacy path and from
/// `evp_pkey_ctx_ctrl_to_param`'s `pkey_id` test in the provider one.
///
/// # Safety
/// `ctx` NULL or live; `md` NULL or a live digest method.
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_CTX_set_rsa_pss_keygen_md(
    ctx: *mut EvpPkeyCtx,
    md: *const EvpMd,
) -> c_int {
    // SAFETY: the caller's contract; the digest travels as a pointer in `p2`, the authority's own
    // `(void *)(md)` cast.
    unsafe {
        EVP_PKEY_CTX_ctrl(
            ctx,
            EVP_PKEY_RSA_PSS,
            EVP_PKEY_OP_KEYGEN,
            EVP_PKEY_CTRL_MD,
            0,
            md.cast_mut().cast::<c_void>(),
        )
    }
}

/// `int EVP_PKEY_CTX_set_rsa_pss_keygen_md_name(EVP_PKEY_CTX *ctx, const char *mdname,`
/// `const char *mdprops)` — `rsa_lib.c:1068-1075`.
///
/// The name-based sibling of the pair above, and the first of the four `int_set_rsa_md_name`
/// callers: the key type is `EVP_PKEY_RSA_PSS` and the parameter keys are the *key generation*
/// `digest`/`properties` pair.
///
/// # Safety
/// `ctx` NULL or live; `mdname` NULL or NUL-terminated; `mdprops` NULL or NUL-terminated.
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_CTX_set_rsa_pss_keygen_md_name(
    ctx: *mut EvpPkeyCtx,
    mdname: *const c_char,
    mdprops: *const c_char,
) -> c_int {
    // SAFETY: the caller's contract, forwarded unchanged.
    unsafe {
        int_set_rsa_md_name(
            ctx,
            EVP_PKEY_RSA_PSS,
            EVP_PKEY_OP_KEYGEN,
            OSSL_PKEY_PARAM_RSA_DIGEST,
            mdname,
            OSSL_PKEY_PARAM_RSA_DIGEST_PROPS,
            mdprops,
        )
    }
}

/// `int EVP_PKEY_CTX_set_rsa_oaep_md(EVP_PKEY_CTX *ctx, const EVP_MD *md)` — `rsa_lib.c:1081-1089`.
///
/// **The key-type test is `EVP_PKEY_CTX_is_a` here and the ctrl's own test is still made**, which is
/// the redundancy the authority's comment does not explain: this function refuses `-1` for a
/// context that is not RSA *before* the call, and the call then asks for `EVP_PKEY_RSA` with
/// `EVP_PKEY_OP_TYPE_CRYPT`.
///
/// `EVP_PKEY_CTX_is_a` **dereferences `ctx` without a NULL test** (`src/evp/pkey_ctx.rs` records
/// that), so a NULL context is a fault on both sides and no NULL arm exists for this control.
///
/// # Safety
/// `ctx` is a **live** context; `md` NULL or a live digest method.
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_CTX_set_rsa_oaep_md(
    ctx: *mut EvpPkeyCtx,
    md: *const EvpMd,
) -> c_int {
    /* If key type not RSA return error. */
    // SAFETY: `ctx` is live per the contract.
    if unsafe { EVP_PKEY_CTX_is_a(ctx, c"RSA".as_ptr()) } == 0 {
        return -1;
    }

    // SAFETY: the caller's contract.
    unsafe {
        EVP_PKEY_CTX_ctrl(
            ctx,
            EVP_PKEY_RSA,
            EVP_PKEY_OP_TYPE_CRYPT,
            EVP_PKEY_CTRL_RSA_OAEP_MD,
            0,
            md.cast_mut().cast::<c_void>(),
        )
    }
}

/// `int EVP_PKEY_CTX_set_rsa_oaep_md_name(EVP_PKEY_CTX *ctx, const char *mdname,`
/// `const char *mdprops)` — `rsa_lib.c:1091-1097`.
///
/// The second `int_set_rsa_md_name` caller: `EVP_PKEY_RSA`, `EVP_PKEY_OP_TYPE_CRYPT`, and the
/// `oaep-digest`/`digest-props` keys — note that the property key is **not** the RSA one. This is
/// the only control where the name form takes a different key type from its `EVP_MD *` sibling's
/// *first test*: `set_rsa_oaep_md` tests `is_a("RSA")` itself, and this one asks
/// `int_set_rsa_md_name`, which tests `evp_pkey_type2name(EVP_PKEY_RSA)`.
///
/// # Safety
/// `ctx` NULL or live; `mdname` NULL or NUL-terminated; `mdprops` NULL or NUL-terminated.
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_CTX_set_rsa_oaep_md_name(
    ctx: *mut EvpPkeyCtx,
    mdname: *const c_char,
    mdprops: *const c_char,
) -> c_int {
    // SAFETY: the caller's contract, forwarded unchanged.
    unsafe {
        int_set_rsa_md_name(
            ctx,
            EVP_PKEY_RSA,
            EVP_PKEY_OP_TYPE_CRYPT,
            OSSL_ASYM_CIPHER_PARAM_OAEP_DIGEST,
            mdname,
            OSSL_ASYM_CIPHER_PARAM_OAEP_DIGEST_PROPS,
            mdprops,
        )
    }
}

/// `int EVP_PKEY_CTX_get_rsa_oaep_md_name(EVP_PKEY_CTX *ctx, char *name, size_t namesize)` —
/// `rsa_lib.c:1099-1105`.
///
/// # Safety
/// `ctx` NULL or live; `name` NULL or writable for `namesize` bytes.
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_CTX_get_rsa_oaep_md_name(
    ctx: *mut EvpPkeyCtx,
    name: *mut c_char,
    namesize: usize,
) -> c_int {
    // SAFETY: the caller's contract, forwarded unchanged.
    unsafe {
        int_get_rsa_md_name(
            ctx,
            EVP_PKEY_RSA,
            EVP_PKEY_OP_TYPE_CRYPT,
            OSSL_ASYM_CIPHER_PARAM_OAEP_DIGEST,
            name,
            namesize,
        )
    }
}

/// `int EVP_PKEY_CTX_get_rsa_oaep_md(EVP_PKEY_CTX *ctx, const EVP_MD **md)` — `rsa_lib.c:1111-1119`.
///
/// `EVP_PKEY_CTX_is_a` again, so this control faults on a NULL context exactly as its setter does
/// and for the same reason.
///
/// # Safety
/// `ctx` is a **live** context; `md` NULL or a live slot the callee writes.
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_CTX_get_rsa_oaep_md(
    ctx: *mut EvpPkeyCtx,
    md: *mut *const EvpMd,
) -> c_int {
    /* If key type not RSA return error. */
    // SAFETY: `ctx` is live per the contract.
    if unsafe { EVP_PKEY_CTX_is_a(ctx, c"RSA".as_ptr()) } == 0 {
        return -1;
    }

    // SAFETY: the caller's contract.
    unsafe {
        EVP_PKEY_CTX_ctrl(
            ctx,
            EVP_PKEY_RSA,
            EVP_PKEY_OP_TYPE_CRYPT,
            EVP_PKEY_CTRL_GET_RSA_OAEP_MD,
            0,
            md.cast::<c_void>(),
        )
    }
}

/// `int EVP_PKEY_CTX_set_rsa_mgf1_md(EVP_PKEY_CTX *ctx, const EVP_MD *md)` — `rsa_lib.c:1125-1129`.
///
/// The operation mask is **`EVP_PKEY_OP_TYPE_SIG | EVP_PKEY_OP_TYPE_CRYPT`**, the union of the two
/// things an MGF1 digest is used for, and the key type is `-1` — so the same control serves a
/// signature context and an encryption context, which is why it cannot name one key type.
///
/// # Safety
/// `ctx` NULL or live; `md` NULL or a live digest method.
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_CTX_set_rsa_mgf1_md(
    ctx: *mut EvpPkeyCtx,
    md: *const EvpMd,
) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        RSA_pkey_ctx_ctrl(
            ctx,
            EVP_PKEY_OP_TYPE_SIG | EVP_PKEY_OP_TYPE_CRYPT,
            EVP_PKEY_CTRL_RSA_MGF1_MD,
            0,
            md.cast_mut().cast::<c_void>(),
        )
    }
}

/// `int EVP_PKEY_CTX_set_rsa_mgf1_md_name(EVP_PKEY_CTX *ctx, const char *mdname,`
/// `const char *mdprops)` — `rsa_lib.c:1131-1138`.
///
/// The third `int_set_rsa_md_name` caller, and the second one whose key type is `-1`: the
/// `mgf1-digest`/`mgf1-properties` pair with both operation bits.
///
/// # Safety
/// `ctx` NULL or live; `mdname` NULL or NUL-terminated; `mdprops` NULL or NUL-terminated.
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_CTX_set_rsa_mgf1_md_name(
    ctx: *mut EvpPkeyCtx,
    mdname: *const c_char,
    mdprops: *const c_char,
) -> c_int {
    // SAFETY: the caller's contract, forwarded unchanged.
    unsafe {
        int_set_rsa_md_name(
            ctx,
            -1,
            EVP_PKEY_OP_TYPE_CRYPT | EVP_PKEY_OP_TYPE_SIG,
            OSSL_PKEY_PARAM_MGF1_DIGEST,
            mdname,
            OSSL_PKEY_PARAM_MGF1_PROPERTIES,
            mdprops,
        )
    }
}

/// `int EVP_PKEY_CTX_get_rsa_mgf1_md_name(EVP_PKEY_CTX *ctx, char *name, size_t namesize)` —
/// `rsa_lib.c:1140-1146`.
///
/// # Safety
/// `ctx` NULL or live; `name` NULL or writable for `namesize` bytes.
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_CTX_get_rsa_mgf1_md_name(
    ctx: *mut EvpPkeyCtx,
    name: *mut c_char,
    namesize: usize,
) -> c_int {
    // SAFETY: the caller's contract, forwarded unchanged.
    unsafe {
        int_get_rsa_md_name(
            ctx,
            -1,
            EVP_PKEY_OP_TYPE_CRYPT | EVP_PKEY_OP_TYPE_SIG,
            OSSL_PKEY_PARAM_MGF1_DIGEST,
            name,
            namesize,
        )
    }
}

/// `int EVP_PKEY_CTX_set_rsa_pss_keygen_mgf1_md(EVP_PKEY_CTX *ctx, const EVP_MD *md)` —
/// `rsa_lib.c:1152-1156`.
///
/// The key-generation pair's MGF1 half: `EVP_PKEY_RSA_PSS` with `EVP_PKEY_OP_KEYGEN` and the
/// *signing* ctrl number `EVP_PKEY_CTRL_RSA_MGF1_MD` — the same number `set_rsa_mgf1_md` uses, with
/// a narrower key type and operation. That is what makes the two distinguishable at all, and it is
/// why the ctrl number alone is not a key.
///
/// # Safety
/// `ctx` NULL or live; `md` NULL or a live digest method.
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_CTX_set_rsa_pss_keygen_mgf1_md(
    ctx: *mut EvpPkeyCtx,
    md: *const EvpMd,
) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        EVP_PKEY_CTX_ctrl(
            ctx,
            EVP_PKEY_RSA_PSS,
            EVP_PKEY_OP_KEYGEN,
            EVP_PKEY_CTRL_RSA_MGF1_MD,
            0,
            md.cast_mut().cast::<c_void>(),
        )
    }
}

/// `int EVP_PKEY_CTX_set_rsa_pss_keygen_mgf1_md_name(EVP_PKEY_CTX *ctx, const char *mdname)` —
/// `rsa_lib.c:1158-1164`.
///
/// The fourth `int_set_rsa_md_name` caller, and the only one that passes **NULL for both the
/// property key and the property value** — so this control can never add a property parameter, and
/// its array is one entry plus the terminator whatever the context is.
///
/// # Safety
/// `ctx` NULL or live; `mdname` NULL or NUL-terminated.
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_CTX_set_rsa_pss_keygen_mgf1_md_name(
    ctx: *mut EvpPkeyCtx,
    mdname: *const c_char,
) -> c_int {
    // SAFETY: the caller's contract, forwarded unchanged.
    unsafe {
        int_set_rsa_md_name(
            ctx,
            EVP_PKEY_RSA_PSS,
            EVP_PKEY_OP_KEYGEN,
            OSSL_PKEY_PARAM_MGF1_DIGEST,
            mdname,
            core::ptr::null(),
            core::ptr::null(),
        )
    }
}

/// `int EVP_PKEY_CTX_get_rsa_mgf1_md(EVP_PKEY_CTX *ctx, const EVP_MD **md)` — `rsa_lib.c:1170-1174`.
///
/// # Safety
/// `ctx` NULL or live; `md` NULL or a live slot the callee writes.
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_CTX_get_rsa_mgf1_md(
    ctx: *mut EvpPkeyCtx,
    md: *mut *const EvpMd,
) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        RSA_pkey_ctx_ctrl(
            ctx,
            EVP_PKEY_OP_TYPE_SIG | EVP_PKEY_OP_TYPE_CRYPT,
            EVP_PKEY_CTRL_GET_RSA_MGF1_MD,
            0,
            md.cast::<c_void>(),
        )
    }
}

/// `int EVP_PKEY_CTX_set_rsa_pss_saltlen(EVP_PKEY_CTX *ctx, int saltlen)` — `rsa_lib.c:1248-1262`.
///
/// The authority's comment records the **widening**: the operation was `EVP_PKEY_OP_SIGN |
/// EVP_PKEY_OP_VERIFY` and is now the whole `EVP_PKEY_OP_TYPE_SIG`, because RSA-PSS uses the salt
/// length for signing, verification *and* recovery. The value itself travels in `p1` and is
/// validated later, by `pkey_rsa_ctrl`'s `RSA_R_INVALID_SALT_LENGTH` arm — not here.
///
/// # Safety
/// `ctx` NULL or live.
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_CTX_set_rsa_pss_saltlen(
    ctx: *mut EvpPkeyCtx,
    saltlen: c_int,
) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        RSA_pkey_ctx_ctrl(
            ctx,
            EVP_PKEY_OP_TYPE_SIG,
            EVP_PKEY_CTRL_RSA_PSS_SALTLEN,
            saltlen,
            core::ptr::null_mut(),
        )
    }
}

/// `int EVP_PKEY_CTX_get_rsa_pss_saltlen(EVP_PKEY_CTX *ctx, int *saltlen)` — `rsa_lib.c:1268-1281`.
///
/// # Safety
/// `ctx` NULL or live; `saltlen` NULL or a live `int` the callee writes.
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_CTX_get_rsa_pss_saltlen(
    ctx: *mut EvpPkeyCtx,
    saltlen: *mut c_int,
) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        RSA_pkey_ctx_ctrl(
            ctx,
            EVP_PKEY_OP_TYPE_SIG,
            EVP_PKEY_CTRL_GET_RSA_PSS_SALTLEN,
            0,
            saltlen.cast::<c_void>(),
        )
    }
}

// ---------------------------------------------------------------------------------------------
// The five `OSSL_PARAM` builders
// ---------------------------------------------------------------------------------------------

/// `int EVP_PKEY_CTX_set_rsa_pss_keygen_saltlen(EVP_PKEY_CTX *ctx, int saltlen)` —
/// `rsa_lib.c:1283-1301`.
///
/// **Not a ctrl at all.** The salt length is built as an `OSSL_SIGNATURE_PARAM_PSS_SALTLEN` **`int`**
/// parameter and handed to the strict setter, so this control never reaches
/// `evp_pkey_ctx_ctrl_to_param`: on a legacy context it answers `-2` (the strict setter's
/// `is_legacy` arm skips the check and `EVP_PKEY_CTX_set_params`'s legacy arm is the ctrl
/// translation, which has no entry for a bare `saltlen` int) where the ctrl-based
/// `set_rsa_pss_saltlen` above would translate.
///
/// **The key type is `RSA-PSS` and the test is `EVP_PKEY_CTX_is_a`**, so a NULL context faults here
/// — except that the `EVP_PKEY_CTX_IS_GEN_OP(ctx)` test comes *first* and dereferences `ctx` too, so
/// the fault is at `:1287` rather than at `:1293`. Either way no NULL arm exists.
///
/// # Safety
/// `ctx` is a **live** context.
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_CTX_set_rsa_pss_keygen_saltlen(
    ctx: *mut EvpPkeyCtx,
    saltlen: c_int,
) -> c_int {
    let mut params: [OsslParam; 2] = [OSSL_PARAM_construct_end(); 2];

    // SAFETY: `ctx` is live per the contract.
    if ctx.is_null() || !unsafe { (*ctx).is_gen_op() } {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::RSA_LIB_1288) };
        /* Uses the same return values as `EVP_PKEY_CTX_ctrl`. */
        return -2;
    }

    // SAFETY: `ctx` is live.
    if unsafe { EVP_PKEY_CTX_is_a(ctx, c"RSA-PSS".as_ptr()) } == 0 {
        return -1;
    }

    let mut saltlen = saltlen;
    // SAFETY: `OSSL_SIGNATURE_PARAM_PSS_SALTLEN` is NUL-terminated and `saltlen` is a live local.
    params[0] = unsafe { OSSL_PARAM_construct_int(OSSL_SIGNATURE_PARAM_PSS_SALTLEN, &mut saltlen) };
    params[1] = OSSL_PARAM_construct_end();

    // SAFETY: `ctx` is live; `params[0]`'s `data` points at the local `saltlen`, which outlives the
    // call, and the array is terminated.
    unsafe { evp_pkey_ctx_set_params_strict(ctx, params.as_mut_ptr()) }
}

/// `int EVP_PKEY_CTX_set_rsa_keygen_bits(EVP_PKEY_CTX *ctx, int bits)` — `rsa_lib.c:1303-1323`.
///
/// The width as a **`size_t`** parameter named `OSSL_PKEY_PARAM_RSA_BITS`, which is the same string
/// as `OSSL_PKEY_PARAM_BITS` — so the key-generation row and the key's own `bits` parameter share a
/// name, and only the method that receives it can tell the two apart. The key type is either RSA or
/// RSA-PSS, tested with two `EVP_PKEY_CTX_is_a` calls joined by `&&`.
///
/// # Safety
/// `ctx` is a **live** context.
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_CTX_set_rsa_keygen_bits(
    ctx: *mut EvpPkeyCtx,
    bits: c_int,
) -> c_int {
    let mut params: [OsslParam; 2] = [OSSL_PARAM_construct_end(); 2];

    // SAFETY: `ctx` is live per the contract.
    if ctx.is_null() || !unsafe { (*ctx).is_gen_op() } {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::RSA_LIB_1309) };
        /* Uses the same return values as `EVP_PKEY_CTX_ctrl`. */
        return -2;
    }

    /* If key type not RSA return error. */
    // SAFETY: `ctx` is live.
    if unsafe { EVP_PKEY_CTX_is_a(ctx, c"RSA".as_ptr()) } == 0
        // SAFETY: `ctx` is non-NULL and live; the name is NUL-terminated. The `&&`
        // short-circuits exactly as the authority's does.
        && unsafe { EVP_PKEY_CTX_is_a(ctx, c"RSA-PSS".as_ptr()) } == 0
    {
        return -1;
    }

    let mut bits2 = bits as usize;
    // SAFETY: `OSSL_PKEY_PARAM_RSA_BITS` is NUL-terminated and `bits2` is a live local.
    params[0] = unsafe { OSSL_PARAM_construct_size_t(OSSL_PKEY_PARAM_RSA_BITS, &mut bits2) };
    params[1] = OSSL_PARAM_construct_end();

    // SAFETY: `ctx` is live; `params[0]`'s `data` points at the local `bits2`, which outlives the
    // call, and the array is terminated.
    unsafe { evp_pkey_ctx_set_params_strict(ctx, params.as_mut_ptr()) }
}

/// `int EVP_PKEY_CTX_set_rsa_keygen_pubexp(EVP_PKEY_CTX *ctx, BIGNUM *pubexp)` —
/// `rsa_lib.c:1325-1341`.
///
/// **The one control that takes custody of memory**, and its comment explains why: a pre-3.0 caller
/// expects the `BIGNUM` it passes to become the context's. So on a *provider* context the previous
/// `rsa_pubexp` is released and the caller's pointer is stored — and it is `EVP_PKEY_CTX_free`'s
/// `BN_free` that later releases it, which is the field `src/evp/pkey_ctx.rs` had been carrying
/// without a writer.
///
/// **The custody transfer happens only when the ctrl answered `> 0`**, so a refused control leaves
/// the caller owning its `BIGNUM`. The asymmetry with `set1_...` below is the whole reason both
/// names exist.
///
/// # Safety
/// `ctx` NULL or live; `pubexp` NULL or a live `BIGNUM` whose ownership transfers on success.
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_CTX_set_rsa_keygen_pubexp(
    ctx: *mut EvpPkeyCtx,
    pubexp: *mut BigNum,
) -> c_int {
    // SAFETY: the caller's contract.
    let ret = unsafe {
        RSA_pkey_ctx_ctrl(
            ctx,
            EVP_PKEY_OP_KEYGEN,
            EVP_PKEY_CTRL_RSA_KEYGEN_PUBEXP,
            0,
            pubexp.cast::<c_void>(),
        )
    };

    /* Satisfy memory semantics for pre-3.0 callers: their expectation is that the input `pubexp`
     * `BIGNUM` becomes managed by the `EVP_PKEY_CTX` on success. */
    // SAFETY: `ret > 0` is only answered by `EVP_PKEY_CTX_ctrl` for a non-NULL context, so the
    // context is live on this path -- which is also why the authority's own test is a bare
    // `evp_pkey_ctx_is_provided(ctx)` there.
    if ret > 0 && unsafe { evp_pkey_ctx_state(ctx) } == EVP_PKEY_STATE_PROVIDER {
        // SAFETY: both are NULL or live `BIGNUM`s.
        unsafe {
            BN_free((*ctx).rsa_pubexp);
            (*ctx).rsa_pubexp = pubexp;
        }
    }

    ret
}

/// `int EVP_PKEY_CTX_set1_rsa_keygen_pubexp(EVP_PKEY_CTX *ctx, BIGNUM *pubexp)` —
/// `rsa_lib.c:1343-1361`.
///
/// **It duplicates on a legacy context and does not on a provider one**, because a provider
/// transforms the value into an `OSSL_PARAM` and copies it there anyway — the authority's comment
/// says exactly that. So this is the *ownership-preserving* spelling: the caller keeps its `BIGNUM`
/// on both paths, and the duplicate is released if the ctrl refuses.
///
/// **`evp_pkey_ctx_is_legacy(ctx)` is `ctx->keymgmt == NULL` and it is evaluated twice**, with the
/// `BN_free` in between. It **dereferences `ctx` without a NULL test**, so a NULL context is a fault
/// on both sides — and unlike `set_rsa_keygen_pubexp` above, this function's first statement is that
/// dereference, so no NULL arm exists.
///
/// The crate's transcription writes the test as a helper on a non-NULL pointer and says so: Rust has
/// no way to reproduce a `((ctx)->keymgmt == NULL)` that is *undefined* for NULL, so the null case
/// is excluded by the contract instead of by a test the authority does not make.
///
/// # Safety
/// `ctx` is a **live** context; `pubexp` NULL or a live `BIGNUM` the caller keeps ownership of.
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_CTX_set1_rsa_keygen_pubexp(
    ctx: *mut EvpPkeyCtx,
    pubexp: *mut BigNum,
) -> c_int {
    let mut pubexp = pubexp;

    /* When we're dealing with a provider, there's no need to duplicate `pubexp`, as it gets copied
     * when transforming to an `OSSL_PARAM` anyway. */
    // SAFETY: `ctx` is live per the contract.
    let legacy = unsafe { (*ctx).is_legacy() };
    if legacy {
        // SAFETY: `pubexp` is NULL or live; `BN_dup(NULL)` answers NULL.
        pubexp = unsafe { BN_dup(pubexp) };
        if pubexp.is_null() {
            return 0;
        }
    }
    // SAFETY: the caller's contract.
    let ret = unsafe {
        EVP_PKEY_CTX_ctrl(
            ctx,
            EVP_PKEY_RSA,
            EVP_PKEY_OP_KEYGEN,
            EVP_PKEY_CTRL_RSA_KEYGEN_PUBEXP,
            0,
            pubexp.cast::<c_void>(),
        )
    };
    // SAFETY: `ctx` is live, so the same test answers the same value it did above.
    if unsafe { (*ctx).is_legacy() } && ret <= 0 {
        // SAFETY: `pubexp` is this call's own duplicate, allocated above.
        unsafe { BN_free(pubexp) };
    }
    ret
}

/// `int EVP_PKEY_CTX_set_rsa_keygen_primes(EVP_PKEY_CTX *ctx, int primes)` — `rsa_lib.c:1363-1383`.
///
/// The prime count as a **`size_t`** `primes` parameter, with the same two-name key-type test as
/// `set_rsa_keygen_bits`. The count is *not* validated here — `rsa_gen.c`'s own `primes < 3` and
/// `ossl_rsa_multip_cap` checks are what refuse an impossible one.
///
/// # Safety
/// `ctx` is a **live** context.
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_CTX_set_rsa_keygen_primes(
    ctx: *mut EvpPkeyCtx,
    primes: c_int,
) -> c_int {
    let mut params: [OsslParam; 2] = [OSSL_PARAM_construct_end(); 2];

    // SAFETY: `ctx` is live per the contract.
    if ctx.is_null() || !unsafe { (*ctx).is_gen_op() } {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::RSA_LIB_1369) };
        /* Uses the same return values as `EVP_PKEY_CTX_ctrl`. */
        return -2;
    }

    /* If key type not RSA return error. */
    // SAFETY: `ctx` is live.
    if unsafe { EVP_PKEY_CTX_is_a(ctx, c"RSA".as_ptr()) } == 0
        // SAFETY: `ctx` is non-NULL and live; the name is NUL-terminated. The `&&`
        // short-circuits exactly as the authority's does.
        && unsafe { EVP_PKEY_CTX_is_a(ctx, c"RSA-PSS".as_ptr()) } == 0
    {
        return -1;
    }

    let mut primes2 = primes as usize;
    // SAFETY: `OSSL_PKEY_PARAM_RSA_PRIMES` is NUL-terminated and `primes2` is a live local.
    params[0] = unsafe { OSSL_PARAM_construct_size_t(OSSL_PKEY_PARAM_RSA_PRIMES, &mut primes2) };
    params[1] = OSSL_PARAM_construct_end();

    // SAFETY: `ctx` is live; `params[0]`'s `data` points at the local `primes2`, which outlives the
    // call, and the array is terminated.
    unsafe { evp_pkey_ctx_set_params_strict(ctx, params.as_mut_ptr()) }
}

// ---------------------------------------------------------------------------------------------
// The OAEP label pair
// ---------------------------------------------------------------------------------------------

/// `int EVP_PKEY_CTX_set0_rsa_oaep_label(EVP_PKEY_CTX *ctx, void *label, int llen)` —
/// `rsa_lib.c:1176-1213`.
///
/// **`set0` means the function takes the buffer, and it frees it after the call** — so a caller
/// passes an `OPENSSL_malloc`ed label and must not use it afterwards, whether or not the control
/// succeeded. The `NULL`/`0` case is special-cased to a pointer to the empty string *before* the
/// parameter is built, which is the authority's "Accept NULL for backward compatibility": a provider
/// that checks for a non-NULL label pointer sees one either way.
///
/// **It reaches `EVP_PKEY_CTX_set_params` through the *strict* wrapper, not through a ctrl**, so the
/// operation test is the caller's: `EVP_PKEY_CTX_IS_ASYM_CIPHER_OP` must hold *before* the key type
/// is even examined, which is why this control's `-2` and `-1` are ordered differently from
/// `int_set_rsa_md_name`'s.
///
/// The `ctx == NULL` case short-circuits the operation test (C's `||` evaluates the left side
/// first), so a NULL context is **safe here** and answers `-2` — one of the three controls in this
/// file for which a NULL arm exists.
///
/// # Safety
/// `ctx` NULL or live; `label` NULL (with `llen == 0`) or an `OPENSSL_malloc`ed buffer of `llen`
/// bytes whose ownership transfers to this call.
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_CTX_set0_rsa_oaep_label(
    ctx: *mut EvpPkeyCtx,
    label: *mut c_void,
    llen: c_int,
) -> c_int {
    let mut params: [OsslParam; 2] = [OSSL_PARAM_construct_end(); 2];
    /* Needed as we swap `label` with `empty` if it is NULL, and `label` is freed at the end of this
     * function. */
    let mut plabel = label;

    // SAFETY: `ctx` is NULL or live; the two clauses are short-circuited in this order.
    if ctx.is_null() || !unsafe { (*ctx).is_asym_cipher_op() } {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::RSA_LIB_1188) };
        /* Uses the same return values as `EVP_PKEY_CTX_ctrl`. */
        return -2;
    }

    /* If key type not RSA return error. */
    // SAFETY: `ctx` is live.
    if unsafe { EVP_PKEY_CTX_is_a(ctx, c"RSA".as_ptr()) } == 0 {
        return -1;
    }

    /* Accept NULL for backward compatibility. */
    if label.is_null() && llen == 0 {
        plabel = c"".as_ptr() as *mut c_void;
    }

    /* Cast away the const. This is read only so should be safe. */
    // SAFETY: `OSSL_ASYM_CIPHER_PARAM_OAEP_LABEL` is NUL-terminated and `plabel` is readable for
    // `llen` bytes.
    params[0] = unsafe {
        OSSL_PARAM_construct_octet_string(OSSL_ASYM_CIPHER_PARAM_OAEP_LABEL, plabel, llen as usize)
    };
    params[1] = OSSL_PARAM_construct_end();

    // SAFETY: `ctx` is live and `params` is a terminated two-entry array whose first entry's buffer
    // is `plabel` for `llen` bytes.
    let ret = unsafe { evp_pkey_ctx_set_params_strict(ctx, params.as_mut_ptr()) };
    if ret <= 0 {
        return ret;
    }

    /* Ownership is supposed to be transferred to the callee. */
    // SAFETY: `label` is the caller's allocation, which this call owns on this path.
    unsafe { crate::runtime::mem::CRYPTO_free(label, FILE_LIB, LINE_FREE_LABEL) };
    1
}

/// `int EVP_PKEY_CTX_get0_rsa_oaep_label(EVP_PKEY_CTX *ctx, unsigned char **label)` —
/// `rsa_lib.c:1215-1242`.
///
/// The read half, and it is **not** the strict getter's mirror: it calls `EVP_PKEY_CTX_get_params`
/// directly, so a parameter the method does not list is *answered* by whatever the method does
/// rather than being refused up front. The answer is the label's length, and it is checked against
/// `INT_MAX` before the cast — the one refusal here that is not a `-2`.
///
/// **The parameter is an `octet_ptr`, not an `octet_string`**: the method writes the *address* of
/// its own label into the caller's `*label` slot rather than copying bytes into a caller buffer, and
/// `return_size` is that label's length. `EVP_PKEY_CTX_get0_rsa_oaep_label`'s `get0` is the promise
/// that the pointer is borrowed.
///
/// # Safety
/// `ctx` NULL or live; `label` NULL or a live slot the callee writes a borrowed pointer into.
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_CTX_get0_rsa_oaep_label(
    ctx: *mut EvpPkeyCtx,
    label: *mut *mut core::ffi::c_uchar,
) -> c_int {
    let mut params: [OsslParam; 2] = [OSSL_PARAM_construct_end(); 2];

    // SAFETY: `ctx` is NULL or live; the two clauses are short-circuited in this order.
    if ctx.is_null() || !unsafe { (*ctx).is_asym_cipher_op() } {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::RSA_LIB_1221) };
        /* Uses the same return values as `EVP_PKEY_CTX_ctrl`. */
        return -2;
    }

    /* If key type not RSA return error. */
    // SAFETY: `ctx` is live.
    if unsafe { EVP_PKEY_CTX_is_a(ctx, c"RSA".as_ptr()) } == 0 {
        return -1;
    }

    // SAFETY: `OSSL_ASYM_CIPHER_PARAM_OAEP_LABEL` is NUL-terminated and `label` is a live slot the
    // callee writes a borrowed pointer into.
    params[0] = unsafe {
        OSSL_PARAM_construct_octet_ptr(
            OSSL_ASYM_CIPHER_PARAM_OAEP_LABEL,
            label.cast::<*mut c_void>(),
            0,
        )
    };
    params[1] = OSSL_PARAM_construct_end();

    // SAFETY: `ctx` is live and `params` is a terminated two-entry array.
    if unsafe { EVP_PKEY_CTX_get_params(ctx, params.as_mut_ptr()) } == 0 {
        return -1;
    }

    let labellen = params[0].return_size;
    if labellen > c_int::MAX as usize {
        return -1;
    }

    labellen as c_int
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The three controls whose first statement dereferences `ctx` and the twenty that answer a
    /// NULL context: the split is a contract, so it is asserted rather than left to the court.
    ///
    /// The ones that cannot be called with NULL are named here and *not* called, which is the same
    /// discipline `RT-RSA`'s arms take.
    #[test]
    fn the_null_context_controls_answer_minus_two_with_a_drained_queue() {
        // Each of these has `ctx == NULL` as its first tested condition.
        // SAFETY: all of these take a NULL context by construction.
        unsafe {
            crate::runtime::err::ERR_clear_error();
            assert_eq!(
                EVP_PKEY_CTX_set0_rsa_oaep_label(core::ptr::null_mut(), core::ptr::null_mut(), 0),
                -2
            );
            assert_eq!(
                EVP_PKEY_CTX_get0_rsa_oaep_label(core::ptr::null_mut(), core::ptr::null_mut()),
                -2
            );
            // The four ctrl wrappers reach `EVP_PKEY_CTX_ctrl`, whose own NULL test answers `-2`.
            assert_eq!(EVP_PKEY_CTX_set_rsa_padding(core::ptr::null_mut(), 1), -2);
            assert_eq!(
                EVP_PKEY_CTX_get_rsa_mgf1_md(core::ptr::null_mut(), core::ptr::null_mut()),
                -2
            );
            // And the `RSA_pkey_ctx_ctrl` door itself.
            assert_eq!(
                RSA_pkey_ctx_ctrl(
                    core::ptr::null_mut(),
                    -1,
                    EVP_PKEY_CTRL_RSA_PADDING,
                    1,
                    core::ptr::null_mut()
                ),
                -2
            );
        }
        // Seven raises at five distinct sites, all of them `EVP_R_COMMAND_NOT_SUPPORTED` except the
        // ctrl's own two.
        assert_ne!(crate::runtime::err::ERR_peek_error(), 0);
        crate::runtime::err::ERR_clear_error();
    }

    /// `RSA_pkey_ctx_ctrl`'s dead guard, asserted as a behaviour: a NULL context is passed *through*
    /// to `EVP_PKEY_CTX_ctrl` rather than being refused by the guard, which is what the guard could
    /// never have done in this crate.
    #[test]
    fn the_pkey_ctx_ctrl_door_passes_null_through_to_the_ctrl() {
        crate::runtime::err::ERR_clear_error();
        // SAFETY: `ctx` is NULL and `p2` is NULL.
        let via_door = unsafe {
            RSA_pkey_ctx_ctrl(
                core::ptr::null_mut(),
                EVP_PKEY_OP_TYPE_SIG,
                EVP_PKEY_CTRL_RSA_PSS_SALTLEN,
                -2,
                core::ptr::null_mut(),
            )
        };
        // SAFETY: the same arguments, straight to the ctrl.
        let direct = unsafe {
            EVP_PKEY_CTX_ctrl(
                core::ptr::null_mut(),
                -1,
                EVP_PKEY_OP_TYPE_SIG,
                EVP_PKEY_CTRL_RSA_PSS_SALTLEN,
                -2,
                core::ptr::null_mut(),
            )
        };
        assert_eq!(via_door, direct);
        assert_eq!(via_door, -2);
        crate::runtime::err::ERR_clear_error();
    }
}
