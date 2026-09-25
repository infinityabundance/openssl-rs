//! Phase 10 — the base provider: `providers/baseprov.c` (183 lines), transcribed whole.
//!
//! The `base` provider is one of OpenSSL's built-in providers. It is deliberately small: it
//! answers four `OSSL_PROV_PARAM_*` questions about itself, and it publishes exactly one
//! `OSSL_OP_RAND` row (`SEED-SRC`) so that a seed source is reachable even when the default
//! provider is not loaded. This module is a transcription of the whole file.
//!
//! # Authority lines transcribed
//!
//! * `base_param_types[]` — `baseprov.c:33-39`;
//! * `base_gettable_params` — `baseprov.c:41-44`;
//! * `base_get_params` — `baseprov.c:46-65`;
//! * `base_rands[]` — `baseprov.c:90-96`, carried as [`crate::provider::seed_src::BASE_RANDS`]
//!   (not duplicated here; see below);
//! * `base_query` — `baseprov.c:98-113`, with the three generated arms answering `NULL`;
//! * `base_teardown` — `baseprov.c:115-119`, without the absent `BIO_meth_free` (see below);
//! * `base_dispatch_table[]` — `baseprov.c:121-129`;
//! * `ossl_base_provider_init` — `baseprov.c:131-183` (the declaration at `:131`, the body at
//!   `:133-183`).
//!
//! # The three generated tables this module deliberately does not carry
//!
//! `base_encoder[]` (`baseprov.c:67-72`), `base_decoder[]` (`:74-79`) and `base_store[]`
//! (`:81-88`) are not literal rows in the authority either: each is an `#include` of a generated
//! `.inc` (`encoders.inc`, `decoders.inc`, `stores.inc`), and the rows those `.inc` files expand
//! reference `ossl_*_encoder_functions`, `ossl_*_decoder_functions` and
//! `ossl_store_*_loader_init` dispatch tables that this crate does **not** transcribe. Those 318
//! rows are `owning_phase: 10` and are still `unimplemented` in the provider census,
//! `forensics/atlas/provider-algorithms.json`. This module therefore does not invent them:
//! `base_query` answers `NULL` for `OSSL_OP_ENCODER` (20), `OSSL_OP_DECODER` (21) and
//! `OSSL_OP_STORE` (22) — the same answer the authority's own `default:` arm gives for an
//! operation a provider does not publish — while their rows remain unlanded and recorded in the
//! census.
//!
//! # The one `OSSL_OP_RAND` row, and why there is exactly one
//!
//! `base_rands[]` on this profile has **exactly one** row. The authority's table
//! (`baseprov.c:90-96`) carries `PROV_NAMES_SEED_SRC` with the property string **`"provider=base"`**
//! and the dispatch table `ossl_seed_src_functions`, followed by a `PROV_NAMES_JITTER` row inside
//! `#ifndef OPENSSL_NO_JITTER` (`baseprov.c:92`). **`OPENSSL_NO_JITTER` is defined in this build**
//! (`configdata.pm:215`), so the `JITTER` row is removed and the published table is `SEED-SRC`
//! alone. That one row is **already** carried by `src/provider/seed_src.rs` as
//! [`crate::provider::seed_src::BASE_RANDS`] (a `pub(crate) static [OsslAlgorithm; 2]`, row plus
//! terminator), whose own docs describe it as the base-provider row; `base_query` below references
//! that static rather than writing a second copy of it.
//!
//! # The provider context, and the bio half that is absent
//!
//! `ossl_base_provider_init` builds the same `PROV_CTX` the default provider builds
//! (`src/provider/ctx.rs`, `providers/common/provider_ctx.c`) and stores the core's libctx, the
//! core handle and the core's `get_params` callback on it. Two of the authority's init statements
//! and one of `base_teardown`'s have **no counterpart in this crate and are omitted with their
//! reason**, exactly as `deflt_teardown`/`ossl_default_provider_init` in `src/provider/digest.rs`
//! omit them:
//!
//! * `ossl_prov_bio_from_dispatch(in)` (`baseprov.c:141`) — its unit
//!   `providers/common/bio_prov.c` is not transcribed, because this crate builds no provider-side
//!   `BIO_METHOD`. The authority's `if (!...) return 0;` therefore has no failing arm here.
//! * `ossl_bio_prov_init_bio_method()` and the `corebiometh` it returns (`baseprov.c:169`) — same
//!   reason; and `ossl_prov_ctx_set0_core_bio_method` (`:177`) does not exist, since `ProvCtx`
//!   carries no `corebiometh` field.
//! * `BIO_meth_free(ossl_prov_ctx_get0_core_bio_method(provctx))` (`baseprov.c:117`) — same
//!   reason; `base_teardown` frees the context and nothing else.
//!
//! # Build facts this transcription depends on
//!
//! * `OSSL_PROV_PARAM_NAME`/`_VERSION`/`_BUILDINFO`/`_STATUS` are `"name"`/`"version"`/
//!   `"buildinfo"`/`"status"` (`include/openssl/core_names.h:512/534/500/527`); the four
//!   constants are declared locally because the crate keeps no shared home for them and
//!   `src/provider/digest.rs:2178-2184` declares its own copies for the same reason.
//! * `OPENSSL_VERSION_STR` and `OPENSSL_FULL_VERSION_STR` are both `"3.6.4"` on a release build
//!   (`opensslv.h:90/93`); both arms read the crate's single captured
//!   [`crate::runtime::init::VERSION_STRING`], as `deflt_get_params` does, rather than carrying a
//!   second literal that could drift.
//! * `ossl_prov_is_running()` (`providers/prov_running.c`) is spelled locally, as every provider
//!   module in this crate spells it: the default and base providers are always in a happy state on
//!   this build.
//!
//! SPDX-License-Identifier: Apache-2.0

// `ossl_base_provider_init` is `pub` because the authority's own `ossl_base_provider_init` has
// external linkage -- a `#[no_mangle] pub extern "C" fn` is that symbol's Rust spelling. The
// enclosing `provider::base` is a `pub(crate)` module, so `unreachable_pub` (a *warn* in
// `Cargo.toml` that `-D warnings` promotes) would otherwise force the ABI part of the way down to
// `pub(crate)`; `src/provider/keymgmt.rs` records the same reason for the same allow.
#![allow(unreachable_pub)]

use core::ffi::{c_char, c_int, c_void};
use core::ptr;

use crate::context::dispatch::{OsslDispatch, OSSL_DISPATCH_END};
use crate::params::{
    OSSL_PARAM_locate, OSSL_PARAM_set_int, OSSL_PARAM_set_utf8_ptr, OsslParam, END,
};
use crate::provider::activate::OsslAlgorithm;
use crate::provider::cipher::{param_integer_defn, param_utf8_ptr};
use crate::provider::core_dispatch::{FUNC_CORE_GET_LIBCTX, FUNC_CORE_GET_PARAMS};
use crate::provider::init::{
    FUNC_PROVIDER_GETTABLE_PARAMS, FUNC_PROVIDER_GET_PARAMS, FUNC_PROVIDER_QUERY_OPERATION,
    FUNC_PROVIDER_TEARDOWN,
};
use crate::runtime::init::VERSION_STRING;

/// `OSSL_PROV_PARAM_NAME` — `include/openssl/core_names.h:512`.
const OSSL_PROV_PARAM_NAME: *const c_char = c"name".as_ptr();
/// `OSSL_PROV_PARAM_VERSION` — `core_names.h:534`.
const OSSL_PROV_PARAM_VERSION: *const c_char = c"version".as_ptr();
/// `OSSL_PROV_PARAM_BUILDINFO` — `core_names.h:500`.
const OSSL_PROV_PARAM_BUILDINFO: *const c_char = c"buildinfo".as_ptr();
/// `OSSL_PROV_PARAM_STATUS` — `core_names.h:527`.
const OSSL_PROV_PARAM_STATUS: *const c_char = c"status".as_ptr();

/// `OSSL_OP_ENCODER` — `include/openssl/core_dispatch.h:295`. Only `base_query` reads it, and
/// this crate keeps no shared home for the operation ids.
const OSSL_OP_ENCODER: c_int = 20;
/// `OSSL_OP_DECODER` — `core_dispatch.h:296`.
const OSSL_OP_DECODER: c_int = 21;
/// `OSSL_OP_STORE` — `core_dispatch.h:297`.
const OSSL_OP_STORE: c_int = 22;
/// `OSSL_OP_RAND` — `core_dispatch.h:287`. The one operation this provider actually publishes.
const OSSL_OP_RAND: c_int = 5;

/// `int ossl_prov_is_running(void)` — `providers/prov_running.c`. The base provider is always in a
/// happy state on this build, so the call the authority makes at `baseprov.c:61` always answers 1.
/// It is spelled locally, as every provider module here spells it (`src/provider/cipher.rs:414`,
/// `src/provider/digest.rs:139`), because the crate exposes no shared `pub(crate)` copy.
#[inline]
fn ossl_prov_is_running() -> c_int {
    1
}

/// `base_param_types[]` — `providers/baseprov.c:33-39`.
///
/// Four descriptors plus the terminator, built with `OSSL_PARAM_DEFN` (`params.h:27-28`): every
/// entry has a NULL `data` and a `data_size` of 0, so it is a **descriptor list** rather than a
/// value list. The three `UTF8_PTR` entries are distinguishable from a `UTF8_STRING` request only
/// by their `data_type`, and the `INTEGER` one from an `int` request only by its `data_size`.
static BASE_PARAM_TYPES: [OsslParam; 5] = [
    param_utf8_ptr(OSSL_PROV_PARAM_NAME),
    param_utf8_ptr(OSSL_PROV_PARAM_VERSION),
    param_utf8_ptr(OSSL_PROV_PARAM_BUILDINFO),
    param_integer_defn(OSSL_PROV_PARAM_STATUS),
    END,
];

/// `static const OSSL_PARAM *base_gettable_params(void *provctx)` — `providers/baseprov.c:41-44`.
///
/// The authority's body returns the table and reads neither argument.
unsafe extern "C" fn base_gettable_params(_provctx: *mut c_void) -> *const OsslParam {
    BASE_PARAM_TYPES.as_ptr()
}

/// `static int base_get_params(void *provctx, OSSL_PARAM params[])` — `providers/baseprov.c:46-65`.
///
/// Each arm locates its parameter in the caller's array and, **only if the caller asked for it**,
/// fills it -- failing the whole call when the fill fails. A key the caller did not ask for is not
/// an error: the authority's `p != NULL && !set(...)` guard skips it and the function still
/// answers 1. The four values the authority supplies are `"OpenSSL Base Provider"`,
/// `OPENSSL_VERSION_STR`, `OPENSSL_FULL_VERSION_STR` and `ossl_prov_is_running()`; the last two
/// are the same `"3.6.4"` here (see the header).
///
/// # Safety
/// The dispatch contract: `params` is NULL or a `key`-terminated array of live, writable
/// [`OsslParam`], each with room for the type it names.
unsafe extern "C" fn base_get_params(_provctx: *mut c_void, params: *mut OsslParam) -> c_int {
    // SAFETY: `params` is the caller's array; `OSSL_PARAM_locate` walks it to its terminator and
    // returns NULL when the key is absent.
    let p = unsafe { OSSL_PARAM_locate(params, OSSL_PROV_PARAM_NAME) };
    if !p.is_null() {
        // SAFETY: `p` is a live entry of the caller's array, which the caller made writable for
        // the type it named. `baseprov.c:52`.
        if unsafe { OSSL_PARAM_set_utf8_ptr(p, c"OpenSSL Base Provider".as_ptr()) } == 0 {
            return 0;
        }
    }
    // SAFETY: as above for each of the remaining three arms.
    let p = unsafe { OSSL_PARAM_locate(params, OSSL_PROV_PARAM_VERSION) };
    if !p.is_null() {
        // SAFETY: `p` is a live, writable entry of the caller's array. `baseprov.c:55`.
        if unsafe { OSSL_PARAM_set_utf8_ptr(p, VERSION_STRING.as_ptr()) } == 0 {
            return 0;
        }
    }
    // SAFETY: as above. `baseprov.c:58`.
    let p = unsafe { OSSL_PARAM_locate(params, OSSL_PROV_PARAM_BUILDINFO) };
    if !p.is_null() {
        // SAFETY: `p` is a live, writable entry of the caller's array.
        if unsafe { OSSL_PARAM_set_utf8_ptr(p, VERSION_STRING.as_ptr()) } == 0 {
            return 0;
        }
    }
    // SAFETY: as above, for an entry the caller made for an `int`. `baseprov.c:61`.
    let p = unsafe { OSSL_PARAM_locate(params, OSSL_PROV_PARAM_STATUS) };
    if !p.is_null() {
        // SAFETY: `p` is a live, writable entry of the caller's array.
        if unsafe { OSSL_PARAM_set_int(p, ossl_prov_is_running()) } == 0 {
            return 0;
        }
    }
    1
}

/// `static const OSSL_ALGORITHM *base_query(void *provctx, int operation_id, int *no_cache)` —
/// `providers/baseprov.c:98-113`, with the three generated arms answered `NULL`.
///
/// The authority's `switch` has four arms and a fall-through to `NULL`: `OSSL_OP_ENCODER` returns
/// `base_encoder`, `OSSL_OP_DECODER` returns `base_decoder`, `OSSL_OP_STORE` returns `base_store`,
/// and `OSSL_OP_RAND` returns `base_rands`. The first three tables are the authority's generated
/// ones and this crate does not transcribe them (318 rows, `owning_phase: 10`, recorded
/// `unimplemented` in `forensics/atlas/provider-algorithms.json` — see the module header), so the
/// three arms answer `NULL` here, the same as the `default:` arm. The `OSSL_OP_RAND` arm returns
/// [`crate::provider::seed_src::BASE_RANDS`], the one row this profile publishes.
///
/// `*no_cache` is set to 0 **before** the arms, so the operation tables are cacheable.
///
/// **The arms are `if operation_id == …` rather than a `match`, and that is load-bearing.**
/// `plan_reconciliation.py`'s and `gen_provider_algorithms.py`'s reader for a crate query function
/// is anchored on this exact shape (`CRATE_QUERY_ARM` in the census), which is why `deflt_query`
/// is written this way too: the census reads the crate's arms rather than keeping a per-operation
/// list of its own, because a list is how a landed row goes invisible (D237, D246). The semantics
/// are identical to a `match`.
///
/// # Safety
/// `no_cache` must be writable; `provctx` is ignored.
unsafe extern "C" fn base_query(
    _provctx: *mut c_void,
    operation_id: c_int,
    no_cache: *mut c_int,
) -> *const OsslAlgorithm {
    // SAFETY: `no_cache` is writable per the contract. `baseprov.c:101`.
    unsafe { *no_cache = 0 };
    if operation_id == OSSL_OP_ENCODER {
        // `baseprov.c:104` returns `base_encoder`, the generated table this module does not carry.
        return ptr::null();
    }
    if operation_id == OSSL_OP_DECODER {
        // `baseprov.c:106` returns `base_decoder`.
        return ptr::null();
    }
    if operation_id == OSSL_OP_STORE {
        // `baseprov.c:108` returns `base_store`.
        return ptr::null();
    }
    if operation_id == OSSL_OP_RAND {
        // `baseprov.c:110` returns `base_rands`, which is `seed_src.rs`'s `BASE_RANDS`.
        return crate::provider::seed_src::BASE_RANDS.as_ptr();
    }
    // `baseprov.c:112` — anything else, exactly as the authority's `default:` arm answers.
    ptr::null()
}

/// `static void base_teardown(void *provctx)` — `providers/baseprov.c:115-119`, without its
/// `BIO_meth_free(ossl_prov_ctx_get0_core_bio_method(provctx))`, whose core `BIO_METHOD` this
/// crate does not build (`src/provider/ctx.rs`). Freeing the context is what keeps a provider that
/// is registered and then dropped from leaking it.
///
/// # Safety
/// The dispatch contract: `provctx` is what `ossl_base_provider_init` published, or NULL.
unsafe extern "C" fn base_teardown(provctx: *mut c_void) {
    // SAFETY: the caller's contract; `ossl_prov_ctx_free` accepts NULL.
    unsafe { crate::provider::ctx::ossl_prov_ctx_free(provctx.cast()) };
}

/// `base_dispatch_table[]` — `providers/baseprov.c:121-129`.
///
/// Four entries plus the terminator, in the authority's order (`TEARDOWN` 1024,
/// `GETTABLE_PARAMS` 1025, `GET_PARAMS` 1026, `QUERY_OPERATION` 1027). `ossl_base_provider_init`
/// publishes this table in `*out`.
static BASE_DISPATCH_TABLE: [OsslDispatch; 5] = [
    OsslDispatch {
        function_id: FUNC_PROVIDER_TEARDOWN,
        function: base_teardown as *mut c_void,
    },
    OsslDispatch {
        function_id: FUNC_PROVIDER_GETTABLE_PARAMS,
        function: base_gettable_params as *mut c_void,
    },
    OsslDispatch {
        function_id: FUNC_PROVIDER_GET_PARAMS,
        function: base_get_params as *mut c_void,
    },
    OsslDispatch {
        function_id: FUNC_PROVIDER_QUERY_OPERATION,
        function: base_query as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_DISPATCH_END,
        function: ptr::null_mut(),
    },
];

/// `int ossl_base_provider_init(const OSSL_CORE_HANDLE *handle, const OSSL_DISPATCH *in,
/// const OSSL_DISPATCH **out, void **provctx)` — `providers/baseprov.c:133-183`, with the two
/// absent bio statements omitted (module header).
///
/// The authority walks `in` for `OSSL_FUNC_CORE_GET_PARAMS` (2) and `OSSL_FUNC_CORE_GET_LIBCTX`
/// (4), refusing when the latter is absent, then builds a `PROV_CTX` and stores the core's libctx,
/// the handle and the `get_params` callback on it. That context is what every later call through
/// `PROV_LIBCTX_OF(provctx)` resolves against, which is why a NULL one would make a
/// private-`OSSL_LIB_CTX` application silently reach the global one.
///
/// The signature matches the crate's [`crate::provider::ProviderInitFn`]; the symbol is exported
/// (`#[no_mangle]`), as the authority's non-`static` `ossl_base_provider_init` is.
///
/// # Safety
/// `out` and `provctx` must be writable; `handle` names the live provider and `in_` is the core
/// dispatch table the registry handed over.
#[no_mangle]
pub unsafe extern "C" fn ossl_base_provider_init(
    handle: *const c_void,
    in_: *const OsslDispatch,
    out: *mut *const OsslDispatch,
    provctx: *mut *mut c_void,
) -> c_int {
    // SAFETY: `in_` is the core's own terminated table; every entry read is within it.
    unsafe {
        if out.is_null() || provctx.is_null() {
            return 0;
        }

        // The authority's first statement is `ossl_prov_bio_from_dispatch(in)` (`baseprov.c:141`),
        // which installs the core `BIO_METHOD`; this crate builds no provider-side BIO method, so
        // the call and its failing arm are omitted (see the module header and `deflt_teardown` in
        // `src/provider/digest.rs`, which omits the same unit).
        let mut c_get_libctx: *const c_void = ptr::null();
        let mut c_get_params: *const c_void = ptr::null();
        let mut d = in_;
        while !d.is_null() && (*d).function_id != OSSL_DISPATCH_END {
            match (*d).function_id {
                FUNC_CORE_GET_PARAMS => c_get_params = (*d).function,
                FUNC_CORE_GET_LIBCTX => c_get_libctx = (*d).function,
                _ => {} // Just ignore anything we don't understand
            }
            d = d.add(1);
        }

        if c_get_libctx.is_null() {
            return 0;
        }

        let ctx = crate::provider::ctx::ossl_prov_ctx_new();
        if ctx.is_null() {
            return 0;
        }
        // SAFETY: `c_get_libctx` is the core's own `OSSL_FUNC_core_get_libctx_fn`, which the
        // registry published with this exact signature, and `handle` is the provider it expects.
        let get_libctx: unsafe extern "C" fn(*const c_void) -> *mut c_void =
            core::mem::transmute(c_get_libctx);
        let libctx = get_libctx(handle);

        crate::provider::ctx::ossl_prov_ctx_set0_libctx(ctx, libctx);
        crate::provider::ctx::ossl_prov_ctx_set0_handle(ctx, handle);
        crate::provider::ctx::ossl_prov_ctx_set0_core_get_params(ctx, c_get_params.cast_mut());

        *out = BASE_DISPATCH_TABLE.as_ptr();
        *provctx = ctx.cast();
    }
    1
}
