//! `providers/common/provider_seeding.c` -- the four seed up-calls a provider publishes.
//!
//! The provider core's random up-calls, and the layer `drbg.c` reaches through the provider context
//! when it needs entropy or a nonce. This is the file D298's measurement found: D287's scope named
//! neither it nor the four names.
//!
//! # What the up-calls are
//!
//! `OSSL_FUNC_{GET,CLEANUP}_{USER_,}ENTROPY` and `_NONCE` are eight ids the provider core looks up
//! on its own dispatch table (`src/context/dispatch.rs`, landed in D299). A provider that has no
//! entropy source of its own answers `NULL` for the `USER_` pair and forwards to its parent or to
//! the core for the other two; this module is that forwarding.
//!
//! # FIPS arms
//!
//! `CORE_HANDLE`'s `FIPS_MODULE` arm calls `FIPS_get_core_handle`, which is not built on this
//! profile; the `ossl_prov_ctx_get0_handle` arm is the one transcribed, and the FIPS function is
//! named in a comment rather than omitted silently.
//!
//! SPDX-License-Identifier: Apache-2.0

#![allow(dead_code)] // the landing caller is `src/provider/rand.rs`'s DRBG instantiate

use core::ffi::{c_int, c_uchar, c_void};
use core::ptr;

// ---- Section 1 imports -----------------------------------------------------------------------
use crate::context::dispatch::{entry_function, OsslDispatch, OSSL_DISPATCH_END};
use crate::provider::ctx::{ossl_prov_ctx_get0_handle, ProvCtx};

// =============================================================================================
// SECTION 1 — `providers/common/provider_seeding.c`
// =============================================================================================
//
// The core hands a provider its entropy and nonce through eight callbacks in the provider's `in`
// table. `ossl_prov_seeding_from_dispatch` records them in file statics; the four up-calls below
// are what a seed source (`seed_src.c`, `test_rng.c`, `fips_crng_test.c`) calls to obtain and
// return a buffer. The *asymmetry* is the whole shape: entropy and nonce are acquired through
// one call and released through another, and the release must reach the same callback family the
// acquire used, which is why each family has its own pair of statics rather than one.
//
// The delegation order is contract and is the reason a "user" callback shadows a plain one:
// `c_get_user_entropy` is consulted *first*, then `c_get_entropy`; the same for nonces. The
// cleanup pair follows the same precedence, so a buffer handed out by `get_user_entropy` is
// returned to `cleanup_user_entropy`. The `set_func` check below is what refuses a second
// dispatch table that names the same id with a *different* function — the "one fips.so shared by
// two libcryptos" sanity check the authority's comment describes.

/// `OSSL_FUNC_GET_USER_ENTROPY` — `core_dispatch.h:179`, id 98.
const OSSL_FUNC_GET_USER_ENTROPY: c_int = 98;
/// `OSSL_FUNC_GET_USER_NONCE` — `core_dispatch.h:180`, id 99.
const OSSL_FUNC_GET_USER_NONCE: c_int = 99;
/// `OSSL_FUNC_GET_ENTROPY` — `core_dispatch.h:188`, id 101.
const OSSL_FUNC_GET_ENTROPY: c_int = 101;
/// `OSSL_FUNC_CLEANUP_ENTROPY` — `core_dispatch.h:189`, id 102.
const OSSL_FUNC_CLEANUP_ENTROPY: c_int = 102;
/// `OSSL_FUNC_GET_NONCE` — `core_dispatch.h:190`, id 103.
const OSSL_FUNC_GET_NONCE: c_int = 103;
/// `OSSL_FUNC_CLEANUP_NONCE` — `core_dispatch.h:191`, id 104.
const OSSL_FUNC_CLEANUP_NONCE: c_int = 104;
/// `OSSL_FUNC_CLEANUP_USER_ENTROPY` — `core_dispatch.h:177`, id 96.
const OSSL_FUNC_CLEANUP_USER_ENTROPY: c_int = 96;
/// `OSSL_FUNC_CLEANUP_USER_NONCE` — `core_dispatch.h:178`, id 97.
const OSSL_FUNC_CLEANUP_USER_NONCE: c_int = 97;

/// `OSSL_FUNC_get_entropy_fn` / `OSSL_FUNC_get_user_entropy_fn` — `core_dispatch.h:192-193`,
/// `size_t (*)(const OSSL_CORE_HANDLE *, unsigned char **, int, size_t, size_t)`. The two C
/// typedefs are the same type; one Rust alias covers both arms. `OSSL_CORE_HANDLE` is
/// `*const c_void`, as `src/provider/child.rs` already spells it.
pub(crate) type CoreGetEntropyFn =
    unsafe extern "C" fn(*const c_void, *mut *mut c_uchar, c_int, usize, usize) -> usize;

/// `OSSL_FUNC_cleanup_entropy_fn` / `OSSL_FUNC_cleanup_user_entropy_fn` —
/// `core_dispatch.h:194-195`, `void (*)(const OSSL_CORE_HANDLE *, unsigned char *, size_t)`.
pub(crate) type CoreCleanupEntropyFn = unsafe extern "C" fn(*const c_void, *mut c_uchar, usize);

/// `OSSL_FUNC_get_nonce_fn` / `OSSL_FUNC_get_user_nonce_fn` — `core_dispatch.h:196-197`,
/// `size_t (*)(const OSSL_CORE_HANDLE *, unsigned char **, size_t, size_t, const void *,
/// size_t)`.
pub(crate) type CoreGetNonceFn = unsafe extern "C" fn(
    *const c_void,
    *mut *mut c_uchar,
    usize,
    usize,
    *const c_void,
    usize,
) -> usize;

/// `OSSL_FUNC_cleanup_nonce_fn` / `OSSL_FUNC_cleanup_user_nonce_fn` — `core_dispatch.h:198-199`,
/// the same shape as [`CoreCleanupEntropyFn`]. Declared separately because the authority's names
/// are separate, not because the width differs.
pub(crate) type CoreCleanupNonceFn = unsafe extern "C" fn(*const c_void, *mut c_uchar, usize);

// `provider_seeding.c:14-21` — the eight file statics. The authority stores a bare function
// pointer with NULL meaning "not offered"; `Option<fn>` is that state in Rust, and it is
// `Copy`, so a read below copies the pointer without forming a reference to mutable static
// storage (the `static_mut_refs` lint).
static mut C_GET_ENTROPY: Option<CoreGetEntropyFn> = None;
static mut C_GET_USER_ENTROPY: Option<CoreGetEntropyFn> = None;
static mut C_CLEANUP_ENTROPY: Option<CoreCleanupEntropyFn> = None;
static mut C_CLEANUP_USER_ENTROPY: Option<CoreCleanupEntropyFn> = None;
static mut C_GET_NONCE: Option<CoreGetNonceFn> = None;
static mut C_GET_USER_NONCE: Option<CoreGetNonceFn> = None;
static mut C_CLEANUP_NONCE: Option<CoreCleanupNonceFn> = None;
static mut C_CLEANUP_USER_NONCE: Option<CoreCleanupNonceFn> = None;

/// `CORE_HANDLE(provctx)` — `provider_seeding.c:30-38`.
///
/// The authority has two arms. The `FIPS_MODULE` arm converts the FIPS provider's internal
/// library context to the *core* handle, because the seed source is external to the FIPS
/// provider and the passed provider context references the wrong one. That arm is compiled out in
/// this profile; the non-FIPS arm is `ossl_prov_ctx_get0_handle`, which the authority's own
/// comment says "should be unused" for a full DRBG chain but is retained for third-party
/// providers. `FIPS_get_core_handle` therefore has no caller here and is listed as missing only
/// so the FIPS arm is not silently forgotten.
///
/// # Safety
/// `prov_ctx` is the `PROV_CTX` the owning provider published, or NULL.
#[inline]
unsafe fn core_handle(prov_ctx: *mut ProvCtx) -> *const c_void {
    // SAFETY: the accessor accepts NULL and answers NULL, which is the macro's own behaviour.
    unsafe { ossl_prov_ctx_get0_handle(prov_ctx) }
}

/// The authority's `set_func(c, f)` macro — `provider_seeding.c:49-55`.
///
/// `if (c == NULL) c = f; else if (c != f) return 0;`. Transcribed as a function returning the
/// macro's implicit `1`/`0`, so each arm of the walk below propagates with a plain test. The
/// equality is pointer identity, which is what `Option<fn>`'s `PartialEq` compares, so a second
/// table naming the same id with the same function is accepted and one naming a *different*
/// function is refused.
///
/// # Safety
/// `slot` is the address of one of this unit's own file statics.
unsafe fn set_func<T: Copy + PartialEq>(slot: *mut Option<T>, f: Option<T>) -> c_int {
    // SAFETY: `slot` points at this unit's own file static per the caller's contract.
    unsafe {
        if (*slot).is_none() {
            *slot = f;
            1
        } else if *slot != f {
            0
        } else {
            1
        }
    }
}

/// `int ossl_prov_seeding_from_dispatch(const OSSL_DISPATCH *fns)` —
/// `provider_seeding.c:41-85`.
///
/// The walk stops at the terminating id and records each of the eight seeding ids in its static.
/// An id the table does not carry is left NULL. The `set_func` refusal propagates as `0`.
///
/// # Safety
/// `fns` is a `OSSL_DISPATCH_END`-terminated array of entries that stay live for the call.
#[allow(clippy::collapsible_match)] // each arm is one `case ... if (...)` of the authority's
                                    // switch, and collapsing the `if` into the arm would lose the
                                    // one-entry-per-id shape that makes these eight ids checkable
                                    // against `core_dispatch.h` in one read (D305)
pub(crate) unsafe fn ossl_prov_seeding_from_dispatch(fns: *const OsslDispatch) -> c_int {
    let mut fns = fns;
    // SAFETY: `fns` walks a terminated table per the caller's contract; every read is inside it.
    unsafe {
        while (*fns).function_id != OSSL_DISPATCH_END {
            match (*fns).function_id {
                OSSL_FUNC_GET_ENTROPY => {
                    if set_func(
                        ptr::addr_of_mut!(C_GET_ENTROPY),
                        entry_function::<CoreGetEntropyFn>(fns),
                    ) == 0
                    {
                        return 0;
                    }
                }
                OSSL_FUNC_GET_USER_ENTROPY => {
                    if set_func(
                        ptr::addr_of_mut!(C_GET_USER_ENTROPY),
                        entry_function::<CoreGetEntropyFn>(fns),
                    ) == 0
                    {
                        return 0;
                    }
                }
                OSSL_FUNC_CLEANUP_ENTROPY => {
                    if set_func(
                        ptr::addr_of_mut!(C_CLEANUP_ENTROPY),
                        entry_function::<CoreCleanupEntropyFn>(fns),
                    ) == 0
                    {
                        return 0;
                    }
                }
                OSSL_FUNC_CLEANUP_USER_ENTROPY => {
                    if set_func(
                        ptr::addr_of_mut!(C_CLEANUP_USER_ENTROPY),
                        entry_function::<CoreCleanupEntropyFn>(fns),
                    ) == 0
                    {
                        return 0;
                    }
                }
                OSSL_FUNC_GET_NONCE => {
                    if set_func(
                        ptr::addr_of_mut!(C_GET_NONCE),
                        entry_function::<CoreGetNonceFn>(fns),
                    ) == 0
                    {
                        return 0;
                    }
                }
                OSSL_FUNC_GET_USER_NONCE => {
                    if set_func(
                        ptr::addr_of_mut!(C_GET_USER_NONCE),
                        entry_function::<CoreGetNonceFn>(fns),
                    ) == 0
                    {
                        return 0;
                    }
                }
                OSSL_FUNC_CLEANUP_NONCE => {
                    if set_func(
                        ptr::addr_of_mut!(C_CLEANUP_NONCE),
                        entry_function::<CoreCleanupNonceFn>(fns),
                    ) == 0
                    {
                        return 0;
                    }
                }
                OSSL_FUNC_CLEANUP_USER_NONCE => {
                    if set_func(
                        ptr::addr_of_mut!(C_CLEANUP_USER_NONCE),
                        entry_function::<CoreCleanupNonceFn>(fns),
                    ) == 0
                    {
                        return 0;
                    }
                }
                _ => {}
            }
            fns = fns.add(1);
        }
    }
    1
}

/// `size_t ossl_prov_get_entropy(PROV_CTX *prov_ctx, unsigned char **pout, int entropy,
/// size_t min_len, size_t max_len)` — `provider_seeding.c:87-97`.
///
/// The precedence is contract: a user-supplied entropy callback shadows the plain one. When
/// neither was installed the answer is `0`, and `pout` is not touched — a caller that sees `0`
/// must not read the buffer.
///
/// # Safety
/// `prov_ctx` is NULL or live; `pout` is writable for one `unsigned char *` and the callback, if
/// called, treats it as such.
pub(crate) unsafe fn ossl_prov_get_entropy(
    prov_ctx: *mut ProvCtx,
    pout: *mut *mut c_uchar,
    entropy: c_int,
    min_len: usize,
    max_len: usize,
) -> usize {
    // SAFETY: the caller's contract; the non-FIPS `CORE_HANDLE` arm.
    let handle = unsafe { core_handle(prov_ctx) };

    // SAFETY: copies this unit's own file static; a function pointer is `Copy`.
    let user = unsafe { C_GET_USER_ENTROPY };
    if let Some(f) = user {
        // SAFETY: the core published this callback with exactly this signature.
        return unsafe { f(handle, pout, entropy, min_len, max_len) };
    }
    // SAFETY: copies this unit's own file static.
    let plain = unsafe { C_GET_ENTROPY };
    if let Some(f) = plain {
        // SAFETY: the core published this callback with exactly this signature.
        return unsafe { f(handle, pout, entropy, min_len, max_len) };
    }
    0
}

/// `void ossl_prov_cleanup_entropy(PROV_CTX *prov_ctx, unsigned char *buf, size_t len)` —
/// `provider_seeding.c:99-108`.
///
/// Silent when no callback is installed, which is the authority's `else if` chain with no final
/// arm. The user callback is preferred, mirroring the acquire side so a buffer is returned to
/// the family that handed it out.
///
/// # Safety
/// `prov_ctx` is NULL or live; `buf` is NULL or a buffer an acquire call returned.
pub(crate) unsafe fn ossl_prov_cleanup_entropy(
    prov_ctx: *mut ProvCtx,
    buf: *mut c_uchar,
    len: usize,
) {
    // SAFETY: the caller's contract; the non-FIPS `CORE_HANDLE` arm.
    let handle = unsafe { core_handle(prov_ctx) };

    // SAFETY: copies this unit's own file static; a function pointer is `Copy`.
    let user = unsafe { C_CLEANUP_USER_ENTROPY };
    if let Some(f) = user {
        // SAFETY: the core published this callback with exactly this signature.
        unsafe { f(handle, buf, len) };
        return;
    }
    // SAFETY: copies this unit's own file static.
    let plain = unsafe { C_CLEANUP_ENTROPY };
    if let Some(f) = plain {
        // SAFETY: the core published this callback with exactly this signature.
        unsafe { f(handle, buf, len) };
    }
}

/// `size_t ossl_prov_get_nonce(PROV_CTX *prov_ctx, unsigned char **pout, size_t min_len,
/// size_t max_len, const void *salt, size_t salt_len)` — `provider_seeding.c:110-121`.
///
/// The nonce call carries the `salt`/`salt_len` pair the entropy call does not; that pair is
/// forwarded untouched, and the delegation order is otherwise the same.
///
/// # Safety
/// As [`ossl_prov_get_entropy`], with `salt` NULL or readable for `salt_len` bytes.
pub(crate) unsafe fn ossl_prov_get_nonce(
    prov_ctx: *mut ProvCtx,
    pout: *mut *mut c_uchar,
    min_len: usize,
    max_len: usize,
    salt: *const c_void,
    salt_len: usize,
) -> usize {
    // SAFETY: the caller's contract; the non-FIPS `CORE_HANDLE` arm.
    let handle = unsafe { core_handle(prov_ctx) };

    // SAFETY: copies this unit's own file static; a function pointer is `Copy`.
    let user = unsafe { C_GET_USER_NONCE };
    if let Some(f) = user {
        // SAFETY: the core published this callback with exactly this signature.
        return unsafe { f(handle, pout, min_len, max_len, salt, salt_len) };
    }
    // SAFETY: copies this unit's own file static.
    let plain = unsafe { C_GET_NONCE };
    if let Some(f) = plain {
        // SAFETY: the core published this callback with exactly this signature.
        return unsafe { f(handle, pout, min_len, max_len, salt, salt_len) };
    }
    0
}

/// `void ossl_prov_cleanup_nonce(PROV_CTX *prov_ctx, unsigned char *buf, size_t len)` —
/// `provider_seeding.c:123-131`.
///
/// # Safety
/// As [`ossl_prov_cleanup_entropy`].
pub(crate) unsafe fn ossl_prov_cleanup_nonce(
    prov_ctx: *mut ProvCtx,
    buf: *mut c_uchar,
    len: usize,
) {
    // SAFETY: the caller's contract; the non-FIPS `CORE_HANDLE` arm.
    let handle = unsafe { core_handle(prov_ctx) };

    // SAFETY: copies this unit's own file static; a function pointer is `Copy`.
    let user = unsafe { C_CLEANUP_USER_NONCE };
    if let Some(f) = user {
        // SAFETY: the core published this callback with exactly this signature.
        unsafe { f(handle, buf, len) };
        return;
    }
    // SAFETY: copies this unit's own file static.
    let plain = unsafe { C_CLEANUP_NONCE };
    if let Some(f) = plain {
        // SAFETY: the core published this callback with exactly this signature.
        unsafe { f(handle, buf, len) };
    }
}
