//! Phase 9 — `crypto/rand/rand_lib.c`, the **seed-source and per-context halves**.
//!
//! # Why this is a subset, and which subset
//!
//! `rand_lib.c` is one translation unit with two jobs:
//!
//! 1. the per-`OSSL_LIB_CTX` RAND state (`rand_global_st`, its slot-5 constructor, the seed
//!    source's lock-protected accessor), and
//! 2. `rand.h`'s twenty-five exports — the method table, the thread-local primary/public/private
//!    DRBGs, the file helpers and the refusal arms.
//!
//! **Only (1) is here.** Job (2) is 9.2's remaining work and is staged at
//! `court/phase9/rand_lib.rs.txt`. The split is not an accident of effort: (1) is what the DRBG
//! provider rows need to exist *at all*. A DRBG's instantiate asks the provider for a nonce, the
//! provider asks the core, and the core's answer runs through `ossl_rand_get_nonce` in
//! `prov_seed.rs`, which needs the per-context seed source — the object this file builds. Until
//! the slot is filled, every instantiation of every default-provider DRBG row is refused with
//! `PROV_R_ERROR_RETRIEVING_NONCE`. RT-DRBG measured exactly that on its first run.
//!
//! # What is absent, and named
//!
//! `do_rand_init`/`RUN_ONCE`, `ossl_rand_cleanup_int`, the seventeen method-table and
//! thread-local-DRBG functions, `RAND_bytes_ex`, `RAND_priv_bytes_ex`, `RAND_seed`,
//! `RAND_add`, `RAND_status`, `RAND_poll`, `RAND_get0_primary`/`_public`/`_private`,
//! `RAND_set0_public`/`_private`, `RAND_set_DRBG_type`, `RAND_set_seed_source_type`,
//! `RAND_set1_random_provider` and the file helpers are all 9.2's and none is stubbed. Each
//! remains `rand.h`'s ledger row, so the obligation is counted rather than implied.
//!
//! SPDX-License-Identifier: Apache-2.0

#![allow(dead_code)] // the landing caller is `context_init`'s slot-5 arm (9.2)

use core::ffi::{c_char, c_int, c_void};
use core::ptr;

use crate::context::lib_ctx_get_data;
use crate::context::OSSL_LIB_CTX_DRBG_INDEX;
use crate::evp::rand::EvpRandCtx;
use crate::provider::OsslProvider;
use crate::runtime::init::OPENSSL_init_crypto;
use crate::runtime::mem::{CRYPTO_free, CRYPTO_strdup, CRYPTO_zalloc};
use crate::runtime::thread::{
    CRYPTO_THREAD_lock_free, CRYPTO_THREAD_lock_new, CRYPTO_THREAD_read_lock, CRYPTO_THREAD_unlock,
    CryptoRwlock,
};

/// `crypto/rand/rand_lib.c`, as the authority's compiler spelled it.
const FILE: *const c_char = c"../../src/openssl-3.6.4/crypto/rand/rand_lib.c".as_ptr();
/// `__LINE__`, inert under `OPENSSL_NO_CRYPTO_MDEBUG`.
const LINE: c_int = 0;

/// `random_provider_fips_name` — `rand_lib.c`.
const RANDOM_PROVIDER_FIPS_NAME: *const c_char = c"fips".as_ptr();

/// `OPENSSL_INIT_BASE_ONLY` — internal to the authority, and private in `runtime/init.rs`; the
/// spelling is repeated here rather than widened because it is not a public macro.
const OPENSSL_INIT_BASE_ONLY: u64 = 0x0004_0000;

// ---------------------------------------------------------------------------------------------
// `RAND_GLOBAL` — `struct rand_global_st` from `rand_lib.c`
// ---------------------------------------------------------------------------------------------

/// The per-`OSSL_LIB_CTX` state, stored in slot 5 by [`ossl_rand_ctx_new`].
///
/// The `#ifndef FIPS_MODULE` fields are present because `FIPS_MODULE` is undefined on this
/// profile.
#[repr(C)]
pub(crate) struct RandGlobal {
    /// `CRYPTO_RWLOCK *lock`.
    pub(crate) lock: *mut CryptoRwlock,
    /// `EVP_RAND_CTX *seed` — the seed source, shared by the primary.
    pub(crate) seed: *mut EvpRandCtx,
    /// `EVP_RAND_CTX *primary` — the primary DRBG.
    pub(crate) primary: *mut EvpRandCtx,
    /// `OSSL_PROVIDER *random_provider` — the nominated randomness provider, or NULL.
    pub(crate) random_provider: *mut OsslProvider,
    /// `char *random_provider_name` — the nominated provider's name, owned.
    pub(crate) random_provider_name: *mut c_char,
    /// `char *rng_name`.
    pub(crate) rng_name: *mut c_char,
    /// `char *rng_cipher`.
    pub(crate) rng_cipher: *mut c_char,
    /// `char *rng_digest`.
    pub(crate) rng_digest: *mut c_char,
    /// `char *rng_propq`.
    pub(crate) rng_propq: *mut c_char,
    /// `char *seed_name`.
    pub(crate) seed_name: *mut c_char,
    /// `char *seed_propq`.
    pub(crate) seed_propq: *mut c_char,
}

// ---------------------------------------------------------------------------------------------
// `rand_get_global` — the module's accessor for the per-context state
// ---------------------------------------------------------------------------------------------

/// `static RAND_GLOBAL *rand_get_global(OSSL_LIB_CTX *libctx)` — the crate's name for the
/// authority's accessor.
///
/// # Safety
/// `libctx` must be NULL or live.
pub(crate) unsafe fn rand_ossl_ctx(libctx: *mut c_void) -> *mut RandGlobal {
    // SAFETY: `lib_ctx_get_data` accepts NULL or a live context and resolves NULL to the
    // thread default, which is what the authority's `rand_get_global` sub-helper does.
    lib_ctx_get_data(libctx, OSSL_LIB_CTX_DRBG_INDEX).cast::<RandGlobal>()
}

// ---------------------------------------------------------------------------------------------
// Slot construction and release: `ossl_rand_ctx_new` / `ossl_rand_ctx_free`
// ---------------------------------------------------------------------------------------------

/// `void *ossl_rand_ctx_new(OSSL_LIB_CTX *libctx)` — the slot-5 constructor.
///
/// The authority's `context_init` calls this (`crypto/context.c:111`) and `context_deinit_objs`
/// calls [`ossl_rand_ctx_free`] (`:236`); this crate's `context_init` does the same, in the
/// same position.
///
/// # Safety
/// The `OSSL_LIB_CTX` constructor contract; `libctx` is unused.
pub(crate) unsafe fn ossl_rand_ctx_new(_libctx: *mut c_void) -> *mut c_void {
    // SAFETY: the allocation is this frame's and every failure path releases it here.
    unsafe {
        let dgbl =
            CRYPTO_zalloc(core::mem::size_of::<RandGlobal>(), FILE, LINE).cast::<RandGlobal>();
        if dgbl.is_null() {
            return ptr::null_mut();
        }

        // `OPENSSL_init_crypto(OPENSSL_INIT_BASE_ONLY, NULL)`: base thread handling must exist
        // before this object does.
        OPENSSL_init_crypto(OPENSSL_INIT_BASE_ONLY, ptr::null());

        let name = CRYPTO_strdup(RANDOM_PROVIDER_FIPS_NAME, FILE, LINE).cast::<c_char>();
        if name.is_null() {
            CRYPTO_free(dgbl.cast::<c_void>(), FILE, LINE);
            return ptr::null_mut();
        }
        (*dgbl).random_provider_name = name;

        let lock = CRYPTO_THREAD_lock_new();
        if lock.is_null() {
            CRYPTO_free((*dgbl).random_provider_name.cast::<c_void>(), FILE, LINE);
            CRYPTO_free(dgbl.cast::<c_void>(), FILE, LINE);
            return ptr::null_mut();
        }
        (*dgbl).lock = lock;

        dgbl.cast::<c_void>()
    }
}

/// `void ossl_rand_ctx_free(void *vdgbl)`.
///
/// # Safety
/// `vdgbl` is NULL or what [`ossl_rand_ctx_new`] returned.
pub(crate) unsafe fn ossl_rand_ctx_free(vdgbl: *mut c_void) {
    let dgbl = vdgbl.cast::<RandGlobal>();
    if dgbl.is_null() {
        return;
    }
    // SAFETY: `dgbl` is live per the contract; every field is a plain pointer or a live object
    // this module owns, and each releaser accepts NULL.
    unsafe {
        CRYPTO_THREAD_lock_free((*dgbl).lock);
        crate::evp::rand::EVP_RAND_CTX_free((*dgbl).primary);
        crate::evp::rand::EVP_RAND_CTX_free((*dgbl).seed);
        CRYPTO_free((*dgbl).random_provider_name.cast::<c_void>(), FILE, LINE);
        CRYPTO_free((*dgbl).rng_name.cast::<c_void>(), FILE, LINE);
        CRYPTO_free((*dgbl).rng_cipher.cast::<c_void>(), FILE, LINE);
        CRYPTO_free((*dgbl).rng_digest.cast::<c_void>(), FILE, LINE);
        CRYPTO_free((*dgbl).rng_propq.cast::<c_void>(), FILE, LINE);
        CRYPTO_free((*dgbl).seed_name.cast::<c_void>(), FILE, LINE);
        CRYPTO_free((*dgbl).seed_propq.cast::<c_void>(), FILE, LINE);
        CRYPTO_free(dgbl.cast::<c_void>(), FILE, LINE);
    }
}

/// `EVP_RAND_CTX *ossl_rand_get0_seed_noncreating(OSSL_LIB_CTX *ctx)` — internal, and built
/// because `FIPS_MODULE` is undefined.
///
/// **The answer is NULL until `RAND_set_seed_source_type` (9.2) names a seed source**, which is
/// the normal case for a default-configured process: `ossl_rand_get_user_entropy` and its
/// siblings then fall back to the platform pool in `prov_seed.rs`. The accessor is here rather
/// than inlined because the fallback must consult the *same* lock-protected field the setter
/// will write.
///
/// # Safety
/// `ctx` must be NULL or live.
pub(crate) unsafe fn ossl_rand_get0_seed_noncreating(ctx: *mut c_void) -> *mut EvpRandCtx {
    // SAFETY: per the contract.
    let dgbl = unsafe { rand_ossl_ctx(ctx) };
    if dgbl.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: `dgbl` is live and its lock was created by `ossl_rand_ctx_new`.
    if unsafe { CRYPTO_THREAD_read_lock((*dgbl).lock) } == 0 {
        return ptr::null_mut();
    }
    // SAFETY: `dgbl` is live and the lock is held.
    let ret = unsafe { (*dgbl).seed };
    // SAFETY: the lock is held by this call.
    unsafe { CRYPTO_THREAD_unlock((*dgbl).lock) };
    ret
}
