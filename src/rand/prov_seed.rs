//! Phase 9 — `crypto/rand/prov_seed.c`, the core side of the provider seeding up-call.
//!
//! # Why this file is load-bearing
//!
//! A provider algorithm that needs randomness does not call the platform: it asks the *core*,
//! through the `OSSL_FUNC_{GET,CLEANUP}_{USER_,}{ENTROPY,NONCE}` dispatch entries this crate
//! publishes from `crypto/provider_core.c`. The core's answer is these eight functions.
//!
//! The chain for a default-provider DRBG is:
//!
//! ```text
//! ossl_prov_drbg_instantiate  (providers/implementations/rands/drbg.c)
//!   -> ossl_prov_get_nonce    (providers/common/provider_seeding.c, provider side)
//!     -> c_get_user_nonce     (this crate's CORE_DISPATCH entry)
//!       -> ossl_rand_get_user_nonce  (this file)
//!         -> ossl_rand_get_nonce     (this file, when no seed source is configured)
//!           -> ossl_rand_pool_new / ossl_pool_add_nonce_data
//! ```
//!
//! Until it existed the candidate refused every instantiation with
//! `PROV_R_ERROR_RETRIEVING_NONCE` -- a residual RT-DRBG measured on its first run rather than
//! one the source said was there.
//!
//! # The `user` variants, and what they consult
//!
//! `*_user_*` asks the configured **seed source** first and falls back to the platform pool.
//! `ossl_rand_get0_seed_noncreating` answers NULL until `RAND_set_seed_source_type` names one,
//! which is the ordinary state of a default-configured process, so the fallback is the arm a
//! probe observes. Both arms are written: the fallback is not a simplification.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_char, c_int, c_uchar, c_void};
use core::ptr;

use crate::evp::rand::{
    evp_rand_can_seed, evp_rand_clear_seed, evp_rand_get_seed, EVP_RAND_generate,
};
use crate::rand::pool::{
    ossl_rand_pool_add, ossl_rand_pool_detach, ossl_rand_pool_free, ossl_rand_pool_length,
    ossl_rand_pool_new,
};
use crate::rand::rand_lib::ossl_rand_get0_seed_noncreating;
use crate::rand::unix::{ossl_pool_acquire_entropy, ossl_pool_add_nonce_data};
use crate::runtime::err::err_sites;
use crate::runtime::err::raise_site;
use crate::runtime::mem::{CRYPTO_clear_free, CRYPTO_free, CRYPTO_malloc};
use crate::runtime::secure::CRYPTO_secure_clear_free;

/// `crypto/rand/prov_seed.c`, as the authority's compiler spelled it.
const FILE: *const c_char = c"../../src/openssl-3.6.4/crypto/rand/prov_seed.c".as_ptr();
/// `__LINE__`, inert under `OPENSSL_NO_CRYPTO_MDEBUG`.
const LINE: c_int = 0;

/// `size_t ossl_rand_get_entropy(OSSL_LIB_CTX *ctx, unsigned char **pout, int entropy, size_t
/// min_len, size_t max_len)` — `prov_seed.c:18-41`. Polls the platform pool.
///
/// # Safety
/// `pout` must be writable; `ctx` is unused on this profile.
pub(crate) unsafe fn ossl_rand_get_entropy(
    _ctx: *mut c_void,
    pout: *mut *mut c_uchar,
    entropy: c_int,
    min_len: usize,
    max_len: usize,
) -> usize {
    // SAFETY: `ossl_rand_pool_new` allocates and dereferences nothing the caller owns.
    let pool = ossl_rand_pool_new(entropy, 1, min_len, max_len);
    if pool.is_null() {
        // SAFETY: a compile-time-constant raise site.
        unsafe { raise_site(&err_sites::PROV_SEED_28) };
        return 0;
    }

    // SAFETY: `pool` is this frame's own and live.
    let entropy_available = unsafe { ossl_pool_acquire_entropy(pool) };

    let mut ret = 0;
    if entropy_available > 0 {
        // SAFETY: `pool` is live and exclusively owned by this frame.
        ret = unsafe { ossl_rand_pool_length(pool) };
        // SAFETY: as above; `detach` hands the buffer's ownership to the caller, which `pout`
        // publishes.
        unsafe { *pout = ossl_rand_pool_detach(pool) };
    }

    // SAFETY: `pool` is live and this frame holds its only reference.
    unsafe { ossl_rand_pool_free(pool) };
    ret
}

/// `size_t ossl_rand_get_user_entropy(OSSL_LIB_CTX *ctx, unsigned char **pout, int entropy,
/// size_t min_len, size_t max_len)` — `prov_seed.c:44-54`. Consults the configured seed source
/// first, and falls back to the platform pool.
///
/// # Safety
/// `pout` must be writable; `ctx` must be NULL or live.
pub(crate) unsafe fn ossl_rand_get_user_entropy(
    ctx: *mut c_void,
    pout: *mut *mut c_uchar,
    entropy: c_int,
    min_len: usize,
    max_len: usize,
) -> usize {
    // SAFETY: `ctx` is NULL or live per the contract.
    let rng = unsafe { ossl_rand_get0_seed_noncreating(ctx) };
    // SAFETY: `rng` is NULL or live, and `evp_rand_can_seed` only reads its method's field.
    if !rng.is_null() && unsafe { evp_rand_can_seed(rng) } != 0 {
        // SAFETY: `rng` is live and can seed, so its `get_seed` callback is present.
        return unsafe {
            evp_rand_get_seed(rng, pout, entropy, min_len, max_len, 0, ptr::null(), 0)
        };
    }
    // SAFETY: per the contract.
    unsafe { ossl_rand_get_entropy(ctx, pout, entropy, min_len, max_len) }
}

/// `void ossl_rand_cleanup_entropy(OSSL_LIB_CTX *ctx, unsigned char *buf, size_t len)` —
/// `prov_seed.c:57-62`.
///
/// # Safety
/// `buf` is the caller's seed allocation of `len` bytes, or NULL.
pub(crate) unsafe fn ossl_rand_cleanup_entropy(_ctx: *mut c_void, buf: *mut c_uchar, len: usize) {
    // SAFETY: per the contract; the crate's `CRYPTO_secure_clear_free` accepts NULL.
    unsafe { CRYPTO_secure_clear_free(buf.cast(), len, FILE, LINE) };
}

/// `void ossl_rand_cleanup_user_entropy(OSSL_LIB_CTX *ctx, unsigned char *buf, size_t len)` —
/// `prov_seed.c:64-71`.
///
/// # Safety
/// `buf` is the caller's seed allocation of `len` bytes, or NULL; `ctx` is NULL or live.
pub(crate) unsafe fn ossl_rand_cleanup_user_entropy(
    ctx: *mut c_void,
    buf: *mut c_uchar,
    len: usize,
) {
    // SAFETY: `ctx` is NULL or live per the contract.
    let rng = unsafe { ossl_rand_get0_seed_noncreating(ctx) };
    // SAFETY: `rng` is NULL or live, and `evp_rand_can_seed` only reads its method's field.
    if !rng.is_null() && unsafe { evp_rand_can_seed(rng) } != 0 {
        // SAFETY: `rng` is live and the buffer is the one its `get_seed` handed out.
        unsafe { evp_rand_clear_seed(rng, buf, len) };
        return;
    }
    // SAFETY: per the contract.
    unsafe { CRYPTO_secure_clear_free(buf.cast(), len, FILE, LINE) };
}

/// `size_t ossl_rand_get_nonce(OSSL_LIB_CTX *ctx, unsigned char **pout, size_t min_len, size_t
/// max_len, const void *salt, size_t salt_len)` — `prov_seed.c:74-94`.
///
/// # Safety
/// `pout` must be writable; `salt` NULL or readable for `salt_len`; `ctx` unused here.
pub(crate) unsafe fn ossl_rand_get_nonce(
    _ctx: *mut c_void,
    pout: *mut *mut c_uchar,
    min_len: usize,
    max_len: usize,
    salt: *const c_void,
    salt_len: usize,
) -> usize {
    // SAFETY: `ossl_rand_pool_new` allocates and dereferences nothing the caller owns.
    let pool = ossl_rand_pool_new(0, 0, min_len, max_len);
    if pool.is_null() {
        // SAFETY: a compile-time-constant raise site.
        unsafe { raise_site(&err_sites::PROV_SEED_84) };
        return 0;
    }

    // SAFETY: `pool` is live and this frame owns it.
    if unsafe { ossl_pool_add_nonce_data(pool) } == 0 {
        // SAFETY: `pool` is live and this frame holds its only reference.
        unsafe { ossl_rand_pool_free(pool) };
        return 0;
    }

    if !salt.is_null() {
        // SAFETY: `pool` is live; `salt` is readable for `salt_len` per the contract.
        if unsafe { ossl_rand_pool_add(pool, salt.cast::<c_uchar>(), salt_len, 0) } == 0 {
            // SAFETY: as above.
            unsafe { ossl_rand_pool_free(pool) };
            return 0;
        }
    }

    // SAFETY: `pool` is live and exclusively owned by this frame.
    let ret = unsafe { ossl_rand_pool_length(pool) };
    // SAFETY: as above; `detach` hands the buffer's ownership to `pout`.
    unsafe { *pout = ossl_rand_pool_detach(pool) };
    // SAFETY: `pool` is live and this frame holds its only reference.
    unsafe { ossl_rand_pool_free(pool) };
    ret
}

/// `size_t ossl_rand_get_user_nonce(OSSL_LIB_CTX *ctx, unsigned char **pout, size_t min_len,
/// size_t max_len, const void *salt, size_t salt_len)` — `prov_seed.c:96-117`.
///
/// # Safety
/// `pout` must be writable; `salt` NULL or readable for `salt_len`; `ctx` NULL or live.
pub(crate) unsafe fn ossl_rand_get_user_nonce(
    ctx: *mut c_void,
    pout: *mut *mut c_uchar,
    min_len: usize,
    max_len: usize,
    salt: *const c_void,
    salt_len: usize,
) -> usize {
    // SAFETY: `ctx` is NULL or live per the contract.
    let rng = unsafe { ossl_rand_get0_seed_noncreating(ctx) };
    if rng.is_null() {
        // SAFETY: per the contract.
        return unsafe { ossl_rand_get_nonce(ctx, pout, min_len, max_len, salt, salt_len) };
    }

    // `CRYPTO_malloc` is a safe function in this crate and dereferences nothing the caller owns.
    let buf = CRYPTO_malloc(min_len, FILE, LINE).cast::<c_uchar>();
    if buf.is_null() {
        return 0;
    }

    // SAFETY: `rng` is live and `buf` is this frame's allocation of `min_len` bytes.
    if unsafe { EVP_RAND_generate(rng, buf, min_len, 0, 0, salt.cast::<c_uchar>(), salt_len) } == 0
    {
        // SAFETY: `buf` is this frame's own allocation.
        unsafe { CRYPTO_free(buf.cast(), FILE, LINE) };
        return 0;
    }
    // SAFETY: `pout` is writable per the contract; ownership of `buf` moves to the caller.
    unsafe { *pout = buf };
    min_len
}

/// `void ossl_rand_cleanup_nonce(OSSL_LIB_CTX *ctx, unsigned char *buf, size_t len)` —
/// `prov_seed.c:119-124`.
///
/// # Safety
/// `buf` is the caller's nonce allocation of `len` bytes, or NULL.
pub(crate) unsafe fn ossl_rand_cleanup_nonce(_ctx: *mut c_void, buf: *mut c_uchar, len: usize) {
    // SAFETY: per the contract; `CRYPTO_clear_free` accepts NULL.
    unsafe { CRYPTO_clear_free(buf.cast(), len, FILE, LINE) };
}

/// `void ossl_rand_cleanup_user_nonce(OSSL_LIB_CTX *ctx, unsigned char *buf, size_t len)` —
/// `prov_seed.c:126-131`.
///
/// # Safety
/// `buf` is the caller's nonce allocation of `len` bytes, or NULL.
pub(crate) unsafe fn ossl_rand_cleanup_user_nonce(
    _ctx: *mut c_void,
    buf: *mut c_uchar,
    len: usize,
) {
    // SAFETY: per the contract.
    unsafe { CRYPTO_clear_free(buf.cast(), len, FILE, LINE) };
}
