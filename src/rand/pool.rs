//! `crypto/rand/rand_pool.c` and `include/crypto/rand_pool.h` — the RAND entropy pool.
//!
//! # Why this unit is landed before anything calls it
//!
//! The pool is the data structure every other part of Phase 9 stands on. `RAND_add` and
//! `RAND_seed` add to one, `ossl_prov_get_entropy` hands one to a DRBG's instantiate, and
//! `ossl_pool_add_nonce_data` mixes one into a DRBG's nonce. It has **no caller** until those
//! land, so the module is deliberately unfinished-looking at the top: `#![allow(dead_code)]` is
//! here with its own reason rather than sprinkled, and the `#[cfg(test)]` module at the bottom is
//! what makes the arithmetic falsifiable meanwhile. The precedent is `src/runtime/rcu.rs` and
//! `src/evp/fetch.rs`, both of which landed ahead of their readers.
//!
//! # The two paths the authority splits on, and why they are one module here
//!
//! `rand_pool.c` is the pool; `ossl_pool_acquire_entropy`, `ossl_rand_pool_init`/`_cleanup` and
//! the `/dev/*` device cache live in `providers/implementations/rands/seeding/rand_unix.c`, which
//! is where the platform calls are and where the admitted profile's `OPENSSL_RAND_SEED_OS` arm
//! selects `GETRANDOM` + `DEVRANDOM`. The seeding half is **not** in this file: it needs a dozen
//! `sys` bindings the crate does not declare, it is reached only through the provider's
//! instantiate, and it is 9.5's. What is here is the part that has no platform dependency at all.
//!
//! # What the layout is
//!
//! `RAND_POOL` is `#[repr(C)]` with the authority's field order and widths, because
//! `providers/implementations/rands/drbg.c` stores one by value in its own context in the
//! authority and the fields are read across the boundary. `buffer`/`len` are the live region,
//! `min_len`/`max_len`/`alloc_len` the allocation policy, and `entropy`/`entropy_requested` are in
//! **bits** while `len` is in bytes -- a unit mix the authority carries and this file preserves.
//!
//! # The arithmetic wraps, and the authority's is undefined
//!
//! The crate builds with `overflow-checks = true`. `entropy_to_bytes` is a `size_t` expression in
//! C (`rand_pool.c:161-162`) whose `bits * factor + 7` can overflow for a caller-supplied
//! `entropy_requested`, and `ossl_rand_pool_entropy_needed` computes a difference that can go
//! negative in C and wrap. Every such operation below is `wrapping_*`, for the reason
//! `docs/UNSAFE.md` gives: the crate's answer for undefined C arithmetic has to be *defined*, and
//! it has to be the answer the C would have produced on the target rather than a panic.
//!
//! SPDX-License-Identifier: Apache-2.0

#![allow(dead_code)] // the landing callers are 9.2's front, 9.4's DRBGs and 9.5's seed sources

use core::ffi::{c_int, c_uchar, c_uint, c_void, CStr};
use core::mem::size_of;
use core::ptr;

use crate::runtime::err::err_sites;
use crate::runtime::err::{raise_site, raise_site_data};
use crate::runtime::mem::{cleanse, CRYPTO_clear_free, CRYPTO_free, CRYPTO_zalloc};
use crate::runtime::secure::{CRYPTO_secure_clear_free, CRYPTO_secure_zalloc};

/// `RAND_POOL_FACTOR` — `include/crypto/rand_pool.h:35`.
const RAND_POOL_FACTOR: usize = 256;

/// `RAND_DRBG_STRENGTH` — `include/openssl/rand.h:37`.
///
/// MISSING(crate): the crate does not define `RAND_DRBG_STRENGTH` anywhere in
/// `src/`; the value is transcribed here.
const RAND_DRBG_STRENGTH: usize = 256;

/// `RAND_POOL_MAX_LENGTH` — `include/crypto/rand_pool.h:36`.
///
/// `(RAND_POOL_FACTOR * 3 * (RAND_DRBG_STRENGTH / 16))` = 12288.
///
/// `pub(crate)` since D311: `rand_lib.c`'s `RAND_add` clamps its `randomness` argument against
/// the pool's maximum, so the front reads it across modules. Widened rather than duplicated,
/// because a second copy would be a second place for the arithmetic to be wrong.
pub(crate) const RAND_POOL_MAX_LENGTH: usize = RAND_POOL_FACTOR * 3 * (RAND_DRBG_STRENGTH / 16);

/// `RAND_POOL_MIN_ALLOCATION(secure)` — `include/crypto/rand_pool.h:59`.
const fn rand_pool_min_allocation(secure: c_int) -> usize {
    if secure != 0 {
        16
    } else {
        48
    }
}

/// `ENTROPY_TO_BYTES(bits, entropy_factor)` — `rand_pool.c:161-162`.
///
/// `(((bits) * (entropy_factor) + 7) / 8)`. The multiply/add are `wrapping_*`
/// because the crate builds with `overflow-checks = true` and the C is a
/// `size_t` expression.
fn entropy_to_bytes(bits: usize, entropy_factor: c_uint) -> usize {
    bits.wrapping_mul(entropy_factor as usize).wrapping_add(7) / 8
}

/// The authority's translation unit, so a failing allocation records its
/// true coordinates.
const FILE: &CStr = c"crypto/rand/rand_pool.c";

// Call-site lines used as the `file`/`line` recorded by the allocator.
const LINE_ZALLOC_POOL: c_int = 25;
const LINE_SECURE_ZALLOC_BUFFER: c_int = 38;
const LINE_ZALLOC_BUFFER: c_int = 40;
const LINE_FREE_POOL_ERR: c_int = 50;
const LINE_ZALLOC_ATTACH: c_int = 63;
const LINE_SECURE_CLEAR_FREE_BUFFER: c_int = 100;
const LINE_CLEAR_FREE_BUFFER: c_int = 102;
const LINE_FREE_POOL: c_int = 105;
const LINE_SECURE_ZALLOC_GROW: c_int = 214;
const LINE_ZALLOC_GROW: c_int = 216;
const LINE_SECURE_CLEAR_FREE_GROW: c_int = 221;
const LINE_CLEAR_FREE_GROW: c_int = 223;

/// `typedef struct rand_pool_st RAND_POOL` — `include/crypto/rand_pool.h:70-82`.
///
/// Field order and widths are the authority's; `attached` and `secure` are
/// C `int`, the lengths and counts are `size_t`.
#[repr(C)]
pub(crate) struct RandPool {
    /// Points to the beginning of the random pool.
    pub(crate) buffer: *mut c_uchar,
    /// Current number of random bytes contained in the pool.
    pub(crate) len: usize,
    /// True pool was attached to existing buffer.
    pub(crate) attached: c_int,
    /// 1: allocated on the secure heap, 0: otherwise.
    pub(crate) secure: c_int,
    /// Minimum number of random bytes requested.
    pub(crate) min_len: usize,
    /// Maximum number of random bytes (allocated buffer size).
    pub(crate) max_len: usize,
    /// Current number of bytes allocated.
    pub(crate) alloc_len: usize,
    /// Current entropy count in bits.
    pub(crate) entropy: usize,
    /// Requested entropy count in bits.
    pub(crate) entropy_requested: usize,
}

/// `RAND_POOL *ossl_rand_pool_new(int entropy_requested, int secure, size_t min_len, size_t max_len)`
/// — `rand_pool.c:22-52`.
///
/// No caller pointer is dereferenced, so this is a safe `pub(crate) fn`; the
/// returned pointer is exclusively owned by the caller.
pub(crate) fn ossl_rand_pool_new(
    entropy_requested: c_int,
    secure: c_int,
    min_len: usize,
    max_len: usize,
) -> *mut RandPool {
    // `CRYPTO_zalloc` is a safe function in this crate: it answers null or
    // `sizeof(RandPool)` zeroed bytes, as the authority's `OPENSSL_zalloc(sizeof(*pool))`.
    let pool =
        CRYPTO_zalloc(size_of::<RandPool>(), FILE.as_ptr(), LINE_ZALLOC_POOL).cast::<RandPool>();

    if pool.is_null() {
        return ptr::null_mut();
    }

    let min_alloc_size = rand_pool_min_allocation(secure);
    // SAFETY: `pool` is a fresh, exclusively owned, zeroed `RandPool`.
    let p = unsafe { &mut *pool };

    p.min_len = min_len;
    p.max_len = if max_len > RAND_POOL_MAX_LENGTH {
        RAND_POOL_MAX_LENGTH
    } else {
        max_len
    };
    p.alloc_len = if min_len < min_alloc_size {
        min_alloc_size
    } else {
        min_len
    };
    if p.alloc_len > p.max_len {
        p.alloc_len = p.max_len;
    }

    if secure != 0 {
        // SAFETY: the secure allocator answers null or `alloc_len` zeroed
        // bytes; the authority's `OPENSSL_secure_zalloc`.
        p.buffer =
            unsafe { CRYPTO_secure_zalloc(p.alloc_len, FILE.as_ptr(), LINE_SECURE_ZALLOC_BUFFER) }
                .cast::<c_uchar>();
    } else {
        // The plain allocator answers null or `alloc_len` zeroed bytes; the authority's
        // `OPENSSL_zalloc`. Safe here for the reason the pool's own allocation is.
        p.buffer = CRYPTO_zalloc(p.alloc_len, FILE.as_ptr(), LINE_ZALLOC_BUFFER).cast::<c_uchar>();
    }

    if p.buffer.is_null() {
        // SAFETY: `pool` came from `CRYPTO_zalloc` above, was never published,
        // and is released exactly once here.
        unsafe { CRYPTO_free(pool.cast::<c_void>(), FILE.as_ptr(), LINE_FREE_POOL_ERR) };
        return ptr::null_mut();
    }

    p.entropy_requested = entropy_requested as usize;
    p.secure = secure;
    pool
}

/// `RAND_POOL *ossl_rand_pool_attach(const unsigned char *buffer, size_t len, size_t entropy)`
/// — `rand_pool.c:60-82`.
///
/// The `const` is cast away exactly as the authority does; attached buffers
/// are never modified or freed.
pub(crate) fn ossl_rand_pool_attach(
    buffer: *const c_uchar,
    len: usize,
    entropy: usize,
) -> *mut RandPool {
    // `CRYPTO_zalloc` is a safe function in this crate and answers null or
    // `sizeof(RandPool)` zeroed bytes.
    let pool =
        CRYPTO_zalloc(size_of::<RandPool>(), FILE.as_ptr(), LINE_ZALLOC_ATTACH).cast::<RandPool>();

    if pool.is_null() {
        return ptr::null_mut();
    }

    // SAFETY: `pool` is a fresh, exclusively owned, zeroed `RandPool`.
    let p = unsafe { &mut *pool };

    p.buffer = buffer as *mut c_uchar;
    p.len = len;
    p.attached = 1;
    p.min_len = p.len;
    p.max_len = p.len;
    p.alloc_len = p.len;
    p.entropy = entropy;
    pool
}

/// `void ossl_rand_pool_free(RAND_POOL *pool)` — `rand_pool.c:87-106`.
///
/// # Safety
/// `pool` is null or a live pool returned by `ossl_rand_pool_new`/`_attach`
/// that is not used again afterwards.
pub(crate) unsafe fn ossl_rand_pool_free(pool: *mut RandPool) {
    if pool.is_null() {
        return;
    }

    // SAFETY: the caller's contract: `pool` is live and exclusively owned.
    let p = unsafe { &mut *pool };

    if p.attached == 0 {
        if p.secure != 0 {
            // SAFETY: `p.buffer` is the secure allocation of `p.alloc_len`
            // bytes, released exactly once; the authority routes this to
            // `OPENSSL_secure_clear_free`.
            unsafe {
                CRYPTO_secure_clear_free(
                    p.buffer.cast::<c_void>(),
                    p.alloc_len,
                    FILE.as_ptr(),
                    LINE_SECURE_CLEAR_FREE_BUFFER,
                )
            };
        } else {
            // SAFETY: `p.buffer` is the plain allocation of `p.alloc_len`
            // bytes, released exactly once; `OPENSSL_clear_free`.
            unsafe {
                CRYPTO_clear_free(
                    p.buffer.cast::<c_void>(),
                    p.alloc_len,
                    FILE.as_ptr(),
                    LINE_CLEAR_FREE_BUFFER,
                )
            };
        }
    }

    // SAFETY: `pool` was allocated by `CRYPTO_zalloc` and is released once.
    unsafe { CRYPTO_free(pool.cast::<c_void>(), FILE.as_ptr(), LINE_FREE_POOL) };
}

/// `const unsigned char *ossl_rand_pool_buffer(RAND_POOL *pool)`
/// — `rand_pool.c:111-114`.
///
/// # Safety
/// `pool` is a live pool.
pub(crate) unsafe fn ossl_rand_pool_buffer(pool: *mut RandPool) -> *const c_uchar {
    // SAFETY: the caller's contract: `pool` is live and readable.
    unsafe { (*pool).buffer }
}

/// `size_t ossl_rand_pool_entropy(RAND_POOL *pool)` — `rand_pool.c:119-122`.
///
/// # Safety
/// `pool` is a live pool.
pub(crate) unsafe fn ossl_rand_pool_entropy(pool: *mut RandPool) -> usize {
    // SAFETY: the caller's contract: `pool` is live and readable.
    unsafe { (*pool).entropy }
}

/// `size_t ossl_rand_pool_length(RAND_POOL *pool)` — `rand_pool.c:127-130`.
///
/// # Safety
/// `pool` is a live pool.
pub(crate) unsafe fn ossl_rand_pool_length(pool: *mut RandPool) -> usize {
    // SAFETY: the caller's contract: `pool` is live and readable.
    unsafe { (*pool).len }
}

/// `unsigned char *ossl_rand_pool_detach(RAND_POOL *pool)` — `rand_pool.c:138-144`.
///
/// The caller now owns the buffer and must either free it or hand it back
/// through `ossl_rand_pool_reattach`.
///
/// # Safety
/// `pool` is a live pool.
pub(crate) unsafe fn ossl_rand_pool_detach(pool: *mut RandPool) -> *mut c_uchar {
    // SAFETY: the caller's contract: `pool` is live and exclusively owned.
    let p = unsafe { &mut *pool };
    let ret = p.buffer;
    p.buffer = ptr::null_mut();
    p.entropy = 0;
    ret
}

/// `void ossl_rand_pool_reattach(RAND_POOL *pool, unsigned char *buffer)`
/// — `rand_pool.c:150-155`.
///
/// Only the buffer previously detached from *this* pool may be passed.
///
/// # Safety
/// `pool` is live; `buffer` is the pointer returned by
/// `ossl_rand_pool_detach(pool)` and is writable for `pool.len` bytes.
pub(crate) unsafe fn ossl_rand_pool_reattach(pool: *mut RandPool, buffer: *mut c_uchar) {
    // SAFETY: the caller's contract: `pool` is live and exclusively owned.
    let p = unsafe { &mut *pool };
    p.buffer = buffer;
    // SAFETY: `p.buffer` is writable for `p.len` bytes per the contract; the
    // authority's `OPENSSL_cleanse(pool->buffer, pool->len)`.
    unsafe { cleanse(p.buffer, p.len) };
    p.len = 0;
}

/// `size_t ossl_rand_pool_entropy_available(RAND_POOL *pool)`
/// — `rand_pool.c:172-181`.
///
/// # Safety
/// `pool` is a live pool.
pub(crate) unsafe fn ossl_rand_pool_entropy_available(pool: *mut RandPool) -> usize {
    // SAFETY: the caller's contract: `pool` is live and readable.
    let p = unsafe { &*pool };
    if p.entropy < p.entropy_requested {
        return 0;
    }
    if p.len < p.min_len {
        return 0;
    }
    p.entropy
}

/// `size_t ossl_rand_pool_entropy_needed(RAND_POOL *pool)`
/// — `rand_pool.c:188-194`.
///
/// # Safety
/// `pool` is a live pool.
pub(crate) unsafe fn ossl_rand_pool_entropy_needed(pool: *mut RandPool) -> usize {
    // SAFETY: the caller's contract: `pool` is live and readable.
    let p = unsafe { &*pool };
    if p.entropy < p.entropy_requested {
        return p.entropy_requested.wrapping_sub(p.entropy);
    }
    0
}

/// `static int rand_pool_grow(RAND_POOL *pool, size_t len)` — `rand_pool.c:197-228`.
///
/// Increase the allocation size — not usable for an attached pool.
///
/// # Safety
/// `pool` is a live pool.
fn rand_pool_grow(pool: *mut RandPool, len: usize) -> c_int {
    // SAFETY: the caller's contract: `pool` is live and exclusively owned.
    let p = unsafe { &mut *pool };

    if len > p.alloc_len.wrapping_sub(p.len) {
        let limit = p.max_len / 2;
        let mut newlen = p.alloc_len;

        if p.attached != 0 || len > p.max_len.wrapping_sub(p.len) {
            // SAFETY: a compile-time-constant raise site.
            unsafe { raise_site(&err_sites::RAND_POOL_205) };
            return 0;
        }

        loop {
            newlen = if newlen < limit {
                newlen.wrapping_mul(2)
            } else {
                p.max_len
            };
            if !(len > newlen.wrapping_sub(p.len)) {
                break;
            }
        }

        // Either the secure or the plain allocator answers null or `newlen` zeroed bytes. Only
        // the secure half needs `unsafe` in this crate.
        let fresh = if p.secure != 0 {
            // SAFETY: a compile-time-constant allocation through the secure heap.
            unsafe { CRYPTO_secure_zalloc(newlen, FILE.as_ptr(), LINE_SECURE_ZALLOC_GROW) }
        } else {
            CRYPTO_zalloc(newlen, FILE.as_ptr(), LINE_ZALLOC_GROW)
        };
        if fresh.is_null() {
            return 0;
        }
        // SAFETY: `fresh` is writable for `newlen` bytes, `p.buffer` for
        // `p.len` bytes, and the regions cannot overlap (fresh allocation).
        unsafe {
            ptr::copy_nonoverlapping(p.buffer, fresh.cast::<c_uchar>(), p.len);
        }
        if p.secure != 0 {
            // SAFETY: `p.buffer` is the secure allocation of `p.alloc_len`
            // bytes, released exactly once here.
            unsafe {
                CRYPTO_secure_clear_free(
                    p.buffer.cast::<c_void>(),
                    p.alloc_len,
                    FILE.as_ptr(),
                    LINE_SECURE_CLEAR_FREE_GROW,
                )
            };
        } else {
            // SAFETY: `p.buffer` is the plain allocation of `p.alloc_len`
            // bytes, released exactly once here.
            unsafe {
                CRYPTO_clear_free(
                    p.buffer.cast::<c_void>(),
                    p.alloc_len,
                    FILE.as_ptr(),
                    LINE_CLEAR_FREE_GROW,
                )
            };
        }
        p.buffer = fresh.cast::<c_uchar>();
        p.alloc_len = newlen;
    }
    1
}

/// `size_t ossl_rand_pool_bytes_needed(RAND_POOL *pool, unsigned int entropy_factor)`
/// — `rand_pool.c:236-281`.
///
/// # Safety
/// `pool` is a live pool.
pub(crate) unsafe fn ossl_rand_pool_bytes_needed(
    pool: *mut RandPool,
    entropy_factor: c_uint,
) -> usize {
    // SAFETY: the caller's contract: `pool` is live and readable.
    let p = unsafe { &*pool };
    // SAFETY: `pool` is the same live pointer the caller's contract covers.
    let entropy_needed = unsafe { ossl_rand_pool_entropy_needed(pool) };

    if entropy_factor < 1 {
        // SAFETY: a compile-time-constant raise site.
        unsafe { raise_site(&err_sites::RAND_POOL_242) };
        return 0;
    }

    let mut bytes_needed = entropy_to_bytes(entropy_needed, entropy_factor);

    if bytes_needed > p.max_len.wrapping_sub(p.len) {
        /* not enough space left */
        // The authority's `ERR_raise_data` format string, verbatim:
        //   "entropy_factor=%u, entropy_needed=%zu, bytes_needed=%zu,"
        //   "pool->max_len=%zu, pool->len=%zu"
        let mut msg = format!(
            "entropy_factor={}, entropy_needed={}, bytes_needed={},pool->max_len={}, pool->len={}",
            entropy_factor, entropy_needed, bytes_needed, p.max_len, p.len
        );
        msg.push('\0');
        // SAFETY: a compile-time-constant site and a NUL-terminated message
        // that outlives the call.
        unsafe { raise_site_data(&err_sites::RAND_POOL_250, msg.as_ptr().cast()) };
        return 0;
    }

    if p.len < p.min_len && bytes_needed < p.min_len.wrapping_sub(p.len) {
        /* to meet the min_len requirement */
        bytes_needed = p.min_len.wrapping_sub(p.len);
    }

    /*
     * Make sure the buffer is large enough for the requested amount of data.
     * ... (see rand_pool.c:262-273 for the full rationale)
     */
    if rand_pool_grow(pool, bytes_needed) == 0 {
        /* persistent error for this pool */
        // SAFETY: the caller's contract: `pool` is live and exclusively owned.
        let p = unsafe { &mut *pool };
        p.max_len = 0;
        p.len = 0;
        return 0;
    }

    bytes_needed
}

/// `size_t ossl_rand_pool_bytes_remaining(RAND_POOL *pool)` — `rand_pool.c:284-287`.
///
/// # Safety
/// `pool` is a live pool.
pub(crate) unsafe fn ossl_rand_pool_bytes_remaining(pool: *mut RandPool) -> usize {
    // SAFETY: the caller's contract: `pool` is live and readable.
    let p = unsafe { &*pool };
    p.max_len.wrapping_sub(p.len)
}

/// `int ossl_rand_pool_add(RAND_POOL *pool, const unsigned char *buffer, size_t len, size_t entropy)`
/// — `rand_pool.c:298-339`.
///
/// # Safety
/// `pool` is a live pool; `buffer` is null or readable for `len` bytes.
pub(crate) unsafe fn ossl_rand_pool_add(
    pool: *mut RandPool,
    buffer: *const c_uchar,
    len: usize,
    entropy: usize,
) -> c_int {
    // SAFETY: the caller's contract: `pool` is live and exclusively owned.
    let p = unsafe { &mut *pool };

    if len > p.max_len.wrapping_sub(p.len) {
        // SAFETY: a compile-time-constant raise site.
        unsafe { raise_site(&err_sites::RAND_POOL_302) };
        return 0;
    }

    if p.buffer.is_null() {
        // SAFETY: a compile-time-constant raise site.
        unsafe { raise_site(&err_sites::RAND_POOL_307) };
        return 0;
    }

    if len > 0 {
        /*
         * Protect against accidentally passing the buffer returned from
         * ossl_rand_pool_add_begin. The `alloc_len` check keeps the
         * end-of-allocation comparison determinate (rand_pool.c:311-323).
         */
        // SAFETY: `p.len < p.alloc_len <=` the allocation of `p.buffer`, so the
        // one-past-`len` pointer is within/at the end of that allocation.
        if p.alloc_len > p.len && unsafe { p.buffer.add(p.len) as *const c_uchar } == buffer {
            // SAFETY: a compile-time-constant raise site.
            unsafe { raise_site(&err_sites::RAND_POOL_321) };
            return 0;
        }
        if rand_pool_grow(pool, len) == 0 {
            return 0;
        }
        // SAFETY: `p.buffer` is writable for `p.alloc_len >= p.len + len`
        // bytes and `buffer` reads for `len` bytes; the regions do not
        // overlap under the caller's contract.
        unsafe {
            ptr::copy_nonoverlapping(buffer, p.buffer.add(p.len), len);
        }
        p.len = p.len.wrapping_add(len);
        p.entropy = p.entropy.wrapping_add(entropy);
    }

    1
}

/// `unsigned char *ossl_rand_pool_add_begin(RAND_POOL *pool, size_t len)`
/// — `rand_pool.c:353-381`.
///
/// # Safety
/// `pool` is a live pool.
pub(crate) unsafe fn ossl_rand_pool_add_begin(pool: *mut RandPool, len: usize) -> *mut c_uchar {
    if len == 0 {
        return ptr::null_mut();
    }

    // SAFETY: the caller's contract: `pool` is live and exclusively owned.
    let p = unsafe { &mut *pool };

    if len > p.max_len.wrapping_sub(p.len) {
        // SAFETY: a compile-time-constant raise site.
        unsafe { raise_site(&err_sites::RAND_POOL_359) };
        return ptr::null_mut();
    }

    if p.buffer.is_null() {
        // SAFETY: a compile-time-constant raise site.
        unsafe { raise_site(&err_sites::RAND_POOL_364) };
        return ptr::null_mut();
    }

    if rand_pool_grow(pool, len) == 0 {
        return ptr::null_mut();
    }

    // SAFETY: `p.len <= p.alloc_len` and the allocation is `p.alloc_len`
    // bytes, so `p.len` is in bounds.
    unsafe { p.buffer.add(p.len) }
}

/// `int ossl_rand_pool_add_end(RAND_POOL *pool, size_t len, size_t entropy)`
/// — `rand_pool.c:392-405`.
///
/// # Safety
/// `pool` is a live pool.
pub(crate) unsafe fn ossl_rand_pool_add_end(
    pool: *mut RandPool,
    len: usize,
    entropy: usize,
) -> c_int {
    // SAFETY: the caller's contract: `pool` is live and exclusively owned.
    let p = unsafe { &mut *pool };

    if len > p.alloc_len.wrapping_sub(p.len) {
        // SAFETY: a compile-time-constant raise site.
        unsafe { raise_site(&err_sites::RAND_POOL_395) };
        return 0;
    }

    if len > 0 {
        p.len = p.len.wrapping_add(len);
        p.entropy = p.entropy.wrapping_add(entropy);
    }

    1
}

/// `int ossl_rand_pool_adin_mix_in(RAND_POOL *pool, const unsigned char *adin, size_t adin_len)`
/// — `rand_pool.c:418-444`.
///
/// # Safety
/// `pool` is a live pool; `adin` is null or readable for `adin_len` bytes.
pub(crate) unsafe fn ossl_rand_pool_adin_mix_in(
    pool: *mut RandPool,
    adin: *const c_uchar,
    adin_len: usize,
) -> c_int {
    if adin.is_null() || adin_len == 0 {
        /* Nothing to mix in -> success */
        return 1;
    }

    // SAFETY: the caller's contract: `pool` is live and exclusively owned.
    let p = unsafe { &mut *pool };

    if p.buffer.is_null() {
        // SAFETY: a compile-time-constant raise site.
        unsafe { raise_site(&err_sites::RAND_POOL_426) };
        return 0;
    }

    if p.len == 0 {
        // SAFETY: a compile-time-constant raise site.
        unsafe { raise_site(&err_sites::RAND_POOL_431) };
        return 0;
    }

    /* xor the additional data into the pool */
    for i in 0..adin_len {
        let idx = i % p.len;
        // SAFETY: `idx < p.len <= p.alloc_len` and `i < adin_len`, so both
        // accesses are in bounds.
        unsafe {
            *p.buffer.add(idx) ^= *adin.add(i);
        }
    }

    1
}

#[cfg(test)]
mod tests {
    //! The pool with no caller yet, tested against the properties the authority's own code states.
    //!
    //! Every assertion below is read off `rand_pool.c` rather than off this transcription: the
    //! clamping in `ossl_rand_pool_new` (`:38-52`), the byte/bit unit mix (`len` in bytes,
    //! `entropy` in bits), the three thresholds `ossl_rand_pool_entropy_available` gates on, the
    //! one-past-the-buffer guard in `ossl_rand_pool_add` (`:311-323`), the detach/reattach
    //! contract, and the XOR in `ossl_rand_pool_adin_mix_in`. A transcription error that moved one
    //! of them would pass a round-trip test and fail one of these.

    use super::*;

    /// `ossl_rand_pool_new` clamps `max_len`, honours the secure/plain minimum allocation, and
    /// records `entropy_requested` in bits.
    #[test]
    fn new_clamps_max_len_and_honours_the_minimum_allocation() {
        // SAFETY: no caller pointer is taken; the pools are freed below.
        unsafe {
            let plain = ossl_rand_pool_new(256, 0, 0, 100_000);
            assert!(!plain.is_null());
            assert_eq!((*plain).max_len, RAND_POOL_MAX_LENGTH);
            assert_eq!((*plain).max_len, 12288);
            assert_eq!((*plain).alloc_len, 48, "RAND_POOL_MIN_ALLOCATION(0)");
            assert_eq!((*plain).min_len, 0);
            assert_eq!((*plain).entropy_requested, 256);
            assert_eq!((*plain).attached, 0);
            assert_eq!((*plain).secure, 0);
            ossl_rand_pool_free(plain);

            // The secure arm's minimum is 16, not 48, and the clamp is applied before it.
            let secure = ossl_rand_pool_new(256, 1, 0, 100);
            assert!(!secure.is_null());
            assert_eq!((*secure).max_len, 100);
            assert_eq!((*secure).alloc_len, 16);
            assert_eq!((*secure).secure, 1);
            ossl_rand_pool_free(secure);
        }
    }

    /// `min_len` above the minimum allocation wins, and above `max_len` the allocation is clipped
    /// to `max_len` rather than refused.
    #[test]
    fn new_lets_min_len_win_and_clips_the_allocation_to_max_len() {
        // SAFETY: as above.
        unsafe {
            let wide = ossl_rand_pool_new(0, 0, 100, 4096);
            assert_eq!((*wide).alloc_len, 100);
            ossl_rand_pool_free(wide);

            let clipped = ossl_rand_pool_new(0, 0, 4096, 100);
            assert_eq!((*clipped).min_len, 4096);
            assert_eq!((*clipped).max_len, 100);
            assert_eq!((*clipped).alloc_len, 100);
            ossl_rand_pool_free(clipped);
        }
    }

    /// `add_begin`/`add_end` place the bytes and count entropy in **bits**, and grow the allocation
    /// when the request exceeds `alloc_len`.
    #[test]
    fn add_begin_then_add_end_places_bytes_and_counts_bits() {
        // SAFETY: the pool is live throughout and freed once at the end.
        unsafe {
            let pool = ossl_rand_pool_new(0, 0, 1, 4096);
            assert!(!pool.is_null());

            // 48 bytes of allocation, so 100 forces `rand_pool_grow`.
            let p = ossl_rand_pool_add_begin(pool, 100);
            assert!(!p.is_null());
            assert!((*pool).alloc_len >= 100, "grow raised the allocation");
            for i in 0..100 {
                *p.add(i) = i as u8;
            }
            assert_eq!(ossl_rand_pool_add_end(pool, 100, 800), 1);

            assert_eq!(ossl_rand_pool_length(pool), 100);
            assert_eq!(ossl_rand_pool_entropy(pool), 800, "entropy is in bits");
            assert_eq!((*pool).len, 100, "len is in bytes");
            let buffer = ossl_rand_pool_buffer(pool);
            for i in 0..100 {
                assert_eq!(*buffer.add(i), i as u8);
            }
            ossl_rand_pool_free(pool);
        }
    }

    /// The three thresholds `ossl_rand_pool_entropy_available` gates on, and the complement
    /// `ossl_rand_pool_entropy_needed` answers.
    #[test]
    fn entropy_available_needs_both_the_bit_count_and_min_len() {
        // SAFETY: each pool is live and freed once.
        unsafe {
            // entropy below the request: 0, and `needed` is the gap.
            let a = ossl_rand_pool_new(256, 0, 4, 64);
            assert_eq!(ossl_rand_pool_entropy_available(a), 0);
            assert_eq!(ossl_rand_pool_entropy_needed(a), 256);

            // entropy satisfied but `len < min_len`: still 0, and `needed` is 0 -- the two
            // thresholds are independent, which is what a single `>=` would get wrong.
            assert_eq!(ossl_rand_pool_add(a, c"abcd".as_ptr().cast(), 4, 256), 1);
            assert_eq!(ossl_rand_pool_length(a), 4);
            assert_eq!(ossl_rand_pool_entropy(a), 256);
            assert_eq!(ossl_rand_pool_entropy_needed(a), 0);

            let b = ossl_rand_pool_new(256, 0, 8, 64);
            assert_eq!(ossl_rand_pool_add(b, c"abcd".as_ptr().cast(), 4, 256), 1);
            assert_eq!(
                ossl_rand_pool_entropy_available(b),
                0,
                "len 4 < min_len 8 blocks it even though entropy is satisfied"
            );

            // both satisfied: the bit count comes back.
            assert_eq!(ossl_rand_pool_add(b, c"efgh".as_ptr().cast(), 4, 0), 1);
            assert_eq!(ossl_rand_pool_entropy_available(b), 256);
            ossl_rand_pool_free(a);
            ossl_rand_pool_free(b);
        }
    }

    /// `ossl_rand_pool_bytes_needed` is `ENTROPY_TO_BYTES(entropy_needed, factor)`, refuses a
    /// factor below the authority's floor, refuses a request that does not fit in `max_len - len`,
    /// and raises the answer to `min_len - len` when the estimate falls short of it.
    #[test]
    fn bytes_needed_is_the_factor_scaled_gap_clamped_by_min_and_max() {
        // SAFETY: each pool is live and freed once.
        unsafe {
            let pool = ossl_rand_pool_new(256, 0, 0, 64);
            assert_eq!(
                ossl_rand_pool_bytes_needed(pool, 0),
                0,
                "factor < 1 refuses"
            );
            assert_eq!(ossl_rand_pool_bytes_needed(pool, 1), 32);
            assert_eq!(ossl_rand_pool_bytes_needed(pool, 2), 64);
            // 256 bits at factor 8 is 256 bytes, which does not fit in max_len 64, so the
            // authority raises and answers 0 rather than clipping to 64. Clipping is the
            // plausible-looking wrong answer, which is why it is asserted.
            assert_eq!(ossl_rand_pool_bytes_needed(pool, 8), 0);
            ossl_rand_pool_free(pool);

            // `min_len` arm: the estimate 32 is below `min_len - len` = 40, so the answer is 40.
            let floored = ossl_rand_pool_new(256, 0, 40, 64);
            assert_eq!(ossl_rand_pool_bytes_needed(floored, 1), 40);
            ossl_rand_pool_free(floored);
        }
    }

    /// `ossl_rand_pool_add` refuses the pointer `ossl_rand_pool_add_begin` just handed out
    /// (`rand_pool.c:311-323`), and refuses an input longer than what remains.
    #[test]
    fn add_refuses_the_pointer_add_begin_handed_out() {
        // SAFETY: the pool is live and freed once; the handed-out pointer is written, not freed.
        unsafe {
            let pool = ossl_rand_pool_new(0, 0, 1, 64);
            let p = ossl_rand_pool_add_begin(pool, 8);
            assert!(!p.is_null());
            assert_eq!(
                ossl_rand_pool_add(pool, p, 8, 0),
                0,
                "the overlap guard fired"
            );
            assert_eq!(ossl_rand_pool_add_end(pool, 8, 0), 1);

            assert_eq!((*pool).len, 8);
            assert_eq!(
                ossl_rand_pool_add(pool, c"xy".as_ptr().cast(), 57, 0),
                0,
                "57 > max_len 64 - len 8"
            );
            ossl_rand_pool_free(pool);
        }
    }

    /// `detach` hands the caller the buffer and zeroes the pool's own length and entropy;
    /// `reattach` takes it back and cleanses it.
    #[test]
    fn detach_hands_the_buffer_over_and_reattach_takes_it_back() {
        // SAFETY: the detached buffer is handed back before it is freed.
        unsafe {
            let pool = ossl_rand_pool_new(0, 0, 1, 64);
            assert_eq!(
                ossl_rand_pool_add(pool, c"abcdef".as_ptr().cast(), 6, 48),
                1
            );

            let buffer = ossl_rand_pool_detach(pool);
            assert!(!buffer.is_null());
            assert_eq!((*pool).buffer, ptr::null_mut());
            assert_eq!(ossl_rand_pool_entropy(pool), 0);
            assert_eq!(ossl_rand_pool_length(pool), 6, "detach does not move len");

            ossl_rand_pool_reattach(pool, buffer);
            assert_eq!((*pool).buffer, buffer);
            assert_eq!(ossl_rand_pool_length(pool), 0, "reattach cleanses");
            for i in 0..6 {
                assert_eq!(*buffer.add(i), 0, "cleansed byte {i}");
            }
            ossl_rand_pool_free(pool);
        }
    }

    /// An attached pool is never freed by `ossl_rand_pool_free`, and reports the caller's length
    /// and entropy.
    #[test]
    fn an_attached_pool_does_not_free_the_callers_buffer() {
        let owned = [0xAAu8; 16];
        // SAFETY: `owned` outlives the pool, and freeing an attached pool does not touch it.
        unsafe {
            let pool = ossl_rand_pool_attach(owned.as_ptr(), owned.len(), 128);
            assert!(!pool.is_null());
            assert_eq!((*pool).attached, 1);
            assert_eq!((*pool).alloc_len, 16);
            assert_eq!((*pool).min_len, 16);
            assert_eq!((*pool).max_len, 16);
            assert_eq!(ossl_rand_pool_length(pool), 16);
            assert_eq!(ossl_rand_pool_entropy(pool), 128);
            ossl_rand_pool_free(pool);
        }
        assert_eq!(owned, [0xAAu8; 16], "the caller's buffer is untouched");
    }

    /// `ossl_rand_pool_adin_mix_in` XORs the additional data into the pool -- **the attention is on
    /// which side is cyclic**: the loop runs over `adin_len` and indexes the pool with
    /// `i % pool->len`, so a short adin touches only a prefix and a long one wraps. That is the
    /// opposite of the reading that looks natural, which is why both directions are driven.
    #[test]
    fn adin_mix_in_xors_the_adin_cyclically_into_the_pool() {
        // SAFETY: the pool is live and freed once; both inputs are in bounds.
        unsafe {
            let pool = ossl_rand_pool_new(0, 0, 4, 64);
            let zeros = [0u8; 4];
            assert_eq!(ossl_rand_pool_add(pool, zeros.as_ptr(), 4, 0), 1);

            let short = [0x0Fu8, 0xF0];
            assert_eq!(
                ossl_rand_pool_adin_mix_in(pool, short.as_ptr(), short.len()),
                1
            );
            let buffer = ossl_rand_pool_buffer(pool);
            assert_eq!(*buffer.add(0), 0x0F);
            assert_eq!(*buffer.add(1), 0xF0);
            assert_eq!(*buffer.add(2), 0, "the loop stops at adin_len");
            assert_eq!(*buffer.add(3), 0);

            // A six-byte adin wraps: indices 4 and 5 land on pool bytes 0 and 1 a second time, so
            // those two are XORed twice and **return to what they were** while bytes 2 and 3 are
            // touched once. Getting this wrong in the obvious direction (expecting 0x0F ^ 0xFF at
            // byte 0) is what this arm exists for.
            let long = [0xFFu8; 6];
            assert_eq!(
                ossl_rand_pool_adin_mix_in(pool, long.as_ptr(), long.len()),
                1
            );
            assert_eq!(
                *buffer.add(0),
                0x0F,
                "byte 0 mixed twice, so it is unchanged"
            );
            assert_eq!(
                *buffer.add(1),
                0xF0,
                "byte 1 mixed twice, so it is unchanged"
            );
            assert_eq!(*buffer.add(2), 0xFF, "byte 2 mixed once");
            assert_eq!(*buffer.add(3), 0xFF, "byte 3 mixed once");

            // Applying the same adin again cancels it everywhere: bytes 2 and 3 return to zero and
            // bytes 0 and 1 are left as the short mix left them, which is the pre-`long` state.
            assert_eq!(
                ossl_rand_pool_adin_mix_in(pool, long.as_ptr(), long.len()),
                1
            );
            assert_eq!(*buffer.add(0), 0x0F);
            assert_eq!(*buffer.add(1), 0xF0);
            assert_eq!(*buffer.add(2), 0, "byte 2 returned to zero");
            assert_eq!(*buffer.add(3), 0);

            // A null adin and a zero-length adin are *successes*; an empty pool is not.
            assert_eq!(ossl_rand_pool_adin_mix_in(pool, ptr::null(), 4), 1);
            assert_eq!(ossl_rand_pool_adin_mix_in(pool, long.as_ptr(), 0), 1);
            ossl_rand_pool_free(pool);

            let empty = ossl_rand_pool_new(0, 0, 0, 64);
            assert_eq!(
                ossl_rand_pool_adin_mix_in(empty, long.as_ptr(), long.len()),
                0,
                "a zero-length pool refuses"
            );
            ossl_rand_pool_free(empty);
        }
    }

    /// `bytes_remaining` is `max_len - len`, and the accessors of a freshly created pool are the
    /// zeroed state rather than garbage.
    #[test]
    fn bytes_remaining_and_a_fresh_pools_accessors() {
        // SAFETY: the pool is live and freed once.
        unsafe {
            let pool = ossl_rand_pool_new(0, 0, 4, 64);
            assert_eq!(ossl_rand_pool_length(pool), 0);
            assert_eq!(ossl_rand_pool_entropy(pool), 0);
            assert_eq!(ossl_rand_pool_bytes_remaining(pool), 64);
            assert_eq!(
                ossl_rand_pool_add(pool, c"abcdefgh".as_ptr().cast(), 8, 0),
                1
            );
            assert_eq!(ossl_rand_pool_bytes_remaining(pool), 56);
            assert!(!ossl_rand_pool_buffer(pool).is_null());
            ossl_rand_pool_free(pool);
        }
    }
}
