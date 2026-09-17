//! Phase 7.4c-ii — `crypto/evp/pbe_scrypt.c`: the two `EVP_PBE_scrypt` entry points.
//!
//! Two exports and one rule, and the rule is the whole of the difference between this file and
//! `p5_crpt2.c`'s PBKDF2 wrapper: **`r` and `p` are bounded by `UINT32_MAX` and `N` is not**. The
//! authority's test is
//!
//! ```c
//! if (r > UINT32_MAX || p > UINT32_MAX) {
//!     ERR_raise(ERR_LIB_EVP, EVP_R_PARAMETER_TOO_LARGE);
//!     return 0;
//! }
//! ```
//!
//! and it happens **before** the `pass`/`salt` NULL normalisation, so an oversized `r` answers 0 with
//! `PARAMETER_TOO_LARGE` even when the caller also passed no salt. The bound is on the *scrypt*
//! parameters and not on `N`, which is a `uint64_t` and is the count a caller actually tunes up.
//!
//! ## NULL means empty, and it means it for both strings
//!
//! `pass == NULL` becomes `""` with a length of **0**, and `salt == NULL` becomes `""` with a length
//! of 0 — the two are separate statements whose only difference is the cast, and both are needed
//! because a caller that passes NULL has not asked for a zero-length salt to be a NUL byte. The
//! authority maintains this "existing behaviour" deliberately (its own comment) and passes the pair
//! as two `octet_string` parameters, so the length is what travels.
//!
//! ## One allocation and two refusals that share a shape
//!
//! ```text
//! maxmem == 0                     -> 32 MB, the compiled default
//! EVP_KDF_CTX_new(NULL)           -> 0, with nothing raised (EVP_KDF_CTX_new tolerates NULL)
//! EVP_KDF_derive(...) != 1        -> 0, with whatever the KDF raised already on the queue
//! ```
//!
//! `EVP_KDF_free(kdf)` is called **before** the context is used, and it is not a use-after-free: the
//! context holds its own reference to the method. That ordering is the authority's and it is why a
//! fetch that fails still reaches the `kctx == NULL` refusal rather than leaking.
//!
//! ## `SCRYPT_MAX_MEM`
//!
//! The authority's `#ifdef SCRYPT_MAX_MEM` is a Configure option and **this build does not define
//! it** (checked in `configdata.pm`), so the `#else` arm is live: `1024 * 1024 * 32`. The
//! `SCRYPT_MAX_MEM == 0` arm — half of `SIZE_MAX` — is therefore dead here and is not transcribed.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_char, c_int, c_void};

use crate::evp::kdf::{
    EVP_KDF_CTX_free, EVP_KDF_CTX_new, EVP_KDF_derive, EVP_KDF_fetch, EVP_KDF_free, EvpKdf,
    EvpKdfCtx,
};
use crate::params::{
    OSSL_PARAM_construct_end, OSSL_PARAM_construct_octet_string, OSSL_PARAM_construct_uint64,
};
use crate::runtime::err::{err_sites, raise_site};

/// `OSSL_KDF_NAME_SCRYPT` — `include/openssl/core_names.h`, the generated one.
const OSSL_KDF_NAME_SCRYPT: *const c_char = c"SCRYPT".as_ptr();
/// `OSSL_KDF_PARAM_PASSWORD`.
pub(crate) const OSSL_KDF_PARAM_PASSWORD: *const c_char = c"pass".as_ptr();
/// `OSSL_KDF_PARAM_SALT`.
pub(crate) const OSSL_KDF_PARAM_SALT: *const c_char = c"salt".as_ptr();
/// `OSSL_KDF_PARAM_SCRYPT_N`.
pub(crate) const OSSL_KDF_PARAM_SCRYPT_N: *const c_char = c"n".as_ptr();
/// `OSSL_KDF_PARAM_SCRYPT_R`.
pub(crate) const OSSL_KDF_PARAM_SCRYPT_R: *const c_char = c"r".as_ptr();
/// `OSSL_KDF_PARAM_SCRYPT_P`.
pub(crate) const OSSL_KDF_PARAM_SCRYPT_P: *const c_char = c"p".as_ptr();
/// `OSSL_KDF_PARAM_SCRYPT_MAXMEM`.
pub(crate) const OSSL_KDF_PARAM_SCRYPT_MAXMEM: *const c_char = c"maxmem_bytes".as_ptr();

/// `SCRYPT_MAX_MEM` — `crypto/evp/pbe_scrypt.c:34`, the `#else` arm, because this build does not
/// define the Configure option. 32 MB.
const SCRYPT_MAX_MEM: u64 = 1024 * 1024 * 32;

/// `int EVP_PBE_scrypt_ex(const char *pass, size_t passlen, const unsigned char *salt,
/// size_t saltlen, uint64_t N, uint64_t r, uint64_t p, uint64_t maxmem, unsigned char *key,
/// size_t keylen, OSSL_LIB_CTX *ctx, const char *propq)` — `crypto/evp/pbe_scrypt.c:37`.
///
/// # Safety
/// `pass` NULL or `passlen` readable bytes; `salt` NULL or `saltlen` readable bytes; `key` `keylen`
/// writable bytes; `ctx` NULL or live; `propq` NULL or NUL-terminated.
// `mirrors the authority's signature exactly`
#[allow(clippy::too_many_arguments)]
#[no_mangle]
pub unsafe extern "C" fn EVP_PBE_scrypt_ex(
    pass: *const c_char,
    passlen: usize,
    salt: *const u8,
    saltlen: usize,
    n: u64,
    r: u64,
    p: u64,
    maxmem: u64,
    key: *mut u8,
    keylen: usize,
    libctx: *mut c_void,
    propq: *const c_char,
) -> c_int {
    let empty: *const c_char = c"".as_ptr();
    let mut rv: c_int = 1;

    /* The bound is on `r` and `p` and not on `N`, and it is tested **before** the NULL normalisation
     * below — so an oversized `r` refuses even with no salt at all. */
    if r > u64::from(u32::MAX) || p > u64::from(u32::MAX) {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::PBE_SCRYPT_50) };
        return 0;
    }

    /* Maintain existing behaviour: NULL is the empty string with length **0**, for both. */
    let (pass, passlen) = if pass.is_null() {
        (empty, 0usize)
    } else {
        (pass, passlen)
    };
    let (salt, saltlen) = if salt.is_null() {
        (empty.cast::<u8>(), 0usize)
    } else {
        (salt, saltlen)
    };
    let maxmem = if maxmem == 0 { SCRYPT_MAX_MEM } else { maxmem };

    /* SAFETY: `libctx` is NULL or live and the two strings are NULL or NUL-terminated. */
    let kdf: *mut EvpKdf = unsafe { EVP_KDF_fetch(libctx, OSSL_KDF_NAME_SCRYPT, propq) };
    // SAFETY: `kdf` is NULL or live, which the constructor tolerates.
    let kctx: *mut EvpKdfCtx = unsafe { EVP_KDF_CTX_new(kdf) };
    /* Released before the context is used, and that is not a use-after-free: the context holds its
     * own reference to the method. */
    // SAFETY: `kdf` is NULL or live and this call gives its reference back.
    unsafe { EVP_KDF_free(kdf) };
    if kctx.is_null() {
        return 0;
    }

    let mut params = [OSSL_PARAM_construct_end(); 7];
    /* SAFETY: the constructors take a name and a buffer; every buffer here is the caller's and
     * every name is a compile-time constant. */
    unsafe {
        params[0] = OSSL_PARAM_construct_octet_string(
            OSSL_KDF_PARAM_PASSWORD,
            pass.cast::<c_void>().cast_mut(),
            passlen,
        );
        params[1] = OSSL_PARAM_construct_octet_string(
            OSSL_KDF_PARAM_SALT,
            salt.cast::<c_void>().cast_mut(),
            saltlen,
        );
        params[2] =
            OSSL_PARAM_construct_uint64(OSSL_KDF_PARAM_SCRYPT_N, &n as *const u64 as *mut u64);
        params[3] =
            OSSL_PARAM_construct_uint64(OSSL_KDF_PARAM_SCRYPT_R, &r as *const u64 as *mut u64);
        params[4] =
            OSSL_PARAM_construct_uint64(OSSL_KDF_PARAM_SCRYPT_P, &p as *const u64 as *mut u64);
        params[5] = OSSL_PARAM_construct_uint64(
            OSSL_KDF_PARAM_SCRYPT_MAXMEM,
            &maxmem as *const u64 as *mut u64,
        );
    }

    // SAFETY: `kctx` is live, `key` is `keylen` writable bytes per the contract, and the array is
    // this frame's own and terminated.
    if unsafe { EVP_KDF_derive(kctx, key, keylen, params.as_ptr()) } != 1 {
        rv = 0;
    }

    // SAFETY: `kctx` is live and this call gives its reference back.
    unsafe { EVP_KDF_CTX_free(kctx) };
    rv
}

/// `int EVP_PBE_scrypt(const char *pass, size_t passlen, const unsigned char *salt, size_t saltlen,
/// uint64_t N, uint64_t r, uint64_t p, uint64_t maxmem, unsigned char *key, size_t keylen)`.
///
/// # Safety
/// As [`EVP_PBE_scrypt_ex`], with a NULL library context and property query.
// `mirrors the authority's signature exactly`
#[allow(clippy::too_many_arguments)]
#[no_mangle]
pub unsafe extern "C" fn EVP_PBE_scrypt(
    pass: *const c_char,
    passlen: usize,
    salt: *const u8,
    saltlen: usize,
    n: u64,
    r: u64,
    p: u64,
    maxmem: u64,
    key: *mut u8,
    keylen: usize,
) -> c_int {
    // SAFETY: the arguments are forwarded under this function's contract, with the two NULLs the
    // authority passes.
    unsafe {
        EVP_PBE_scrypt_ex(
            pass,
            passlen,
            salt,
            saltlen,
            n,
            r,
            p,
            maxmem,
            key,
            keylen,
            core::ptr::null_mut(),
            core::ptr::null(),
        )
    }
}
