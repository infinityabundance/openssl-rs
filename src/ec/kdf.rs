//! Phase 8.7 — `crypto/ec/ecdh_kdf.c`: the X9.63 KDF wrapper and its deprecated spelling.
//!
//! The unit is sixty lines and defines **two functions**: `ossl_ecdh_kdf_X9_63`
//! (`include/crypto/ec.h:56`), the `OSSL_KDF_PARAM`-building body the provider's ECDH exchange
//! row reaches, and `ECDH_KDF_X9_62` (`ec.h:1302`), the ABI-compatibility name that forwards to
//! it. Neither computes the KDF — both fetch `OSSL_KDF_NAME_X963KDF` and drive it, which is why
//! the `X963KDF` row [`crate::provider::kdf`] publishes is what makes them answer
//! (`docs/DECISIONS.md` D296, D346).
//!
//! **`ECDH_KDF_X9_62` is inside `#ifndef OPENSSL_NO_DEPRECATED_3_0`** (`ecdh_kdf.c:43-55`) and
//! that macro is absent from the admitted `configuration.h`, so the wrapper is compiled.
//!
//! The one difference from its DH sibling is that the refusals are **not** symmetric:
//! `ossl_ecdh_kdf_X9_63` has no early answer for a NULL `md` — it passes
//! `EVP_MD_get0_name(md)` straight into the descriptor — and a failed `EVP_KDF_CTX_new` is a
//! silent `0` rather than a `goto err`, so the fetch's reference is still released on that path.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_char, c_int, c_void};
use core::ptr;

use crate::evp::digest::{EVP_MD_get0_name, EvpMd};
use crate::evp::kdf::{
    EVP_KDF_CTX_free, EVP_KDF_CTX_new, EVP_KDF_derive, EVP_KDF_fetch, EVP_KDF_free, EvpKdfCtx,
};
use crate::params::{
    OSSL_PARAM_construct_end, OSSL_PARAM_construct_octet_string, OSSL_PARAM_construct_utf8_string,
    OsslParam, END,
};

/// `OSSL_KDF_NAME_X963KDF` — `core_names.h:82` (`"X963KDF"`).
const OSSL_KDF_NAME_X963KDF: *const c_char = c"X963KDF".as_ptr();
/// `OSSL_KDF_PARAM_DIGEST` — `core_names.h:281`, aliased from `OSSL_ALG_PARAM_DIGEST`.
const OSSL_KDF_PARAM_DIGEST: *const c_char = c"digest".as_ptr();
/// `OSSL_KDF_PARAM_KEY` — `core_names.h:294`.
const OSSL_KDF_PARAM_KEY: *const c_char = c"key".as_ptr();
/// `OSSL_KDF_PARAM_INFO` — `core_names.h:289`.
const OSSL_KDF_PARAM_INFO: *const c_char = c"info".as_ptr();

/// `int ossl_ecdh_kdf_X9_63(unsigned char *out, size_t outlen, const unsigned char *Z,
/// size_t Zlen, const unsigned char *sinfo, size_t sinfolen, const EVP_MD *md,
/// OSSL_LIB_CTX *libctx, const char *propq)` — `ecdh_kdf.c:24-41`.
///
/// The `OSSL_PARAM` array is `params[4]`: `digest`, `key`, `info` and the terminator. The
/// context is created and released inside the one `if`, so a refused `EVP_KDF_CTX_new` leaves
/// the fetched `kdf` to the single `EVP_KDF_free` below it.
///
/// # Safety
/// `out` writable for `outlen` bytes; `Z`/`sinfo` readable for their lengths; `md` live.
///
/// `pub(crate)` since 8.8's `EVP_PKEY_METHOD` slice (D355): `crypto/ec/ec_pmeth.c`'s
/// `pkey_ec_kdf_derive` is the authority's second caller, and `src/ec/pmeth.rs` is where it lands.
#[allow(clippy::too_many_arguments)] // the authority's own signature has nine parameters.
#[allow(non_snake_case)] // the authority's own symbol name
pub(crate) unsafe fn ossl_ecdh_kdf_X9_63(
    out: *mut u8,
    outlen: usize,
    z: *const u8,
    z_len: usize,
    sinfo: *const u8,
    sinfo_len: usize,
    md: *const EvpMd,
    libctx: *mut c_void,
    propq: *const c_char,
) -> c_int {
    let mut ret = 0;
    let mut params: [OsslParam; 4] = [END; 4];

    // SAFETY: `md` is live per the contract.
    let mdname = unsafe { EVP_MD_get0_name(md) };
    // SAFETY: `libctx`/`propq` are per the contract.
    let kdf = unsafe { EVP_KDF_fetch(libctx, OSSL_KDF_NAME_X963KDF, propq) };

    // SAFETY: `kdf` is NULL or live; the crate's `EVP_KDF_CTX_new` refuses a NULL method.
    let kctx: *mut EvpKdfCtx = unsafe { EVP_KDF_CTX_new(kdf) };
    if !kctx.is_null() {
        // SAFETY: the descriptors borrow live data and the array is large enough.
        unsafe {
            params[0] =
                OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST, mdname.cast_mut(), 0);
            params[1] =
                OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_KEY, z.cast_mut().cast(), z_len);
            params[2] = OSSL_PARAM_construct_octet_string(
                OSSL_KDF_PARAM_INFO,
                sinfo.cast_mut().cast(),
                sinfo_len,
            );
            params[3] = OSSL_PARAM_construct_end();

            ret = (EVP_KDF_derive(kctx, out, outlen, params.as_ptr()) > 0) as c_int;
            EVP_KDF_CTX_free(kctx);
        }
    }
    // SAFETY: `kdf` is NULL or a fetched reference.
    unsafe { EVP_KDF_free(kdf) };
    ret
}

/// `int ECDH_KDF_X9_62(unsigned char *out, size_t outlen, const unsigned char *Z, size_t Zlen,
/// const unsigned char *sinfo, size_t sinfolen, const EVP_MD *md)` — `ecdh_kdf.c:47-55`.
///
/// The old name for `ecdh_KDF_X9_63`, retained for ABI compatibility: a forwarding call with a
/// NULL library context and a NULL property query, so the fetch resolves in the default context.
///
/// # Safety
/// `out` writable for `outlen` bytes; `Z`/`sinfo` readable for their lengths; `md` live.
#[no_mangle]
pub unsafe extern "C" fn ECDH_KDF_X9_62(
    out: *mut u8,
    outlen: usize,
    z: *const u8,
    z_len: usize,
    sinfo: *const u8,
    sinfo_len: usize,
    md: *const EvpMd,
) -> c_int {
    // SAFETY: every pointer is per this function's contract.
    unsafe {
        ossl_ecdh_kdf_X9_63(
            out,
            outlen,
            z,
            z_len,
            sinfo,
            sinfo_len,
            md,
            ptr::null_mut(),
            ptr::null(),
        )
    }
}
