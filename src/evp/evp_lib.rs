//! Phase 11.7 — `crypto/evp/evp_lib.c`'s two `X509_ALGOR **` hand-offs.
//!
//! `crypto/evp/evp_lib.c` is one authority translation unit whose exports the crate grouped by
//! the object each takes: the `EVP_CIPHER_CTX` accessors landed in `src/evp/cipher_ctx.rs` and the
//! `EVP_PKEY_CTX` ones in `src/evp/pkey_ctx.rs`. Two of them could not land with their siblings,
//! because each takes an `X509_ALGOR **` and fills it with `d2i_X509_ALGOR`, which is Phase 11's
//! codec (`X509_ALGOR_it`, `d2i_X509_ALGOR`, `i2d_X509_ALGOR`, landed in `src/asn1/x_algor.rs`);
//! Phase 7 recorded the pair as handed on in `forensics/tools/phase7_obligations.py`'s
//! `HANDED_ON`, and this is the stratum that writes them.
//!
//! ## One shape, two objects
//!
//! Both functions are the same two passes:
//!
//! ```text
//! ask for the length under OSSL_SIGNATURE_PARAM_ALGORITHM_ID ("algorithm-id")
//! if the parameter was not modified, or its length is zero
//!     -> raise EVP_R_GETTING_ALGORITHMIDENTIFIER_NOT_SUPPORTED, answer -2
//! if a destination was given and the length fits a long
//!     ask again into a fresh buffer, then d2i_X509_ALGOR it into *alg
//!     -> answer 1 on success, -1 otherwise
//! ```
//!
//! The `-2` and the raise are the whole of the observable refusal: an absent parameter leaves
//! `*alg` untouched and `ret` at `-1`, and only the zero-length case raises. The authority's own
//! `err:` label has no raise of its own, so the `goto err` arms differ from the `-2` arm in that
//! one bit and are written out here rather than collapsed.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_char, c_int, c_long, c_uchar, c_void};
use core::ptr;

use crate::asn1::x_algor::{d2i_X509_ALGOR, X509Algor};
use crate::evp::cipher_ctx::{EVP_CIPHER_CTX_get_params, EvpCipherCtx};
use crate::evp::pkey_ctx::{EVP_PKEY_CTX_get_params, EvpPkeyCtx};
use crate::params::{
    OSSL_PARAM_construct_end, OSSL_PARAM_construct_octet_string, OSSL_PARAM_modified, OsslParam,
};
use crate::runtime::err::{err_sites, raise_site};
use crate::runtime::mem::{CRYPTO_free, CRYPTO_malloc};

/// `OSSL_SIGNATURE_PARAM_ALGORITHM_ID` — `include/openssl/core_names.h:546`, value
/// `"algorithm-id"`. The key a signature provider answers the `AlgorithmIdentifier` DER under.
const OSSL_SIGNATURE_PARAM_ALGORITHM_ID: *const c_char = c"algorithm-id".as_ptr();

/// `crypto/evp/evp_lib.c`, the unit's own path, for the two allocation coordinates.
const FILE: *const c_char = c"../../src/openssl-3.6.4/crypto/evp/evp_lib.c".as_ptr();
/// `EVP_CIPHER_CTX_get_algor`'s `OPENSSL_malloc(aid_len)` (`evp_lib.c:1361`).
const LINE_MALLOC_AID_CIPHER: c_int = 1361;
/// Its `OPENSSL_free(aid)` (`evp_lib.c:1369`).
const LINE_FREE_AID_CIPHER: c_int = 1369;
/// `EVP_PKEY_CTX_get_algor`'s `OPENSSL_malloc(aid_len)` (`evp_lib.c:1479`).
const LINE_MALLOC_AID_PKEY: c_int = 1479;
/// Its `OPENSSL_free(aid)` (`evp_lib.c:1487`).
const LINE_FREE_AID_PKEY: c_int = 1487;

/// `int EVP_CIPHER_CTX_get_algor(EVP_CIPHER_CTX *ctx, X509_ALGOR **alg)` —
/// `crypto/evp/evp_lib.c:1337-1373`.
///
/// The cipher twin of [`EVP_PKEY_CTX_get_algor`]; the two differ only in the context type and the
/// allocation coordinates their unit records. See the module doc for the shared shape.
///
/// # Safety
/// `ctx` must be a live `EvpCipherCtx`; `alg` is NULL or a writable `X509_ALGOR *` slot. A decode
/// that succeeds overwrites the caller's `*alg` slot with a fresh object the caller owns.
#[no_mangle]
pub unsafe extern "C" fn EVP_CIPHER_CTX_get_algor(
    ctx: *mut EvpCipherCtx,
    alg: *mut *mut X509Algor,
) -> c_int {
    let mut ret = -1;
    let mut aid_len: usize = 0;
    let mut params: [OsslParam; 2] = [OSSL_PARAM_construct_end(), OSSL_PARAM_construct_end()];

    // SAFETY: the constructor writes one entry of this frame's array; the NULL buffer asks for the
    // length alone.
    unsafe {
        params[0] = OSSL_PARAM_construct_octet_string(
            OSSL_SIGNATURE_PARAM_ALGORITHM_ID,
            ptr::null_mut(),
            0,
        );
    }
    // SAFETY: `ctx` is live and `params` is this frame's terminated array.
    if unsafe { EVP_CIPHER_CTX_get_params(ctx, params.as_mut_ptr()) } <= 0 {
        return ret;
    }

    // SAFETY: `params` is the array the provider just answered into.
    if unsafe { OSSL_PARAM_modified(params.as_ptr()) } != 0 {
        aid_len = params[0].return_size;
    }
    if aid_len == 0 {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::EVP_LIB_1353) };
        return -2;
    }
    if !alg.is_null() && aid_len <= c_long::MAX as usize {
        // SAFETY: this allocates a fresh block of `aid_len` bytes.
        let aid = CRYPTO_malloc(aid_len, FILE, LINE_MALLOC_AID_CIPHER).cast::<c_uchar>();
        if !aid.is_null() {
            // SAFETY: the constructor writes one entry of this frame's array, and `aid` holds
            // `aid_len` writable bytes.
            unsafe {
                params[0] = OSSL_PARAM_construct_octet_string(
                    OSSL_SIGNATURE_PARAM_ALGORITHM_ID,
                    aid.cast::<c_void>(),
                    aid_len,
                )
            };
            let mut pp: *const c_uchar = aid;
            // SAFETY: `ctx` is live, `params` is this frame's array, `pp` is this frame's slot, and
            // `alg` is the caller's out-parameter.
            unsafe {
                if EVP_CIPHER_CTX_get_params(ctx, params.as_mut_ptr()) != 0
                    && OSSL_PARAM_modified(params.as_ptr()) != 0
                    && !d2i_X509_ALGOR(alg, &mut pp, aid_len as c_long).is_null()
                {
                    ret = 1;
                }
            }
        }
        // SAFETY: `aid` is NULL or the block allocated above, released exactly once.
        unsafe { CRYPTO_free(aid.cast::<c_void>(), FILE, LINE_FREE_AID_CIPHER) };
    }
    ret
}

/// `int EVP_PKEY_CTX_get_algor(EVP_PKEY_CTX *ctx, X509_ALGOR **alg)` —
/// `crypto/evp/evp_lib.c:1455-1491`.
///
/// The `EVP_PKEY` twin of [`EVP_CIPHER_CTX_get_algor`]: same parameter, same two passes, same
/// `-2` on an absent identifier. It differs only in the context type and the two allocation
/// coordinates.
///
/// # Safety
/// `ctx` must be a live `EvpPkeyCtx`; `alg` is NULL or a writable `X509_ALGOR *` slot. A decode
/// that succeeds overwrites the caller's `*alg` slot with a fresh object the caller owns.
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_CTX_get_algor(
    ctx: *mut EvpPkeyCtx,
    alg: *mut *mut X509Algor,
) -> c_int {
    let mut ret = -1;
    let mut aid_len: usize = 0;
    let mut params: [OsslParam; 2] = [OSSL_PARAM_construct_end(), OSSL_PARAM_construct_end()];

    // SAFETY: the constructor writes one entry of this frame's array; the NULL buffer asks for the
    // length alone.
    unsafe {
        params[0] = OSSL_PARAM_construct_octet_string(
            OSSL_SIGNATURE_PARAM_ALGORITHM_ID,
            ptr::null_mut(),
            0,
        );
    }
    // SAFETY: `ctx` is live and `params` is this frame's terminated array.
    if unsafe { EVP_PKEY_CTX_get_params(ctx, params.as_mut_ptr()) } <= 0 {
        return ret;
    }

    // SAFETY: `params` is the array the provider just answered into.
    if unsafe { OSSL_PARAM_modified(params.as_ptr()) } != 0 {
        aid_len = params[0].return_size;
    }
    if aid_len == 0 {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::EVP_LIB_1471) };
        return -2;
    }
    if !alg.is_null() && aid_len <= c_long::MAX as usize {
        // SAFETY: this allocates a fresh block of `aid_len` bytes.
        let aid = CRYPTO_malloc(aid_len, FILE, LINE_MALLOC_AID_PKEY).cast::<c_uchar>();
        if !aid.is_null() {
            // SAFETY: the constructor writes one entry of this frame's array, and `aid` holds
            // `aid_len` writable bytes.
            unsafe {
                params[0] = OSSL_PARAM_construct_octet_string(
                    OSSL_SIGNATURE_PARAM_ALGORITHM_ID,
                    aid.cast::<c_void>(),
                    aid_len,
                )
            };
            let mut pp: *const c_uchar = aid;
            // SAFETY: `ctx` is live, `params` is this frame's array, `pp` is this frame's slot, and
            // `alg` is the caller's out-parameter.
            unsafe {
                if EVP_PKEY_CTX_get_params(ctx, params.as_mut_ptr()) != 0
                    && OSSL_PARAM_modified(params.as_ptr()) != 0
                    && !d2i_X509_ALGOR(alg, &mut pp, aid_len as c_long).is_null()
                {
                    ret = 1;
                }
            }
        }
        // SAFETY: `aid` is NULL or the block allocated above, released exactly once.
        unsafe { CRYPTO_free(aid.cast::<c_void>(), FILE, LINE_FREE_AID_PKEY) };
    }
    ret
}
