//! Phase 8 — `crypto/slh_dsa/slh_dsa_hash_ctx.c`: the per-operation hash context.
//!
//! `slh_dsa_hash_ctx.c` is 114 lines and defines the three-object lifetime
//! (`ossl_slh_dsa_hash_ctx_new`/`_dup`/`_free`, `:26-114`). The context caches the key's
//! prefetched methods so the tree functions do not fetch per hash: one `EVP_MD_CTX` on the key's
//! `md` (SHAKE-256 or SHA2-256), an optional second on `md_big` (SHA2-512, or *the same pointer*
//! as the first for category 1 and for every SHAKE set, `:39-50`), and an optional `EVP_MAC_CTX`
//! on the key's `hmac` (SHA-2 only, `:51-55`).
//!
//! **`md_big_ctx == md_ctx` is the aliasing the whole file is written around.** The free
//! (`:109-110`) and the dup (`:82-88`) both test identity before releasing or duplicating the
//! second context, because for a category 1 SHA-2 key and for every SHAKE key the two members
//! are one object. A transcription that duplicated unconditionally would double-free on the SHAKE
//! path, which is exactly what the identity test is for.
//!
//! SPDX-License-Identifier: Apache-2.0

#![allow(unreachable_pub)]

use core::ffi::{c_char, c_int};

use crate::evp::digest::{EVP_DigestInit_ex2, EVP_MD_CTX_dup, EVP_MD_CTX_free, EVP_MD_CTX_new};
use crate::evp::mac::{EVP_MAC_CTX_dup, EVP_MAC_CTX_free, EVP_MAC_CTX_new};
use crate::runtime::mem::{CRYPTO_clear_free, CRYPTO_zalloc};

use super::adrs::ossl_slh_get_adrs_fn;
use super::hash::ossl_slh_get_hash_fn;
use super::{SlhDsaHashCtx, SlhDsaKey};

/// The unit's own `__FILE__` — `slh_dsa_hash_ctx.c` is a plain `.c`.
const FILE: *const c_char = c"../../src/openssl-3.6.4/crypto/slh_dsa/slh_dsa_hash_ctx.c".as_ptr();
/// `slh_dsa_hash_ctx.c:28`, the `OPENSSL_zalloc(sizeof(*ret))` in `..._new`.
const LINE_ZALLOC_NEW: c_int = 28;
/// `slh_dsa_hash_ctx.c:70`, the `OPENSSL_zalloc` in `..._dup`.
const LINE_ZALLOC_DUP: c_int = 70;
/// `slh_dsa_hash_ctx.c:113`, the `OPENSSL_clear_free` in `..._free`.
const LINE_CLEAR_FREE: c_int = 113;

/// `SLH_DSA_HASH_CTX *ossl_slh_dsa_hash_ctx_new(const SLH_DSA_KEY *key)` —
/// `slh_dsa_hash_ctx.c:26-61`.
///
/// # Safety
/// `key` is live; its `md`, `md_big`, `hmac` members are the fetched methods `key_hash_init`
/// resolved (NULL `md` is a fetch failure this crate never builds).
pub(crate) unsafe fn ossl_slh_dsa_hash_ctx_new(key: *const SlhDsaKey) -> *mut SlhDsaHashCtx {
    let ret = CRYPTO_zalloc(core::mem::size_of::<SlhDsaHashCtx>(), FILE, LINE_ZALLOC_NEW)
        .cast::<SlhDsaHashCtx>();
    if ret.is_null() {
        return core::ptr::null_mut();
    }

    // SAFETY: `ret` is a fresh zeroed block this call owns; `key` is live per the contract.
    unsafe {
        (*ret).key = key;
        (*ret).md_ctx = EVP_MD_CTX_new();
        if (*ret).md_ctx.is_null() {
            ossl_slh_dsa_hash_ctx_free(ret);
            return core::ptr::null_mut();
        }
        if EVP_DigestInit_ex2((*ret).md_ctx, (*key).md, core::ptr::null()) != 1 {
            ossl_slh_dsa_hash_ctx_free(ret);
            return core::ptr::null_mut();
        }
        if !(*key).md_big.is_null() {
            /* Gets here for SHA2 algorithms. */
            if (*key).md_big == (*key).md {
                (*ret).md_big_ctx = (*ret).md_ctx;
            } else {
                (*ret).md_big_ctx = EVP_MD_CTX_new();
                if (*ret).md_big_ctx.is_null() {
                    ossl_slh_dsa_hash_ctx_free(ret);
                    return core::ptr::null_mut();
                }
                if EVP_DigestInit_ex2((*ret).md_big_ctx, (*key).md_big, core::ptr::null()) != 1 {
                    ossl_slh_dsa_hash_ctx_free(ret);
                    return core::ptr::null_mut();
                }
            }
            if !(*key).hmac.is_null() {
                (*ret).hmac_ctx = EVP_MAC_CTX_new((*key).hmac);
                if (*ret).hmac_ctx.is_null() {
                    ossl_slh_dsa_hash_ctx_free(ret);
                    return core::ptr::null_mut();
                }
            }
        }
    }
    ret
}

/// `SLH_DSA_HASH_CTX *ossl_slh_dsa_hash_ctx_dup(const SLH_DSA_HASH_CTX *src)` —
/// `slh_dsa_hash_ctx.c:68-97`.
///
/// # Safety
/// `src` is live.
pub(crate) unsafe fn ossl_slh_dsa_hash_ctx_dup(src: *const SlhDsaHashCtx) -> *mut SlhDsaHashCtx {
    let ret = CRYPTO_zalloc(core::mem::size_of::<SlhDsaHashCtx>(), FILE, LINE_ZALLOC_DUP)
        .cast::<SlhDsaHashCtx>();
    if ret.is_null() {
        return core::ptr::null_mut();
    }

    // SAFETY: `ret` is fresh; `src` is live per the contract. The identity tests below are the
    // authority's and are what stop a double-dup/double-free of the shared first context.
    unsafe {
        (*ret).hmac_digest_used = (*src).hmac_digest_used;
        (*ret).key = (*src).key;
        if !(*src).md_ctx.is_null() {
            (*ret).md_ctx = EVP_MD_CTX_dup((*src).md_ctx);
            if (*ret).md_ctx.is_null() {
                ossl_slh_dsa_hash_ctx_free(ret);
                return core::ptr::null_mut();
            }
        }
        if !(*src).md_big_ctx.is_null() {
            if (*src).md_big_ctx != (*src).md_ctx {
                (*ret).md_big_ctx = EVP_MD_CTX_dup((*src).md_big_ctx);
                if (*ret).md_big_ctx.is_null() {
                    ossl_slh_dsa_hash_ctx_free(ret);
                    return core::ptr::null_mut();
                }
            } else {
                (*ret).md_big_ctx = (*ret).md_ctx;
            }
        }
        if !(*src).hmac_ctx.is_null() {
            (*ret).hmac_ctx = EVP_MAC_CTX_dup((*src).hmac_ctx);
            if (*ret).hmac_ctx.is_null() {
                ossl_slh_dsa_hash_ctx_free(ret);
                return core::ptr::null_mut();
            }
        }
    }
    ret
}

/// `void ossl_slh_dsa_hash_ctx_free(SLH_DSA_HASH_CTX *ctx)` — `slh_dsa_hash_ctx.c:104-114`.
///
/// # Safety
/// `ctx` is NULL or live.
pub(crate) unsafe fn ossl_slh_dsa_hash_ctx_free(ctx: *mut SlhDsaHashCtx) {
    if ctx.is_null() {
        return;
    }
    // SAFETY: `ctx` is live per the contract.
    unsafe {
        EVP_MD_CTX_free((*ctx).md_ctx);
        if (*ctx).md_big_ctx != (*ctx).md_ctx {
            EVP_MD_CTX_free((*ctx).md_big_ctx);
        }
        EVP_MAC_CTX_free((*ctx).hmac_ctx);
        CRYPTO_clear_free(
            ctx.cast(),
            core::mem::size_of::<SlhDsaHashCtx>(),
            FILE,
            LINE_CLEAR_FREE,
        );
    }
}

/// `static int slh_dsa_key_hash_init(SLH_DSA_KEY *key)` — `slh_dsa_key.c:34-66`.
///
/// The SHA-2/SHAKE method resolution the key's constructor calls, kept in this module because it
/// is the *other* half of the context's prerequisites: it is where `md`, `md_big`, `hmac`,
/// `adrs_func` and `hash_func` are set. The authority has it in `slh_dsa_key.c`; the split is
/// only for readability here and the body is the authority's.
///
/// # Safety
/// `key` is live with `params` non-NULL; its `libctx`/`propq` are the caller's fetching context.
pub(crate) unsafe fn slh_dsa_key_hash_init(key: *mut SlhDsaKey) -> c_int {
    // SAFETY: `key` is live per the contract.
    unsafe {
        let is_shake = (*(*key).params).is_shake;
        let security_category = (*(*key).params).security_category;
        let digest_alg: *const c_char = if is_shake != 0 {
            c"SHAKE-256".as_ptr()
        } else {
            c"SHA2-256".as_ptr()
        };

        (*key).md = crate::evp::digest::EVP_MD_fetch((*key).libctx, digest_alg, (*key).propq);
        if (*key).md.is_null() {
            return 0;
        }
        if is_shake == 0 {
            if security_category == 1 {
                /* For category 1 SHA2-256 is used for all hash operations. */
                (*key).md_big = (*key).md;
            } else {
                (*key).md_big = crate::evp::digest::EVP_MD_fetch(
                    (*key).libctx,
                    c"SHA2-512".as_ptr(),
                    (*key).propq,
                );
                if (*key).md_big.is_null() {
                    return 0;
                }
            }
            (*key).hmac =
                crate::evp::mac::EVP_MAC_fetch((*key).libctx, c"HMAC".as_ptr(), (*key).propq);
            if (*key).hmac.is_null() {
                return 0;
            }
        }
        (*key).adrs_func = ossl_slh_get_adrs_fn(c_int::from(is_shake == 0));
        (*key).hash_func = ossl_slh_get_hash_fn(is_shake);
    }
    1
}
