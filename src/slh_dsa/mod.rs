//! Phase 8 — `crypto/slh_dsa/`: the SLH-DSA (FIPS 205) key, signature and hypertree units.
//!
//! This module is the crate's transcription of the ten `crypto/slh_dsa/*.c` files the SLH-DSA
//! provider rows are built on — `slh_params.c`, `slh_adrs.c`, `slh_hash.c`,
//! `slh_dsa_hash_ctx.c`, `slh_wots.c`, `slh_xmss.c`, `slh_fors.c`, `slh_hypertree.c`,
//! `slh_dsa.c` and `slh_dsa_key.c` — transcribed whole per D327's rule. The four headers are
//! modelled field-for-field: `slh_params.h`'s [`SlhDsaParams`], `slh_adrs.h`'s [`SlhAdrsFunc`],
//! `slh_hash.h`'s [`SlhHashFunc`] and `slh_dsa_key.h`'s [`SlhDsaKey`].
//!
//! ## The shared types are the two headers' structs, not a Rust-shaped rewrite
//!
//! `SLH_DSA_HASH_CTX` (`slh_dsa_local.h:51-66`) is the object every hash and tree function takes,
//! and it caches the key's prefetched `EVP_MD`/`EVP_MAC` methods plus one scratch buffer. The
//! `key` member is borrowed, not owned (`:52`), and `md_big_ctx` may *be* `md_ctx`
//! (`slh_dsa_hash_ctx.c:41-43`), so the two pointers are compared by identity on free and dup.
//! Both are reproduced rather than tidied.
//!
//! ## Every function is `unsafe extern "C"` because the authority's call graph is
//!
//! The tree functions are reached through the key's own [`SlhHashFunc`]/[`SlhAdrsFunc`] method
//! tables, so their signatures are the C ABI's. `SlhDsaKey`'s accessor macros
//! (`slh_dsa_key.h:13-18`) are written as methods that answer the same interior pointers.
//!
//! SPDX-License-Identifier: Apache-2.0

// The ten units are transcribed whole before the provider rows that publish them are landed, so
// a great deal of this module is not reached yet: the two provider units
// (`providers/implementations/keymgmt/slh_dsa_kmgmt.c.in` and `.../signature/slh_dsa_sig.c.in`)
// are the only callers of the key, the hash context and the sign/verify entry points, and they
// are a separate pass. Every function here is the authority's and is reached the moment those
// units land; the allow is a statement about *when*, not a claim that any of it is unused.
#![allow(dead_code)]

pub(crate) mod adrs;
pub(crate) mod dsa;
pub(crate) mod fors;
pub(crate) mod hash;
pub(crate) mod hash_ctx;
pub(crate) mod hypertree;
pub(crate) mod key;
pub(crate) mod params;
pub(crate) mod wots;
pub(crate) mod xmss;

#[cfg(test)]
mod tests;

use core::ffi::{c_char, c_int, c_void};

use crate::evp::digest::{EvpMd, EvpMdCtx};
use crate::evp::mac::{EvpMac, EvpMacCtx};

use self::adrs::SlhAdrsFunc;
use self::hash::SlhHashFunc;
use self::params::SlhDsaParams;

/// `SLH_DSA_MAX_N` — `include/crypto/slh_dsa.h:21`, the maximum security parameter.
pub(crate) const SLH_DSA_MAX_N: usize = 32;
/// `SLH_MAX_N` — `slh_dsa_local.h:20`, the same bound as the local header spells it.
pub(crate) const SLH_MAX_N: usize = 32;
/// `MAX_DIGEST_SIZE` — `slh_hash.c:19`, SHA-512 for categories 3 and 5.
pub(crate) const MAX_DIGEST_SIZE: usize = 64;
/// `SLH_DSA_HASH_SCRATCH_LEN` — `slh_dsa_local.h:49`, `64 + 2 * SLH_MAX_N`.
pub(crate) const SLH_DSA_HASH_SCRATCH_LEN: usize = 64 + 2 * SLH_MAX_N;
/// `SLH_DSA_MAX_CONTEXT_STRING_LEN` — `include/crypto/slh_dsa.h:20`.
pub(crate) const SLH_DSA_MAX_CONTEXT_STRING_LEN: usize = 255;

/// `struct slh_dsa_hash_ctx_st` — `slh_dsa_local.h:51-66`.
#[repr(C)]
pub(crate) struct SlhDsaHashCtx {
    /// `const SLH_DSA_KEY *key` — borrowed, **not** owned by this object.
    pub(crate) key: *const SlhDsaKey,
    /// `EVP_MD_CTX *md_ctx` — either SHAKE or SHA-256.
    pub(crate) md_ctx: *mut EvpMdCtx,
    /// `EVP_MD_CTX *md_big_ctx` — either SHA-512 or *the same pointer as* `md_ctx` for SHA-256.
    pub(crate) md_big_ctx: *mut EvpMdCtx,
    /// `EVP_MAC_CTX *hmac_ctx` — required by the SHA algorithms for `PRFmsg()`.
    pub(crate) hmac_ctx: *mut EvpMacCtx,
    /// `int hmac_digest_used` — the lazy-init flag for `hmac_ctx`'s digest.
    pub(crate) hmac_digest_used: c_int,
    /// `uint8_t scratch[SLH_DSA_HASH_SCRATCH_LEN]`.
    pub(crate) scratch: [u8; SLH_DSA_HASH_SCRATCH_LEN],
}

/// `struct slh_dsa_key_st` — `slh_dsa_key.h:23-50`.
///
/// The four `|n|`-byte components live in `priv_`: `SK_SEED`, `SK_PRF`, `PK_SEED`, `PK_ROOT`
/// (`slh_dsa_key.h:25-31`, the `4 * SLH_DSA_MAX_N`-byte block). `pub_` is NULL until either a
/// private or a public key is loaded, and then points at `priv_ + n * 2` — the `PK_SEED` slot,
/// which is what `SLH_DSA_PUB` answers (`slh_dsa_key.h:14,17`).
#[repr(C)]
pub(crate) struct SlhDsaKey {
    /// `uint8_t priv[4 * SLH_DSA_MAX_N]`.
    pub(crate) priv_: [u8; 4 * SLH_DSA_MAX_N],
    /// `uint8_t *pub`.
    pub(crate) pub_: *mut u8,
    /// `OSSL_LIB_CTX *libctx`.
    pub(crate) libctx: *mut c_void,
    /// `char *propq`.
    pub(crate) propq: *mut c_char,
    /// `int has_priv`.
    pub(crate) has_priv: c_int,
    /// `const SLH_DSA_PARAMS *params`.
    pub(crate) params: *const SlhDsaParams,
    /// `const SLH_ADRS_FUNC *adrs_func`.
    pub(crate) adrs_func: *const SlhAdrsFunc,
    /// `const SLH_HASH_FUNC *hash_func`.
    pub(crate) hash_func: *const SlhHashFunc,
    /// `EVP_MD *md` — used for SHAKE and SHA-256.
    pub(crate) md: *mut EvpMd,
    /// `EVP_MD *md_big` — used for SHA-256 or SHA-512.
    pub(crate) md_big: *mut EvpMd,
    /// `EVP_MAC *hmac`.
    pub(crate) hmac: *mut EvpMac,
}

impl SlhDsaKey {
    /// `SLH_DSA_SK_SEED(key)` — `slh_dsa_key.h:13`, `(key)->priv`.
    ///
    /// # Safety
    /// `self` must be live.
    pub(crate) unsafe fn sk_seed(self_ptr: *const SlhDsaKey) -> *const u8 {
        // SAFETY: `self_ptr` is live per the contract.
        unsafe { (*self_ptr).priv_.as_ptr() }
    }

    /// `SLH_DSA_SK_PRF(key)` — `slh_dsa_key.h:14`, `priv + n`.
    ///
    /// # Safety
    /// `self_ptr` must be live and its `params` non-NULL.
    pub(crate) unsafe fn sk_prf(self_ptr: *const SlhDsaKey) -> *const u8 {
        // SAFETY: `self_ptr` is live and `params` is non-NULL per the contract.
        unsafe {
            (*self_ptr)
                .priv_
                .as_ptr()
                .add((*(*self_ptr).params).n as usize)
        }
    }

    /// `SLH_DSA_PK_SEED(key)` — `slh_dsa_key.h:15`, `priv + n * 2`.
    ///
    /// # Safety
    /// `self_ptr` must be live and its `params` non-NULL.
    pub(crate) unsafe fn pk_seed(self_ptr: *const SlhDsaKey) -> *const u8 {
        // SAFETY: `self_ptr` is live and `params` is non-NULL per the contract.
        unsafe {
            (*self_ptr)
                .priv_
                .as_ptr()
                .add(2 * (*(*self_ptr).params).n as usize)
        }
    }

    /// `SLH_DSA_PK_ROOT(key)` — `slh_dsa_key.h:16`, `priv + n * 3`.
    ///
    /// # Safety
    /// `self_ptr` must be live and its `params` non-NULL.
    pub(crate) unsafe fn pk_root(self_ptr: *const SlhDsaKey) -> *const u8 {
        // SAFETY: `self_ptr` is live and `params` is non-NULL per the contract.
        unsafe {
            (*self_ptr)
                .priv_
                .as_ptr()
                .add(3 * (*(*self_ptr).params).n as usize)
        }
    }

    /// `SLH_DSA_PUB(key)` — `slh_dsa_key.h:17`, an alias of `SLH_DSA_PK_SEED`.
    ///
    /// # Safety
    /// `self_ptr` must be live and its `params` non-NULL.
    pub(crate) unsafe fn pub_region(self_ptr: *mut SlhDsaKey) -> *mut u8 {
        // SAFETY: `self_ptr` is live and `params` is non-NULL per the contract.
        unsafe {
            (*self_ptr)
                .priv_
                .as_mut_ptr()
                .add(2 * (*(*self_ptr).params).n as usize)
        }
    }

    /// `SLH_DSA_PRIV(key)` — `slh_dsa_key.h:18`, an alias of `SLH_DSA_SK_SEED`.
    ///
    /// # Safety
    /// `self_ptr` must be live.
    pub(crate) unsafe fn priv_region(self_ptr: *mut SlhDsaKey) -> *mut u8 {
        // SAFETY: `self_ptr` is live per the contract.
        unsafe { (*self_ptr).priv_.as_mut_ptr() }
    }
}
