//! Phase 8 — `crypto/slh_dsa/slh_dsa_key.c`: the SLH-DSA key object.
//!
//! `slh_dsa_key.c` is 527 lines and defines the whole key lifetime and its accessors: the
//! constructor (`ossl_slh_dsa_key_new`, `:97-122`), the destructor (`:127-135`), the selection
//! dup (`:145-176`), the equality (`:188-218`), the presence and pairwise checks (`:220-247`),
//! the `OSSL_PARAM` import (`:267-322`), the root computation (`slh_dsa_compute_pk_root`,
//! `:335-354`), the key generator (`ossl_slh_dsa_generate_key`, `:370-400`) and the twenty small
//! accessors.
//!
//! ## The four `|n|`-byte components share one 128-byte block
//!
//! `priv[4 * SLH_DSA_MAX_N]` holds `SK_SEED || SK_PRF || PK_SEED || PK_ROOT` (`slh_dsa_key.h`),
//! and `pub` is a pointer into the third slot, or NULL until a key is loaded. [`super::SlhDsaKey`]
//! models that layout and `SlhDsaKey`'s four accessors answer the same interior pointers the
//! macros do.
//!
//! ## `key_fromdata` accepts three shapes, and one of them is a bare seed
//!
//! A private import may be all four components (the function returns immediately, `:288-293`), or
//! just `SK_SEED || SK_PRF` (`:294-297`) in which case a separate public key **must** be present
//! (`:300-311`); the public import alone is the third. The `err:` path cleanses the whole private
//! block unconditionally (`:319`), because a private key of unexpected length may already have
//! been written into `priv` before `has_priv` was set.
//!
//! ## `SLH_DSA_PUB` is a slot, not an allocation
//!
//! Every place the authority writes `key->pub = SLH_DSA_PUB(key)` it is storing the address of
//! `priv + n * 2`. The crate's [`SlhDsaKey::pub_region`] is that address, so "has a public key"
//! is `pub != NULL` and the comparison reads `pk_len = 2n` bytes from it.
//!
//! ## `ossl_slh_dsa_key_to_text` lands with the text encoder that is its only caller
//!
//! `ossl_slh_dsa_key_to_text` (`:488-526`, the `#ifndef FIPS_MODULE` tail) was **withheld** until
//! Phase 10.1: its three helpers are `BIO_printf` and `ossl_bio_print_labeled_buf`, and the latter
//! is `crypto/encode_decode/encoder_lib.c`'s function `src/encoder_lib.rs` withheld (`encoder_lib.c`
//! `:785`) because the default provider published no encoder that reached it. Its own only caller is
//! `encode_key2text.c:454`, the text-encoder unit. That unit now lands (10.1's PQC helper slice), so
//! this printer lands with it, the same way the authority's own three `ossl_bio_print_*` helpers did
//! with `encode_key2text.c`'s first rows (D434).
//!
//! SPDX-License-Identifier: Apache-2.0

#![allow(unreachable_pub)]

use core::ffi::{c_char, c_int, c_void};
use core::ptr;

use crate::encoder_lib::ossl_bio_print_labeled_buf;
use crate::evp::digest::{EVP_MD_free, EVP_MD_up_ref};
use crate::evp::mac::{EVP_MAC_free, EVP_MAC_up_ref};
use crate::evp::pkey::{OSSL_KEYMGMT_SELECT_PRIVATE_KEY, OSSL_KEYMGMT_SELECT_PUBLIC_KEY};
use crate::params::OSSL_PARAM_get_octet_string;
use crate::rand::rand_lib::{RAND_bytes_ex, RAND_priv_bytes_ex};
use crate::runtime::bio::print::BIO_printf;
use crate::runtime::bio::Bio;
use crate::runtime::err::{err_sites, raise_site, raise_site_data};
use crate::runtime::mem::{
    CRYPTO_free, CRYPTO_memcmp, CRYPTO_strdup, CRYPTO_zalloc, OPENSSL_cleanse,
};
use crate::runtime::str::OPENSSL_strcasecmp;

use super::hash_ctx::{
    ossl_slh_dsa_hash_ctx_free, ossl_slh_dsa_hash_ctx_new, slh_dsa_key_hash_init,
};
use super::params::ossl_slh_dsa_params_get;
use super::xmss::ossl_slh_xmss_node;
use super::{SlhDsaHashCtx, SlhDsaKey, SLH_DSA_MAX_N};

/// `OSSL_KEYMGMT_SELECT_KEYPAIR` — `core_dispatch.h:649`, `PRIVATE_KEY | PUBLIC_KEY`.
///
/// `OSSL_KEYMGMT_SELECT_PRIVATE_KEY` and `..._PUBLIC_KEY` are **imported** from
/// `src/evp/pkey.rs`, which spells them at the header's values. This module used to carry its own
/// copies at `0x02` and `0x04` — each one bit left of `core_dispatch.h:640-641` — and the two
/// provider units that call these functions were built on the wrong pair (D402).
pub(crate) const OSSL_KEYMGMT_SELECT_KEYPAIR: c_int =
    OSSL_KEYMGMT_SELECT_PRIVATE_KEY | OSSL_KEYMGMT_SELECT_PUBLIC_KEY;

/// The unit's own `__FILE__` — `slh_dsa_key.c` is a plain `.c`.
const FILE: *const c_char = c"../../src/openssl-3.6.4/crypto/slh_dsa/slh_dsa_key.c".as_ptr();
/// `slh_dsa_key.c:106`, the `OPENSSL_zalloc(sizeof(*ret))` in `..._new`.
const LINE_ZALLOC_NEW: c_int = 106;
/// `slh_dsa_key.c:152`, the `OPENSSL_zalloc` in `..._dup`.
const LINE_ZALLOC_DUP: c_int = 152;
/// `slh_dsa_key.c:134`, the `OPENSSL_free(key)` in `..._free`.
const LINE_FREE_KEY: c_int = 134;

/// `static void slh_dsa_key_hash_cleanup(SLH_DSA_KEY *key)` — `slh_dsa_key.c:23-32`.
///
/// # Safety
/// `key` is live; its `propq`/`md`/`md_big`/`hmac` are the values `..._hash_init` left, or NULL.
pub(crate) unsafe fn slh_dsa_key_hash_cleanup(key: *mut SlhDsaKey) {
    // SAFETY: `key` is live per the contract.
    unsafe {
        CRYPTO_free((*key).propq.cast::<c_void>(), FILE, LINE_FREE_PROPQ);
        if (*key).md_big != (*key).md {
            EVP_MD_free((*key).md_big);
        }
        (*key).md_big = ptr::null_mut();
        EVP_MD_free((*key).md);
        EVP_MAC_free((*key).hmac);
        (*key).md = ptr::null_mut();
    }
}

/// `slh_dsa_key.c:27`, the `OPENSSL_free(key->propq)` in `..._hash_cleanup`.
const LINE_FREE_PROPQ: c_int = 27;

/// `static void slh_dsa_key_hash_dup(SLH_DSA_KEY *dst, const SLH_DSA_KEY *src)` —
/// `slh_dsa_key.c:68-76`.
///
/// The destination's members were already bitwise-copied from the source by `..._dup`'s
/// `*ret = *src`, so this only takes the references the copy shares. `dst` is accepted and
/// unread, exactly as the authority's parameter is.
///
/// # Safety
/// `src` is live; `dst` was bitwise-copied from it.
unsafe fn slh_dsa_key_hash_dup(_dst: *mut SlhDsaKey, src: *const SlhDsaKey) {
    // SAFETY: `src` is live per the contract.
    unsafe {
        if !(*src).md_big.is_null() && (*src).md_big != (*src).md {
            EVP_MD_up_ref((*src).md_big);
        }
        if !(*src).md.is_null() {
            EVP_MD_up_ref((*src).md);
        }
        if !(*src).hmac.is_null() {
            EVP_MAC_up_ref((*src).hmac);
        }
    }
}

/// `OSSL_LIB_CTX *ossl_slh_dsa_key_get0_libctx(const SLH_DSA_KEY *key)` —
/// `slh_dsa_key.c:84-87`.
///
/// # Safety
/// `key` is NULL or live.
pub(crate) unsafe fn ossl_slh_dsa_key_get0_libctx(key: *const SlhDsaKey) -> *mut c_void {
    if key.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: `key` is live per the contract.
    unsafe { (*key).libctx }
}

/// `SLH_DSA_KEY *ossl_slh_dsa_key_new(OSSL_LIB_CTX *libctx, const char *propq,`
/// `const char *alg)` — `slh_dsa_key.c:97-122`.
///
/// # Safety
/// `alg` is NULL or NUL-terminated; `propq` is NULL or NUL-terminated.
pub(crate) unsafe fn ossl_slh_dsa_key_new(
    libctx: *mut c_void,
    propq: *const c_char,
    alg: *const c_char,
) -> *mut SlhDsaKey {
    // SAFETY: `alg` is NULL or a C string per the contract.
    let params = unsafe { ossl_slh_dsa_params_get(alg) };
    if params.is_null() {
        return ptr::null_mut();
    }

    let ret =
        CRYPTO_zalloc(core::mem::size_of::<SlhDsaKey>(), FILE, LINE_ZALLOC_NEW).cast::<SlhDsaKey>();
    if ret.is_null() {
        return ret;
    }

    // SAFETY: `ret` is a fresh zeroed block this call owns.
    unsafe {
        (*ret).libctx = libctx;
        (*ret).params = params;
        if !propq.is_null() {
            (*ret).propq = CRYPTO_strdup(propq, FILE, LINE_STRDUP_PROPQ);
            if (*ret).propq.is_null() {
                ossl_slh_dsa_key_free(ret);
                return ptr::null_mut();
            }
        }
        if slh_dsa_key_hash_init(ret) == 0 {
            ossl_slh_dsa_key_free(ret);
            return ptr::null_mut();
        }
    }
    ret
}

/// `slh_dsa_key.c:111`, the `OPENSSL_strdup(propq)` in `..._new`.
const LINE_STRDUP_PROPQ: c_int = 111;

/// `void ossl_slh_dsa_key_free(SLH_DSA_KEY *key)` — `slh_dsa_key.c:127-135`.
///
/// # Safety
/// `key` is NULL or live.
pub(crate) unsafe fn ossl_slh_dsa_key_free(key: *mut SlhDsaKey) {
    if key.is_null() {
        return;
    }
    // SAFETY: `key` is live per the contract.
    unsafe {
        slh_dsa_key_hash_cleanup(key);
        OPENSSL_cleanse(
            (*key).priv_.as_mut_ptr().cast::<c_void>(),
            core::mem::size_of::<[u8; 4 * SLH_DSA_MAX_N]>() >> 1,
        );
        CRYPTO_free(key.cast::<c_void>(), FILE, LINE_FREE_KEY);
    }
}

/// `SLH_DSA_KEY *ossl_slh_dsa_key_dup(const SLH_DSA_KEY *src, int selection)` —
/// `slh_dsa_key.c:145-176`.
///
/// # Safety
/// `src` is NULL or live.
pub(crate) unsafe fn ossl_slh_dsa_key_dup(
    src: *const SlhDsaKey,
    selection: c_int,
) -> *mut SlhDsaKey {
    if src.is_null() {
        return ptr::null_mut();
    }
    let ret =
        CRYPTO_zalloc(core::mem::size_of::<SlhDsaKey>(), FILE, LINE_ZALLOC_DUP).cast::<SlhDsaKey>();
    if ret.is_null() {
        return ret;
    }

    // SAFETY: `ret` is fresh and `src` is live; the raw copy is the authority's `*ret = *src`, and
    // the three `NULL`s/zero undo the pointer state the copy carried over.
    unsafe {
        ptr::write(ret, ptr::read(src));
        (*ret).propq = ptr::null_mut();
        (*ret).pub_ = ptr::null_mut();
        (*ret).has_priv = 0;
        slh_dsa_key_hash_dup(ret, src);
        if !(*src).propq.is_null() {
            (*ret).propq = CRYPTO_strdup((*src).propq, FILE, LINE_STRDUP_PROPQ);
            if (*ret).propq.is_null() {
                ossl_slh_dsa_key_free(ret);
                return ptr::null_mut();
            }
        }
        if (selection & OSSL_KEYMGMT_SELECT_KEYPAIR) != 0 {
            /* The public components are present if the private key is present. */
            if !(*src).pub_.is_null() {
                (*ret).pub_ = SlhDsaKey::pub_region(ret);
            }
            if (selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0 {
                (*ret).has_priv = (*src).has_priv;
            }
        }
    }
    ret
}

/// `int ossl_slh_dsa_key_equal(const SLH_DSA_KEY *key1, const SLH_DSA_KEY *key2,`
/// `int selection)` — `slh_dsa_key.c:188-218`.
///
/// The two nested selection tests are the authority's own; collapsing them would be the same
/// answer by a different shape, so the nesting is kept and the lint is silenced here.
///
/// # Safety
/// Both keys are live.
#[allow(clippy::collapsible_if)] // the authority's own nested selection tests
pub(crate) unsafe fn ossl_slh_dsa_key_equal(
    key1: *const SlhDsaKey,
    key2: *const SlhDsaKey,
    selection: c_int,
) -> c_int {
    let mut key_checked: c_int = 0;

    /* The parameter sets must match - i.e. the same algorithm name. */
    // SAFETY: both keys are live per the contract.
    unsafe {
        if (*key1).params != (*key2).params {
            return 0;
        }

        if (selection & OSSL_KEYMGMT_SELECT_KEYPAIR) != 0 {
            if (selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0 {
                if !(*key1).pub_.is_null() && !(*key2).pub_.is_null() {
                    let pk_len = (*(*key1).params).pk_len as usize;
                    if CRYPTO_memcmp((*key1).pub_.cast(), (*key2).pub_.cast(), pk_len) != 0 {
                        return 0;
                    }
                    key_checked = 1;
                }
            }
            if key_checked == 0 && (selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0 {
                if (*key1).has_priv != 0 && (*key2).has_priv != 0 {
                    let pk_len = (*(*key1).params).pk_len as usize;
                    if CRYPTO_memcmp(
                        (*key1).priv_.as_ptr().cast(),
                        (*key2).priv_.as_ptr().cast(),
                        pk_len,
                    ) != 0
                    {
                        return 0;
                    }
                    key_checked = 1;
                }
            }
            return key_checked;
        }
    }
    1
}

/// `int ossl_slh_dsa_key_has(const SLH_DSA_KEY *key, int selection)` — `slh_dsa_key.c:220-231`.
///
/// # Safety
/// `key` is live.
pub(crate) unsafe fn ossl_slh_dsa_key_has(key: *const SlhDsaKey, selection: c_int) -> c_int {
    // SAFETY: `key` is live per the contract.
    unsafe {
        if (selection & OSSL_KEYMGMT_SELECT_KEYPAIR) != 0 {
            if (*key).pub_.is_null() {
                return 0; /* No public key */
            }
            if (selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0 && (*key).has_priv == 0 {
                return 0; /* No private key */
            }
            return 1;
        }
    }
    0
}

/// `int ossl_slh_dsa_key_pairwise_check(const SLH_DSA_KEY *key)` — `slh_dsa_key.c:233-247`.
///
/// # Safety
/// `key` is live.
pub(crate) unsafe fn ossl_slh_dsa_key_pairwise_check(key: *const SlhDsaKey) -> c_int {
    // SAFETY: `key` is live per the contract.
    unsafe {
        if (*key).pub_.is_null() || (*key).has_priv == 0 {
            return 0;
        }

        let ctx = ossl_slh_dsa_hash_ctx_new(key);
        if ctx.is_null() {
            return 0;
        }
        let ret = slh_dsa_compute_pk_root(ctx, key.cast_mut(), 1);
        ossl_slh_dsa_hash_ctx_free(ctx);
        ret
    }
}

/// `void ossl_slh_dsa_key_reset(SLH_DSA_KEY *key)` — `slh_dsa_key.c:249-256`.
///
/// # Safety
/// `key` is live.
pub(crate) unsafe fn ossl_slh_dsa_key_reset(key: *mut SlhDsaKey) {
    // SAFETY: `key` is live per the contract.
    unsafe {
        (*key).pub_ = ptr::null_mut();
        if (*key).has_priv != 0 {
            (*key).has_priv = 0;
            OPENSSL_cleanse(
                (*key).priv_.as_mut_ptr().cast::<c_void>(),
                (*key).priv_.len(),
            );
        }
    }
}

/// `int ossl_slh_dsa_key_fromdata(SLH_DSA_KEY *key, const OSSL_PARAM *param_pub,`
/// `const OSSL_PARAM *param_priv, int include_private)` — `slh_dsa_key.c:267-322`.
///
/// # Safety
/// `key` is live; the two parameter arrays are NULL or terminated.
pub(crate) unsafe fn ossl_slh_dsa_key_fromdata(
    key: *mut SlhDsaKey,
    param_pub: *const crate::params::OsslParam,
    param_priv: *const crate::params::OsslParam,
    include_private: c_int,
) -> c_int {
    if key.is_null() {
        return 0;
    }

    // SAFETY: `key` is live per the contract and its accessors take its own address.
    unsafe {
        /* The private key consists of 4 elements: SK_SEED, SK_PRF, PK_SEED and PK_ROOT. */
        let priv_len = ossl_slh_dsa_key_get_priv_len(key);
        /* The size of either SK_SEED + SK_PRF OR PK_SEED + PK_ROOT. */
        let key_len = priv_len >> 1;
        let mut data_len: usize = 0;

        /* Private key is optional. */
        if include_private != 0 && !param_priv.is_null() {
            let mut p: *mut c_void = (*key).priv_.as_mut_ptr().cast();
            if OSSL_PARAM_get_octet_string(param_priv, &mut p, priv_len, &mut data_len) == 0 {
                return 0;
            }
            /* If the data read includes all 4 elements then we are finished. */
            if data_len == priv_len {
                (*key).has_priv = 1;
                (*key).pub_ = SlhDsaKey::pub_region(key);
                return 1;
            }
            /* Otherwise it must be just SK_SEED + SK_PRF. */
            if data_len != key_len {
                return fromdata_err(key);
            }
            (*key).has_priv = 1;
        }

        /*
         * When the private key does not contain the public key there MUST be a separate public
         * key, since the private key cannot exist without the public key elements.
         */
        let mut p: *mut c_void = SlhDsaKey::pub_region(key).cast();
        if param_pub.is_null()
            || OSSL_PARAM_get_octet_string(param_pub, &mut p, key_len, &mut data_len) == 0
            || data_len != key_len
        {
            return fromdata_err(key);
        }
        (*key).pub_ = p.cast::<u8>();
    }
    1
}

/// The authority's `err:` label of `ossl_slh_dsa_key_fromdata` — `slh_dsa_key.c:313-321`.
///
/// # Safety
/// `key` is live.
unsafe fn fromdata_err(key: *mut SlhDsaKey) -> c_int {
    // SAFETY: `key` is live per the contract.
    unsafe {
        OPENSSL_cleanse(
            (*key).priv_.as_mut_ptr().cast::<c_void>(),
            (*key).priv_.len(),
        );
        ossl_slh_dsa_key_reset(key);
    }
    0
}

/// `static int slh_dsa_compute_pk_root(SLH_DSA_HASH_CTX *ctx, SLH_DSA_KEY *out, int validate)` —
/// `slh_dsa_key.c:335-354`.
///
/// # Safety
/// `ctx` is live; `out` is live with `params` set.
unsafe fn slh_dsa_compute_pk_root(
    ctx: *mut SlhDsaHashCtx,
    out: *mut SlhDsaKey,
    validate: c_int,
) -> c_int {
    // SAFETY: `ctx` is live per the contract.
    let key = unsafe { (*ctx).key };
    // SAFETY: `key` is live and its method table is the authority's.
    let (zero, set_layer_address, params) = unsafe {
        (
            (*(*key).adrs_func).zero,
            (*(*key).adrs_func).set_layer_address,
            (*key).params,
        )
    };
    let mut adrs = [0u8; super::adrs::SLH_ADRS_SIZE_MAX];
    let mut pk_root = [0u8; SLH_DSA_MAX_N];

    // SAFETY: `adrs` is writable for its own size.
    unsafe {
        zero(adrs.as_mut_ptr());
        set_layer_address(adrs.as_mut_ptr(), (*params).d - 1);
    }

    // SAFETY: `out` is live; the two buffered destinations are this frame's or `out`'s own.
    unsafe {
        let dst = if validate != 0 {
            pk_root.as_mut_ptr()
        } else {
            SlhDsaKey::pk_root(out).cast_mut()
        };
        let n = (*params).n as usize;

        /* Generate the ROOT public key. */
        if ossl_slh_xmss_node(
            ctx,
            SlhDsaKey::sk_seed(key),
            0,
            (*params).hm,
            SlhDsaKey::pk_seed(key),
            adrs.as_mut_ptr(),
            dst,
            n,
        ) == 0
        {
            return 0;
        }
        if validate != 0
            && core::slice::from_raw_parts(dst, n)
                != core::slice::from_raw_parts(SlhDsaKey::pk_root(out), n)
        {
            return 0;
        }
    }
    1
}

/// `int ossl_slh_dsa_generate_key(SLH_DSA_HASH_CTX *ctx, SLH_DSA_KEY *out,`
/// `OSSL_LIB_CTX *lib_ctx, const uint8_t *entropy, size_t entropy_len)` —
/// `slh_dsa_key.c:370-400`.
///
/// # Safety
/// `ctx` is live; `out` is live with `params` set; `entropy` is readable for `entropy_len` or NULL.
pub(crate) unsafe fn ossl_slh_dsa_generate_key(
    ctx: *mut SlhDsaHashCtx,
    out: *mut SlhDsaKey,
    lib_ctx: *mut c_void,
    entropy: *const u8,
    entropy_len: usize,
) -> c_int {
    // SAFETY: `out` is live per the contract.
    unsafe {
        let n = (*(*out).params).n as usize;
        let secret_key_len = 2 * n;
        let pk_seed_len = n;
        let entropy_len_expected = secret_key_len + pk_seed_len;
        let priv_ = SlhDsaKey::priv_region(out);
        let pub_ = SlhDsaKey::pub_region(out);

        if !entropy.is_null() && entropy_len != 0 {
            if entropy_len != entropy_len_expected {
                return generate_err(out, priv_, secret_key_len);
            }
            ptr::copy_nonoverlapping(entropy, priv_, entropy_len_expected);
        } else if RAND_priv_bytes_ex(lib_ctx, priv_, secret_key_len, 0) <= 0
            || RAND_bytes_ex(lib_ctx, pub_, pk_seed_len, 0) <= 0
        {
            return generate_err(out, priv_, secret_key_len);
        }
        if slh_dsa_compute_pk_root(ctx, out, 0) == 0 {
            return generate_err(out, priv_, secret_key_len);
        }
        (*out).pub_ = pub_;
        (*out).has_priv = 1;
    }
    1
}

/// The authority's `err:` label of `ossl_slh_dsa_generate_key` — `slh_dsa_key.c:395-399`.
///
/// # Safety
/// `out` is live; `priv_` points at its private block and at least `secret_key_len` bytes.
unsafe fn generate_err(out: *mut SlhDsaKey, priv_: *mut u8, secret_key_len: usize) -> c_int {
    // SAFETY: `out` is live and `priv_` is its own private block.
    unsafe {
        (*out).pub_ = ptr::null_mut();
        (*out).has_priv = 0;
        OPENSSL_cleanse(priv_.cast::<c_void>(), secret_key_len);
    }
    0
}

/// `int ossl_slh_dsa_key_type_matches(const SLH_DSA_KEY *key, const char *alg)` —
/// `slh_dsa_key.c:412-415`.
///
/// # Safety
/// `key` is live with `params` set; `alg` is NULL or NUL-terminated.
pub(crate) unsafe fn ossl_slh_dsa_key_type_matches(
    key: *const SlhDsaKey,
    alg: *const c_char,
) -> c_int {
    // SAFETY: `key` is live per the contract.
    unsafe { OPENSSL_strcasecmp((*(*key).params).alg, alg) }
        .eq(&0)
        .into()
}

/// Returns the public key data, or NULL if there is no public key.
///
/// # Safety
/// `key` is live.
pub(crate) unsafe fn ossl_slh_dsa_key_get_pub(key: *const SlhDsaKey) -> *const u8 {
    // SAFETY: `key` is live per the contract.
    unsafe { (*key).pub_ }
}

/// Returns `2 * |n|`, the size of `PK_SEED + PK_ROOT`. — `slh_dsa_key.c:424-427`.
///
/// # Safety
/// `key` is live with `params` set.
pub(crate) unsafe fn ossl_slh_dsa_key_get_pub_len(key: *const SlhDsaKey) -> usize {
    // SAFETY: `key` is live per the contract.
    unsafe { 2 * (*(*key).params).n as usize }
}

/// Returns the private key data, or NULL if there is no private key. — `slh_dsa_key.c:430-433`.
///
/// # Safety
/// `key` is live.
pub(crate) unsafe fn ossl_slh_dsa_key_get_priv(key: *const SlhDsaKey) -> *const u8 {
    // SAFETY: `key` is live per the contract.
    unsafe {
        if (*key).has_priv != 0 {
            (*key).priv_.as_ptr()
        } else {
            ptr::null()
        }
    }
}

/// Returns `4 * |n|`, the size of both key components. — `slh_dsa_key.c:440-443`.
///
/// # Safety
/// `key` is live with `params` set.
pub(crate) unsafe fn ossl_slh_dsa_key_get_priv_len(key: *const SlhDsaKey) -> usize {
    // SAFETY: `key` is live per the contract.
    unsafe { 4 * (*(*key).params).n as usize }
}

/// `size_t ossl_slh_dsa_key_get_n(const SLH_DSA_KEY *key)` — `slh_dsa_key.c:445-448`.
///
/// # Safety
/// `key` is live with `params` set.
pub(crate) unsafe fn ossl_slh_dsa_key_get_n(key: *const SlhDsaKey) -> usize {
    // SAFETY: `key` is live per the contract.
    unsafe { (*(*key).params).n as usize }
}

/// `int ossl_slh_dsa_key_get_security_category(const SLH_DSA_KEY *key)` —
/// `slh_dsa_key.c:450-453`.
///
/// # Safety
/// `key` is live with `params` set.
pub(crate) unsafe fn ossl_slh_dsa_key_get_security_category(key: *const SlhDsaKey) -> c_int {
    // SAFETY: `key` is live per the contract.
    unsafe { (*(*key).params).security_category as c_int }
}

/// `size_t ossl_slh_dsa_key_get_sig_len(const SLH_DSA_KEY *key)` — `slh_dsa_key.c:455-458`.
///
/// # Safety
/// `key` is live with `params` set.
pub(crate) unsafe fn ossl_slh_dsa_key_get_sig_len(key: *const SlhDsaKey) -> usize {
    // SAFETY: `key` is live per the contract.
    unsafe { (*(*key).params).sig_len as usize }
}

/// `const char *ossl_slh_dsa_key_get_name(const SLH_DSA_KEY *key)` — `slh_dsa_key.c:459-462`.
///
/// # Safety
/// `key` is live with `params` set.
pub(crate) unsafe fn ossl_slh_dsa_key_get_name(key: *const SlhDsaKey) -> *const c_char {
    // SAFETY: `key` is live per the contract.
    unsafe { (*(*key).params).alg }
}

/// `int ossl_slh_dsa_key_get_type(const SLH_DSA_KEY *key)` — `slh_dsa_key.c:463-466`.
///
/// # Safety
/// `key` is live with `params` set.
pub(crate) unsafe fn ossl_slh_dsa_key_get_type(key: *const SlhDsaKey) -> c_int {
    // SAFETY: `key` is live per the contract.
    unsafe { (*(*key).params).type_ }
}

/// `int ossl_slh_dsa_set_priv(SLH_DSA_KEY *key, const uint8_t *priv, size_t priv_len)` —
/// `slh_dsa_key.c:468-476`.
///
/// # Safety
/// `key` is live; `priv` is readable for `priv_len`.
pub(crate) unsafe fn ossl_slh_dsa_set_priv(
    key: *mut SlhDsaKey,
    priv_: *const u8,
    priv_len: usize,
) -> c_int {
    // SAFETY: `key` is live per the contract.
    unsafe {
        if ossl_slh_dsa_key_get_priv_len(key) != priv_len {
            return 0;
        }
        ptr::copy_nonoverlapping(priv_, (*key).priv_.as_mut_ptr(), priv_len);
        (*key).has_priv = 1;
        (*key).pub_ = SlhDsaKey::pub_region(key);
    }
    1
}

/// `int ossl_slh_dsa_set_pub(SLH_DSA_KEY *key, const uint8_t *pub, size_t pub_len)` —
/// `slh_dsa_key.c:478-486`.
///
/// # Safety
/// `key` is live; `pub` is readable for `pub_len`.
pub(crate) unsafe fn ossl_slh_dsa_set_pub(
    key: *mut SlhDsaKey,
    pub_: *const u8,
    pub_len: usize,
) -> c_int {
    // SAFETY: `key` is live per the contract.
    unsafe {
        if ossl_slh_dsa_key_get_pub_len(key) != pub_len {
            return 0;
        }
        (*key).pub_ = SlhDsaKey::pub_region(key);
        ptr::copy_nonoverlapping(pub_, (*key).pub_, pub_len);
        (*key).has_priv = 0;
    }
    1
}

/// `int ossl_slh_dsa_key_to_text(BIO *out, const SLH_DSA_KEY *key, int selection)` —
/// `slh_dsa_key.c:488-526`.
///
/// The `#ifndef FIPS_MODULE` tail: a public key is required regardless of `selection`, the private
/// half is printed only when the private-key bit is set, and the public key is always printed last.
///
/// # Safety
/// `out` is NULL or live; `key` is NULL or live.
pub(crate) unsafe fn ossl_slh_dsa_key_to_text(
    out: *mut Bio,
    key: *const SlhDsaKey,
    selection: c_int,
) -> c_int {
    if out.is_null() || key.is_null() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::SLH_DSA_KEY_494) };
        return 0;
    }
    // SAFETY: `key` is live past the guard.
    let name = unsafe { ossl_slh_dsa_key_get_name(key) };
    // SAFETY: `key` is live.
    if unsafe { ossl_slh_dsa_key_get_pub(key) }.is_null() {
        // Regardless of the |selection|, there must be a public key.
        // SAFETY: `name` is a static literal from the key's params.
        unsafe { raise_missing_key(&err_sites::SLH_DSA_KEY_500, name) };
        return 0;
    }

    // SAFETY: `key` is live; the accessors answer borrowed interior pointers.
    unsafe {
        if (selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0 {
            if ossl_slh_dsa_key_get_priv(key).is_null() {
                raise_missing_key(&err_sites::SLH_DSA_KEY_507, name);
                return 0;
            }
            if BIO_printf(out, c"%s Private-Key:\n".as_ptr(), name) <= 0 {
                return 0;
            }
            if ossl_bio_print_labeled_buf(
                out,
                c"priv:".as_ptr(),
                ossl_slh_dsa_key_get_priv(key),
                ossl_slh_dsa_key_get_priv_len(key),
            ) == 0
            {
                return 0;
            }
        } else if (selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0
            && BIO_printf(out, c"%s Public-Key:\n".as_ptr(), name) <= 0
        {
            return 0;
        }

        if ossl_bio_print_labeled_buf(
            out,
            c"pub:".as_ptr(),
            ossl_slh_dsa_key_get_pub(key),
            ossl_slh_dsa_key_get_pub_len(key),
        ) == 0
        {
            return 0;
        }
    }

    1
}

/// Raise the `PROV_R_MISSING_KEY` `"no %s key material available"` refusal with `name`.
///
/// # Safety
/// `name` must be NUL-terminated.
unsafe fn raise_missing_key(site: &err_sites::ErrSite, name: *const c_char) {
    // SAFETY: `name` is NUL-terminated per the contract.
    let bytes = unsafe { core::ffi::CStr::from_ptr(name) }.to_bytes();
    let mut msg = Vec::with_capacity(bytes.len() + 27);
    msg.extend_from_slice(b"no ");
    msg.extend_from_slice(bytes);
    msg.extend_from_slice(b" key material available");
    msg.push(0);
    // SAFETY: `msg` is NUL-terminated just above.
    unsafe { raise_site_data(site, msg.as_ptr().cast()) };
}
