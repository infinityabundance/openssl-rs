//! `crypto/ml_dsa/ml_dsa_key.c` — the ML-DSA key object: its lifecycle, serialisation and the
//! getters the provider rows read.
//!
//! This file is the whole of `ml_dsa_key.c:1-571`: the three flag/parameter readers
//! (`ossl_ml_dsa_key_params`, `ossl_ml_dsa_key_get_seed`, `ossl_ml_dsa_key_get_prov_flags`),
//! `ossl_ml_dsa_set_prekey`, the allocator pair `ossl_ml_dsa_key_new`/`_free`/`_reset`, the
//! `_dup`/`_equal`/`_has` trio, `public_from_private` and its three callers
//! (`_public_from_private`, `_pairwise_check`, `keygen_internal`), the seed-driven
//! `ossl_ml_dsa_generate_key` (FIPS 204 `ML-DSA.KeyGen_internal`), and the twelve `ossl_ml_dsa_*`
//! getters the keymgmt row consumes.
//!
//! ## `s1` owns the block `s2` and `t0` point into
//!
//! `ml_dsa_key.h:55` allocates `s1.poly` with space for `s2` and `t0` after it, so
//! [`ossl_ml_dsa_key_priv_alloc`] allocates `l + 2 * k` polynomials and re-points `s2`/`t0` into
//! the tail, while [`ossl_ml_dsa_key_reset`] frees only `s1` and re-initialises the two tail
//! vectors to empty. This is the same shared-tail shape `ml_kem`'s `add_storage` recovers.
//!
//! ## The one raise
//!
//! The file holds a single `ERR_raise_data`, `ossl_ml_dsa_generate_key`'s seed/private-key
//! mismatch check at `:501`. Its coordinate is `err_sites::ML_DSA_KEY_501`, carrying the
//! authority's own library and reason (`ERR_LIB_PROV`, `PROV_R_INVALID_KEY`); the `%s` format
//! argument is `out->params->alg`, so [`raise_with_alg`] concatenates the algorithm name into the
//! message the way the authority's `printf` does.
//!
//! ## The two digest names carry their hyphen
//!
//! `ossl_ml_dsa_key_new` fetches `"SHAKE-128"` and `"SHAKE-256"`, and this file reproduces those
//! spellings rather than `ml_kem`'s unhyphenated pair.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_char, c_int, c_uchar, c_void};
use core::ptr;
use std::ffi::CStr;

use crate::evp::digest::{
    EVP_MD_CTX_free, EVP_MD_CTX_new, EVP_MD_fetch, EVP_MD_free, EVP_MD_up_ref, EvpMdCtx,
};
use crate::evp::pkey::{OSSL_KEYMGMT_SELECT_PRIVATE_KEY, OSSL_KEYMGMT_SELECT_PUBLIC_KEY};
use crate::rand::rand_lib::RAND_priv_bytes_ex;
use crate::runtime::err::{err_sites, raise_site_data};
use crate::runtime::mem::{
    CRYPTO_clear_free, CRYPTO_free, CRYPTO_malloc_array, CRYPTO_memcmp, CRYPTO_memdup,
    CRYPTO_zalloc, OPENSSL_cleanse,
};
use crate::runtime::mem_coords::SeamFile;
use crate::runtime::secure::{CRYPTO_secure_clear_free, CRYPTO_secure_free, CRYPTO_secure_malloc};

use super::encoders::{ossl_ml_dsa_pk_encode, ossl_ml_dsa_sk_encode};
use super::hash::shake_xof;
use super::poly::{
    matrix_init, matrix_mult_vector, poly_add, vector_copy, vector_equal, vector_ntt,
    vector_ntt_inverse, vector_power2_round, Poly, Vector,
};
use super::sample::{ossl_ml_dsa_matrix_expand_A, ossl_ml_dsa_vector_expand_S};
use super::{
    ossl_ml_dsa_params_get, MlDsaKey, MlDsaParams, ML_DSA_KEY_PROV_FLAGS_DEFAULT,
    ML_DSA_KEY_RETAIN_SEED, ML_DSA_K_BYTES, ML_DSA_PRIV_SEED_BYTES, ML_DSA_RHO_BYTES,
    ML_DSA_SEED_BYTES, ML_DSA_TR_BYTES,
};

/// `OSSL_KEYMGMT_SELECT_KEYPAIR` — `core_dispatch.h:649`, `PRIVATE_KEY | PUBLIC_KEY`.
///
/// `src/evp/pkey.rs` keeps its own copy private, so this unit carries the authority's pair
/// directly rather than widening another module's constant.
const OSSL_KEYMGMT_SELECT_KEYPAIR: c_int = 0x01 | 0x02;

/// The unit's own `__FILE__`, for the allocator's debug arguments.
const FILE_C: &CStr = c"../../src/openssl-3.6.4/crypto/ml_dsa/ml_dsa_key.c";
const FILE: *const c_char = FILE_C.as_ptr();
const FILE_SEAM: SeamFile = SeamFile::new(FILE_C);

/// `ossl_ml_dsa_set_prekey`'s `OPENSSL_secure_malloc(sk_len)`, `ml_dsa_key.c:52`.
const LINE_SET_PREKEY_SK: c_int = 52;
/// `ossl_ml_dsa_set_prekey`'s `OPENSSL_secure_malloc(seed_len)`, `ml_dsa_key.c:59`.
const LINE_SET_PREKEY_SEED: c_int = 59;
/// `ossl_ml_dsa_set_prekey`'s err-arm `OPENSSL_secure_clear_free(key->priv_encoding, sk_len)`,
/// `ml_dsa_key.c:69`.
const LINE_SET_PREKEY_CLEAR_SK: c_int = 69;
/// `ossl_ml_dsa_set_prekey`'s err-arm `OPENSSL_secure_clear_free(key->seed, seed_len)`,
/// `ml_dsa_key.c:70`.
const LINE_SET_PREKEY_CLEAR_SEED: c_int = 70;
/// `ossl_ml_dsa_key_new`'s `OPENSSL_zalloc(sizeof(*ret))`, `ml_dsa_key.c:93`.
const LINE_KEY_NEW: c_int = 93;
/// `ossl_ml_dsa_key_pub_alloc`'s `vector_alloc(&key->t1, key->params->k)`, `ml_dsa_key.c:113`.
const LINE_PUB_ALLOC: c_int = 113;
/// `ossl_ml_dsa_key_priv_alloc`'s `vector_secure_alloc(&key->s1, l + 2 * k)`, `ml_dsa_key.c:123`.
const LINE_PRIV_ALLOC: c_int = 123;
/// `ossl_ml_dsa_key_free`'s `OPENSSL_free(key)`, `ml_dsa_key.c:144`.
const LINE_KEY_FREE: c_int = 144;
/// `ossl_ml_dsa_key_reset`'s `vector_secure_free(&key->s1, l + 2 * k)`, `ml_dsa_key.c:160`.
const LINE_RESET_SECURE_FREE_S1: c_int = 160;
/// `ossl_ml_dsa_key_reset`'s `vector_free(&key->t1)`, `ml_dsa_key.c:165`.
const LINE_RESET_T1_FREE: c_int = 165;
/// `ossl_ml_dsa_key_reset`'s `OPENSSL_free(key->pub_encoding)`, `ml_dsa_key.c:167`.
const LINE_RESET_PUB: c_int = 167;
/// `ossl_ml_dsa_key_reset`'s `OPENSSL_secure_clear_free(key->priv_encoding, sk_len)`,
/// `ml_dsa_key.c:170`.
const LINE_RESET_PRV: c_int = 170;
/// `ossl_ml_dsa_key_reset`'s `OPENSSL_secure_clear_free(key->seed, ML_DSA_SEED_BYTES)`,
/// `ml_dsa_key.c:173`.
const LINE_RESET_SEED: c_int = 173;
/// `ossl_ml_dsa_key_dup`'s `OPENSSL_zalloc(sizeof(*ret))`, `ml_dsa_key.c:197`.
const LINE_DUP_ZALLOC: c_int = 197;
/// `ossl_ml_dsa_key_dup`'s `OPENSSL_memdup(src->pub_encoding, ...)`, `ml_dsa_key.c:212`.
const LINE_DUP_PUB: c_int = 212;
/// `ossl_ml_dsa_key_dup`'s `OPENSSL_secure_malloc(src->params->sk_len)`, `ml_dsa_key.c:227`.
const LINE_DUP_PRV: c_int = 227;
/// `ossl_ml_dsa_key_dup`'s `OPENSSL_secure_malloc(ML_DSA_SEED_BYTES)`, `ml_dsa_key.c:233`.
const LINE_DUP_SEED: c_int = 233;
/// `public_from_private`'s `OPENSSL_malloc_array(k + l + k * l, ...)`, `ml_dsa_key.c:333`.
const LINE_PFP_ALLOC_POLYS: c_int = 333;
/// `public_from_private`'s `OPENSSL_free(polys)`, `ml_dsa_key.c:365`.
const LINE_PFP_FREE_POLYS: c_int = 365;
/// `ossl_ml_dsa_key_public_from_private`'s `vector_alloc(&t0, key->params->k)`,
/// `ml_dsa_key.c:375`.
const LINE_PFP_T0_ALLOC: c_int = 375;
/// `ossl_ml_dsa_key_public_from_private`'s `vector_free(&t0)`, `ml_dsa_key.c:386`.
const LINE_PFP_T0_FREE: c_int = 386;
/// `ossl_ml_dsa_key_pairwise_check`'s `OPENSSL_malloc_array(2 * k, ...)`, `ml_dsa_key.c:402`.
const LINE_PWC_ALLOC_POLYS: c_int = 402;
/// `ossl_ml_dsa_key_pairwise_check`'s `OPENSSL_clear_free(polys, 2 * k * sizeof(*polys))`,
/// `ml_dsa_key.c:417`.
const LINE_PWC_FREE_POLYS: c_int = 417;
/// `ossl_ml_dsa_generate_key`'s `OPENSSL_secure_malloc(seed_len)`, `ml_dsa_key.c:483`.
const LINE_GENKEY_SEED: c_int = 483;
/// `ossl_ml_dsa_generate_key`'s `OPENSSL_secure_free(out->seed)`, `ml_dsa_key.c:486`.
const LINE_GENKEY_SEED_FREE: c_int = 486;
/// `ossl_ml_dsa_generate_key`'s `OPENSSL_secure_clear_free(sk, key->params->sk_len)`,
/// `ml_dsa_key.c:505`.
const LINE_GENKEY_CLEAR_SK: c_int = 505;
/// `keygen_internal`'s `OPENSSL_clear_free(out->seed, ML_DSA_SEED_BYTES)`, `ml_dsa_key.c:467`.
const LINE_KEYGEN_CLEAR_SEED: c_int = 467;

// ---------------------------------------------------------------------------------------------
// Ownership of a key buffer
// ---------------------------------------------------------------------------------------------

/// An owned key buffer allocated through the crate's allocator seam.
///
/// The block stays the allocation the authority itself makes -- a `CRYPTO_malloc_array` for a
/// `Poly` scratch block, or `CRYPTO_secure_malloc` for the private encoding and the seed -- at the
/// authority's exact size and `file`/`line`, because a Rust `Box`/`Vec` would hide both the
/// allocation and its release from a caller-installed `CRYPTO_set_mem_functions` hook. Only its
/// *ownership* is this type: the `new_*` constructors allocate it, [`Self::adopt`] and its two
/// siblings take up a block the crate allocated inside a helper or reclaimed from a key field,
/// `Drop` is its single release, and [`Self::into_raw`] hands the block to a `#[repr(C)]`
/// `MlDsaKey` field whose address the exported ABI exposes. The key block itself, whose release is
/// a compound destructor body, and the `s1`/`t1` vectors, whose allocation lives in `poly.rs`, stay
/// on the raw seam.
struct OwnedBuf {
    ptr: *mut c_uchar,
    release: BufRelease,
}

/// How the authority releases a key buffer.
enum BufRelease {
    /// The authority's plain `CRYPTO_free(ptr, file, line)` (`pub_encoding`).
    Plain { file: *const c_char, line: c_int },
    /// The authority's cleansing `CRYPTO_clear_free(ptr, num, file, line)` (the `polys` scratch of
    /// `public_from_private`/`pairwise_check`).
    Cleansed {
        num: usize,
        file: *const c_char,
        line: c_int,
    },
    /// The authority's `CRYPTO_secure_free(ptr, file, line)` (the seed on a refused RNG).
    Secure { file: *const c_char, line: c_int },
    /// The authority's cleansing `CRYPTO_secure_clear_free(ptr, num, file, line)` (`priv_encoding`
    /// and the seed).
    SecureCleansed {
        num: usize,
        file: *const c_char,
        line: c_int,
    },
}

impl OwnedBuf {
    /// `OPENSSL_malloc_array(count, size, file, line)`, or `None` when the allocator answers NULL.
    fn new_array(count: usize, size: usize, file: SeamFile, line: c_int) -> Option<OwnedBuf> {
        let file = file.as_ptr();
        let raw = unsafe {
            // SAFETY: `file` is NULL or a NUL-terminated coordinate valid for the call (a static literal/default, or a precondition established by the calling boundary), so `malloc_request`/the installed hook may read it.
            CRYPTO_malloc_array(count, size, file, line)
        }
        .cast::<c_uchar>();
        if raw.is_null() {
            return None;
        }
        Some(OwnedBuf {
            ptr: raw,
            release: BufRelease::Plain { file, line },
        })
    }

    /// `OPENSSL_malloc_array(count, size, file, line)` for a block the authority frees through its
    /// cleansing `OPENSSL_clear_free(ptr, count * size)`, or `None` when the allocator answers NULL.
    fn new_array_cleansed(
        count: usize,
        size: usize,
        file: SeamFile,
        line: c_int,
    ) -> Option<OwnedBuf> {
        let file = file.as_ptr();
        let raw = unsafe {
            // SAFETY: `file` is NULL or a NUL-terminated coordinate valid for the call (a static literal/default, or a precondition established by the calling boundary), so `malloc_request`/the installed hook may read it.
            CRYPTO_malloc_array(count, size, file, line)
        }
        .cast::<c_uchar>();
        if raw.is_null() {
            return None;
        }
        // `CRYPTO_malloc_array` succeeded, so `count * size` did not overflow.
        Some(OwnedBuf {
            ptr: raw,
            release: BufRelease::Cleansed {
                num: count * size,
                file,
                line,
            },
        })
    }

    /// `CRYPTO_secure_malloc(len, file, line)`, or `None` when the allocator answers NULL.
    fn new_secure(len: usize, file: SeamFile, line: c_int) -> Option<OwnedBuf> {
        let file = file.as_ptr();
        // SAFETY: `file` is NULL or a NUL-terminated C string, per this unit's `FILE`.
        let raw = unsafe { CRYPTO_secure_malloc(len, file, line) }.cast::<c_uchar>();
        if raw.is_null() {
            return None;
        }
        Some(OwnedBuf {
            ptr: raw,
            release: BufRelease::Secure { file, line },
        })
    }

    /// `CRYPTO_secure_malloc(len, file, line)` for a block the authority frees through its cleansing
    /// `CRYPTO_secure_clear_free(ptr, len, ...)`, or `None` when the allocator answers NULL.
    fn new_secure_cleansed(len: usize, file: SeamFile, line: c_int) -> Option<OwnedBuf> {
        let file = file.as_ptr();
        // SAFETY: `file` is NULL or a NUL-terminated C string, per this unit's `FILE`.
        let raw = unsafe { CRYPTO_secure_malloc(len, file, line) }.cast::<c_uchar>();
        if raw.is_null() {
            return None;
        }
        Some(OwnedBuf {
            ptr: raw,
            release: BufRelease::SecureCleansed {
                num: len,
                file,
                line,
            },
        })
    }

    /// Take up a plain block the crate allocated inside a helper (an `OPENSSL_memdup`) or reclaimed
    /// from the public encoding, for release by `Drop` at the authority's own site.
    ///
    /// # Safety
    /// `ptr` is NULL or a live plain block the crate allocated that no one else owns, and `file`
    /// is NULL or a NUL-terminated C string.
    unsafe fn adopt(ptr: *mut c_uchar, file: *const c_char, line: c_int) -> Option<OwnedBuf> {
        if ptr.is_null() {
            return None;
        }
        Some(OwnedBuf {
            ptr,
            release: BufRelease::Plain { file, line },
        })
    }

    /// Take up a block reclaimed from a key field, for release by `Drop` through the authority's
    /// cleansing `OPENSSL_clear_free(ptr, num)`.
    ///
    /// # Safety
    /// `ptr` is NULL or a live block the crate allocated that no one else owns and that is readable
    /// for `num` bytes, and `file` is NULL or a NUL-terminated C string.
    unsafe fn adopt_cleansed(
        ptr: *mut c_uchar,
        num: usize,
        file: *const c_char,
        line: c_int,
    ) -> Option<OwnedBuf> {
        if ptr.is_null() {
            return None;
        }
        Some(OwnedBuf {
            ptr,
            release: BufRelease::Cleansed { num, file, line },
        })
    }

    /// Take up a secure block reclaimed from a key field, for release by `Drop` through the
    /// authority's cleansing `CRYPTO_secure_clear_free(ptr, num, ...)`.
    ///
    /// # Safety
    /// `ptr` is NULL or a live secure block the crate allocated that no one else owns and that is
    /// readable for `num` bytes, and `file` is NULL or a NUL-terminated C string.
    unsafe fn adopt_secure_cleansed(
        ptr: *mut c_uchar,
        num: usize,
        file: *const c_char,
        line: c_int,
    ) -> Option<OwnedBuf> {
        if ptr.is_null() {
            return None;
        }
        Some(OwnedBuf {
            ptr,
            release: BufRelease::SecureCleansed { num, file, line },
        })
    }

    /// The writable start of the buffer.
    fn as_ptr(&self) -> *mut c_uchar {
        self.ptr
    }

    /// Give up ownership of the block to the key field it is stored in.
    fn into_raw(self) -> *mut c_uchar {
        let p = self.ptr;
        core::mem::forget(self);
        p
    }
}

impl Drop for OwnedBuf {
    /// The buffer's single release, through the same seam the authority uses.
    fn drop(&mut self) {
        match self.release {
            BufRelease::Plain { file, line } => {
                // SAFETY: `self.ptr` is the block this handle owns and has not released; the
                // authority's own `CRYPTO_free` accepts NULL.
                unsafe { CRYPTO_free(self.ptr.cast::<c_void>(), file, line) };
            }
            BufRelease::Cleansed { num, file, line } => {
                // SAFETY: `self.ptr` is the block this handle owns and has not released, readable
                // for `num` bytes; `CRYPTO_clear_free` cleanses then releases it and accepts NULL.
                unsafe { CRYPTO_clear_free(self.ptr.cast::<c_void>(), num, file, line) };
            }
            BufRelease::Secure { file, line } => {
                // SAFETY: as the plain arm; `CRYPTO_secure_free` accepts NULL.
                unsafe { CRYPTO_secure_free(self.ptr.cast::<c_void>(), file, line) };
            }
            BufRelease::SecureCleansed { num, file, line } => {
                // SAFETY: `self.ptr` is the block this handle owns and has not released, readable
                // for `num` bytes; `CRYPTO_secure_clear_free` cleanses then releases it and accepts
                // NULL.
                unsafe { CRYPTO_secure_clear_free(self.ptr.cast::<c_void>(), num, file, line) };
            }
        }
    }
}

/// `memcmp(a, b, n)` — the authority's own call, not a crate symbol.
///
/// The public-key comparison in [`ossl_ml_dsa_key_equal`] is over public data, so the authority
/// uses libc's non-constant-time `memcmp` here rather than `CRYPTO_memcmp`.
///
/// # Safety
/// Both pointers must be readable for `n` bytes.
unsafe fn libc_memcmp(a: *const u8, b: *const u8, n: usize) -> c_int {
    // SAFETY: both pointers are readable for `n` bytes per the contract.
    let (a, b) = unsafe {
        (
            core::slice::from_raw_parts(a, n),
            core::slice::from_raw_parts(b, n),
        )
    };
    match a.cmp(b) {
        core::cmp::Ordering::Less => -1,
        core::cmp::Ordering::Equal => 0,
        core::cmp::Ordering::Greater => 1,
    }
}

/// Raise an error whose message is `prefix || algorithm_name || suffix`.
///
/// The authority's format string at `ml_dsa_key.c:502-503` is
/// `"explicit %s private key does not match seed"` fed `out->params->alg`, so the three pieces are
/// concatenated into one NUL-terminated buffer rather than formatted by `printf`.
///
/// # Safety
/// `alg` must be a NUL-terminated C string.
unsafe fn raise_with_alg(
    site: &crate::runtime::err::err_sites::ErrSite,
    prefix: &str,
    alg: *const c_char,
    suffix: &str,
) {
    // SAFETY: `alg` is NUL-terminated per the contract.
    let bytes = unsafe { CStr::from_ptr(alg) }.to_bytes();
    let mut msg = Vec::with_capacity(prefix.len() + bytes.len() + suffix.len() + 1);
    msg.extend_from_slice(prefix.as_bytes());
    msg.extend_from_slice(bytes);
    msg.extend_from_slice(suffix.as_bytes());
    msg.push(0);
    // SAFETY: `msg` is NUL-terminated just above.
    unsafe { raise_site_data(site, msg.as_ptr().cast()) };
}

/// `ossl_ml_dsa_key_params(key)` — `ml_dsa_key.c:21-24`.
///
/// # Safety
/// `key` must be a live `ML_DSA_KEY`.
pub(crate) unsafe fn ossl_ml_dsa_key_params(key: *const MlDsaKey) -> *const MlDsaParams {
    // SAFETY: `key` is live per the contract.
    unsafe { (*key).params }
}

/// `ossl_ml_dsa_key_get_seed(key)` — `ml_dsa_key.c:27-30`. NULL if there is no seed.
///
/// # Safety
/// `key` must be a live `ML_DSA_KEY`.
pub(crate) unsafe fn ossl_ml_dsa_key_get_seed(key: *const MlDsaKey) -> *const u8 {
    // SAFETY: `key` is live per the contract.
    unsafe { (*key).seed as *const u8 }
}

/// `ossl_ml_dsa_key_get_prov_flags(key)` — `ml_dsa_key.c:32-35`.
///
/// # Safety
/// `key` must be a live `ML_DSA_KEY`.
pub(crate) unsafe fn ossl_ml_dsa_key_get_prov_flags(key: *const MlDsaKey) -> c_int {
    // SAFETY: `key` is live per the contract.
    unsafe { (*key).prov_flags }
}

/// `ossl_ml_dsa_set_prekey(key, flags_set, flags_clr, seed, seed_len, sk, sk_len)` —
/// `ml_dsa_key.c:37-74`.
///
/// Stores an unloaded prekey: an optional secure copy of `sk` and an optional secure copy of the
/// `(rho, K)` seed, then applies the flag mask.
///
/// # Safety
/// `key` must be live, or NULL; `seed`/`sk` must be NULL or readable for `seed_len`/`sk_len` bytes.
pub(crate) unsafe fn ossl_ml_dsa_set_prekey(
    key: *mut MlDsaKey,
    flags_set: c_int,
    flags_clr: c_int,
    seed: *const u8,
    seed_len: usize,
    sk: *const u8,
    sk_len: usize,
) -> c_int {
    // SAFETY: the arguments are live per the contract.
    unsafe {
        if key.is_null()
            || !(*key).pub_encoding.is_null()
            || !(*key).priv_encoding.is_null()
            || (!sk.is_null() && sk_len != (*(*key).params).sk_len)
            || (!seed.is_null() && seed_len != ML_DSA_SEED_BYTES)
            || !(*key).seed.is_null()
        {
            return 0;
        }

        let mut ret = 0;
        // The handles own the blocks this arm allocates: a refusal below drops them at the
        // authority's own `err:` site (its two cleansing secure frees), and a success hands each
        // block to its key field through `into_raw`.
        let mut priv_owned: Option<OwnedBuf> = None;
        let mut seed_owned: Option<OwnedBuf> = None;
        // The C's `goto end` on either allocation failure.
        'end: {
            if !sk.is_null() {
                let Some(buf) =
                    OwnedBuf::new_secure_cleansed(sk_len, FILE_SEAM, LINE_SET_PREKEY_SK)
                else {
                    break 'end;
                };
                ptr::copy_nonoverlapping(sk, buf.as_ptr(), sk_len);
                priv_owned = Some(buf);
            }

            if !seed.is_null() {
                let Some(buf) =
                    OwnedBuf::new_secure_cleansed(seed_len, FILE_SEAM, LINE_SET_PREKEY_SEED)
                else {
                    break 'end;
                };
                ptr::copy_nonoverlapping(seed, buf.as_ptr(), seed_len);
                seed_owned = Some(buf);
            }

            (*key).prov_flags |= flags_set;
            (*key).prov_flags &= !flags_clr;
            ret = 1;
        }

        if ret == 0 {
            // The C's `err:`-site release: each handle's `Drop` runs the authority's own cleansing
            // `CRYPTO_secure_clear_free`, and a block that was never allocated releases nothing.
            return ret;
        }
        if let Some(buf) = priv_owned {
            (*key).priv_encoding = buf.into_raw();
        }
        if let Some(buf) = seed_owned {
            (*key).seed = buf.into_raw();
        }
        ret
    }
}

/// `ossl_ml_dsa_key_new(libctx, propq, evp_type)` — `ml_dsa_key.c:84-107`.
///
/// # Safety
/// `propq` must be NULL or a NUL-terminated C string.
pub(crate) unsafe fn ossl_ml_dsa_key_new(
    libctx: *mut c_void,
    propq: *const c_char,
    evp_type: c_int,
) -> *mut MlDsaKey {
    let params = ossl_ml_dsa_params_get(evp_type);
    if params.is_null() {
        return ptr::null_mut();
    }

    // SAFETY: `CRYPTO_zalloc` answers NULL on failure, which is checked.
    let ret = unsafe {
        // SAFETY: `file` is NULL or a NUL-terminated coordinate valid for the call (a static literal/default, or a precondition established by the calling boundary), so `malloc_request`/the installed hook may read it.
        CRYPTO_zalloc(core::mem::size_of::<MlDsaKey>(), FILE, LINE_KEY_NEW)
    }
    .cast::<MlDsaKey>();
    if !ret.is_null() {
        // SAFETY: `ret` is a fresh, zeroed allocation; every field is written below.
        unsafe {
            (*ret).libctx = libctx;
            (*ret).params = params;
            (*ret).prov_flags = ML_DSA_KEY_PROV_FLAGS_DEFAULT;
            (*ret).shake128_md = EVP_MD_fetch(libctx, c"SHAKE-128".as_ptr(), propq);
            (*ret).shake256_md = EVP_MD_fetch(libctx, c"SHAKE-256".as_ptr(), propq);
            if (*ret).shake128_md.is_null() || (*ret).shake256_md.is_null() {
                ossl_ml_dsa_key_free(ret);
                return ptr::null_mut();
            }
        }
    }
    ret
}

/// `ossl_ml_dsa_key_pub_alloc(key)` — `ml_dsa_key.c:109-114`.
///
/// Allocates `t1`'s `k` polynomials; answers 0 if `t1` is already allocated.
///
/// # Safety
/// `key` must be a live `ML_DSA_KEY`.
pub(crate) unsafe fn ossl_ml_dsa_key_pub_alloc(key: *mut MlDsaKey) -> c_int {
    // SAFETY: `key` is live per the contract.
    unsafe {
        if !(*key).t1.poly.is_null() {
            return 0;
        }
        (*key).t1.alloc((*(*key).params).k, FILE, LINE_PUB_ALLOC)
    }
}

/// The single secret block `s1`, `s2` and `t0` are laid out in.
///
/// `ml_dsa_key.h:55`: `s1.poly` names `l + 2k` polynomials, `s2` starts at `l`, `t0` at `l + k`.
/// The handle borrows the three members and the two counts, so the extent is checked once and each
/// component is a safe sub-slice of the one block. Construction is unsafe (the member invariant is
/// the key's); the accessors after it are safe.
struct PrivBlock<'a> {
    s1: &'a mut Vector,
    s2: &'a mut Vector,
    t0: &'a mut Vector,
    l: usize,
    k: usize,
}

impl<'a> PrivBlock<'a> {
    /// `l + 2k`, checked.
    fn count(l: usize, k: usize) -> Option<usize> {
        l.checked_add(k.checked_mul(2)?)
    }

    /// Allocate the block and point `s2`/`t0` into its tail.
    ///
    /// # Safety
    ///
    /// `key` is live and `key.s1` is empty (the authority's `vector_secure_alloc` precondition).
    unsafe fn alloc(key: &'a mut MlDsaKey) -> c_int {
        let params = key.params;
        // SAFETY: `params` is the key's static parameter set.
        let (k, l) = unsafe { ((*params).k, (*params).l) };
        let Some(count) = Self::count(l, k) else {
            return 0;
        };
        if !key.s1.poly.is_null() {
            return 0;
        }
        // SAFETY: `s1` is empty and the secure allocator takes the checked extent.
        if unsafe { key.s1.secure_alloc(count, FILE, LINE_PRIV_ALLOC) } == 0 {
            return 0;
        }
        let mut block = PrivBlock {
            s1: &mut key.s1,
            s2: &mut key.s2,
            t0: &mut key.t0,
            l,
            k,
        };
        // SAFETY: `secure_alloc` just published the `count`-polynomial block.
        unsafe { block.fix_tails() };
        1
    }

    /// Borrow an already-allocated block.
    ///
    /// # Safety
    ///
    /// `s1.poly` is non-null and names `count(l, k)` polynomials, with `s2`/`t0` at the offsets
    /// [`Self::alloc`] published.
    unsafe fn of(key: &'a mut MlDsaKey) -> PrivBlock<'a> {
        let params = key.params;
        // SAFETY: `params` is the key's static parameter set.
        let (k, l) = unsafe { ((*params).k, (*params).l) };
        PrivBlock {
            s1: &mut key.s1,
            s2: &mut key.s2,
            t0: &mut key.t0,
            l,
            k,
        }
    }

    /// Publish `s1.num_poly` and the two tail members.
    ///
    /// # Safety
    ///
    /// `s1.poly` names `count(l, k)` polynomials.
    unsafe fn fix_tails(&mut self) {
        let base = self.s1.poly;
        self.s1.num_poly = self.l;
        // SAFETY: the checked extent puts both offsets inside the block.
        *self.s2 = Vector::init(unsafe { base.add(self.l) }, self.k);
        // SAFETY: `l + k <= l + 2k` for the checked extent.
        *self.t0 = Vector::init(unsafe { base.add(self.l + self.k) }, self.k);
    }

    /// Release the whole block (secure-cleansing) and empty all three members.
    fn clear(self, file: *const c_char, line: c_int) {
        let Some(count) = Self::count(self.l, self.k) else {
            return;
        };
        // `secure_free` cleanses the `count`-polynomial extent and empties `s1`.
        // SAFETY: `s1` is the block this handle owns; `count` is its checked extent.
        unsafe { self.s1.secure_free(count, file, line) };
        self.s2.poly = ptr::null_mut();
        self.s2.num_poly = 0;
        self.t0.poly = ptr::null_mut();
        self.t0.num_poly = 0;
    }

    /// The `s1` component.
    fn s1(&self) -> &[Poly] {
        // SAFETY: the handle's invariant gives `s1.poly` `l` polynomials.
        unsafe { core::slice::from_raw_parts(self.s1.poly, self.l) }
    }

    /// The `s2` component (the tail starting at `l`).
    fn s2(&self) -> &[Poly] {
        // SAFETY: `s2.poly` names `k` polynomials inside the block.
        unsafe { core::slice::from_raw_parts(self.s2.poly, self.k) }
    }

    /// The `t0` component (the tail starting at `l + k`).
    fn t0(&self) -> &[Poly] {
        // SAFETY: `t0.poly` names `k` polynomials inside the block.
        unsafe { core::slice::from_raw_parts(self.t0.poly, self.k) }
    }

    /// The `s1` component, mutably.
    fn s1_mut(&mut self) -> &mut [Poly] {
        // SAFETY: the handle's invariant gives `s1.poly` `l` polynomials and the borrow is unique.
        unsafe { core::slice::from_raw_parts_mut(self.s1.poly, self.l) }
    }
}

/// `ossl_ml_dsa_key_priv_alloc(key)` — `ml_dsa_key.c:116-131`.
///
/// Allocates `s1`'s `l + 2 * k` polynomials and re-points `s2`/`t0` into the tail; answers 0 if
/// `s1` is already allocated.
///
/// # Safety
/// `key` must be a live `ML_DSA_KEY`.
pub(crate) unsafe fn ossl_ml_dsa_key_priv_alloc(key: *mut MlDsaKey) -> c_int {
    // SAFETY: `key` is live per the contract; `PrivBlock::alloc` establishes the member layout.
    unsafe { PrivBlock::alloc(&mut *key) }
}

/// `ossl_ml_dsa_key_free(key)` — `ml_dsa_key.c:136-145`. Destroy a key.
///
/// # Safety
/// `key` must be live, or NULL.
pub(crate) unsafe fn ossl_ml_dsa_key_free(key: *mut MlDsaKey) {
    if key.is_null() {
        return;
    }
    // SAFETY: `key` is live per the contract.
    unsafe {
        EVP_MD_free((*key).shake128_md);
        EVP_MD_free((*key).shake256_md);
        ossl_ml_dsa_key_reset(key);
        CRYPTO_free(key.cast(), FILE, LINE_KEY_FREE);
    }
}

/// `ossl_ml_dsa_key_reset(key)` — `ml_dsa_key.c:150-175`. Factory reset.
///
/// # Safety
/// `key` must be a live `ML_DSA_KEY`.
pub(crate) unsafe fn ossl_ml_dsa_key_reset(key: *mut MlDsaKey) {
    // SAFETY: `key` is live per the contract.
    unsafe {
        // The allocation for |s1.poly| subsumes those for |s2| and |t0|, which must not be
        // accessed after |s1|'s poly is freed.
        if !(*key).s1.poly.is_null() {
            // SAFETY: the block was published by `ossl_ml_dsa_key_priv_alloc`. The handle's
            // `clear` is the single cleansing release of the `l + 2k` extent.
            let block = PrivBlock::of(&mut *key);
            block.clear(FILE, LINE_RESET_SECURE_FREE_S1);
        }
        // The |t1| vector is public and allocated separately.
        (*key).t1.free(FILE, LINE_RESET_T1_FREE);
        OPENSSL_cleanse((*key).k.as_mut_ptr().cast(), ML_DSA_K_BYTES);
        // Each handle's `Drop` runs the authority's own release at the authority's own site: the
        // plain free for the public encoding and the cleansing secure free for the private encoding
        // and the seed. A NULL field releases nothing.
        // SAFETY: `pub_encoding` is a live plain block this key owns.
        drop(OwnedBuf::adopt((*key).pub_encoding, FILE, LINE_RESET_PUB));
        (*key).pub_encoding = ptr::null_mut();
        // SAFETY: `priv_encoding` is a live secure block this key owns, readable for `sk_len` bytes.
        drop(OwnedBuf::adopt_secure_cleansed(
            (*key).priv_encoding,
            (*(*key).params).sk_len,
            FILE,
            LINE_RESET_PRV,
        ));
        (*key).priv_encoding = ptr::null_mut();
        // SAFETY: `seed` is a live secure block this key owns.
        drop(OwnedBuf::adopt_secure_cleansed(
            (*key).seed,
            ML_DSA_SEED_BYTES,
            FILE,
            LINE_RESET_SEED,
        ));
        (*key).seed = ptr::null_mut();
    }
}

/// `ossl_ml_dsa_key_dup(src, selection)` — `ml_dsa_key.c:185-249`. Duplicate a key.
///
/// # Safety
/// `src` must be live, or NULL.
pub(crate) unsafe fn ossl_ml_dsa_key_dup(src: *const MlDsaKey, selection: c_int) -> *mut MlDsaKey {
    // SAFETY: `src` is live per the contract.
    unsafe {
        if src.is_null() {
            return ptr::null_mut();
        }

        // Prekeys with just a seed or private key are not dupable.
        if (*src).pub_encoding.is_null()
            && (!(*src).priv_encoding.is_null() || !(*src).seed.is_null())
        {
            return ptr::null_mut();
        }

        let ret = CRYPTO_zalloc(core::mem::size_of::<MlDsaKey>(), FILE, LINE_DUP_ZALLOC)
            .cast::<MlDsaKey>();
        if !ret.is_null() {
            (*ret).libctx = (*src).libctx;
            (*ret).params = (*src).params;
            (*ret).prov_flags = (*src).prov_flags;

            let mut ok = 1;
            // The C's `goto err` on any allocation or copy failure.
            'err: {
                if (selection & OSSL_KEYMGMT_SELECT_KEYPAIR) == 0 {
                    break 'err;
                }
                if !(*src).pub_encoding.is_null() {
                    // The public components are present if the private key is present.
                    ptr::copy_nonoverlapping(
                        (*src).rho.as_ptr(),
                        (*ret).rho.as_mut_ptr(),
                        ML_DSA_RHO_BYTES,
                    );
                    ptr::copy_nonoverlapping(
                        (*src).tr.as_ptr(),
                        (*ret).tr.as_mut_ptr(),
                        ML_DSA_TR_BYTES,
                    );
                    if !(*src).t1.poly.is_null() {
                        if ossl_ml_dsa_key_pub_alloc(ret) == 0 {
                            ok = 0;
                            break 'err;
                        }
                        vector_copy((*ret).t1.as_mut_slice(), (*src).t1.as_slice());
                    }
                    // `CRYPTO_memdup` answers NULL or a plain `pk_len`-byte block the crate
                    // allocated; the handle adopts it so the refusal arm releases it at the
                    // authority's own site.
                    // SAFETY: `src.pub_encoding` is a live `pk_len`-byte block.
                    match OwnedBuf::adopt(
                        CRYPTO_memdup(
                            (*src).pub_encoding.cast(),
                            (*(*src).params).pk_len,
                            FILE,
                            LINE_DUP_PUB,
                        )
                        .cast::<c_uchar>(),
                        FILE,
                        LINE_DUP_PUB,
                    ) {
                        Some(buf) => (*ret).pub_encoding = buf.into_raw(),
                        None => {
                            ok = 0;
                            break 'err;
                        }
                    }
                }
                if (selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0 {
                    if !(*src).priv_encoding.is_null() {
                        ptr::copy_nonoverlapping(
                            (*src).k.as_ptr(),
                            (*ret).k.as_mut_ptr(),
                            ML_DSA_K_BYTES,
                        );
                        if !(*src).s1.poly.is_null() {
                            if ossl_ml_dsa_key_priv_alloc(ret) == 0 {
                                ok = 0;
                                break 'err;
                            }
                            vector_copy((*ret).s1.as_mut_slice(), (*src).s1.as_slice());
                            vector_copy((*ret).s2.as_mut_slice(), (*src).s2.as_slice());
                            vector_copy((*ret).t0.as_mut_slice(), (*src).t0.as_slice());
                        }
                        match OwnedBuf::new_secure_cleansed(
                            (*(*src).params).sk_len,
                            FILE_SEAM,
                            LINE_DUP_PRV,
                        ) {
                            Some(buf) => {
                                ptr::copy_nonoverlapping(
                                    (*src).priv_encoding,
                                    buf.as_ptr(),
                                    (*(*src).params).sk_len,
                                );
                                (*ret).priv_encoding = buf.into_raw();
                            }
                            None => {
                                ok = 0;
                                break 'err;
                            }
                        }
                    }
                    if !(*src).seed.is_null() {
                        match OwnedBuf::new_secure_cleansed(
                            ML_DSA_SEED_BYTES,
                            FILE_SEAM,
                            LINE_DUP_SEED,
                        ) {
                            Some(buf) => {
                                ptr::copy_nonoverlapping(
                                    (*src).seed,
                                    buf.as_ptr(),
                                    ML_DSA_SEED_BYTES,
                                );
                                (*ret).seed = buf.into_raw();
                            }
                            None => {
                                ok = 0;
                                break 'err;
                            }
                        }
                    }
                }
            }

            if ok == 0 {
                ossl_ml_dsa_key_free(ret);
                return ptr::null_mut();
            }

            EVP_MD_up_ref((*src).shake128_md);
            EVP_MD_up_ref((*src).shake256_md);
            (*ret).shake128_md = (*src).shake128_md;
            (*ret).shake256_md = (*src).shake256_md;
        }
        ret
    }
}

/// `ossl_ml_dsa_key_equal(key1, key2, selection)` — `ml_dsa_key.c:263-294`.
///
/// # Safety
/// Both keys must be live `ML_DSA_KEY`s.
pub(crate) unsafe fn ossl_ml_dsa_key_equal(
    key1: *const MlDsaKey,
    key2: *const MlDsaKey,
    selection: c_int,
) -> c_int {
    // SAFETY: both keys are live per the contract.
    unsafe {
        if (*key1).params != (*key2).params {
            return 0;
        }

        if (selection & OSSL_KEYMGMT_SELECT_KEYPAIR) != 0 {
            let mut key_checked = 0;
            if (selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0
                && !(*key1).pub_encoding.is_null()
                && !(*key2).pub_encoding.is_null()
            {
                if libc_memcmp(
                    (*key1).pub_encoding,
                    (*key2).pub_encoding,
                    (*(*key1).params).pk_len,
                ) != 0
                {
                    return 0;
                }
                key_checked = 1;
            }
            if key_checked == 0
                && (selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0
                && !(*key1).priv_encoding.is_null()
                && !(*key2).priv_encoding.is_null()
            {
                if CRYPTO_memcmp(
                    (*key1).priv_encoding.cast(),
                    (*key2).priv_encoding.cast(),
                    (*(*key1).params).sk_len,
                ) != 0
                {
                    return 0;
                }
                key_checked = 1;
            }
            return key_checked;
        }
        1
    }
}

/// `ossl_ml_dsa_key_has(key, selection)` — `ml_dsa_key.c:296-308`.
///
/// # Safety
/// `key` must be a live `ML_DSA_KEY`.
pub(crate) unsafe fn ossl_ml_dsa_key_has(key: *const MlDsaKey, selection: c_int) -> c_int {
    // SAFETY: `key` is live per the contract.
    unsafe {
        if (selection & OSSL_KEYMGMT_SELECT_KEYPAIR) != 0 {
            // Note that the public key always exists if there is a private key.
            if ossl_ml_dsa_key_get_pub(key).is_null() {
                return 0;
            }
            if (selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0
                && ossl_ml_dsa_key_get_priv(key).is_null()
            {
                return 0;
            }
            return 1;
        }
        0
    }
}

/// `public_from_private(key, md_ctx, t1, t0)` — `ml_dsa_key.c:322-367`.
///
/// Given a private key containing `rho`, `s1` & `s2`, computes `t = NTT_inv(A' * NTT(s1)) + s2`
/// and returns `t`'s compressed halves.
///
/// # Safety
/// `key` must hold allocated `s1`/`s2`; `t1`/`t0` must be initialised vectors of `k` polynomials.
unsafe fn public_from_private(
    key: *const MlDsaKey,
    md_ctx: *mut EvpMdCtx,
    t1: *mut Vector,
    t0: *mut Vector,
) -> c_int {
    // SAFETY: the arguments are live per the contract.
    unsafe {
        let mut ret = 0;
        let params = (*key).params;
        let k = (*params).k as u32;
        let l = (*params).l as u32;

        // `polys` is this frame's scratch block; the handle owns it, so its `Drop` runs the
        // authority's own plain `CRYPTO_free` at the authority's own site.
        let Some(polys) = OwnedBuf::new_array(
            (k + l + k * l) as usize,
            core::mem::size_of::<Poly>(),
            FILE_SEAM,
            LINE_PFP_ALLOC_POLYS,
        ) else {
            return 0;
        };
        let polys_ptr = polys.as_ptr().cast::<Poly>();

        let mut t = Vector::init(polys_ptr, k as usize);
        let mut s1_ntt = Vector::init(t.poly.add(k as usize), l as usize);
        let mut a_ntt = matrix_init(s1_ntt.poly.add(l as usize), k as usize, l as usize);

        // The C's `goto err`.
        'err: {
            // Using rho generate A' = A in NTT form.
            if ossl_ml_dsa_matrix_expand_A(
                md_ctx,
                (*key).shake128_md,
                (*key).rho.as_ptr(),
                &mut a_ntt,
            ) == 0
            {
                break 'err;
            }

            // t = NTT_inv(A' * NTT(s1)) + s2
            vector_copy(s1_ntt.as_mut_slice(), (*key).s1.as_slice());
            vector_ntt(s1_ntt.as_mut_slice());

            matrix_mult_vector(&a_ntt, &s1_ntt, &mut t);
            vector_ntt_inverse(t.as_mut_slice());
            // `vector_add(&t, &key->s2, &t)` accumulates in place. `ml_dsa_vector.h:99-106` is a
            // `poly_add` per polynomial and `Poly` is `Copy`, so a value copy of each left operand
            // expresses the same thing — as `ntt.rs` does for its own in-place `poly_add`.
            let n = t.num_poly;
            let s2 = Vector::init((*key).s2.poly, (*key).s2.num_poly);
            let t_slice = t.as_mut_slice();
            let s2_slice = s2.as_slice();
            for (t_poly, s2_poly) in t_slice.iter_mut().zip(s2_slice.iter()).take(n) {
                let lhs = *t_poly;
                poly_add(&lhs, s2_poly, t_poly);
            }

            // Compress t.
            vector_power2_round(&t, &mut *t1, &mut *t0);

            ret = 1;
        }

        // The low bits of |t| are private and |s1_ntt| is secret, wipe both. The trailing |a_ntt|
        // matrix is not wiped: per FIPS 204 section 3.6.3 the matrix A is easily computed from the
        // public key and does not require any special protections.
        OPENSSL_cleanse(
            polys.as_ptr().cast(),
            (k + l) as usize * core::mem::size_of::<Poly>(),
        );
        ret
    }
}

/// `ossl_ml_dsa_key_public_from_private(key)` — `ml_dsa_key.c:369-389`.
///
/// # Safety
/// `key` must be a live `ML_DSA_KEY` whose `s1`/`s2` are allocated.
pub(crate) unsafe fn ossl_ml_dsa_key_public_from_private(key: *mut MlDsaKey) -> c_int {
    // SAFETY: `key` is live per the contract.
    unsafe {
        let mut t0 = Vector::empty();
        // t0 is already in the private key.
        if t0.alloc((*(*key).params).k, FILE, LINE_PFP_T0_ALLOC) == 0 {
            return 0;
        }

        let md_ctx = EVP_MD_CTX_new();
        let mut ret = 0;
        if !md_ctx.is_null()
            && ossl_ml_dsa_key_pub_alloc(key) != 0
            && public_from_private(key, md_ctx, &mut (*key).t1, &mut t0) != 0
            && vector_equal(t0.as_slice(), (*key).t0.as_slice()) != 0
            && ossl_ml_dsa_pk_encode(key) != 0
            && shake_xof(
                md_ctx,
                (*key).shake256_md,
                (*key).pub_encoding,
                (*(*key).params).pk_len,
                (*key).tr.as_mut_ptr(),
                ML_DSA_TR_BYTES,
            ) != 0
        {
            ret = 1;
        }

        Vector::zero(t0.as_mut_slice());
        t0.free(FILE, LINE_PFP_T0_FREE);
        EVP_MD_CTX_free(md_ctx);
        ret
    }
}

/// `ossl_ml_dsa_key_pairwise_check(key)` — `ml_dsa_key.c:391-419`.
///
/// # Safety
/// `key` must be a live `ML_DSA_KEY` with a populated private half.
pub(crate) unsafe fn ossl_ml_dsa_key_pairwise_check(key: *const MlDsaKey) -> c_int {
    // SAFETY: `key` is live per the contract.
    unsafe {
        if (*key).pub_encoding.is_null() || (*key).priv_encoding.is_null() {
            return 0;
        }
        let k = (*(*key).params).k as u32;

        // `polys` is this frame's scratch block; the handle owns it, so its `Drop` runs the
        // authority's own cleansing `CRYPTO_clear_free` at the authority's own site.
        let Some(polys) = OwnedBuf::new_array_cleansed(
            (2 * k) as usize,
            core::mem::size_of::<Poly>(),
            FILE_SEAM,
            LINE_PWC_ALLOC_POLYS,
        ) else {
            return 0;
        };
        let polys_ptr = polys.as_ptr().cast::<Poly>();
        let md_ctx = EVP_MD_CTX_new();

        let mut ret = 0;
        // The C's `goto err`.
        'err: {
            if md_ctx.is_null() {
                break 'err;
            }

            let mut t1 = Vector::init(polys_ptr, k as usize);
            let mut t0 = Vector::init(polys_ptr.add(k as usize), k as usize);
            if public_from_private(key, md_ctx, &mut t1, &mut t0) == 0 {
                break 'err;
            }

            ret = (vector_equal(t1.as_slice(), (*key).t1.as_slice()) != 0
                && vector_equal(t0.as_slice(), (*key).t0.as_slice()) != 0)
                as c_int;
        }
        EVP_MD_CTX_free(md_ctx);
        ret
    }
}

/// `keygen_internal(out)` — `ml_dsa_key.c:429-474`, FIPS 204 Algorithm 6
/// `ML-DSA.KeyGen_internal()`.
///
/// Expands the `out->seed` `(rho, K)` pair into `rho[32] || rho'[64] || K[32]` and derives the full
/// key pair from it.
///
/// # Safety
/// `out` must be a live key with `seed` set.
unsafe fn keygen_internal(out: *mut MlDsaKey) -> c_int {
    // SAFETY: `out` is live per the contract.
    unsafe {
        let mut ret = 0;
        let mut augmented_seed = [0u8; ML_DSA_SEED_BYTES + 2];
        let mut expanded_seed = [0u8; ML_DSA_RHO_BYTES + ML_DSA_PRIV_SEED_BYTES + ML_DSA_K_BYTES];
        let rho = expanded_seed.as_ptr(); /* p = Public Random Seed */
        let priv_seed = expanded_seed.as_ptr().add(ML_DSA_RHO_BYTES);
        let k_seed = priv_seed.add(ML_DSA_PRIV_SEED_BYTES);
        let params = (*out).params;

        let mut md_ctx: *mut EvpMdCtx = ptr::null_mut();
        // The C's `goto err`.
        'err: {
            if (*out).seed.is_null() {
                break 'err;
            }
            md_ctx = EVP_MD_CTX_new();
            if md_ctx.is_null()
                || ossl_ml_dsa_key_pub_alloc(out) == 0
                || ossl_ml_dsa_key_priv_alloc(out) == 0
            {
                break 'err;
            }

            // augmented_seed = seed || k || l
            ptr::copy_nonoverlapping((*out).seed, augmented_seed.as_mut_ptr(), ML_DSA_SEED_BYTES);
            augmented_seed[ML_DSA_SEED_BYTES] = (*params).k as u8;
            augmented_seed[ML_DSA_SEED_BYTES + 1] = (*params).l as u8;
            // Expand the seed into p[32], p'[64], K[32].
            if shake_xof(
                md_ctx,
                (*out).shake256_md,
                augmented_seed.as_ptr(),
                ML_DSA_SEED_BYTES + 2,
                expanded_seed.as_mut_ptr(),
                ML_DSA_RHO_BYTES + ML_DSA_PRIV_SEED_BYTES + ML_DSA_K_BYTES,
            ) == 0
            {
                break 'err;
            }

            ptr::copy_nonoverlapping(rho, (*out).rho.as_mut_ptr(), ML_DSA_RHO_BYTES);
            ptr::copy_nonoverlapping(k_seed, (*out).k.as_mut_ptr(), ML_DSA_K_BYTES);

            ret = (ossl_ml_dsa_vector_expand_S(
                md_ctx,
                (*out).shake256_md,
                (*params).eta,
                priv_seed,
                &mut (*out).s1,
                &mut (*out).s2,
            ) != 0
                && public_from_private(out, md_ctx, &mut (*out).t1, &mut (*out).t0) != 0
                && ossl_ml_dsa_pk_encode(out) != 0
                && shake_xof(
                    md_ctx,
                    (*out).shake256_md,
                    (*out).pub_encoding,
                    (*(*out).params).pk_len,
                    (*out).tr.as_mut_ptr(),
                    ML_DSA_TR_BYTES,
                ) != 0
                && ossl_ml_dsa_sk_encode(out) != 0) as c_int;
        }

        if !(*out).seed.is_null() && ((*out).prov_flags & ML_DSA_KEY_RETAIN_SEED) == 0 {
            // The seed was allocated by `new_secure` (`OPENSSL_secure_malloc`), so its matching
            // release is the secure-heap cleansing free. The authority calls
            // `OPENSSL_clear_free` here, which routes to the plain `free`; that is an invalid free
            // once the secure heap is initialised (AGENTS.md section 17: do not reproduce UB).
            // With no secure heap the block is a plain fallback and
            // `CRYPTO_secure_clear_free` cleanses and releases it through the same seam and
            // coordinates, so allocator-hook observability is unchanged on that path.
            // SAFETY: `seed` is a live secure block this key owns, readable for
            // `ML_DSA_SEED_BYTES`; the handle's `Drop` runs `CRYPTO_secure_clear_free`.
            drop(OwnedBuf::adopt_secure_cleansed(
                (*out).seed,
                ML_DSA_SEED_BYTES,
                FILE,
                LINE_KEYGEN_CLEAR_SEED,
            ));
            (*out).seed = ptr::null_mut();
        }
        EVP_MD_CTX_free(md_ctx);
        OPENSSL_cleanse(augmented_seed.as_mut_ptr().cast(), ML_DSA_SEED_BYTES + 2);
        OPENSSL_cleanse(
            expanded_seed.as_mut_ptr().cast(),
            ML_DSA_RHO_BYTES + ML_DSA_PRIV_SEED_BYTES + ML_DSA_K_BYTES,
        );
        ret
    }
}

/// `ossl_ml_dsa_generate_key(out)` — `ml_dsa_key.c:476-508`.
///
/// Draws the `(rho, K)` seed if the key has none, then runs [`keygen_internal`]. When a private
/// prekey is present, the generated key must match it.
///
/// # Safety
/// `out` must be a live `ML_DSA_KEY`.
pub(crate) unsafe fn ossl_ml_dsa_generate_key(out: *mut MlDsaKey) -> c_int {
    // SAFETY: `out` is live per the contract.
    unsafe {
        let seed_len = ML_DSA_SEED_BYTES;

        if (*out).seed.is_null() {
            // The handle owns the seed until it is handed to `out->seed`; a refused RNG drops it
            // through the authority's own `CRYPTO_secure_free` at the authority's own site.
            let Some(seed) = OwnedBuf::new_secure(seed_len, FILE_SEAM, LINE_GENKEY_SEED) else {
                return 0;
            };
            if RAND_priv_bytes_ex((*out).libctx, seed.as_ptr(), seed_len, 0) <= 0 {
                return 0;
            }
            (*out).seed = seed.into_raw();
        }

        // `sk` is the private prekey being dropped; the handle adopts it so the authority's
        // cleansing `CRYPTO_secure_clear_free` is its single release at the `err:` site below.
        // SAFETY: `out->priv_encoding` is a live secure block this key owns, readable for
        // `sk_len` bytes.
        let sk = OwnedBuf::adopt_secure_cleansed(
            (*out).priv_encoding,
            (*(*out).params).sk_len,
            FILE,
            LINE_GENKEY_CLEAR_SK,
        );
        (*out).priv_encoding = ptr::null_mut();
        let Some(sk) = sk else {
            return keygen_internal(out);
        };
        let mut ret = keygen_internal(out);
        if ret != 0 && libc_memcmp((*out).priv_encoding, sk.as_ptr(), (*(*out).params).sk_len) != 0
        {
            ret = 0;
            ossl_ml_dsa_key_reset(out);
            raise_with_alg(
                &err_sites::ML_DSA_KEY_501,
                "explicit ",
                (*(*out).params).alg,
                " private key does not match seed",
            );
        }
        // `sk` releases here, through the authority's own cleansing secure free.
        ret
    }
}

/// `ossl_ml_dsa_key_matches(key, evp_type)` — `ml_dsa_key.c:520-523`.
///
/// # Safety
/// `key` must be a live `ML_DSA_KEY`.
pub(crate) unsafe fn ossl_ml_dsa_key_matches(key: *const MlDsaKey, evp_type: c_int) -> c_int {
    // SAFETY: `key` is live per the contract.
    unsafe { ((*(*key).params).evp_type == evp_type) as c_int }
}

/// `ossl_ml_dsa_key_get_pub(key)` — `ml_dsa_key.c:526-529`. NULL if there is no public key.
///
/// # Safety
/// `key` must be a live `ML_DSA_KEY`.
pub(crate) unsafe fn ossl_ml_dsa_key_get_pub(key: *const MlDsaKey) -> *const u8 {
    // SAFETY: `key` is live per the contract.
    unsafe { (*key).pub_encoding as *const u8 }
}

/// `ossl_ml_dsa_key_get_pub_len(key)` — `ml_dsa_key.c:532-535`.
///
/// # Safety
/// `key` must be a live `ML_DSA_KEY`.
pub(crate) unsafe fn ossl_ml_dsa_key_get_pub_len(key: *const MlDsaKey) -> usize {
    // SAFETY: `key` is live per the contract.
    unsafe { (*(*key).params).pk_len }
}

/// `ossl_ml_dsa_key_get_collision_strength_bits(key)` — `ml_dsa_key.c:537-540`.
///
/// # Safety
/// `key` must be a live `ML_DSA_KEY`.
pub(crate) unsafe fn ossl_ml_dsa_key_get_collision_strength_bits(key: *const MlDsaKey) -> usize {
    // SAFETY: `key` is live per the contract.
    unsafe { (*(*key).params).bit_strength as usize }
}

/// `ossl_ml_dsa_key_get_security_category(key)` — `ml_dsa_key.c:542-545`.
///
/// # Safety
/// `key` must be a live `ML_DSA_KEY`.
pub(crate) unsafe fn ossl_ml_dsa_key_get_security_category(key: *const MlDsaKey) -> c_int {
    // SAFETY: `key` is live per the contract.
    unsafe { (*(*key).params).security_category }
}

/// `ossl_ml_dsa_key_get_priv(key)` — `ml_dsa_key.c:548-551`. NULL if there is no private key.
///
/// # Safety
/// `key` must be a live `ML_DSA_KEY`.
pub(crate) unsafe fn ossl_ml_dsa_key_get_priv(key: *const MlDsaKey) -> *const u8 {
    // SAFETY: `key` is live per the contract.
    unsafe { (*key).priv_encoding as *const u8 }
}

/// `ossl_ml_dsa_key_get_priv_len(key)` — `ml_dsa_key.c:553-556`.
///
/// # Safety
/// `key` must be a live `ML_DSA_KEY`.
pub(crate) unsafe fn ossl_ml_dsa_key_get_priv_len(key: *const MlDsaKey) -> usize {
    // SAFETY: `key` is live per the contract.
    unsafe { (*(*key).params).sk_len }
}

/// `ossl_ml_dsa_key_get_sig_len(key)` — `ml_dsa_key.c:558-561`.
///
/// # Safety
/// `key` must be a live `ML_DSA_KEY`.
pub(crate) unsafe fn ossl_ml_dsa_key_get_sig_len(key: *const MlDsaKey) -> usize {
    // SAFETY: `key` is live per the contract.
    unsafe { (*(*key).params).sig_len }
}

/// `ossl_ml_dsa_key_get0_libctx(key)` — `ml_dsa_key.c:563-566`.
///
/// # Safety
/// `key` must be live, or NULL.
pub(crate) unsafe fn ossl_ml_dsa_key_get0_libctx(key: *const MlDsaKey) -> *mut c_void {
    // SAFETY: `key` is live, or NULL which is checked, per the contract.
    unsafe {
        if key.is_null() {
            ptr::null_mut()
        } else {
            (*key).libctx
        }
    }
}

/// `ossl_ml_dsa_key_get_name(key)` — `ml_dsa_key.c:568-571`.
///
/// # Safety
/// `key` must be a live `ML_DSA_KEY`.
pub(crate) unsafe fn ossl_ml_dsa_key_get_name(key: *const MlDsaKey) -> *const c_char {
    // SAFETY: `key` is live per the contract.
    unsafe { (*(*key).params).alg }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::unwrap_used)]

    use super::*;

    #[test]
    fn the_private_block_derives_the_three_components() {
        let _g = crate::test_support::lock_global_state();
        // SAFETY: the key is created, generated and freed here; the block is borrowed only while
        // the key is live.
        unsafe {
            let key = ossl_ml_dsa_key_new(
                core::ptr::null_mut(),
                core::ptr::null(),
                super::super::EVP_PKEY_ML_DSA_65,
            );
            assert!(!key.is_null());
            assert_eq!(ossl_ml_dsa_generate_key(key), 1);
            let params = (*key).params;
            let (k, l) = ((*params).k, (*params).l);

            let mut block = PrivBlock::of(&mut *key);
            assert_eq!(block.s1().len(), l);
            assert_eq!(block.s2().len(), k);
            assert_eq!(block.t0().len(), k);
            // The tails are the exact offsets `alloc` published.
            assert_eq!(block.s2().as_ptr(), block.s1().as_ptr().add(l));
            assert_eq!(block.t0().as_ptr(), block.s1().as_ptr().add(l + k));

            // The mutable view is the same storage.
            block.s1_mut()[0].coeff[0] = 0xDEAD_BEEF;
            assert_eq!(block.s1()[0].coeff[0], 0xDEAD_BEEF);
            let _ = block;

            // A refused re-allocation leaves the published block untouched.
            assert_eq!(ossl_ml_dsa_key_priv_alloc(key), 0);
            ossl_ml_dsa_key_free(key);
        }
    }
}
