//! `providers/implementations/rands/` -- the DRBG framework and its three instantiations.
//!
//! Three translation units in one module, because they are one mechanism: `drbg.c` is the
//! `PROV_DRBG` state machine and the provider side, and `drbg_ctr.c`, `drbg_hash.c` and
//! `drbg_hmac.c` are its three instantiations, each a table of four virtual functions
//! (`instantiate`/`uninstantiate`/`reseed`/`generate`) plus its own context.
//!
//! # What this module is for
//!
//! `RAND_get0_primary` resolves the default DRBG through `EVP_RAND_fetch(NULL, "CTR-DRBG", NULL)`,
//! so the front above this module cannot answer a byte until the provider publishes a RAND row.
//! This is that row's implementation, and the reason Phase 8's object layers are blocked on Phase 9
//! (`docs/DECISIONS.md` D286).
//!
//! # The `.c.in` arms and the generated decoders
//!
//! The three instantiations are generated from `drbg_*.c.in`. On this profile the generated files
//! exist only as build products, and the authority's `produce_param_decoder` output is generated C
//! rather than source: it is modelled the way `src/provider/mac.rs` models the same shape -- a
//! `repeated_param_site` raise plus one locate per field -- and the fact that only the *coordinates*
//! are unrecoverable is recorded at each decoder rather than the decoder being omitted.
//!
//! # FIPS arms
//!
//! `FIPS_MODULE` is undefined on this profile, so the `ossl_FIPS_*` arms are named in comments and
//! not written. `OSS_FIPS_IND_*` are no-ops and `1` respectively, as the authority's
//! `fips_indicators.h` resolves them.
//!
//! SPDX-License-Identifier: Apache-2.0

#![allow(dead_code)]
// the landing caller is the `OSSL_OP_RAND` arm of `deflt_query` (9.4)

// The authority's own spellings survive transcription (`ctr_XOR`, `ctr_BCC_*`, `V_tmp`), because a
// name the tooling cannot join to a C identifier is indistinguishable from a name that is absent.
#![allow(non_snake_case)]

use core::ffi::{c_char, c_int, c_uchar, c_uint, c_ushort, c_void};
use core::ptr;
use core::sync::atomic::{AtomicU32, Ordering};

use crate::aes::AES_BLOCK_SIZE;
use crate::context::dispatch::{OsslDispatch, OSSL_DISPATCH_END};
use crate::evp::cipher::{
    EVP_CIPHER_fetch, EVP_CIPHER_free, EVP_CIPHER_get0_name, EVP_CIPHER_get_key_length, EvpCipher,
};
use crate::evp::cipher_ctx::{
    EVP_CIPHER_CTX_free, EVP_CIPHER_CTX_new, EVP_CipherInit_ex, EVP_CipherUpdate, EvpCipherCtx,
};
use crate::evp::digest::{
    EVP_DigestFinal, EVP_DigestInit_ex, EVP_DigestUpdate, EVP_MD_CTX_free, EVP_MD_CTX_new,
    EVP_MD_fetch, EVP_MD_free, EVP_MD_get0_name, EVP_MD_get_size, EVP_MD_xof, EvpMd, EvpMdCtx,
};
use crate::evp::mac::{
    EVP_MAC_CTX_free, EVP_MAC_CTX_get0_mac, EVP_MAC_CTX_new, EVP_MAC_fetch, EVP_MAC_final,
    EVP_MAC_free, EVP_MAC_get0_name, EVP_MAC_init, EVP_MAC_update, EvpMacCtx,
};
/// The RAND dispatch ids and the nineteen function-pointer types are `src/evp/rand.rs`'s.
/// **They are currently private `const`s there**, so integration must raise them to
/// `pub(crate)`; the duplicate-free reference below is the form that wants.
use crate::evp::rand::{
    RandClearSeedFn, RandEnableLockingFn, RandGetCtxParamsFn, RandGetSeedFn, RandLockFn,
    RandNonceFn, RandUnlockFn, OSSL_FUNC_RAND_CLEAR_SEED, OSSL_FUNC_RAND_ENABLE_LOCKING,
    OSSL_FUNC_RAND_FREECTX, OSSL_FUNC_RAND_GENERATE, OSSL_FUNC_RAND_GETTABLE_CTX_PARAMS,
    OSSL_FUNC_RAND_GET_CTX_PARAMS, OSSL_FUNC_RAND_GET_SEED, OSSL_FUNC_RAND_INSTANTIATE,
    OSSL_FUNC_RAND_LOCK, OSSL_FUNC_RAND_NEWCTX, OSSL_FUNC_RAND_NONCE, OSSL_FUNC_RAND_RESEED,
    OSSL_FUNC_RAND_SETTABLE_CTX_PARAMS, OSSL_FUNC_RAND_SET_CTX_PARAMS,
    OSSL_FUNC_RAND_UNINSTANTIATE, OSSL_FUNC_RAND_UNLOCK, OSSL_FUNC_RAND_VERIFY_ZEROIZATION,
};
use crate::params::{
    OSSL_PARAM_get_int, OSSL_PARAM_get_time_t, OSSL_PARAM_get_uint, OSSL_PARAM_locate_const,
    OSSL_PARAM_set_int, OSSL_PARAM_set_size_t, OSSL_PARAM_set_time_t, OSSL_PARAM_set_uint,
    OSSL_PARAM_set_utf8_string, OsslParam, END,
};
use crate::provider::activate::OsslAlgorithm;
use crate::provider::cipher::{
    param_int,
    param_size_t,
    // MISSING (needed for the generated lists below): these two constructors are the only
    // authority list entries that `param_int`/`param_size_t` cannot spell faithfully.
    param_time_t,
    param_uint,
    param_uint64,
    param_utf8_string,
    repeated_param_site,
};
use crate::provider::ctx::{prov_libctx_of, ProvCtx};
use crate::provider::util::prov_digest::{
    ossl_prov_digest_load, ossl_prov_digest_md, ossl_prov_digest_reset, ossl_prov_digest_set_md,
    ProvDigest,
};
use crate::provider::util::{
    OSSL_ALG_PARAM_CIPHER, OSSL_ALG_PARAM_DIGEST, OSSL_ALG_PARAM_ENGINE, OSSL_ALG_PARAM_PROPERTIES,
};
use crate::runtime::err::{err_sites, raise_site};
use crate::runtime::mem::{cleanse, CRYPTO_free, CRYPTO_malloc, CRYPTO_strndup, CRYPTO_zalloc};
use crate::runtime::secure::{
    CRYPTO_secure_clear_free, CRYPTO_secure_malloc, CRYPTO_secure_zalloc,
};
use crate::runtime::str::OPENSSL_strcasecmp;
use crate::runtime::thread::{
    CRYPTO_THREAD_lock_free, CRYPTO_THREAD_lock_new, CRYPTO_THREAD_read_lock, CRYPTO_THREAD_unlock,
    CRYPTO_THREAD_write_lock, CRYPTO_atomic_add, CryptoRwlock,
};
use crate::runtime::time::TimeT;

// D310: the two non-DRBG `OSSL_OP_RAND` rows the default provider publishes. They are imported
// rather than pathed inline because the provider census's reader joins a row's alias sequence to
// its dispatch expression on **one line**, and a fully-qualified path makes rustfmt break the
// chain across three lines -- the reader then cannot see rows it must not skip.
use crate::provider::seed_src::{SEED_SRC_FUNCTIONS, TEST_RNG_FUNCTIONS};

// D307: the three helpers this module reaches that landed in D304/D305, plus the platform clock.
use crate::context::lib_ctx_get_data as ossl_lib_ctx_get_data;
use crate::context::OSSL_LIB_CTX_DRBG_NONCE_INDEX;
use crate::provider::seeding::{
    ossl_prov_cleanup_entropy, ossl_prov_cleanup_nonce, ossl_prov_get_entropy, ossl_prov_get_nonce,
};
use crate::provider::util::ossl_prov_macctx_load;
use crate::runtime::bio::sys::time;
use crate::runtime::thread::openssl_get_fork_id;

// =============================================================================================
// Translation-unit coordinates
//
// `drbg.c` is a hand-written source and keeps the out-of-source prefix the crate's cipher rows
// use; the three algorithm units are generated from `.c.in` and, per `src/provider/mac.rs`'s
// `FILE` note, the compiler spells a generated TU with its build-relative path only. The two
// `OPENSSL_secure_*` contexts are the ones the authority passes to `CRYPTO_set_mem_functions`.
// =============================================================================================

/// `providers/implementations/rands/drbg.c`.
const FILE_DRBG: *const c_char =
    c"../../src/openssl-3.6.4/providers/implementations/rands/drbg.c".as_ptr();
/// `providers/implementations/rands/drbg_ctr.c` (generated from `drbg_ctr.c.in`).
const FILE_DRBG_CTR: *const c_char = c"providers/implementations/rands/drbg_ctr.c".as_ptr();
/// `providers/implementations/rands/drbg_hash.c` (generated from `drbg_hash.c.in`).
const FILE_DRBG_HASH: *const c_char = c"providers/implementations/rands/drbg_hash.c".as_ptr();
/// `providers/implementations/rands/drbg_hmac.c` (generated from `drbg_hmac.c.in`).
const FILE_DRBG_HMAC: *const c_char = c"providers/implementations/rands/drbg_hmac.c".as_ptr();
/// `__LINE__`, inert under `OPENSSL_NO_CRYPTO_MDEBUG`.
const LINE: c_int = 0;

// `OSSL_LIB_CTX_DRBG_NONCE_INDEX` — `include/internal/cryptlib.h:102`, slot **6**. **D309 moved it
// to its home**, `src/context/mod.rs`, which is also where it is filled: `context_init` calls
// `ossl_prov_drbg_nonce_ctx_new` for every context, exactly as `crypto/context.c:172` does. It is
// imported at the top of this module; the slot's absence is what `prov_drbg_get_nonce` reports as
// `PROV_R_ERROR_RETRIEVING_NONCE`.

// =============================================================================================
// Constants — `providers/implementations/include/prov/drbg.h` and `include/crypto/rand.h`
// =============================================================================================

/// `DRBG_DEFAULT_PERS_STRING` — `prov/drbg.h:45`. ASCII "OpenSSL NIST SP 800-90A DRBG" written
/// in hex for EBCDIC compatibility; 29 bytes including the implicit trailing NUL that
/// `sizeof(ossl_pers_string)` counts.
const DRBG_DEFAULT_PERS_STRING: &[u8] = b"\x4f\x70\x65\x6e\x53\x53\x4c\x20\x4e\x49\x53\x54\x20\x53\x50\x20\x38\x30\x30\x2d\x39\x30\x41\x20\x44\x52\x42\x47";

/// `DRBG_MAX_LENGTH` — `INT32_MAX`, the maximum input size in bytes.
const DRBG_MAX_LENGTH: usize = i32::MAX as usize;
/// `RESEED_INTERVAL` — `(1 << 8)`.
const RESEED_INTERVAL: c_uint = 1 << 8;
/// `TIME_INTERVAL` — `(60 * 60)`.
const TIME_INTERVAL: TimeT = 60 * 60;
/// `MAX_RESEED_INTERVAL` — `(1 << 24)`; declared by the authority, unused by these units.
const MAX_RESEED_INTERVAL: c_uint = 1 << 24;
/// `MAX_RESEED_TIME_INTERVAL` — `(1 << 20)`; declared by the authority, unused by these units.
const MAX_RESEED_TIME_INTERVAL: TimeT = 1 << 20;

/// `EVP_MAX_MD_SIZE` — `include/openssl/evp.h:34`; `PROV_DRBG_HMAC`'s `K`/`V` arrays.
const EVP_MAX_MD_SIZE: usize = 64;

/// `EVP_RAND_STATE_UNINITIALISED` — `include/openssl/evp.h:1345`. `EVP_RAND_STATE_ERROR` is
/// `src/evp/rand.rs`'s; the other two are declared here because that module does not.
const EVP_RAND_STATE_UNINITIALISED: c_int = 0;
/// `EVP_RAND_STATE_READY` — `include/openssl/evp.h:1346`.
const EVP_RAND_STATE_READY: c_int = 1;

/// `int ossl_prov_is_running(void)` — the default provider is always in a happy state on this
/// build, as `src/provider/mac.rs`, `cipher.rs` and `digest.rs` already spell it.
#[inline]
fn is_running() -> c_int {
    1
}

/// The authority's `ERR_raise(...); return 0;` pair, in one place.
#[inline]
fn fail_at(site: &err_sites::ErrSite) -> c_int {
    // SAFETY: `site` is a generated compile-time constant whose three string pointers are
    // `'static`; no caller state is touched.
    unsafe { raise_site(site) };
    0
}

// =============================================================================================
// `struct prov_drbg_st` — `prov/drbg.h:59-165`
// =============================================================================================

/// `int (*instantiate)(PROV_DRBG *, const unsigned char *, size_t, const unsigned char *,
/// size_t, const unsigned char *, size_t)` — one of the four cached virtual functions.
pub(crate) type ProvDrbgInstantiateFn = unsafe extern "C" fn(
    *mut ProvDrbg,
    *const c_uchar,
    usize,
    *const c_uchar,
    usize,
    *const c_uchar,
    usize,
) -> c_int;
/// `int (*uninstantiate)(PROV_DRBG *)`.
pub(crate) type ProvDrbgUninstantiateFn = unsafe extern "C" fn(*mut ProvDrbg) -> c_int;
/// `int (*reseed)(PROV_DRBG *, const unsigned char *, size_t, const unsigned char *, size_t)`.
pub(crate) type ProvDrbgReseedFn =
    unsafe extern "C" fn(*mut ProvDrbg, *const c_uchar, usize, *const c_uchar, usize) -> c_int;
/// `int (*generate)(PROV_DRBG *, unsigned char *, size_t, const unsigned char *, size_t)`.
pub(crate) type ProvDrbgGenerateFn =
    unsafe extern "C" fn(*mut ProvDrbg, *mut c_uchar, usize, *const c_uchar, usize) -> c_int;
/// `int (*dnew)(PROV_DRBG *ctx)`.
pub(crate) type ProvDrbgNewFn = unsafe extern "C" fn(*mut ProvDrbg) -> c_int;
/// `void (*dfree)(void *vctx)`.
pub(crate) type ProvDrbgFreeFn = unsafe extern "C" fn(*mut c_void);

/// `struct prov_drbg_st` — `prov/drbg.h:59-165`. `OSSL_FIPS_IND_DECLARE` contributes no field
/// when `FIPS_MODULE` is undefined, so the struct ends at the callback block.
#[repr(C)]
pub(crate) struct ProvDrbg {
    /// `CRYPTO_RWLOCK *lock` — NULL until `ossl_drbg_enable_locking` (or the TSAN build) makes
    /// one; every lock site tests it for NULL first.
    pub lock: *mut CryptoRwlock,
    /// `PROV_CTX *provctx`.
    pub provctx: *mut ProvCtx,
    /// `instantiate`.
    pub instantiate: ProvDrbgInstantiateFn,
    /// `uninstantiate`.
    pub uninstantiate: ProvDrbgUninstantiateFn,
    /// `reseed`.
    pub reseed: ProvDrbgReseedFn,
    /// `generate`.
    pub generate: ProvDrbgGenerateFn,
    /// `void *parent` — the parent `PROV_RAND`, opaque here.
    pub parent: *mut c_void,
    /// `parent_enable_locking`.
    pub parent_enable_locking: Option<RandEnableLockingFn>,
    /// `parent_lock`.
    pub parent_lock: Option<RandLockFn>,
    /// `parent_unlock`.
    pub parent_unlock: Option<RandUnlockFn>,
    /// `parent_get_ctx_params`.
    pub parent_get_ctx_params: Option<RandGetCtxParamsFn>,
    /// `parent_nonce`.
    pub parent_nonce: Option<RandNonceFn>,
    /// `parent_get_seed`.
    pub parent_get_seed: Option<RandGetSeedFn>,
    /// `parent_clear_seed`.
    pub parent_clear_seed: Option<RandClearSeedFn>,
    /// `int fork_id` — `openssl_get_fork_id()` as of the last (re)seed.
    pub fork_id: c_int,
    /// `unsigned short flags`.
    pub flags: c_ushort,
    /// `unsigned int strength`.
    pub strength: c_uint,
    /// `size_t max_request`.
    pub max_request: usize,
    /// `size_t min_entropylen`.
    pub min_entropylen: usize,
    /// `size_t max_entropylen`.
    pub max_entropylen: usize,
    /// `size_t min_noncelen`.
    pub min_noncelen: usize,
    /// `size_t max_noncelen`.
    pub max_noncelen: usize,
    /// `size_t max_perslen`.
    pub max_perslen: usize,
    /// `size_t max_adinlen`.
    pub max_adinlen: usize,
    /// `unsigned int generate_counter` — starts at 1 and counts generates since the last reseed.
    pub generate_counter: c_uint,
    /// `unsigned int reseed_interval` — ignored when zero.
    pub reseed_interval: c_uint,
    /// `time_t reseed_time`.
    pub reseed_time: TimeT,
    /// `time_t reseed_time_interval` — ignored when zero.
    pub reseed_time_interval: TimeT,
    /// `TSAN_QUALIFIER unsigned int reseed_counter` — a relaxed atomic in the authority
    /// (`internal/tsan_assist.h` under `__STDC_VERSION__ >= 201112L`), modelled with the same
    /// ordering. Ignored when zero.
    pub reseed_counter: AtomicU32,
    /// `unsigned int reseed_next_counter`.
    pub reseed_next_counter: c_uint,
    /// `unsigned int parent_reseed_counter`.
    pub parent_reseed_counter: c_uint,
    /// `size_t seedlen`.
    pub seedlen: usize,
    /// `DRBG_STATUS state`.
    pub state: c_int,
    /// `void *data` — the per-type `PROV_DRBG_{CTR,HASH,HMAC}`.
    pub data: *mut c_void,
    /// `void *callback_arg`.
    pub callback_arg: *mut c_void,
    /// `OSSL_INOUT_CALLBACK *get_entropy_fn` — the legacy callback block; unused by the shipped
    /// rows (the authority keeps it "purely for legacy reasons").
    pub get_entropy_fn: *mut c_void,
    /// `OSSL_CALLBACK *cleanup_entropy_fn`.
    pub cleanup_entropy_fn: *mut c_void,
    /// `OSSL_INOUT_CALLBACK *get_nonce_fn`.
    pub get_nonce_fn: *mut c_void,
    /// `OSSL_CALLBACK *cleanup_nonce_fn`.
    pub cleanup_nonce_fn: *mut c_void,
}

/// `PROV_DRBG_NONCE_GLOBAL` — `drbg.c:259-262`, the nonce counter's own global, kept out of the
/// `OSSL_LIB_CTX` to avoid the recursion `ossl_prov_drbg_nonce_ctx_new`'s comment describes.
pub(crate) struct ProvDrbgNonceGlobal {
    /// `CRYPTO_RWLOCK *rand_nonce_lock`.
    pub rand_nonce_lock: *mut CryptoRwlock,
    /// `int rand_nonce_count`.
    pub rand_nonce_count: c_int,
}

// =============================================================================================
// `drbg.c` — locking helpers
// =============================================================================================

/// `int ossl_drbg_lock(void *vctx)` — `drbg.c:53-56`. A hint only, ignored.
///
/// # Safety
/// The dispatch contract.
pub(crate) unsafe extern "C" fn ossl_drbg_lock(_vctx: *mut c_void) -> c_int {
    1
}

/// `void ossl_drbg_unlock(void *vctx)` — `drbg.c:59-61`. A hint only, ignored.
///
/// # Safety
/// The dispatch contract.
pub(crate) unsafe extern "C" fn ossl_drbg_unlock(_vctx: *mut c_void) {}

/// `static int ossl_drbg_lock_parent(PROV_DRBG *drbg)` — `drbg.c:63-74`.
///
/// # Safety
/// `drbg` must be a live `ProvDrbg`.
unsafe fn ossl_drbg_lock_parent(drbg: *mut ProvDrbg) -> c_int {
    // SAFETY: `drbg` is live per the contract.
    unsafe {
        let parent = (*drbg).parent;
        if !parent.is_null() {
            if let Some(lock) = (*drbg).parent_lock {
                if lock(parent) == 0 {
                    raise_site(&err_sites::PROV_DRBG_70);
                    return 0;
                }
            }
        }
        1
    }
}

/// `static void ossl_drbg_unlock_parent(PROV_DRBG *drbg)` — `drbg.c:76-82`.
///
/// # Safety
/// `drbg` must be a live `ProvDrbg`.
unsafe fn ossl_drbg_unlock_parent(drbg: *mut ProvDrbg) {
    // SAFETY: `drbg` is live per the contract.
    unsafe {
        let parent = (*drbg).parent;
        if !parent.is_null() {
            if let Some(unlock) = (*drbg).parent_unlock {
                unlock(parent);
            }
        }
    }
}

/// `static int get_parent_strength(PROV_DRBG *drbg, unsigned int *str)` — `drbg.c:84-107`.
///
/// # Safety
/// `drbg` is live and `str` is writable for one `c_uint`.
unsafe fn get_parent_strength(drbg: *mut ProvDrbg, str_: *mut c_uint) -> c_int {
    // SAFETY: `drbg` and `str_` are per the contract.
    unsafe {
        let parent = (*drbg).parent;
        let Some(get_ctx_params) = (*drbg).parent_get_ctx_params else {
            raise_site(&err_sites::PROV_DRBG_91);
            return 0;
        };
        let mut params: [OsslParam; 2] = [END, END];
        // SAFETY: `str_` is the caller's one-word output.
        params[0] = crate::params::OSSL_PARAM_construct_uint(OSSL_RAND_PARAM_STRENGTH, str_);
        params[1] = END;
        if ossl_drbg_lock_parent(drbg) == 0 {
            raise_site(&err_sites::PROV_DRBG_97);
            return 0;
        }
        let res = get_ctx_params(parent, params.as_mut_ptr());
        ossl_drbg_unlock_parent(drbg);
        if res == 0 {
            raise_site(&err_sites::PROV_DRBG_103);
            return 0;
        }
        1
    }
}

/// `static unsigned int get_parent_reseed_count(PROV_DRBG *drbg)` — `drbg.c:109-130`.
///
/// # Safety
/// `drbg` must be a live `ProvDrbg`.
unsafe fn get_parent_reseed_count(drbg: *mut ProvDrbg) -> c_uint {
    // SAFETY: `drbg` is live per the contract.
    unsafe {
        let parent = (*drbg).parent;
        let mut r: c_uint = 0;
        let mut params: [OsslParam; 2] = [END, END];
        params[0] =
            crate::params::OSSL_PARAM_construct_uint(OSSL_DRBG_PARAM_RESEED_COUNTER, &mut r);
        params[1] = END;
        if ossl_drbg_lock_parent(drbg) == 0 {
            raise_site(&err_sites::PROV_DRBG_117);
            // `r = tsan_load(&drbg->reseed_counter) - 2; if (r == 0) r = UINT_MAX;`
            let mut v = (*drbg)
                .reseed_counter
                .load(Ordering::Relaxed)
                .wrapping_sub(2);
            if v == 0 {
                v = c_uint::MAX;
            }
            return v;
        }
        if let Some(get_ctx_params) = (*drbg).parent_get_ctx_params {
            if get_ctx_params(parent, params.as_mut_ptr()) == 0 {
                r = 0;
            }
        }
        ossl_drbg_unlock_parent(drbg);
        r
    }
}

// =============================================================================================
// `drbg.c` — seeding callbacks and the entropy/nonce plumbing
// =============================================================================================

/// `size_t ossl_drbg_get_seed(void *vdrbg, unsigned char **pout, int entropy, size_t min_len,
/// size_t max_len, int prediction_resistance, const unsigned char *adin, size_t adin_len)`
/// — `drbg.c:144-183`. The `sizeof(drbg)` in the authority is the size of the *pointer*; here
/// that is `size_of::<*mut ProvDrbg>()` and it is intentional.
///
/// # Safety
/// The `OSSL_FUNC_rand_get_seed_fn` contract.
pub(crate) unsafe extern "C" fn ossl_drbg_get_seed(
    vdrbg: *mut c_void,
    pout: *mut *mut c_uchar,
    entropy: c_int,
    min_len: usize,
    max_len: usize,
    prediction_resistance: c_int,
    adin: *const c_uchar,
    adin_len: usize,
) -> usize {
    // SAFETY: `vdrbg` is the `ProvDrbg` the dispatch contract names.
    unsafe {
        let _ = (adin, adin_len); // `ossl_unused` upstream: the address is the only adin used
        let drbg = vdrbg.cast::<ProvDrbg>();
        let mut bytes_needed = if entropy >= 0 {
            (entropy as usize).wrapping_add(7) / 8
        } else {
            0
        };
        if bytes_needed < min_len {
            bytes_needed = min_len;
        }
        if bytes_needed > max_len {
            bytes_needed = max_len;
        }
        let buffer = CRYPTO_secure_malloc(bytes_needed, FILE_DRBG, LINE).cast::<c_uchar>();
        if buffer.is_null() {
            return 0;
        }
        let strength = (*drbg).strength;
        let mut identity = drbg;
        if ossl_prov_drbg_generate(
            drbg,
            buffer,
            bytes_needed,
            strength,
            prediction_resistance,
            ptr::addr_of_mut!(identity).cast::<c_uchar>(),
            core::mem::size_of::<*mut ProvDrbg>(),
        ) == 0
        {
            CRYPTO_secure_clear_free(buffer.cast(), bytes_needed, FILE_DRBG, LINE);
            raise_site(&err_sites::PROV_DRBG_178);
            return 0;
        }
        *pout = buffer;
        bytes_needed
    }
}

/// `void ossl_drbg_clear_seed(ossl_unused void *vdrbg, unsigned char *out, size_t outlen)`
/// — `drbg.c:186-190`.
///
/// # Safety
/// The `OSSL_FUNC_rand_clear_seed_fn` contract.
pub(crate) unsafe extern "C" fn ossl_drbg_clear_seed(
    _vdrbg: *mut c_void,
    out: *mut c_uchar,
    outlen: usize,
) {
    // SAFETY: `out`/`outlen` are the caller's release request.
    unsafe { CRYPTO_secure_clear_free(out.cast(), outlen, FILE_DRBG, LINE) };
}

/// `static size_t get_entropy(PROV_DRBG *drbg, unsigned char **pout, int entropy, size_t
/// min_len, size_t max_len, int prediction_resistance)` — `drbg.c:192-244`.
///
/// # Safety
/// `drbg` is live and the parent callbacks uphold their own contracts.
unsafe fn get_entropy(
    drbg: *mut ProvDrbg,
    pout: *mut *mut c_uchar,
    entropy: c_int,
    min_len: usize,
    max_len: usize,
    prediction_resistance: c_int,
) -> usize {
    // SAFETY: `drbg` is live per the contract.
    unsafe {
        if (*drbg).parent.is_null() {
            return ossl_prov_get_entropy((*drbg).provctx, pout, entropy, min_len, max_len);
        }
        let Some(parent_get_seed) = (*drbg).parent_get_seed else {
            raise_site(&err_sites::PROV_DRBG_208);
            return 0;
        };
        let mut p_str: c_uint = 0;
        if get_parent_strength(drbg, &mut p_str) == 0 {
            return 0;
        }
        if (*drbg).strength > p_str {
            raise_site(&err_sites::PROV_DRBG_218);
            return 0;
        }
        if ossl_drbg_lock_parent(drbg) == 0 {
            return 0;
        }
        let parent = (*drbg).parent;
        let ent = if entropy > 0 {
            entropy
        } else {
            (*drbg).strength as c_int
        };
        let mut identity = drbg;
        let bytes = parent_get_seed(
            parent,
            pout,
            ent,
            min_len,
            max_len,
            prediction_resistance,
            ptr::addr_of_mut!(identity).cast::<c_uchar>(),
            core::mem::size_of::<*mut ProvDrbg>(),
        );
        ossl_drbg_unlock_parent(drbg);
        bytes
    }
}

/// `static void cleanup_entropy(PROV_DRBG *drbg, unsigned char *out, size_t outlen)`
/// — `drbg.c:246-256`.
///
/// # Safety
/// `drbg` is live and `out`/`outlen` name a seed the matching `get_entropy` returned.
unsafe fn cleanup_entropy(drbg: *mut ProvDrbg, out: *mut c_uchar, outlen: usize) {
    // SAFETY: `drbg` is live per the contract.
    unsafe {
        if (*drbg).parent.is_null() {
            ossl_prov_cleanup_entropy((*drbg).provctx, out, outlen);
        } else if let Some(parent_clear_seed) = (*drbg).parent_clear_seed {
            if ossl_drbg_lock_parent(drbg) == 0 {
                return;
            }
            parent_clear_seed((*drbg).parent, out, outlen);
            ossl_drbg_unlock_parent(drbg);
        }
    }
}

/// `void *ossl_prov_drbg_nonce_ctx_new(OSSL_LIB_CTX *libctx)` — `drbg.c:271-285`.
///
/// # Safety
/// The `OSSL_LIB_CTX` callback contract; `libctx` is unused.
pub(crate) unsafe fn ossl_prov_drbg_nonce_ctx_new(_libctx: *mut c_void) -> *mut c_void {
    // SAFETY: the allocation is this frame's and is released on the failure path.
    unsafe {
        let dngbl = CRYPTO_zalloc(core::mem::size_of::<ProvDrbgNonceGlobal>(), FILE_DRBG, LINE)
            .cast::<ProvDrbgNonceGlobal>();
        if dngbl.is_null() {
            return ptr::null_mut();
        }
        (*dngbl).rand_nonce_lock = CRYPTO_THREAD_lock_new();
        if (*dngbl).rand_nonce_lock.is_null() {
            CRYPTO_free(dngbl.cast(), FILE_DRBG, LINE);
            return ptr::null_mut();
        }
        dngbl.cast()
    }
}

/// `void ossl_prov_drbg_nonce_ctx_free(void *vdngbl)` — `drbg.c:287-297`.
///
/// # Safety
/// `vdngbl` is NULL or what `ossl_prov_drbg_nonce_ctx_new` returned.
pub(crate) unsafe fn ossl_prov_drbg_nonce_ctx_free(vdngbl: *mut c_void) {
    // SAFETY: `vdngbl` is per the contract; both frees accept NULL.
    unsafe {
        if vdngbl.is_null() {
            return;
        }
        let dngbl = vdngbl.cast::<ProvDrbgNonceGlobal>();
        CRYPTO_THREAD_lock_free((*dngbl).rand_nonce_lock);
        CRYPTO_free(vdngbl, FILE_DRBG, LINE);
    }
}

/// `static size_t prov_drbg_get_nonce(PROV_DRBG *drbg, unsigned char **pout, size_t min_len,
/// size_t max_len)` — `drbg.c:300-338`.
///
/// # Safety
/// `drbg` is live and the parent nonce callback upholds its own contract.
unsafe fn prov_drbg_get_nonce(
    drbg: *mut ProvDrbg,
    pout: *mut *mut c_uchar,
    min_len: usize,
    max_len: usize,
) -> usize {
    // SAFETY: `drbg` is live per the contract.
    unsafe {
        let libctx = crate::provider::ctx::ossl_prov_ctx_get0_libctx((*drbg).provctx);
        let dngbl = ossl_lib_ctx_get_data(libctx, OSSL_LIB_CTX_DRBG_NONCE_INDEX)
            .cast::<ProvDrbgNonceGlobal>();
        if dngbl.is_null() {
            return 0;
        }
        if !(*drbg).parent.is_null() {
            if let Some(parent_nonce) = (*drbg).parent_nonce {
                let n = parent_nonce(
                    (*drbg).parent,
                    ptr::null_mut(),
                    0,
                    (*drbg).min_noncelen,
                    (*drbg).max_noncelen,
                );
                if n > 0 {
                    let buf = CRYPTO_malloc(n, FILE_DRBG, LINE).cast::<c_uchar>();
                    if !buf.is_null() {
                        let ret = parent_nonce(
                            (*drbg).parent,
                            buf,
                            0,
                            (*drbg).min_noncelen,
                            (*drbg).max_noncelen,
                        );
                        if ret == n {
                            *pout = buf;
                            return ret;
                        }
                        CRYPTO_free(buf.cast(), FILE_DRBG, LINE);
                    }
                }
            }
        }
        // Use the built-in nonce source plus this DRBG's own identity.
        let mut data: ProvDrbgNonce = ProvDrbgNonce {
            drbg: drbg.cast(),
            count: 0,
        };
        if CRYPTO_atomic_add(
            &mut (*dngbl).rand_nonce_count,
            1,
            &mut data.count,
            (*dngbl).rand_nonce_lock,
        ) == 0
        {
            return 0;
        }
        ossl_prov_get_nonce(
            (*drbg).provctx,
            pout,
            min_len,
            max_len,
            ptr::addr_of!(data).cast(),
            core::mem::size_of::<ProvDrbgNonce>(),
        )
    }
}

/// The anonymous `struct { void *drbg; int count; } data;` of `prov_drbg_get_nonce`.
#[repr(C)]
struct ProvDrbgNonce {
    drbg: *mut c_void,
    count: c_int,
}

// =============================================================================================
// `drbg.c` — instantiate / uninstantiate / reseed / generate
// =============================================================================================

/// `int ossl_prov_drbg_instantiate(PROV_DRBG *drbg, unsigned int strength, int
/// prediction_resistance, const unsigned char *pers, size_t perslen)` — `drbg.c:349-465`.
///
/// # Safety
/// `drbg` is live and locked, and the callback pointers it caches are non-NULL.
pub(crate) unsafe fn ossl_prov_drbg_instantiate(
    drbg: *mut ProvDrbg,
    strength: c_uint,
    prediction_resistance: c_int,
    pers: *const c_uchar,
    perslen: usize,
) -> c_int {
    // SAFETY: `drbg` is live per the contract.
    unsafe {
        let mut nonce: *mut c_uchar = ptr::null_mut();
        let mut noncelen: usize = 0;

        // The authority's `goto end` is this labeled block. Its `end:` arm releases the nonce
        // and then answers `state == READY`, so both the release and the final test run on
        // *every* exit — success or failure — which is why the failures below `break` rather
        // than `return`.
        'end: {
            if strength > (*drbg).strength {
                raise_site(&err_sites::PROV_DRBG_359);
                break 'end;
            }
            let mut min_entropy: c_uint = (*drbg).strength;
            let mut min_entropylen: usize = (*drbg).min_entropylen;
            let mut max_entropylen: usize = (*drbg).max_entropylen;

            let mut pers = pers;
            let mut perslen = perslen;
            if pers.is_null() {
                pers = DRBG_DEFAULT_PERS_STRING.as_ptr();
                perslen = DRBG_DEFAULT_PERS_STRING.len() + 1;
            }
            if perslen > (*drbg).max_perslen {
                raise_site(&err_sites::PROV_DRBG_371);
                break 'end;
            }
            if (*drbg).state != EVP_RAND_STATE_UNINITIALISED {
                if (*drbg).state == crate::evp::rand::EVP_RAND_STATE_ERROR {
                    raise_site(&err_sites::PROV_DRBG_377);
                } else {
                    raise_site(&err_sites::PROV_DRBG_379);
                }
                break 'end;
            }
            (*drbg).state = crate::evp::rand::EVP_RAND_STATE_ERROR;

            if (*drbg).min_noncelen > 0 {
                if let Some(parent_nonce) = (*drbg).parent_nonce {
                    noncelen = parent_nonce(
                        (*drbg).parent,
                        ptr::null_mut(),
                        (*drbg).strength,
                        (*drbg).min_noncelen,
                        (*drbg).max_noncelen,
                    );
                    if noncelen == 0 {
                        raise_site(&err_sites::PROV_DRBG_391);
                        break 'end;
                    }
                    nonce = CRYPTO_malloc(noncelen, FILE_DRBG, LINE).cast::<c_uchar>();
                    if nonce.is_null() {
                        raise_site(&err_sites::PROV_DRBG_396);
                        break 'end;
                    }
                    let got = parent_nonce(
                        (*drbg).parent,
                        nonce,
                        (*drbg).strength,
                        (*drbg).min_noncelen,
                        (*drbg).max_noncelen,
                    );
                    if noncelen != got {
                        raise_site(&err_sites::PROV_DRBG_400);
                        break 'end;
                    }
                } else if !(*drbg).parent.is_null() {
                    // NIST SP800-90Ar1 9.1: fold the nonce into the entropy request.
                    min_entropy += (*drbg).strength / 2;
                    min_entropylen += (*drbg).min_noncelen;
                    max_entropylen += (*drbg).max_noncelen;
                } else {
                    // parent == NULL
                    noncelen = prov_drbg_get_nonce(
                        drbg,
                        &mut nonce,
                        (*drbg).min_noncelen,
                        (*drbg).max_noncelen,
                    );
                    if noncelen < (*drbg).min_noncelen || noncelen > (*drbg).max_noncelen {
                        raise_site(&err_sites::PROV_DRBG_423);
                        break 'end;
                    }
                }
            }

            (*drbg).reseed_next_counter = (*drbg).reseed_counter.load(Ordering::Relaxed);
            if (*drbg).reseed_next_counter != 0 {
                (*drbg).reseed_next_counter = (*drbg).reseed_next_counter.wrapping_add(1);
                if (*drbg).reseed_next_counter == 0 {
                    (*drbg).reseed_next_counter = 1;
                }
            }

            let mut entropy: *mut c_uchar = ptr::null_mut();
            let entropylen = get_entropy(
                drbg,
                &mut entropy,
                min_entropy as c_int,
                min_entropylen,
                max_entropylen,
                prediction_resistance,
            );
            if entropylen < min_entropylen || entropylen > max_entropylen {
                raise_site(&err_sites::PROV_DRBG_442);
                break 'end;
            }

            if ((*drbg).instantiate)(drbg, entropy, entropylen, nonce, noncelen, pers, perslen) == 0
            {
                cleanup_entropy(drbg, entropy, entropylen);
                raise_site(&err_sites::PROV_DRBG_449);
                break 'end;
            }
            cleanup_entropy(drbg, entropy, entropylen);

            (*drbg).state = EVP_RAND_STATE_READY;
            (*drbg).generate_counter = 1;
            (*drbg).reseed_time = time(ptr::null_mut());
            (*drbg)
                .reseed_counter
                .store((*drbg).reseed_next_counter, Ordering::Relaxed);
        };

        if !nonce.is_null() {
            ossl_prov_cleanup_nonce((*drbg).provctx, nonce, noncelen);
        }
        if (*drbg).state == EVP_RAND_STATE_READY {
            1
        } else {
            0
        }
    }
}

/// `int ossl_prov_drbg_uninstantiate(PROV_DRBG *drbg)` — `drbg.c:474-478`.
///
/// # Safety
/// `drbg` must be live.
pub(crate) unsafe fn ossl_prov_drbg_uninstantiate(drbg: *mut ProvDrbg) -> c_int {
    // SAFETY: `drbg` is live per the contract.
    unsafe { (*drbg).state = EVP_RAND_STATE_UNINITIALISED };
    1
}

/// `static int ossl_prov_drbg_reseed_unlocked(PROV_DRBG *drbg, int prediction_resistance,
/// const unsigned char *ent, size_t ent_len, const unsigned char *adin, size_t adinlen)`
/// — `drbg.c:480-585`, without the `FIPS_MODULE` arm (in which `ent` is fed as additional
/// input and `reseed()` is called with a NULL entropy).
///
/// # Safety
/// `drbg` is live and the cached callbacks are non-NULL.
unsafe fn ossl_prov_drbg_reseed_unlocked(
    drbg: *mut ProvDrbg,
    prediction_resistance: c_int,
    ent: *const c_uchar,
    ent_len: usize,
    adin: *const c_uchar,
    adinlen: usize,
) -> c_int {
    // SAFETY: `drbg` is live per the contract.
    unsafe {
        if is_running() == 0 {
            return 0;
        }
        if (*drbg).state != EVP_RAND_STATE_READY {
            rand_drbg_restart(drbg);
            if (*drbg).state == crate::evp::rand::EVP_RAND_STATE_ERROR {
                raise_site(&err_sites::PROV_DRBG_498);
                return 0;
            }
            if (*drbg).state == EVP_RAND_STATE_UNINITIALISED {
                raise_site(&err_sites::PROV_DRBG_502);
                return 0;
            }
        }

        if !ent.is_null() {
            if ent_len < (*drbg).min_entropylen {
                raise_site(&err_sites::PROV_DRBG_509);
                (*drbg).state = crate::evp::rand::EVP_RAND_STATE_ERROR;
                return 0;
            }
            if ent_len > (*drbg).max_entropylen {
                raise_site(&err_sites::PROV_DRBG_514);
                (*drbg).state = crate::evp::rand::EVP_RAND_STATE_ERROR;
                return 0;
            }
        }

        let mut adin = adin;
        let mut adinlen = adinlen;
        if adin.is_null() {
            adinlen = 0;
        } else if adinlen > (*drbg).max_adinlen {
            raise_site(&err_sites::PROV_DRBG_523);
            return 0;
        }

        (*drbg).state = crate::evp::rand::EVP_RAND_STATE_ERROR;

        (*drbg).reseed_next_counter = (*drbg).reseed_counter.load(Ordering::Relaxed);
        if (*drbg).reseed_next_counter != 0 {
            (*drbg).reseed_next_counter = (*drbg).reseed_next_counter.wrapping_add(1);
            if (*drbg).reseed_next_counter == 0 {
                (*drbg).reseed_next_counter = 1;
            }
        }

        if !ent.is_null() {
            // #ifdef FIPS_MODULE: `reseed(drbg, NULL, 0, ent, ent_len)`.
            if ((*drbg).reseed)(drbg, ent, ent_len, adin, adinlen) == 0 {
                raise_site(&err_sites::PROV_DRBG_551);
                return 0;
            }
            // There is no point adding the same additional input twice.
            adin = ptr::null();
            adinlen = 0;
        }

        let mut entropy: *mut c_uchar = ptr::null_mut();
        let entropylen = get_entropy(
            drbg,
            &mut entropy,
            (*drbg).strength as c_int,
            (*drbg).min_entropylen,
            (*drbg).max_entropylen,
            prediction_resistance,
        );
        if entropylen < (*drbg).min_entropylen || entropylen > (*drbg).max_entropylen {
            raise_site(&err_sites::PROV_DRBG_566);
            cleanup_entropy(drbg, entropy, entropylen);
            return 0;
        }

        if ((*drbg).reseed)(drbg, entropy, entropylen, adin, adinlen) == 0 {
            cleanup_entropy(drbg, entropy, entropylen);
            return 0;
        }

        (*drbg).state = EVP_RAND_STATE_READY;
        (*drbg).generate_counter = 1;
        (*drbg).reseed_time = time(ptr::null_mut());
        (*drbg)
            .reseed_counter
            .store((*drbg).reseed_next_counter, Ordering::Relaxed);
        if !(*drbg).parent.is_null() {
            (*drbg).parent_reseed_counter = get_parent_reseed_count(drbg);
        }

        cleanup_entropy(drbg, entropy, entropylen);
        if (*drbg).state == EVP_RAND_STATE_READY {
            1
        } else {
            0
        }
    }
}

/// `int ossl_prov_drbg_reseed(PROV_DRBG *drbg, int prediction_resistance, const unsigned char
/// *ent, size_t ent_len, const unsigned char *adin, size_t adinlen)` — `drbg.c:594-610`.
///
/// # Safety
/// `drbg` is live.
pub(crate) unsafe fn ossl_prov_drbg_reseed(
    drbg: *mut ProvDrbg,
    prediction_resistance: c_int,
    ent: *const c_uchar,
    ent_len: usize,
    adin: *const c_uchar,
    adinlen: usize,
) -> c_int {
    // SAFETY: `drbg` is live per the contract.
    unsafe {
        if !(*drbg).lock.is_null() && CRYPTO_THREAD_write_lock((*drbg).lock) == 0 {
            return 0;
        }
        let ret = ossl_prov_drbg_reseed_unlocked(
            drbg,
            prediction_resistance,
            ent,
            ent_len,
            adin,
            adinlen,
        );
        if !(*drbg).lock.is_null() {
            CRYPTO_THREAD_unlock((*drbg).lock);
        }
        ret
    }
}

/// `int ossl_prov_drbg_generate(PROV_DRBG *drbg, unsigned char *out, size_t outlen, unsigned
/// int strength, int prediction_resistance, const unsigned char *adin, size_t adinlen)`
/// — `drbg.c:622-712`. The reseed triggers are: fork id changed, generate counter reached the
/// reseed interval, the reseed time interval elapsed (or the clock went backwards), or the
/// parent's reseed counter differs.
///
/// # Safety
/// `drbg` is live and `out` is writable for `outlen`.
pub(crate) unsafe fn ossl_prov_drbg_generate(
    drbg: *mut ProvDrbg,
    out: *mut c_uchar,
    outlen: usize,
    strength: c_uint,
    prediction_resistance: c_int,
    adin: *const c_uchar,
    adinlen: usize,
) -> c_int {
    // SAFETY: `drbg` is live per the contract.
    unsafe {
        if is_running() == 0 {
            return 0;
        }
        let fork_id = openssl_get_fork_id();
        let reseed_time_interval = (*drbg).reseed_time_interval;
        let now = if reseed_time_interval > 0 {
            time(ptr::null_mut())
        } else {
            0
        };

        if !(*drbg).lock.is_null() && CRYPTO_THREAD_write_lock((*drbg).lock) == 0 {
            return 0;
        }

        let mut reseed_required = 0;
        let mut adin = adin;
        let mut adinlen = adinlen;

        if (*drbg).state != EVP_RAND_STATE_READY {
            rand_drbg_restart(drbg);
            if (*drbg).state == crate::evp::rand::EVP_RAND_STATE_ERROR {
                raise_site(&err_sites::PROV_DRBG_648);
                return generate_fail(drbg);
            }
            if (*drbg).state == EVP_RAND_STATE_UNINITIALISED {
                raise_site(&err_sites::PROV_DRBG_652);
                return generate_fail(drbg);
            }
        }
        if strength > (*drbg).strength {
            raise_site(&err_sites::PROV_DRBG_657);
            return generate_fail(drbg);
        }
        if outlen > (*drbg).max_request {
            raise_site(&err_sites::PROV_DRBG_662);
            return generate_fail(drbg);
        }
        if adinlen > (*drbg).max_adinlen {
            raise_site(&err_sites::PROV_DRBG_666);
            return generate_fail(drbg);
        }

        if (*drbg).fork_id != fork_id {
            (*drbg).fork_id = fork_id;
            reseed_required = 1;
        }
        if (*drbg).reseed_interval > 0 && (*drbg).generate_counter >= (*drbg).reseed_interval {
            reseed_required = 1;
        }
        if reseed_time_interval > 0
            && (now < (*drbg).reseed_time
                || now.wrapping_sub((*drbg).reseed_time) >= reseed_time_interval)
        {
            reseed_required = 1;
        }
        if !(*drbg).parent.is_null()
            && get_parent_reseed_count(drbg) != (*drbg).parent_reseed_counter
        {
            reseed_required = 1;
        }

        if reseed_required != 0 || prediction_resistance != 0 {
            if ossl_prov_drbg_reseed_unlocked(
                drbg,
                prediction_resistance,
                ptr::null(),
                0,
                adin,
                adinlen,
            ) == 0
            {
                raise_site(&err_sites::PROV_DRBG_691);
                return generate_fail(drbg);
            }
            adin = ptr::null();
            adinlen = 0;
        }

        if ((*drbg).generate)(drbg, out, outlen, adin, adinlen) == 0 {
            (*drbg).state = crate::evp::rand::EVP_RAND_STATE_ERROR;
            raise_site(&err_sites::PROV_DRBG_700);
            return generate_fail(drbg);
        }

        (*drbg).generate_counter = (*drbg).generate_counter.wrapping_add(1);
        if !(*drbg).lock.is_null() {
            CRYPTO_THREAD_unlock((*drbg).lock);
        }
        1
    }
}

/// The `err:` tail of `ossl_prov_drbg_generate`'s three `goto err` paths and its success path:
/// unlock (if locked) and answer `ret`.
///
/// # Safety
/// `drbg` must be live and, if `lock` is non-NULL, held by this thread.
unsafe fn generate_fail(drbg: *mut ProvDrbg) -> c_int {
    // SAFETY: `drbg` is live per the contract.
    unsafe {
        if !(*drbg).lock.is_null() {
            CRYPTO_THREAD_unlock((*drbg).lock);
        }
    }
    0
}

/// `static int rand_drbg_restart(PROV_DRBG *drbg)` — `drbg.c:731-743`.
///
/// # Safety
/// `drbg` must be live.
unsafe fn rand_drbg_restart(drbg: *mut ProvDrbg) -> c_int {
    // SAFETY: `drbg` is live per the contract.
    unsafe {
        if (*drbg).state == crate::evp::rand::EVP_RAND_STATE_ERROR {
            ((*drbg).uninstantiate)(drbg);
        }
        if (*drbg).state == EVP_RAND_STATE_UNINITIALISED {
            ossl_prov_drbg_instantiate(drbg, (*drbg).strength, 0, ptr::null(), 0);
        }
        if (*drbg).state == EVP_RAND_STATE_READY {
            1
        } else {
            0
        }
    }
}

// =============================================================================================
// `drbg.c` — the provider side
// =============================================================================================

/// `static const OSSL_DISPATCH *find_call(const OSSL_DISPATCH *dispatch, int function)`
/// — `drbg.c:746-756`.
///
/// # Safety
/// `dispatch` is NULL or a `OSSL_DISPATCH_END`-terminated table.
unsafe fn find_call(dispatch: *const OsslDispatch, function: c_int) -> *const OsslDispatch {
    // SAFETY: the table is END-terminated per the contract.
    unsafe {
        if !dispatch.is_null() {
            let mut d = dispatch;
            while (*d).function_id != 0 {
                if (*d).function_id == function {
                    return d;
                }
                d = d.add(1);
            }
        }
        ptr::null()
    }
}

/// `int ossl_drbg_enable_locking(void *vctx)` — `drbg.c:758-775`.
///
/// # Safety
/// `vctx` is NULL or a live `ProvDrbg`.
pub(crate) unsafe extern "C" fn ossl_drbg_enable_locking(vctx: *mut c_void) -> c_int {
    // SAFETY: `vctx` is per the contract.
    unsafe {
        let drbg = vctx.cast::<ProvDrbg>();
        if !drbg.is_null() && (*drbg).lock.is_null() {
            if let Some(parent_enable) = (*drbg).parent_enable_locking {
                if parent_enable((*drbg).parent) == 0 {
                    raise_site(&err_sites::PROV_DRBG_765);
                    return 0;
                }
            }
            (*drbg).lock = CRYPTO_THREAD_lock_new();
            if (*drbg).lock.is_null() {
                raise_site(&err_sites::PROV_DRBG_770);
                return 0;
            }
        }
        1
    }
}

/// `PROV_DRBG *ossl_rand_drbg_new(void *provctx, void *parent, const OSSL_DISPATCH *p_dispatch,
/// int (*dnew)(PROV_DRBG *ctx), void (*dfree)(void *vctx), int (*instantiate)(...), int
/// (*uninstantiate)(...), int (*reseed)(...), int (*generate)(...))` — `drbg.c:785-867`.
///
/// # Safety
/// All callback pointers uphold their own contracts; `p_dispatch` is NULL or an
/// `OSSL_DISPATCH_END`-terminated table.
#[allow(clippy::too_many_arguments)] // mirrors the authority's signature exactly
pub(crate) unsafe fn ossl_rand_drbg_new(
    provctx: *mut ProvCtx,
    parent: *mut c_void,
    p_dispatch: *const OsslDispatch,
    dnew: ProvDrbgNewFn,
    dfree: ProvDrbgFreeFn,
    instantiate: ProvDrbgInstantiateFn,
    uninstantiate: ProvDrbgUninstantiateFn,
    reseed: ProvDrbgReseedFn,
    generate: ProvDrbgGenerateFn,
) -> *mut ProvDrbg {
    // SAFETY: the allocation and the callback table are per the contract.
    unsafe {
        if is_running() == 0 {
            return ptr::null_mut();
        }
        let drbg =
            CRYPTO_zalloc(core::mem::size_of::<ProvDrbg>(), FILE_DRBG, LINE).cast::<ProvDrbg>();
        if drbg.is_null() {
            return ptr::null_mut();
        }

        (*drbg).provctx = provctx;
        (*drbg).instantiate = instantiate;
        (*drbg).uninstantiate = uninstantiate;
        (*drbg).reseed = reseed;
        (*drbg).generate = generate;
        (*drbg).fork_id = openssl_get_fork_id();

        (*drbg).parent = parent;
        if let Some(pfunc) = non_null(find_call(p_dispatch, OSSL_FUNC_RAND_ENABLE_LOCKING)) {
            (*drbg).parent_enable_locking = Some(entry_function(pfunc));
        }
        if let Some(pfunc) = non_null(find_call(p_dispatch, OSSL_FUNC_RAND_LOCK)) {
            (*drbg).parent_lock = Some(entry_function(pfunc));
        }
        if let Some(pfunc) = non_null(find_call(p_dispatch, OSSL_FUNC_RAND_UNLOCK)) {
            (*drbg).parent_unlock = Some(entry_function(pfunc));
        }
        if let Some(pfunc) = non_null(find_call(p_dispatch, OSSL_FUNC_RAND_GET_CTX_PARAMS)) {
            (*drbg).parent_get_ctx_params = Some(entry_function(pfunc));
        }
        if let Some(pfunc) = non_null(find_call(p_dispatch, OSSL_FUNC_RAND_NONCE)) {
            (*drbg).parent_nonce = Some(entry_function(pfunc));
        }
        if let Some(pfunc) = non_null(find_call(p_dispatch, OSSL_FUNC_RAND_GET_SEED)) {
            (*drbg).parent_get_seed = Some(entry_function(pfunc));
        }
        if let Some(pfunc) = non_null(find_call(p_dispatch, OSSL_FUNC_RAND_CLEAR_SEED)) {
            (*drbg).parent_clear_seed = Some(entry_function(pfunc));
        }

        // Set some default maximums up.
        (*drbg).max_entropylen = DRBG_MAX_LENGTH;
        (*drbg).max_noncelen = DRBG_MAX_LENGTH;
        (*drbg).max_perslen = DRBG_MAX_LENGTH;
        (*drbg).max_adinlen = DRBG_MAX_LENGTH;
        (*drbg).generate_counter = 1;
        (*drbg).reseed_counter = AtomicU32::new(1);
        (*drbg).reseed_interval = RESEED_INTERVAL;
        (*drbg).reseed_time_interval = TIME_INTERVAL;

        if dnew(drbg) == 0 {
            dfree(drbg.cast());
            return ptr::null_mut();
        }

        if !parent.is_null() {
            let mut p_str: c_uint = 0;
            if get_parent_strength(drbg, &mut p_str) == 0 {
                dfree(drbg.cast());
                return ptr::null_mut();
            }
            if (*drbg).strength > p_str {
                raise_site(&err_sites::PROV_DRBG_854);
                dfree(drbg.cast());
                return ptr::null_mut();
            }
        }
        // #ifdef TSAN_REQUIRES_LOCKING: ossl_drbg_enable_locking(drbg).
        drbg
    }
}

/// The `OSSL_FUNC_##name(const OSSL_DISPATCH *opf)` cast — `core_dispatch.h`'s
/// `OSSL_CORE_MAKE_FUNC`. `crate::context::dispatch::entry_function` is the crate's form.
///
/// # Safety
/// `entry` must be a well-formed entry whose id names `T`.
unsafe fn entry_function<T: Copy>(entry: *const OsslDispatch) -> T {
    // SAFETY: the caller's contract; the entry was selected by its id.
    unsafe { crate::context::dispatch::entry_function::<T>(entry).unwrap_unchecked() }
}

/// `NULL`-turn for `find_call`'s answer.
fn non_null(p: *const OsslDispatch) -> Option<*const OsslDispatch> {
    if p.is_null() {
        None
    } else {
        Some(p)
    }
}

/// `void ossl_rand_drbg_free(PROV_DRBG *drbg)` — `drbg.c:869-876`.
///
/// # Safety
/// `drbg` is NULL or a live `ProvDrbg`, and its `data` has already been released by its
/// algorithm-specific `dfree`.
pub(crate) unsafe fn ossl_rand_drbg_free(drbg: *mut ProvDrbg) {
    // SAFETY: `drbg` is per the contract; both frees accept NULL.
    unsafe {
        if drbg.is_null() {
            return;
        }
        CRYPTO_THREAD_lock_free((*drbg).lock);
        CRYPTO_free(drbg.cast(), FILE_DRBG, LINE);
    }
}

/// `int ossl_drbg_get_ctx_params(PROV_DRBG *drbg, const struct drbg_get_ctx_params_st *p)`
/// — `drbg.c:882-931`. The trailing `OSSL_FIPS_IND_GET_CTX_FROM_PARAM(drbg, p->ind)` is the
/// literal `1` on this profile and is a comment here.
///
/// # Safety
/// `drbg` is live and `p` names a decoded request.
pub(crate) unsafe fn ossl_drbg_get_ctx_params(
    drbg: *mut ProvDrbg,
    p: *const DrbgGetCtxParams,
) -> c_int {
    // SAFETY: `drbg` and `p` are per the contract.
    unsafe {
        if !(*p).state.is_null() && OSSL_PARAM_set_int((*p).state, (*drbg).state) == 0 {
            return 0;
        }
        if !(*p).str.is_null() && OSSL_PARAM_set_uint((*p).str, (*drbg).strength) == 0 {
            return 0;
        }
        if !(*p).minentlen.is_null()
            && OSSL_PARAM_set_size_t((*p).minentlen, (*drbg).min_entropylen) == 0
        {
            return 0;
        }
        if !(*p).maxentlen.is_null()
            && OSSL_PARAM_set_size_t((*p).maxentlen, (*drbg).max_entropylen) == 0
        {
            return 0;
        }
        if !(*p).minnonlen.is_null()
            && OSSL_PARAM_set_size_t((*p).minnonlen, (*drbg).min_noncelen) == 0
        {
            return 0;
        }
        if !(*p).maxnonlen.is_null()
            && OSSL_PARAM_set_size_t((*p).maxnonlen, (*drbg).max_noncelen) == 0
        {
            return 0;
        }
        if !(*p).maxperlen.is_null()
            && OSSL_PARAM_set_size_t((*p).maxperlen, (*drbg).max_perslen) == 0
        {
            return 0;
        }
        if !(*p).maxadlen.is_null()
            && OSSL_PARAM_set_size_t((*p).maxadlen, (*drbg).max_adinlen) == 0
        {
            return 0;
        }
        if !(*p).reseed_req.is_null()
            && OSSL_PARAM_set_uint((*p).reseed_req, (*drbg).reseed_interval) == 0
        {
            return 0;
        }
        if !(*p).reseed_time.is_null()
            && OSSL_PARAM_set_time_t((*p).reseed_time, (*drbg).reseed_time) == 0
        {
            return 0;
        }
        // Note: the list declares this `uint64`, but the authority writes it with `set_time_t`.
        if !(*p).reseed_int.is_null()
            && OSSL_PARAM_set_time_t((*p).reseed_int, (*drbg).reseed_time_interval) == 0
        {
            return 0;
        }
        // OSSL_FIPS_IND_GET_CTX_FROM_PARAM(drbg, p->ind) — 1 when FIPS_MODULE is undefined.
        1
    }
}

/// `int ossl_drbg_get_ctx_params_no_lock(PROV_DRBG *drbg, const struct drbg_get_ctx_params_st
/// *p, const OSSL_PARAM params[], int *complete)` — `drbg.c:937-966`. Sets `*complete` to 1
/// when the caller's array consisted entirely of the two lock-free keys.
///
/// # Safety
/// `drbg` is live, `p` is decoded, `params` is key-terminated, `complete` is writable.
pub(crate) unsafe fn ossl_drbg_get_ctx_params_no_lock(
    drbg: *mut ProvDrbg,
    p: *const DrbgGetCtxParams,
    params: *const OsslParam,
    complete: *mut c_int,
) -> c_int {
    // SAFETY: the arguments are per the contract.
    unsafe {
        let mut cnt: usize = 0;
        if !(*p).maxreq.is_null() {
            if OSSL_PARAM_set_size_t((*p).maxreq, (*drbg).max_request) == 0 {
                return 0;
            }
            cnt += 1;
        }
        if !(*p).reseed_cnt.is_null() {
            let v = (*drbg).reseed_counter.load(Ordering::Relaxed);
            if OSSL_PARAM_set_uint((*p).reseed_cnt, v) == 0 {
                return 0;
            }
            cnt += 1;
        }
        if (*params.add(cnt)).key.is_null() {
            *complete = 1;
        } else {
            *complete = 0;
        }
        1
    }
}

/// `int ossl_drbg_set_ctx_params(PROV_DRBG *drbg, const struct drbg_set_ctx_params_st *p)`
/// — `drbg.c:968-980`.
///
/// # Safety
/// `drbg` is live and `p` is decoded.
pub(crate) unsafe fn ossl_drbg_set_ctx_params(
    drbg: *mut ProvDrbg,
    p: *const DrbgSetCtxParams,
) -> c_int {
    // SAFETY: `drbg` and `p` are per the contract.
    unsafe {
        if !(*p).reseed_req.is_null()
            && OSSL_PARAM_get_uint((*p).reseed_req, &mut (*drbg).reseed_interval) == 0
        {
            return 0;
        }
        if !(*p).reseed_time.is_null()
            && OSSL_PARAM_get_time_t((*p).reseed_time, &mut (*drbg).reseed_time_interval) == 0
        {
            return 0;
        }
        1
    }
}

/// `int ossl_drbg_verify_digest(PROV_DRBG *drbg, OSSL_LIB_CTX *libctx, const EVP_MD *md)`
/// — `drbg.c:1004-1026`, without its `FIPS_MODULE` arms (`digest_allowed()` and the
/// restricted-digests indicator).
///
/// # Safety
/// `drbg` is live and `md` is a live method.
pub(crate) unsafe fn ossl_drbg_verify_digest(
    _drbg: *mut ProvDrbg,
    _libctx: *mut c_void,
    md: *const EvpMd,
) -> c_int {
    // SAFETY: `md` is live per the contract.
    unsafe {
        // Outside of FIPS, any digest that is not an XOF is allowed.
        if EVP_MD_xof(md) != 0 {
            raise_site(&err_sites::PROV_DRBG_1021);
            return 0;
        }
    }
    1
}

// =============================================================================================
// The two decoded-parameter shapes from `prov/drbg.h:215-254`
// =============================================================================================

/// `struct drbg_get_ctx_params_st` — `prov/drbg.h:215-234`.
#[repr(C)]
pub(crate) struct DrbgGetCtxParams {
    pub state: *mut OsslParam,
    pub str: *mut OsslParam,
    pub maxreq: *mut OsslParam,
    pub minentlen: *mut OsslParam,
    pub maxentlen: *mut OsslParam,
    pub minnonlen: *mut OsslParam,
    pub maxnonlen: *mut OsslParam,
    pub maxperlen: *mut OsslParam,
    pub maxadlen: *mut OsslParam,
    pub reseed_cnt: *mut OsslParam,
    pub reseed_time: *mut OsslParam,
    pub reseed_req: *mut OsslParam,
    pub reseed_int: *mut OsslParam,
    pub ind: *mut OsslParam,
    pub cipher: *mut OsslParam,
    pub df: *mut OsslParam,
    pub digest: *mut OsslParam,
    pub mac: *mut OsslParam,
}

impl DrbgGetCtxParams {
    /// The `memset(r, 0, sizeof(*r))` the generated decoder opens with.
    pub(crate) const EMPTY: Self = Self {
        state: ptr::null_mut(),
        str: ptr::null_mut(),
        maxreq: ptr::null_mut(),
        minentlen: ptr::null_mut(),
        maxentlen: ptr::null_mut(),
        minnonlen: ptr::null_mut(),
        maxnonlen: ptr::null_mut(),
        maxperlen: ptr::null_mut(),
        maxadlen: ptr::null_mut(),
        reseed_cnt: ptr::null_mut(),
        reseed_time: ptr::null_mut(),
        reseed_req: ptr::null_mut(),
        reseed_int: ptr::null_mut(),
        ind: ptr::null_mut(),
        cipher: ptr::null_mut(),
        df: ptr::null_mut(),
        digest: ptr::null_mut(),
        mac: ptr::null_mut(),
    };
}

/// `struct drbg_set_ctx_params_st` — `prov/drbg.h:243-254`.
#[repr(C)]
pub(crate) struct DrbgSetCtxParams {
    pub propq: *const OsslParam,
    pub engine: *const OsslParam,
    pub cipher: *const OsslParam,
    pub df: *const OsslParam,
    pub digest: *const OsslParam,
    pub mac: *const OsslParam,
    pub ind_d: *const OsslParam,
    pub prov: *const OsslParam,
    pub reseed_req: *const OsslParam,
    pub reseed_time: *const OsslParam,
}

impl DrbgSetCtxParams {
    pub(crate) const EMPTY: Self = Self {
        propq: ptr::null(),
        engine: ptr::null(),
        cipher: ptr::null(),
        df: ptr::null(),
        digest: ptr::null(),
        mac: ptr::null(),
        ind_d: ptr::null(),
        prov: ptr::null(),
        reseed_req: ptr::null(),
        reseed_time: ptr::null(),
    };
}

// =============================================================================================
// Parameter-name constants — `include/openssl/core_names.h` (generated from `paramnames.pm`)
// =============================================================================================

/// `OSSL_RAND_PARAM_STATE` — `"state"`.
const OSSL_RAND_PARAM_STATE: *const c_char = c"state".as_ptr();
/// `OSSL_RAND_PARAM_STRENGTH` — `"strength"`.
const OSSL_RAND_PARAM_STRENGTH: *const c_char = c"strength".as_ptr();
/// `OSSL_RAND_PARAM_MAX_REQUEST` — `"max_request"`.
const OSSL_RAND_PARAM_MAX_REQUEST: *const c_char = c"max_request".as_ptr();
/// `OSSL_DRBG_PARAM_RESEED_REQUESTS` — `"reseed_requests"`.
const OSSL_DRBG_PARAM_RESEED_REQUESTS: *const c_char = c"reseed_requests".as_ptr();
/// `OSSL_DRBG_PARAM_RESEED_TIME_INTERVAL` — `"reseed_time_interval"`.
const OSSL_DRBG_PARAM_RESEED_TIME_INTERVAL: *const c_char = c"reseed_time_interval".as_ptr();
/// `OSSL_DRBG_PARAM_MIN_ENTROPYLEN` — `"min_entropylen"`.
const OSSL_DRBG_PARAM_MIN_ENTROPYLEN: *const c_char = c"min_entropylen".as_ptr();
/// `OSSL_DRBG_PARAM_MAX_ENTROPYLEN` — `"max_entropylen"`.
const OSSL_DRBG_PARAM_MAX_ENTROPYLEN: *const c_char = c"max_entropylen".as_ptr();
/// `OSSL_DRBG_PARAM_MIN_NONCELEN` — `"min_noncelen"`.
const OSSL_DRBG_PARAM_MIN_NONCELEN: *const c_char = c"min_noncelen".as_ptr();
/// `OSSL_DRBG_PARAM_MAX_NONCELEN` — `"max_noncelen"`.
const OSSL_DRBG_PARAM_MAX_NONCELEN: *const c_char = c"max_noncelen".as_ptr();
/// `OSSL_DRBG_PARAM_MAX_PERSLEN` — `"max_perslen"`.
const OSSL_DRBG_PARAM_MAX_PERSLEN: *const c_char = c"max_perslen".as_ptr();
/// `OSSL_DRBG_PARAM_MAX_ADINLEN` — `"max_adinlen"`.
const OSSL_DRBG_PARAM_MAX_ADINLEN: *const c_char = c"max_adinlen".as_ptr();
/// `OSSL_DRBG_PARAM_RESEED_COUNTER` — `"reseed_counter"`.
const OSSL_DRBG_PARAM_RESEED_COUNTER: *const c_char = c"reseed_counter".as_ptr();
/// `OSSL_DRBG_PARAM_RESEED_TIME` — `"reseed_time"`.
const OSSL_DRBG_PARAM_RESEED_TIME: *const c_char = c"reseed_time".as_ptr();
/// `OSSL_DRBG_PARAM_USE_DF` — `"use_derivation_function"`.
const OSSL_DRBG_PARAM_USE_DF: *const c_char = c"use_derivation_function".as_ptr();
/// `OSSL_DRBG_PARAM_CIPHER` — aliased to `OSSL_ALG_PARAM_CIPHER` (`"cipher"`).
const OSSL_DRBG_PARAM_CIPHER: *const c_char = OSSL_ALG_PARAM_CIPHER;
/// `OSSL_DRBG_PARAM_DIGEST` — aliased to `OSSL_ALG_PARAM_DIGEST` (`"digest"`).
const OSSL_DRBG_PARAM_DIGEST: *const c_char = OSSL_ALG_PARAM_DIGEST;
/// `OSSL_DRBG_PARAM_MAC` — `OSSL_ALG_PARAM_MAC` (`"mac"`).
const OSSL_DRBG_PARAM_MAC: *const c_char = c"mac".as_ptr();
/// `OSSL_DRBG_PARAM_PROPERTIES` — aliased to `OSSL_ALG_PARAM_PROPERTIES` (`"properties"`).
const OSSL_DRBG_PARAM_PROPERTIES: *const c_char = OSSL_ALG_PARAM_PROPERTIES;
/// `OSSL_PROV_PARAM_CORE_PROV_NAME` — `"provider-name"`.
const OSSL_PROV_PARAM_CORE_PROV_NAME: *const c_char = c"provider-name".as_ptr();
/// `OSSL_KDF_PARAM_FIPS_APPROVED_INDICATOR` — `"fips-indicator"`; the `fips` decoder entry is
/// absent on this profile and the constant is present for completeness.
const OSSL_KDF_PARAM_FIPS_APPROVED_INDICATOR: *const c_char = c"fips-indicator".as_ptr();
/// `OSSL_KDF_PARAM_FIPS_DIGEST_CHECK` — `"digest-check"`; likewise FIPS-only.
const OSSL_KDF_PARAM_FIPS_DIGEST_CHECK: *const c_char = c"digest-check".as_ptr();

// =============================================================================================
// `drbg_ctr.c` — the CTR-DRBG
// =============================================================================================

/// `struct rand_drbg_ctr_st` — `drbg_ctr.c:53-67`.
#[repr(C)]
pub(crate) struct ProvDrbgCtr {
    /// `EVP_CIPHER_CTX *ctx_ecb`.
    pub ctx_ecb: *mut EvpCipherCtx,
    /// `EVP_CIPHER_CTX *ctx_ctr`.
    pub ctx_ctr: *mut EvpCipherCtx,
    /// `EVP_CIPHER_CTX *ctx_df`.
    pub ctx_df: *mut EvpCipherCtx,
    /// `EVP_CIPHER *cipher_ecb`.
    pub cipher_ecb: *mut EvpCipher,
    /// `EVP_CIPHER *cipher_ctr`.
    pub cipher_ctr: *mut EvpCipher,
    /// `size_t keylen`.
    pub keylen: usize,
    /// `int use_df`.
    pub use_df: c_int,
    /// `unsigned char K[32]`.
    pub k: [c_uchar; 32],
    /// `unsigned char V[16]`.
    pub v: [c_uchar; 16],
    /// `unsigned char bltmp[16]` — temporary block storage used by `ctr_df`.
    pub bltmp: [c_uchar; 16],
    /// `size_t bltmp_pos`.
    pub bltmp_pos: usize,
    /// `unsigned char KX[48]`.
    pub kx: [c_uchar; 48],
}

/// `static void inc_128(PROV_DRBG_CTR *ctr)` — `drbg_ctr.c:72-83`.
///
/// # Safety
/// `ctr` must be live.
unsafe fn inc_128(ctr: *mut ProvDrbgCtr) {
    // SAFETY: `ctr` is live per the contract.
    unsafe {
        let mut n: u32 = 16;
        let mut c: u32 = 1;
        loop {
            n -= 1;
            c += (*ctr).v[n as usize] as u32;
            (*ctr).v[n as usize] = c as u8;
            c >>= 8;
            if n == 0 {
                break;
            }
        }
    }
}

/// `static void ctr_XOR(PROV_DRBG_CTR *ctr, const unsigned char *in, size_t inlen)`
/// — `drbg_ctr.c:85-111`.
///
/// # Safety
/// `ctr` is live and `in` is readable for `inlen` (or NULL with `inlen` 0).
unsafe fn ctr_XOR(ctr: *mut ProvDrbgCtr, in_: *const c_uchar, inlen: usize) {
    // SAFETY: `ctr` and `in_` are per the contract.
    unsafe {
        if in_.is_null() || inlen == 0 {
            return;
        }
        let mut n = if inlen < (*ctr).keylen {
            inlen
        } else {
            (*ctr).keylen
        };
        // `ossl_assert(n <= sizeof(ctr->K))` is `n <= 32` under `NDEBUG`, which is how the
        // authority compiles (`include/internal/common.h`); the crate has no shared symbol and
        // reproduces the live guard inline, as its other sites do.
        if n > (*ctr).k.len() {
            return;
        }
        for i in 0..n {
            (*ctr).k[i] ^= *in_.add(i);
        }
        if inlen <= (*ctr).keylen {
            return;
        }
        n = inlen - (*ctr).keylen;
        if n > 16 {
            n = 16;
        }
        for i in 0..n {
            (*ctr).v[i] ^= *in_.add(i + (*ctr).keylen);
        }
    }
}

/// `static int ctr_BCC_block(PROV_DRBG_CTR *ctr, unsigned char *out, const unsigned char *in,
/// int len)` — `drbg_ctr.c:116-128`.
///
/// # Safety
/// `ctr`/`out`/`in` must be valid for the lengths used.
unsafe fn ctr_BCC_block(
    ctr: *mut ProvDrbgCtr,
    out: *mut c_uchar,
    in_: *const c_uchar,
    len: c_int,
) -> c_int {
    // SAFETY: the buffers are per the contract.
    unsafe {
        let mut outlen = AES_BLOCK_SIZE as c_int;
        for i in 0..len as usize {
            *out.add(i) ^= *in_.add(i);
        }
        if EVP_CipherUpdate((*ctr).ctx_df, out, &mut outlen, out, len) == 0 || outlen != len {
            return 0;
        }
        1
    }
}

/// `static int ctr_BCC_blocks(PROV_DRBG_CTR *ctr, const unsigned char *in)` — `drbg_ctr.c:133-145`.
///
/// # Safety
/// `ctr` is live and `in` is readable for 16 bytes.
unsafe fn ctr_BCC_blocks(ctr: *mut ProvDrbgCtr, in_: *const c_uchar) -> c_int {
    // SAFETY: the buffers are this frame's / the caller's.
    unsafe {
        let mut in_tmp = [0u8; 48];
        let mut num_of_blk: usize = 2;
        ptr::copy_nonoverlapping(in_, in_tmp.as_mut_ptr(), 16);
        ptr::copy_nonoverlapping(in_, in_tmp.as_mut_ptr().add(16), 16);
        if (*ctr).keylen != 16 {
            ptr::copy_nonoverlapping(in_, in_tmp.as_mut_ptr().add(32), 16);
            num_of_blk = 3;
        }
        ctr_BCC_block(
            ctr,
            (*ctr).kx.as_mut_ptr(),
            in_tmp.as_ptr(),
            (AES_BLOCK_SIZE * num_of_blk) as c_int,
        )
    }
}

/// `static int ctr_BCC_init(PROV_DRBG_CTR *ctr)` — `drbg_ctr.c:151-161`.
///
/// # Safety
/// `ctr` must be live.
unsafe fn ctr_BCC_init(ctr: *mut ProvDrbgCtr) -> c_int {
    // SAFETY: `ctr` is live per the contract.
    unsafe {
        let mut bltmp = [0u8; 48];
        cleanse((*ctr).kx.as_mut_ptr().cast(), 48);
        let num_of_blk: usize = if (*ctr).keylen == 16 { 2 } else { 3 };
        bltmp[AES_BLOCK_SIZE + 3] = 1;
        bltmp[(AES_BLOCK_SIZE * 2) + 3] = 2;
        ctr_BCC_block(
            ctr,
            (*ctr).kx.as_mut_ptr(),
            bltmp.as_ptr(),
            (num_of_blk * AES_BLOCK_SIZE) as c_int,
        )
    }
}

/// `static int ctr_BCC_update(PROV_DRBG_CTR *ctr, const unsigned char *in, size_t inlen)`
/// — `drbg_ctr.c:166-199`.
///
/// # Safety
/// `ctr` is live and `in` readable for `inlen`.
unsafe fn ctr_BCC_update(ctr: *mut ProvDrbgCtr, in_: *const c_uchar, inlen: usize) -> c_int {
    // SAFETY: `ctr` and `in_` are per the contract.
    unsafe {
        if in_.is_null() || inlen == 0 {
            return 1;
        }
        let mut in_ = in_;
        let mut inlen = inlen;

        if (*ctr).bltmp_pos != 0 {
            let left = 16 - (*ctr).bltmp_pos;
            if inlen >= left {
                ptr::copy_nonoverlapping(
                    in_,
                    (*ctr).bltmp.as_mut_ptr().add((*ctr).bltmp_pos),
                    left,
                );
                if ctr_BCC_blocks(ctr, (*ctr).bltmp.as_ptr()) == 0 {
                    return 0;
                }
                (*ctr).bltmp_pos = 0;
                inlen -= left;
                in_ = in_.add(left);
            }
        }

        while inlen >= 16 {
            if ctr_BCC_blocks(ctr, in_) == 0 {
                return 0;
            }
            in_ = in_.add(16);
            inlen -= 16;
        }

        if inlen > 0 {
            ptr::copy_nonoverlapping(in_, (*ctr).bltmp.as_mut_ptr().add((*ctr).bltmp_pos), inlen);
            (*ctr).bltmp_pos += inlen;
        }
        1
    }
}

/// `static int ctr_BCC_final(PROV_DRBG_CTR *ctr)` — `drbg_ctr.c:201-209`.
///
/// # Safety
/// `ctr` must be live.
unsafe fn ctr_BCC_final(ctr: *mut ProvDrbgCtr) -> c_int {
    // SAFETY: `ctr` is live per the contract.
    unsafe {
        if (*ctr).bltmp_pos != 0 {
            cleanse(
                (*ctr).bltmp.as_mut_ptr().add((*ctr).bltmp_pos).cast(),
                16 - (*ctr).bltmp_pos,
            );
            if ctr_BCC_blocks(ctr, (*ctr).bltmp.as_ptr()) == 0 {
                return 0;
            }
        }
        1
    }
}

/// `static int ctr_df(PROV_DRBG_CTR *ctr, const unsigned char *in1, size_t in1len, const
/// unsigned char *in2, size_t in2len, const unsigned char *in3, size_t in3len)`
/// — `drbg_ctr.c:211-266`. BCC-based derivation function of SP800-90A 10.3.3.
///
/// # Safety
/// `ctr` is live and each input is readable for its stated length (or NULL).
unsafe fn ctr_df(
    ctr: *mut ProvDrbgCtr,
    in1: *const c_uchar,
    in1len: usize,
    in2: *const c_uchar,
    in2len: usize,
    in3: *const c_uchar,
    in3len: usize,
) -> c_int {
    // SAFETY: `ctr` and the inputs are per the contract.
    unsafe {
        let c80: c_uchar = 0x80;
        let mut in1len = in1len;
        let mut in2len = in2len;
        let mut in3len = in3len;
        if in1.is_null() {
            in1len = 0;
        }
        if in2.is_null() {
            in2len = 0;
        }
        if in3.is_null() {
            in3len = 0;
        }
        let inlen = in1len.wrapping_add(in2len).wrapping_add(in3len);

        if ctr_BCC_init(ctr) == 0 {
            return 0;
        }

        let mut p = (*ctr).bltmp.as_mut_ptr();
        *p = ((inlen >> 24) & 0xff) as c_uchar;
        p = p.add(1);
        *p = ((inlen >> 16) & 0xff) as c_uchar;
        p = p.add(1);
        *p = ((inlen >> 8) & 0xff) as c_uchar;
        p = p.add(1);
        *p = (inlen & 0xff) as c_uchar;
        p = p.add(1);
        // NB keylen is at most 32 bytes.
        *p = 0;
        p = p.add(1);
        *p = 0;
        p = p.add(1);
        *p = 0;
        p = p.add(1);
        *p = (((*ctr).keylen + 16) & 0xff) as c_uchar;
        (*ctr).bltmp_pos = 8;

        if ctr_BCC_update(ctr, in1, in1len) == 0
            || ctr_BCC_update(ctr, in2, in2len) == 0
            || ctr_BCC_update(ctr, in3, in3len) == 0
            || ctr_BCC_update(ctr, &c80, 1) == 0
            || ctr_BCC_final(ctr) == 0
        {
            return 0;
        }

        // Set up key K.
        if EVP_CipherInit_ex(
            (*ctr).ctx_ecb,
            ptr::null(),
            ptr::null_mut(),
            (*ctr).kx.as_ptr(),
            ptr::null(),
            -1,
        ) == 0
        {
            return 0;
        }
        // X follows key K.
        let mut outlen = AES_BLOCK_SIZE as c_int;
        if EVP_CipherUpdate(
            (*ctr).ctx_ecb,
            (*ctr).kx.as_mut_ptr(),
            &mut outlen,
            (*ctr).kx.as_ptr().add((*ctr).keylen),
            AES_BLOCK_SIZE as c_int,
        ) == 0
            || outlen != AES_BLOCK_SIZE as c_int
        {
            return 0;
        }
        let mut outlen = AES_BLOCK_SIZE as c_int;
        if EVP_CipherUpdate(
            (*ctr).ctx_ecb,
            (*ctr).kx.as_mut_ptr().add(16),
            &mut outlen,
            (*ctr).kx.as_ptr(),
            AES_BLOCK_SIZE as c_int,
        ) == 0
            || outlen != AES_BLOCK_SIZE as c_int
        {
            return 0;
        }
        if (*ctr).keylen != 16 {
            let mut outlen = AES_BLOCK_SIZE as c_int;
            if EVP_CipherUpdate(
                (*ctr).ctx_ecb,
                (*ctr).kx.as_mut_ptr().add(32),
                &mut outlen,
                (*ctr).kx.as_ptr().add(16),
                AES_BLOCK_SIZE as c_int,
            ) == 0
                || outlen != AES_BLOCK_SIZE as c_int
            {
                return 0;
            }
        }
        1
    }
}

/// `static int ctr_update(PROV_DRBG *drbg, const unsigned char *in1, size_t in1len, const
/// unsigned char *in2, size_t in2len, const unsigned char *nonce, size_t noncelen)`
/// — `drbg_ctr.c:274-318`.
///
/// # Safety
/// `drbg` is live with a `ProvDrbgCtr` in `data`.
unsafe fn ctr_update(
    drbg: *mut ProvDrbg,
    in1: *const c_uchar,
    in1len: usize,
    in2: *const c_uchar,
    in2len: usize,
    nonce: *const c_uchar,
    noncelen: usize,
) -> c_int {
    // SAFETY: `drbg` is live per the contract.
    unsafe {
        let ctr = (*drbg).data.cast::<ProvDrbgCtr>();
        let mut V_tmp = [0u8; 48];
        let mut out = [0u8; 48];
        let mut outlen = AES_BLOCK_SIZE as c_int;

        // The correct key is already set up.
        ptr::copy_nonoverlapping((*ctr).v.as_ptr(), V_tmp.as_mut_ptr(), 16);
        inc_128(ctr);
        ptr::copy_nonoverlapping((*ctr).v.as_ptr(), V_tmp.as_mut_ptr().add(16), 16);
        let len: c_uchar = if (*ctr).keylen == 16 {
            32
        } else {
            inc_128(ctr);
            ptr::copy_nonoverlapping((*ctr).v.as_ptr(), V_tmp.as_mut_ptr().add(32), 16);
            48
        };
        if EVP_CipherUpdate(
            (*ctr).ctx_ecb,
            out.as_mut_ptr(),
            &mut outlen,
            V_tmp.as_ptr(),
            len as c_int,
        ) == 0
            || outlen != len as c_int
        {
            return 0;
        }
        ptr::copy_nonoverlapping(out.as_ptr(), (*ctr).k.as_mut_ptr(), (*ctr).keylen);
        ptr::copy_nonoverlapping(out.as_ptr().add((*ctr).keylen), (*ctr).v.as_mut_ptr(), 16);

        if (*ctr).use_df != 0 {
            // If no input, reuse the existing derived value.
            if (!in1.is_null() || !nonce.is_null() || !in2.is_null())
                && ctr_df(ctr, in1, in1len, nonce, noncelen, in2, in2len) == 0
            {
                return 0;
            }
            // If this is a reuse input, in1len != 0.
            if in1len != 0 {
                ctr_XOR(ctr, (*ctr).kx.as_ptr(), (*drbg).seedlen);
            }
        } else {
            ctr_XOR(ctr, in1, in1len);
            ctr_XOR(ctr, in2, in2len);
        }

        if EVP_CipherInit_ex(
            (*ctr).ctx_ecb,
            ptr::null(),
            ptr::null_mut(),
            (*ctr).k.as_ptr(),
            ptr::null(),
            -1,
        ) == 0
            || EVP_CipherInit_ex(
                (*ctr).ctx_ctr,
                ptr::null(),
                ptr::null_mut(),
                (*ctr).k.as_ptr(),
                ptr::null(),
                -1,
            ) == 0
        {
            return 0;
        }
        1
    }
}

/// `static int drbg_ctr_instantiate(PROV_DRBG *drbg, const unsigned char *entropy, size_t
/// entropylen, const unsigned char *nonce, size_t noncelen, const unsigned char *pers,
/// size_t perslen)` — `drbg_ctr.c:320-339`.
///
/// # Safety
/// `drbg` is live with a `ProvDrbgCtr` in `data`.
unsafe extern "C" fn drbg_ctr_instantiate(
    drbg: *mut ProvDrbg,
    entropy: *const c_uchar,
    entropylen: usize,
    nonce: *const c_uchar,
    noncelen: usize,
    pers: *const c_uchar,
    perslen: usize,
) -> c_int {
    // SAFETY: `drbg` is live per the contract.
    unsafe {
        let ctr = (*drbg).data.cast::<ProvDrbgCtr>();
        if entropy.is_null() {
            return 0;
        }
        cleanse((*ctr).k.as_mut_ptr().cast(), 32);
        cleanse((*ctr).v.as_mut_ptr().cast(), 16);
        if EVP_CipherInit_ex(
            (*ctr).ctx_ecb,
            ptr::null(),
            ptr::null_mut(),
            (*ctr).k.as_ptr(),
            ptr::null(),
            -1,
        ) == 0
        {
            return 0;
        }
        inc_128(ctr);
        if ctr_update(drbg, entropy, entropylen, pers, perslen, nonce, noncelen) == 0 {
            return 0;
        }
        1
    }
}

/// `static int drbg_ctr_instantiate_wrapper(void *vdrbg, unsigned int strength, int
/// prediction_resistance, const unsigned char *pstr, size_t pstr_len, const OSSL_PARAM
/// params[])` — `drbg_ctr.c:341-366`.
///
/// # Safety
/// The `OSSL_FUNC_rand_instantiate_fn` contract.
unsafe extern "C" fn drbg_ctr_instantiate_wrapper(
    vdrbg: *mut c_void,
    strength: c_uint,
    prediction_resistance: c_int,
    pstr: *const c_uchar,
    pstr_len: usize,
    params: *const OsslParam,
) -> c_int {
    // SAFETY: the dispatch contract.
    unsafe {
        let drbg = vdrbg.cast::<ProvDrbg>();
        let mut p = DrbgSetCtxParams::EMPTY;
        if drbg.is_null() || drbg_ctr_set_ctx_params_decoder(params, &mut p) == 0 {
            return 0;
        }
        if !(*drbg).lock.is_null() && CRYPTO_THREAD_write_lock((*drbg).lock) == 0 {
            return 0;
        }
        let mut ret = 0;
        if is_running() != 0 && drbg_ctr_set_ctx_params_locked(drbg, &p) != 0 {
            ret = ossl_prov_drbg_instantiate(drbg, strength, prediction_resistance, pstr, pstr_len);
        }
        if !(*drbg).lock.is_null() {
            CRYPTO_THREAD_unlock((*drbg).lock);
        }
        ret
    }
}

/// `static int drbg_ctr_reseed(PROV_DRBG *drbg, const unsigned char *entropy, size_t entropylen,
/// const unsigned char *adin, size_t adinlen)` — `drbg_ctr.c:368-381`.
///
/// # Safety
/// `drbg` is live with a `ProvDrbgCtr` in `data`.
unsafe extern "C" fn drbg_ctr_reseed(
    drbg: *mut ProvDrbg,
    entropy: *const c_uchar,
    entropylen: usize,
    adin: *const c_uchar,
    adinlen: usize,
) -> c_int {
    // SAFETY: `drbg` is live per the contract.
    unsafe {
        let ctr = (*drbg).data.cast::<ProvDrbgCtr>();
        if entropy.is_null() {
            return 0;
        }
        inc_128(ctr);
        if ctr_update(drbg, entropy, entropylen, adin, adinlen, ptr::null(), 0) == 0 {
            return 0;
        }
        1
    }
}

/// `static int drbg_ctr_reseed_wrapper(void *vdrbg, int prediction_resistance, const unsigned
/// char *ent, size_t ent_len, const unsigned char *adin, size_t adin_len)` — `drbg_ctr.c:383-391`.
///
/// # Safety
/// The `OSSL_FUNC_rand_reseed_fn` contract.
unsafe extern "C" fn drbg_ctr_reseed_wrapper(
    vdrbg: *mut c_void,
    prediction_resistance: c_int,
    ent: *const c_uchar,
    ent_len: usize,
    adin: *const c_uchar,
    adin_len: usize,
) -> c_int {
    // SAFETY: the dispatch contract.
    unsafe {
        ossl_prov_drbg_reseed(
            vdrbg.cast::<ProvDrbg>(),
            prediction_resistance,
            ent,
            ent_len,
            adin,
            adin_len,
        )
    }
}

/// `static void ctr96_inc(unsigned char *counter)` — `drbg_ctr.c:393-403`.
///
/// # Safety
/// `counter` must be writable for 12 bytes.
unsafe fn ctr96_inc(counter: *mut c_uchar) {
    // SAFETY: `counter` is writable per the contract.
    unsafe {
        let mut n: u32 = 12;
        let mut c: u32 = 1;
        loop {
            n -= 1;
            c += *counter.add(n as usize) as u32;
            *counter.add(n as usize) = c as u8;
            c >>= 8;
            if n == 0 {
                break;
            }
        }
    }
}

/// `static int drbg_ctr_generate(PROV_DRBG *drbg, unsigned char *out, size_t outlen, const
/// unsigned char *adin, size_t adinlen)` — `drbg_ctr.c:405-477`. Requests larger than 2^30 are
/// chunked so `EVP_CipherUpdate`'s `int` length cannot be exceeded.
///
/// # Safety
/// `drbg` is live with a `ProvDrbgCtr` in `data`; `out` writable for `outlen`.
unsafe extern "C" fn drbg_ctr_generate(
    drbg: *mut ProvDrbg,
    out: *mut c_uchar,
    outlen: usize,
    adin: *const c_uchar,
    adinlen: usize,
) -> c_int {
    // SAFETY: `drbg` is live per the contract.
    unsafe {
        let ctr = (*drbg).data.cast::<ProvDrbgCtr>();
        let mut out = out;
        let mut outlen = outlen;
        let mut adin = adin;
        let mut adinlen = adinlen;

        if !adin.is_null() && adinlen != 0 {
            inc_128(ctr);
            if ctr_update(drbg, adin, adinlen, ptr::null(), 0, ptr::null(), 0) == 0 {
                return 0;
            }
            // This means we reuse the derived value.
            if (*ctr).use_df != 0 {
                adin = ptr::null();
                adinlen = 1;
            }
        } else {
            adinlen = 0;
        }

        inc_128(ctr);

        if outlen == 0 {
            inc_128(ctr);
            if ctr_update(drbg, adin, adinlen, ptr::null(), 0, ptr::null(), 0) == 0 {
                return 0;
            }
            return 1;
        }

        cleanse(out.cast(), outlen);

        loop {
            if EVP_CipherInit_ex(
                (*ctr).ctx_ctr,
                ptr::null(),
                ptr::null_mut(),
                ptr::null(),
                (*ctr).v.as_ptr(),
                -1,
            ) == 0
            {
                return 0;
            }
            // `outlen` is `size_t` while `EVP_CipherUpdate` takes an `int`; process at most
            // 2^30 bytes per pass, the greatest AES multiple at or below 2^31-1.
            let buflen: c_int = if outlen > (1usize << 30) {
                1 << 30
            } else {
                outlen as c_int
            };
            let mut blocks: c_uint = (buflen as u32).div_ceil(16);
            let mut buflen = buflen;
            let mut ctr32: c_uint =
                crate::modes::get_u32_be((*ctr).v.as_ptr().add(12)).wrapping_add(blocks);
            if ctr32 < blocks {
                // 32-bit counter overflow into V.
                if ctr32 != 0 {
                    blocks -= ctr32;
                    buflen = (blocks * 16) as c_int;
                    ctr32 = 0;
                }
                ctr96_inc((*ctr).v.as_mut_ptr());
            }
            crate::modes::put_u32_be((*ctr).v.as_mut_ptr().add(12), ctr32);

            let mut outl: c_int = 0;
            if EVP_CipherUpdate((*ctr).ctx_ctr, out, &mut outl, out, buflen) == 0 || outl != buflen
            {
                return 0;
            }
            out = out.add(buflen as usize);
            outlen -= buflen as usize;
            if outlen == 0 {
                break;
            }
        }

        if ctr_update(drbg, adin, adinlen, ptr::null(), 0, ptr::null(), 0) == 0 {
            return 0;
        }
        1
    }
}

/// `static int drbg_ctr_generate_wrapper(void *vdrbg, unsigned char *out, size_t outlen,
/// unsigned int strength, int prediction_resistance, const unsigned char *adin, size_t
/// adin_len)` — `drbg_ctr.c:479-487`.
///
/// # Safety
/// The `OSSL_FUNC_rand_generate_fn` contract.
unsafe extern "C" fn drbg_ctr_generate_wrapper(
    vdrbg: *mut c_void,
    out: *mut c_uchar,
    outlen: usize,
    strength: c_uint,
    prediction_resistance: c_int,
    adin: *const c_uchar,
    adin_len: usize,
) -> c_int {
    // SAFETY: the dispatch contract.
    unsafe {
        ossl_prov_drbg_generate(
            vdrbg.cast::<ProvDrbg>(),
            out,
            outlen,
            strength,
            prediction_resistance,
            adin,
            adin_len,
        )
    }
}

/// `static int drbg_ctr_uninstantiate(PROV_DRBG *drbg)` — `drbg_ctr.c:489-499`.
///
/// # Safety
/// `drbg` is live with a `ProvDrbgCtr` in `data`.
unsafe extern "C" fn drbg_ctr_uninstantiate(drbg: *mut ProvDrbg) -> c_int {
    // SAFETY: `drbg` is live per the contract.
    unsafe {
        let ctr = (*drbg).data.cast::<ProvDrbgCtr>();
        cleanse((*ctr).k.as_mut_ptr().cast(), 32);
        cleanse((*ctr).v.as_mut_ptr().cast(), 16);
        cleanse((*ctr).bltmp.as_mut_ptr().cast(), 16);
        cleanse((*ctr).kx.as_mut_ptr().cast(), 48);
        (*ctr).bltmp_pos = 0;
        ossl_prov_drbg_uninstantiate(drbg)
    }
}

/// `static int drbg_ctr_uninstantiate_wrapper(void *vdrbg)` — `drbg_ctr.c:501-515`.
///
/// # Safety
/// The `OSSL_FUNC_rand_uninstantiate_fn` contract.
unsafe extern "C" fn drbg_ctr_uninstantiate_wrapper(vdrbg: *mut c_void) -> c_int {
    // SAFETY: the dispatch contract.
    unsafe {
        let drbg = vdrbg.cast::<ProvDrbg>();
        if !(*drbg).lock.is_null() && CRYPTO_THREAD_write_lock((*drbg).lock) == 0 {
            return 0;
        }
        let ret = drbg_ctr_uninstantiate(drbg);
        if !(*drbg).lock.is_null() {
            CRYPTO_THREAD_unlock((*drbg).lock);
        }
        ret
    }
}

/// `static int drbg_ctr_verify_zeroization(void *vdrbg)` — `drbg_ctr.c:517-538`. The authority's
/// `PROV_DRBG_VERIFY_ZEROIZATION` macro is a `goto err` on the first non-zero byte.
///
/// # Safety
/// The `OSSL_FUNC_rand_verify_zeroization_fn` contract.
unsafe extern "C" fn drbg_ctr_verify_zeroization(vdrbg: *mut c_void) -> c_int {
    // SAFETY: the dispatch contract.
    unsafe {
        let drbg = vdrbg.cast::<ProvDrbg>();
        let ctr = (*drbg).data.cast::<ProvDrbgCtr>();
        if !(*drbg).lock.is_null() && CRYPTO_THREAD_read_lock((*drbg).lock) == 0 {
            return 0;
        }
        let mut ret = 0;
        let zero = (*ctr).k.iter().all(|b| *b == 0)
            && (*ctr).v.iter().all(|b| *b == 0)
            && (*ctr).bltmp.iter().all(|b| *b == 0)
            && (*ctr).kx.iter().all(|b| *b == 0);
        if zero && (*ctr).bltmp_pos == 0 {
            ret = 1;
        }
        if !(*drbg).lock.is_null() {
            CRYPTO_THREAD_unlock((*drbg).lock);
        }
        ret
    }
}

/// `static int drbg_ctr_init_lengths(PROV_DRBG *drbg)` — `drbg_ctr.c:540-571`.
///
/// # Safety
/// `drbg` is live with a `ProvDrbgCtr` in `data`.
unsafe fn drbg_ctr_init_lengths(drbg: *mut ProvDrbg) -> c_int {
    // SAFETY: `drbg` is live per the contract.
    unsafe {
        let ctr = (*drbg).data.cast::<ProvDrbgCtr>();
        (*drbg).max_request = 1 << 16;
        if (*ctr).use_df != 0 {
            (*drbg).min_entropylen = 0;
            (*drbg).max_entropylen = DRBG_MAX_LENGTH;
            (*drbg).min_noncelen = 0;
            (*drbg).max_noncelen = DRBG_MAX_LENGTH;
            (*drbg).max_perslen = DRBG_MAX_LENGTH;
            (*drbg).max_adinlen = DRBG_MAX_LENGTH;
            if (*ctr).keylen > 0 {
                (*drbg).min_entropylen = (*ctr).keylen;
                (*drbg).min_noncelen = (*drbg).min_entropylen / 2;
            }
        } else {
            let len = if (*ctr).keylen > 0 {
                (*drbg).seedlen
            } else {
                DRBG_MAX_LENGTH
            };
            (*drbg).min_entropylen = len;
            (*drbg).max_entropylen = len;
            // Nonce not used.
            (*drbg).min_noncelen = 0;
            (*drbg).max_noncelen = 0;
            (*drbg).max_perslen = len;
            (*drbg).max_adinlen = len;
        }
        1
    }
}

/// `static int drbg_ctr_init(PROV_DRBG *drbg)` — `drbg_ctr.c:573-644`, without the
/// `FIPS_MODULE` requirement that `use_df` be set.
///
/// # Safety
/// `drbg` is live with a `ProvDrbgCtr` in `data`.
unsafe fn drbg_ctr_init(drbg: *mut ProvDrbg) -> c_int {
    // SAFETY: `drbg` is live per the contract.
    unsafe {
        let ctr = (*drbg).data.cast::<ProvDrbgCtr>();
        if (*ctr).cipher_ctr.is_null() {
            raise_site(&err_sites::PROV_DRBG_CTR_577);
            return 0;
        }
        let keylen = EVP_CIPHER_get_key_length((*ctr).cipher_ctr) as usize;
        (*ctr).keylen = keylen;
        if (*ctr).ctx_ecb.is_null() {
            (*ctr).ctx_ecb = EVP_CIPHER_CTX_new();
        }
        if (*ctr).ctx_ctr.is_null() {
            (*ctr).ctx_ctr = EVP_CIPHER_CTX_new();
        }
        if (*ctr).ctx_ecb.is_null() || (*ctr).ctx_ctr.is_null() {
            raise_site(&err_sites::PROV_DRBG_CTR_586);
            EVP_CIPHER_CTX_free((*ctr).ctx_ecb);
            EVP_CIPHER_CTX_free((*ctr).ctx_ctr);
            (*ctr).ctx_ecb = ptr::null_mut();
            (*ctr).ctx_ctr = ptr::null_mut();
            return 0;
        }
        if EVP_CipherInit_ex(
            (*ctr).ctx_ecb,
            (*ctr).cipher_ecb,
            ptr::null_mut(),
            ptr::null(),
            ptr::null(),
            1,
        ) == 0
            || EVP_CipherInit_ex(
                (*ctr).ctx_ctr,
                (*ctr).cipher_ctr,
                ptr::null_mut(),
                ptr::null(),
                ptr::null(),
                1,
            ) == 0
        {
            raise_site(&err_sites::PROV_DRBG_CTR_594);
            EVP_CIPHER_CTX_free((*ctr).ctx_ecb);
            EVP_CIPHER_CTX_free((*ctr).ctx_ctr);
            (*ctr).ctx_ecb = ptr::null_mut();
            (*ctr).ctx_ctr = ptr::null_mut();
            return 0;
        }

        (*drbg).strength = (keylen * 8) as c_uint;
        (*drbg).seedlen = keylen + 16;

        // #ifdef FIPS_MODULE: use_df == 0 is refused with
        // PROV_R_DERIVATION_FUNCTION_INIT_FAILED and the message "FIPS requires the use of a
        // derivation function".

        if (*ctr).use_df != 0 {
            const DF_KEY: [c_uchar; 32] = [
                0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
                0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
                0x1c, 0x1d, 0x1e, 0x1f,
            ];
            if (*ctr).ctx_df.is_null() {
                (*ctr).ctx_df = EVP_CIPHER_CTX_new();
            }
            if (*ctr).ctx_df.is_null() {
                raise_site(&err_sites::PROV_DRBG_CTR_625);
                EVP_CIPHER_CTX_free((*ctr).ctx_ecb);
                EVP_CIPHER_CTX_free((*ctr).ctx_ctr);
                (*ctr).ctx_ecb = ptr::null_mut();
                (*ctr).ctx_ctr = ptr::null_mut();
                return 0;
            }
            // Set the key schedule for df_key.
            if EVP_CipherInit_ex(
                (*ctr).ctx_df,
                (*ctr).cipher_ecb,
                ptr::null_mut(),
                DF_KEY.as_ptr(),
                ptr::null(),
                1,
            ) == 0
            {
                raise_site(&err_sites::PROV_DRBG_CTR_631);
                EVP_CIPHER_CTX_free((*ctr).ctx_ecb);
                EVP_CIPHER_CTX_free((*ctr).ctx_ctr);
                (*ctr).ctx_ecb = ptr::null_mut();
                (*ctr).ctx_ctr = ptr::null_mut();
                return 0;
            }
        }
        drbg_ctr_init_lengths(drbg)
    }
}

/// `static int drbg_ctr_new(PROV_DRBG *drbg)` — `drbg_ctr.c:646-658`.
///
/// # Safety
/// `drbg` must be live.
unsafe extern "C" fn drbg_ctr_new(drbg: *mut ProvDrbg) -> c_int {
    // SAFETY: `drbg` is live per the contract.
    unsafe {
        let ctr = CRYPTO_secure_zalloc(core::mem::size_of::<ProvDrbgCtr>(), FILE_DRBG_CTR, LINE)
            .cast::<ProvDrbgCtr>();
        if ctr.is_null() {
            return 0;
        }
        (*ctr).use_df = 1;
        (*drbg).data = ctr.cast();
        // OSSL_FIPS_IND_INIT(drbg) is a no-op when FIPS_MODULE is undefined.
        drbg_ctr_init_lengths(drbg)
    }
}

/// `static void *drbg_ctr_new_wrapper(void *provctx, void *parent, const OSSL_DISPATCH
/// *parent_dispatch)` — `drbg_ctr.c:660-667`.
///
/// # Safety
/// The `OSSL_FUNC_rand_newctx_fn` contract.
unsafe extern "C" fn drbg_ctr_new_wrapper(
    provctx: *mut c_void,
    parent: *mut c_void,
    parent_dispatch: *const OsslDispatch,
) -> *mut c_void {
    // SAFETY: the dispatch contract; the callback addresses are this module's.
    unsafe {
        ossl_rand_drbg_new(
            provctx.cast::<ProvCtx>(),
            parent,
            parent_dispatch,
            drbg_ctr_new,
            drbg_ctr_free,
            drbg_ctr_instantiate,
            drbg_ctr_uninstantiate,
            drbg_ctr_reseed,
            drbg_ctr_generate,
        )
        .cast()
    }
}

/// `static void drbg_ctr_free(void *vdrbg)` — `drbg_ctr.c:669-684`.
///
/// # Safety
/// `vdrbg` is NULL or what `drbg_ctr_new_wrapper` returned.
unsafe extern "C" fn drbg_ctr_free(vdrbg: *mut c_void) {
    // SAFETY: `vdrbg` is per the contract.
    unsafe {
        let drbg = vdrbg.cast::<ProvDrbg>();
        if !drbg.is_null() {
            let ctr = (*drbg).data.cast::<ProvDrbgCtr>();
            if !ctr.is_null() {
                EVP_CIPHER_CTX_free((*ctr).ctx_ecb);
                EVP_CIPHER_CTX_free((*ctr).ctx_ctr);
                EVP_CIPHER_CTX_free((*ctr).ctx_df);
                EVP_CIPHER_free((*ctr).cipher_ecb);
                EVP_CIPHER_free((*ctr).cipher_ctr);
                CRYPTO_secure_clear_free(
                    ctr.cast(),
                    core::mem::size_of::<ProvDrbgCtr>(),
                    FILE_DRBG_CTR,
                    LINE,
                );
            }
        }
        ossl_rand_drbg_free(drbg);
    }
}

// ---- CTR generated get-ctx-params decoder ---------------------------------------------------

/// The get-decoder's repeat raise sites. The generated decoder is the one `produce_param_decoder`
// emits for the spec at `drbg_ctr.c.in:689-706`: the fields are `cipher`, `df`, `state`, `str`,
/// `maxreq`, `minentlen`, `maxentlen`, `minnonlen`, `maxnonlen`, `maxperlen`, `maxadlen`,
/// `reseed_cnt`, `reseed_time`, `reseed_req`, `reseed_int` (`ind` is `fips`-guarded and absent).
///
/// **The line numbers of the generated raise sites are not recoverable from the `.c.in`**, so
/// the `err_sites::PROV_DRBG_CTR_DECODER_*` names below do not exist yet and must be generated
/// by the same tool that produced `PROV_CMAC_PROV_*` (reason `PROV_R_REPEATED_PARAMETER`, 252;
/// function `drbg_ctr_get_ctx_params_decoder`).
const DRBG_CTR_GET_PARAMS_DECODER_KEYS: [(&err_sites::ErrSite, *const c_char); 15] = [
    (&err_sites::PROV_DRBG_CTR_751, OSSL_DRBG_PARAM_CIPHER),
    (&err_sites::PROV_DRBG_CTR_1015, OSSL_DRBG_PARAM_USE_DF),
    (&err_sites::PROV_DRBG_CTR_991, OSSL_RAND_PARAM_STATE),
    (&err_sites::PROV_DRBG_CTR_1002, OSSL_RAND_PARAM_STRENGTH),
    (&err_sites::PROV_DRBG_CTR_835, OSSL_RAND_PARAM_MAX_REQUEST),
    (
        &err_sites::PROV_DRBG_CTR_861,
        OSSL_DRBG_PARAM_MIN_ENTROPYLEN,
    ),
    (
        &err_sites::PROV_DRBG_CTR_802,
        OSSL_DRBG_PARAM_MAX_ENTROPYLEN,
    ),
    (&err_sites::PROV_DRBG_CTR_872, OSSL_DRBG_PARAM_MIN_NONCELEN),
    (&err_sites::PROV_DRBG_CTR_813, OSSL_DRBG_PARAM_MAX_NONCELEN),
    (&err_sites::PROV_DRBG_CTR_824, OSSL_DRBG_PARAM_MAX_PERSLEN),
    (&err_sites::PROV_DRBG_CTR_791, OSSL_DRBG_PARAM_MAX_ADINLEN),
    (
        &err_sites::PROV_DRBG_CTR_915,
        OSSL_DRBG_PARAM_RESEED_COUNTER,
    ),
    (&err_sites::PROV_DRBG_CTR_962, OSSL_DRBG_PARAM_RESEED_TIME),
    (
        &err_sites::PROV_DRBG_CTR_926,
        OSSL_DRBG_PARAM_RESEED_REQUESTS,
    ),
    (
        &err_sites::PROV_DRBG_CTR_953,
        OSSL_DRBG_PARAM_RESEED_TIME_INTERVAL,
    ),
];

/// `drbg_ctr_get_ctx_params_decoder` — generated by `produce_param_decoder` at
/// `drbg_ctr.c.in:689-706`. Transcribed as the crate's repeated-key scan plus one locate per
/// field, which is `src/provider/mac.rs`'s form for the same generated machinery.
///
/// # Safety
/// `params` is NULL or key-terminated; `r` is writable.
unsafe fn drbg_ctr_get_ctx_params_decoder(
    params: *const OsslParam,
    r: *mut DrbgGetCtxParams,
) -> c_int {
    // SAFETY: the arguments are per the contract.
    unsafe {
        ptr::write(r, DrbgGetCtxParams::EMPTY);
        if let Some(site) = repeated_param_site(params, &DRBG_CTR_GET_PARAMS_DECODER_KEYS) {
            return fail_at(site);
        }
        (*r).cipher = OSSL_PARAM_locate_const(params, OSSL_DRBG_PARAM_CIPHER) as *mut OsslParam;
        (*r).df = OSSL_PARAM_locate_const(params, OSSL_DRBG_PARAM_USE_DF) as *mut OsslParam;
        (*r).state = OSSL_PARAM_locate_const(params, OSSL_RAND_PARAM_STATE) as *mut OsslParam;
        (*r).str = OSSL_PARAM_locate_const(params, OSSL_RAND_PARAM_STRENGTH) as *mut OsslParam;
        (*r).maxreq =
            OSSL_PARAM_locate_const(params, OSSL_RAND_PARAM_MAX_REQUEST) as *mut OsslParam;
        (*r).minentlen =
            OSSL_PARAM_locate_const(params, OSSL_DRBG_PARAM_MIN_ENTROPYLEN) as *mut OsslParam;
        (*r).maxentlen =
            OSSL_PARAM_locate_const(params, OSSL_DRBG_PARAM_MAX_ENTROPYLEN) as *mut OsslParam;
        (*r).minnonlen =
            OSSL_PARAM_locate_const(params, OSSL_DRBG_PARAM_MIN_NONCELEN) as *mut OsslParam;
        (*r).maxnonlen =
            OSSL_PARAM_locate_const(params, OSSL_DRBG_PARAM_MAX_NONCELEN) as *mut OsslParam;
        (*r).maxperlen =
            OSSL_PARAM_locate_const(params, OSSL_DRBG_PARAM_MAX_PERSLEN) as *mut OsslParam;
        (*r).maxadlen =
            OSSL_PARAM_locate_const(params, OSSL_DRBG_PARAM_MAX_ADINLEN) as *mut OsslParam;
        (*r).reseed_cnt =
            OSSL_PARAM_locate_const(params, OSSL_DRBG_PARAM_RESEED_COUNTER) as *mut OsslParam;
        (*r).reseed_time =
            OSSL_PARAM_locate_const(params, OSSL_DRBG_PARAM_RESEED_TIME) as *mut OsslParam;
        (*r).reseed_req =
            OSSL_PARAM_locate_const(params, OSSL_DRBG_PARAM_RESEED_REQUESTS) as *mut OsslParam;
        (*r).reseed_int =
            OSSL_PARAM_locate_const(params, OSSL_DRBG_PARAM_RESEED_TIME_INTERVAL) as *mut OsslParam;
        1
    }
}

/// `drbg_ctr_get_ctx_params_list[]` — generated at `drbg_ctr.c.in:689-706`, in spec order, with
/// the `fips` entry absent.
static DRBG_CTR_GET_CTX_PARAMS_LIST: [OsslParam; 16] = [
    param_utf8_string(OSSL_DRBG_PARAM_CIPHER),
    param_int(OSSL_DRBG_PARAM_USE_DF),
    param_int(OSSL_RAND_PARAM_STATE),
    param_uint(OSSL_RAND_PARAM_STRENGTH),
    param_size_t(OSSL_RAND_PARAM_MAX_REQUEST),
    param_size_t(OSSL_DRBG_PARAM_MIN_ENTROPYLEN),
    param_size_t(OSSL_DRBG_PARAM_MAX_ENTROPYLEN),
    param_size_t(OSSL_DRBG_PARAM_MIN_NONCELEN),
    param_size_t(OSSL_DRBG_PARAM_MAX_NONCELEN),
    param_size_t(OSSL_DRBG_PARAM_MAX_PERSLEN),
    param_size_t(OSSL_DRBG_PARAM_MAX_ADINLEN),
    param_uint(OSSL_DRBG_PARAM_RESEED_COUNTER),
    param_time_t(OSSL_DRBG_PARAM_RESEED_TIME),
    param_uint(OSSL_DRBG_PARAM_RESEED_REQUESTS),
    param_uint64(OSSL_DRBG_PARAM_RESEED_TIME_INTERVAL),
    END,
];

/// `static int drbg_ctr_get_ctx_params(void *vdrbg, OSSL_PARAM params[])` — `drbg_ctr.c:709-746`.
///
/// # Safety
/// The `OSSL_FUNC_rand_get_ctx_params_fn` contract.
unsafe extern "C" fn drbg_ctr_get_ctx_params(vdrbg: *mut c_void, params: *mut OsslParam) -> c_int {
    // SAFETY: the dispatch contract.
    unsafe {
        let drbg = vdrbg.cast::<ProvDrbg>();
        let mut p = DrbgGetCtxParams::EMPTY;
        if drbg.is_null() || drbg_ctr_get_ctx_params_decoder(params, &mut p) == 0 {
            return 0;
        }
        let mut complete: c_int = 0;
        if ossl_drbg_get_ctx_params_no_lock(drbg, &p, params, &mut complete) == 0 {
            return 0;
        }
        if complete != 0 {
            return 1;
        }
        let ctr = (*drbg).data.cast::<ProvDrbgCtr>();
        if !(*drbg).lock.is_null() && CRYPTO_THREAD_read_lock((*drbg).lock) == 0 {
            return 0;
        }
        let mut ret = 0;
        if !p.df.is_null() && OSSL_PARAM_set_int(p.df, (*ctr).use_df) == 0 {
            // goto err
            if !(*drbg).lock.is_null() {
                CRYPTO_THREAD_unlock((*drbg).lock);
            }
            return ret;
        }
        if !p.cipher.is_null()
            && ((*ctr).cipher_ctr.is_null()
                || OSSL_PARAM_set_utf8_string(p.cipher, EVP_CIPHER_get0_name((*ctr).cipher_ctr))
                    == 0)
        {
            if !(*drbg).lock.is_null() {
                CRYPTO_THREAD_unlock((*drbg).lock);
            }
            return ret;
        }
        ret = ossl_drbg_get_ctx_params(drbg, &p);
        if !(*drbg).lock.is_null() {
            CRYPTO_THREAD_unlock((*drbg).lock);
        }
        ret
    }
}

/// `static const OSSL_PARAM *drbg_ctr_gettable_ctx_params(void *vctx, void *provctx)`
/// — `drbg_ctr.c:748-752`.
///
/// # Safety
/// The `OSSL_FUNC_rand_gettable_ctx_params_fn` contract.
unsafe extern "C" fn drbg_ctr_gettable_ctx_params(
    _vctx: *mut c_void,
    _provctx: *mut c_void,
) -> *const OsslParam {
    DRBG_CTR_GET_CTX_PARAMS_LIST.as_ptr()
}

// ---- CTR set-ctx-params decoder and body ----------------------------------------------------

/// The set-decoder's repeat raise sites, from the spec at `drbg_ctr.c.in:820-827`: `propq`,
/// `cipher`, `df`, `prov`, `reseed_req`, `reseed_time`. The generated sites are missing for the
/// same reason as the get-decoder's.
const DRBG_CTR_SET_PARAMS_DECODER_KEYS: [(&err_sites::ErrSite, *const c_char); 6] = [
    (&err_sites::PROV_DRBG_CTR_1202, OSSL_DRBG_PARAM_PROPERTIES),
    (&err_sites::PROV_DRBG_CTR_1179, OSSL_DRBG_PARAM_CIPHER),
    (&err_sites::PROV_DRBG_CTR_1284, OSSL_DRBG_PARAM_USE_DF),
    (
        &err_sites::PROV_DRBG_CTR_1213,
        OSSL_PROV_PARAM_CORE_PROV_NAME,
    ),
    (
        &err_sites::PROV_DRBG_CTR_1255,
        OSSL_DRBG_PARAM_RESEED_REQUESTS,
    ),
    (
        &err_sites::PROV_DRBG_CTR_1266,
        OSSL_DRBG_PARAM_RESEED_TIME_INTERVAL,
    ),
];

/// `drbg_ctr_set_ctx_params_decoder` — generated at `drbg_ctr.c.in:820-827`.
///
/// # Safety
/// `params` is NULL or key-terminated; `r` is writable.
unsafe fn drbg_ctr_set_ctx_params_decoder(
    params: *const OsslParam,
    r: *mut DrbgSetCtxParams,
) -> c_int {
    // SAFETY: the arguments are per the contract.
    unsafe {
        ptr::write(r, DrbgSetCtxParams::EMPTY);
        if let Some(site) = repeated_param_site(params, &DRBG_CTR_SET_PARAMS_DECODER_KEYS) {
            return fail_at(site);
        }
        (*r).propq = OSSL_PARAM_locate_const(params, OSSL_DRBG_PARAM_PROPERTIES);
        (*r).cipher = OSSL_PARAM_locate_const(params, OSSL_DRBG_PARAM_CIPHER);
        (*r).df = OSSL_PARAM_locate_const(params, OSSL_DRBG_PARAM_USE_DF);
        (*r).prov = OSSL_PARAM_locate_const(params, OSSL_PROV_PARAM_CORE_PROV_NAME);
        (*r).reseed_req = OSSL_PARAM_locate_const(params, OSSL_DRBG_PARAM_RESEED_REQUESTS);
        (*r).reseed_time = OSSL_PARAM_locate_const(params, OSSL_DRBG_PARAM_RESEED_TIME_INTERVAL);
        1
    }
}

/// `drbg_ctr_set_ctx_params_list[]` — generated at `drbg_ctr.c.in:820-827`, in spec order.
static DRBG_CTR_SET_CTX_PARAMS_LIST: [OsslParam; 7] = [
    param_utf8_string(OSSL_DRBG_PARAM_PROPERTIES),
    param_utf8_string(OSSL_DRBG_PARAM_CIPHER),
    param_int(OSSL_DRBG_PARAM_USE_DF),
    param_utf8_string(OSSL_PROV_PARAM_CORE_PROV_NAME),
    param_uint(OSSL_DRBG_PARAM_RESEED_REQUESTS),
    param_uint64(OSSL_DRBG_PARAM_RESEED_TIME_INTERVAL),
    END,
];

/// `static int drbg_ctr_set_ctx_params_locked(PROV_DRBG *ctx, const struct drbg_set_ctx_params_st
/// *p)` — `drbg_ctr.c:754-815`. The `cipher` arm rewrites the trailing `CTR` to `ECB`, fetches
/// both names in `PROV_LIBCTX_OF(ctx->provctx)` under `provider=default` (unless the caller's
/// `properties` says otherwise), and re-runs `drbg_ctr_init`.
///
/// # Safety
/// `ctx` is live and `p` is decoded.
unsafe fn drbg_ctr_set_ctx_params_locked(ctx: *mut ProvDrbg, p: *const DrbgSetCtxParams) -> c_int {
    // SAFETY: `ctx` and `p` are per the contract.
    unsafe {
        let ctr = (*ctx).data.cast::<ProvDrbgCtr>();
        let libctx = prov_libctx_of((*ctx).provctx.cast());
        let mut cipher_init = 0;

        if !(*p).df.is_null() {
            let mut i: c_int = 0;
            if OSSL_PARAM_get_int((*p).df, &mut i) != 0 {
                // FIPS errors out in drbg_ctr_init() later.
                (*ctr).use_df = if i != 0 { 1 } else { 0 };
                cipher_init = 1;
            }
        }

        // #ifndef FIPS_MODULE
        let mut propquery: *const c_char = c"provider=default".as_ptr();
        if !(*p).propq.is_null() && (*(*p).propq).data_type == crate::params::OSSL_PARAM_UTF8_STRING
        {
            propquery = (*(*p).propq).data.cast();
        }
        // #endif

        if !(*p).cipher.is_null() {
            let ctr_str_len = 3usize; // sizeof("CTR") - 1
            let ecb_str_len = 3usize; // sizeof("ECB") - 1
            let base = (*(*p).cipher).data.cast::<c_char>();
            if (*(*p).cipher).data_type != crate::params::OSSL_PARAM_UTF8_STRING
                || (*(*p).cipher).data_size < ctr_str_len
            {
                return 0;
            }
            if OPENSSL_strcasecmp(
                c"CTR".as_ptr(),
                base.add((*(*p).cipher).data_size - ctr_str_len),
            ) != 0
            {
                raise_site(&err_sites::PROV_DRBG_CTR_1105);
                return 0;
            }
            let ecb = CRYPTO_strndup(base, (*(*p).cipher).data_size, FILE_DRBG_CTR, LINE);
            if ecb.is_null() {
                return 0;
            }
            ptr::copy_nonoverlapping(
                c"ECB".as_ptr(),
                ecb.add((*(*p).cipher).data_size - ecb_str_len),
                4,
            );
            EVP_CIPHER_free((*ctr).cipher_ecb);
            EVP_CIPHER_free((*ctr).cipher_ctr);
            (*ctr).cipher_ctr = ptr::null_mut();
            (*ctr).cipher_ecb = ptr::null_mut();
            // Fetch from our own provider first; the fetch falls back on its own.
            (*ctr).cipher_ctr = EVP_CIPHER_fetch(libctx, base, propquery);
            (*ctr).cipher_ecb = EVP_CIPHER_fetch(libctx, ecb, propquery);
            CRYPTO_free(ecb.cast(), FILE_DRBG_CTR, LINE);
            if (*ctr).cipher_ctr.is_null() || (*ctr).cipher_ecb.is_null() {
                raise_site(&err_sites::PROV_DRBG_CTR_1124);
                return 0;
            }
            cipher_init = 1;
        }

        if cipher_init != 0 && drbg_ctr_init(ctx) == 0 {
            return 0;
        }
        ossl_drbg_set_ctx_params(ctx, p)
    }
}

/// `static int drbg_ctr_set_ctx_params(void *vctx, const OSSL_PARAM params[])`
/// — `drbg_ctr.c:830-848`.
///
/// # Safety
/// The `OSSL_FUNC_rand_set_ctx_params_fn` contract.
unsafe extern "C" fn drbg_ctr_set_ctx_params(vctx: *mut c_void, params: *const OsslParam) -> c_int {
    // SAFETY: the dispatch contract.
    unsafe {
        let drbg = vctx.cast::<ProvDrbg>();
        let mut p = DrbgSetCtxParams::EMPTY;
        if drbg.is_null() || drbg_ctr_set_ctx_params_decoder(params, &mut p) == 0 {
            return 0;
        }
        if !(*drbg).lock.is_null() && CRYPTO_THREAD_write_lock((*drbg).lock) == 0 {
            return 0;
        }
        let ret = drbg_ctr_set_ctx_params_locked(drbg, &p);
        if !(*drbg).lock.is_null() {
            CRYPTO_THREAD_unlock((*drbg).lock);
        }
        ret
    }
}

/// `static const OSSL_PARAM *drbg_ctr_settable_ctx_params(void *vctx, void *provctx)`
/// — `drbg_ctr.c:850-854`.
///
/// # Safety
/// The `OSSL_FUNC_rand_settable_ctx_params_fn` contract.
unsafe extern "C" fn drbg_ctr_settable_ctx_params(
    _vctx: *mut c_void,
    _provctx: *mut c_void,
) -> *const OsslParam {
    DRBG_CTR_SET_CTX_PARAMS_LIST.as_ptr()
}

/// `const OSSL_DISPATCH ossl_drbg_ctr_functions[]` — `drbg_ctr.c:856-879`, sixteen entries.
pub(crate) static DRBG_CTR_FUNCTIONS: [OsslDispatch; 17] = [
    OsslDispatch {
        function_id: OSSL_FUNC_RAND_NEWCTX,
        function: drbg_ctr_new_wrapper as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_RAND_FREECTX,
        function: drbg_ctr_free as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_RAND_INSTANTIATE,
        function: drbg_ctr_instantiate_wrapper as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_RAND_UNINSTANTIATE,
        function: drbg_ctr_uninstantiate_wrapper as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_RAND_GENERATE,
        function: drbg_ctr_generate_wrapper as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_RAND_RESEED,
        function: drbg_ctr_reseed_wrapper as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_RAND_ENABLE_LOCKING,
        function: ossl_drbg_enable_locking as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_RAND_LOCK,
        function: ossl_drbg_lock as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_RAND_UNLOCK,
        function: ossl_drbg_unlock as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_RAND_SETTABLE_CTX_PARAMS,
        function: drbg_ctr_settable_ctx_params as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_RAND_SET_CTX_PARAMS,
        function: drbg_ctr_set_ctx_params as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_RAND_GETTABLE_CTX_PARAMS,
        function: drbg_ctr_gettable_ctx_params as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_RAND_GET_CTX_PARAMS,
        function: drbg_ctr_get_ctx_params as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_RAND_VERIFY_ZEROIZATION,
        function: drbg_ctr_verify_zeroization as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_RAND_GET_SEED,
        function: ossl_drbg_get_seed as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_RAND_CLEAR_SEED,
        function: ossl_drbg_clear_seed as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_DISPATCH_END,
        function: ptr::null_mut(),
    },
];

// =============================================================================================
// `drbg_hash.c` — the HASH-DRBG
// =============================================================================================

/// `HASH_PRNG_MAX_SEEDLEN` — `(888 / 8)`.
const HASH_PRNG_MAX_SEEDLEN: usize = 888 / 8;
/// `HASH_PRNG_SMALL_SEEDLEN` — `(440 / 8)`.
const HASH_PRNG_SMALL_SEEDLEN: usize = 440 / 8;
/// `MAX_BLOCKLEN_USING_SMALL_SEEDLEN` — `(256 / 8)`.
const MAX_BLOCKLEN_USING_SMALL_SEEDLEN: usize = 256 / 8;
/// `INBYTE_IGNORE` — `((unsigned char)0xFF)`.
const INBYTE_IGNORE: c_uchar = 0xFF;

/// `struct rand_drbg_hash_st` — `drbg_hash.c:61-69`.
#[repr(C)]
pub(crate) struct ProvDrbgHash {
    /// `PROV_DIGEST digest`.
    pub digest: ProvDigest,
    /// `EVP_MD_CTX *ctx`.
    pub ctx: *mut EvpMdCtx,
    /// `size_t blocklen`.
    pub blocklen: usize,
    /// `unsigned char V[HASH_PRNG_MAX_SEEDLEN]`.
    pub v: [c_uchar; HASH_PRNG_MAX_SEEDLEN],
    /// `unsigned char C[HASH_PRNG_MAX_SEEDLEN]`.
    pub c: [c_uchar; HASH_PRNG_MAX_SEEDLEN],
    /// `unsigned char vtmp[HASH_PRNG_MAX_SEEDLEN]` — always at least the maximum digest length.
    pub vtmp: [c_uchar; HASH_PRNG_MAX_SEEDLEN],
}

/// `static int hash_df(PROV_DRBG *drbg, unsigned char *out, const unsigned char inbyte, const
/// unsigned char *in, size_t inlen, const unsigned char *in2, size_t in2len, const unsigned
/// char *in3, size_t in3len)` — `drbg_hash.c:80-141`. SP800-90Ar1 10.3.1.
///
/// # Safety
/// `drbg` is live with a `ProvDrbgHash` in `data`.
#[allow(clippy::too_many_arguments)] // mirrors the authority's signature exactly
unsafe fn hash_df(
    drbg: *mut ProvDrbg,
    out: *mut c_uchar,
    inbyte: c_uchar,
    in_: *const c_uchar,
    inlen: usize,
    in2: *const c_uchar,
    in2len: usize,
    in3: *const c_uchar,
    in3len: usize,
) -> c_int {
    // SAFETY: `drbg` is live per the contract.
    unsafe {
        let hash = (*drbg).data.cast::<ProvDrbgHash>();
        let ctx = (*hash).ctx;
        let vtmp = (*hash).vtmp.as_mut_ptr();
        let mut tmp = [0u8; 1 + 4 + 1];
        let mut tmp_sz = 0usize;
        let mut out = out;
        let mut outlen = (*drbg).seedlen;
        let num_bits_returned = outlen * 8;

        // (Step 3) counter = 1.
        tmp[tmp_sz] = 1;
        tmp_sz += 1;
        tmp[tmp_sz] = ((num_bits_returned >> 24) & 0xff) as c_uchar;
        tmp_sz += 1;
        tmp[tmp_sz] = ((num_bits_returned >> 16) & 0xff) as c_uchar;
        tmp_sz += 1;
        tmp[tmp_sz] = ((num_bits_returned >> 8) & 0xff) as c_uchar;
        tmp_sz += 1;
        tmp[tmp_sz] = (num_bits_returned & 0xff) as c_uchar;
        tmp_sz += 1;
        if inbyte != INBYTE_IGNORE {
            tmp[tmp_sz] = inbyte;
            tmp_sz += 1;
        }

        loop {
            let md = ossl_prov_digest_md(&(*hash).digest);
            if EVP_DigestInit_ex(ctx, md, ptr::null_mut()) == 0
                || EVP_DigestUpdate(ctx, tmp.as_ptr().cast(), tmp_sz) == 0
                || EVP_DigestUpdate(ctx, in_.cast::<c_void>(), inlen) == 0
                || (!in2.is_null() && EVP_DigestUpdate(ctx, in2.cast::<c_void>(), in2len) == 0)
                || (!in3.is_null() && EVP_DigestUpdate(ctx, in3.cast::<c_void>(), in3len) == 0)
            {
                return 0;
            }
            if outlen < (*hash).blocklen {
                if EVP_DigestFinal(ctx, vtmp, ptr::null_mut()) == 0 {
                    return 0;
                }
                ptr::copy_nonoverlapping(vtmp, out, outlen);
                cleanse(vtmp.cast(), (*hash).blocklen);
                break;
            } else if EVP_DigestFinal(ctx, out, ptr::null_mut()) == 0 {
                return 0;
            }
            outlen -= (*hash).blocklen;
            if outlen == 0 {
                break;
            }
            // (Step 4.2) counter++.
            tmp[0] = tmp[0].wrapping_add(1);
            out = out.add((*hash).blocklen);
        }
        1
    }
}

/// `static int hash_df1(PROV_DRBG *drbg, unsigned char *out, const unsigned char in_byte, const
/// unsigned char *in1, size_t in1len)` — `drbg_hash.c:144-149`.
///
/// # Safety
/// As `hash_df`.
unsafe fn hash_df1(
    drbg: *mut ProvDrbg,
    out: *mut c_uchar,
    in_byte: c_uchar,
    in1: *const c_uchar,
    in1len: usize,
) -> c_int {
    // SAFETY: the arguments are forwarded under `hash_df`'s contract.
    unsafe {
        hash_df(
            drbg,
            out,
            in_byte,
            in1,
            in1len,
            ptr::null(),
            0,
            ptr::null(),
            0,
        )
    }
}

/// `static int add_bytes(PROV_DRBG *drbg, unsigned char *dst, unsigned char *in, size_t inlen)`
/// — `drbg_hash.c:157-185`. `dst = (dst + in) mod 2^seedlen_bits`, final carry ignored.
///
/// # Safety
/// `drbg` is live and `dst`/`in` are valid for their stated lengths.
unsafe fn add_bytes(
    drbg: *mut ProvDrbg,
    dst: *mut c_uchar,
    in_: *mut c_uchar,
    inlen: usize,
) -> c_int {
    // SAFETY: `drbg` and the buffers are per the contract.
    unsafe {
        debug_assert!((*drbg).seedlen >= 1 && inlen >= 1 && inlen <= (*drbg).seedlen);
        let mut d = dst.add((*drbg).seedlen - 1);
        let mut add = in_.add(inlen - 1);
        let mut carry: c_uchar = 0;
        let mut i = inlen;
        while i > 0 {
            let result = (*d as c_int) + (*add as c_int) + (carry as c_int);
            carry = (result >> 8) as c_uchar;
            *d = (result & 0xff) as c_uchar;
            d = d.sub(1);
            add = add.sub(1);
            i -= 1;
        }
        if carry != 0 {
            // Add the carry to the top of dst if inlen is not the same size.
            let mut i = (*drbg).seedlen - inlen;
            while i > 0 {
                // The authority writes `*d += 1;` on an `unsigned char`
                // (drbg_hash.c.in:181), which wraps silently on 0xff. The
                // crate is built with `overflow-checks = true`, so the `+=`
                // would panic on the wrap; use `wrapping_add` to preserve the
                // C semantics. Carry can only be 1.
                *d = (*d).wrapping_add(1);
                if *d != 0 {
                    break;
                }
                d = d.sub(1);
                i -= 1;
            }
        }
        1
    }
}

/// `static int add_hash_to_v(PROV_DRBG *drbg, unsigned char inbyte, const unsigned char *adin,
/// size_t adinlen)` — `drbg_hash.c:188-200`.
///
/// # Safety
/// `drbg` is live with a `ProvDrbgHash` in `data`.
unsafe fn add_hash_to_v(
    drbg: *mut ProvDrbg,
    inbyte: c_uchar,
    adin: *const c_uchar,
    adinlen: usize,
) -> c_int {
    // SAFETY: `drbg` is live per the contract.
    unsafe {
        let hash = (*drbg).data.cast::<ProvDrbgHash>();
        let ctx = (*hash).ctx;
        let md = ossl_prov_digest_md(&(*hash).digest);
        let seedlen = (*drbg).seedlen;
        if EVP_DigestInit_ex(ctx, md, ptr::null_mut()) == 0
            || EVP_DigestUpdate(ctx, (&inbyte as *const c_uchar).cast::<c_void>(), 1) == 0
            || EVP_DigestUpdate(ctx, (*hash).v.as_ptr().cast::<c_void>(), seedlen) == 0
            || (!adin.is_null() && EVP_DigestUpdate(ctx, adin.cast::<c_void>(), adinlen) == 0)
            || EVP_DigestFinal(ctx, (*hash).vtmp.as_mut_ptr(), ptr::null_mut()) == 0
        {
            return 0;
        }
        let blocklen = (*hash).blocklen;
        add_bytes(
            drbg,
            (*hash).v.as_mut_ptr(),
            (*hash).vtmp.as_mut_ptr(),
            blocklen,
        )
    }
}

/// `static int hash_gen(PROV_DRBG *drbg, unsigned char *out, size_t outlen)` — `drbg_hash.c:220-250`.
///
/// # Safety
/// `drbg` is live with a `ProvDrbgHash` in `data`; `out` writable for `outlen`.
unsafe fn hash_gen(drbg: *mut ProvDrbg, out: *mut c_uchar, outlen: usize) -> c_int {
    // SAFETY: `drbg` is live per the contract.
    unsafe {
        let hash = (*drbg).data.cast::<ProvDrbgHash>();
        let one: c_uchar = 1;
        if outlen == 0 {
            return 1;
        }
        let seedlen = (*drbg).seedlen;
        ptr::copy_nonoverlapping((*hash).v.as_ptr(), (*hash).vtmp.as_mut_ptr(), seedlen);
        let mut out = out;
        let mut outlen = outlen;
        loop {
            let md = ossl_prov_digest_md(&(*hash).digest);
            if EVP_DigestInit_ex((*hash).ctx, md, ptr::null_mut()) == 0
                || EVP_DigestUpdate((*hash).ctx, (*hash).vtmp.as_ptr().cast::<c_void>(), seedlen)
                    == 0
            {
                return 0;
            }
            if outlen < (*hash).blocklen {
                if EVP_DigestFinal((*hash).ctx, (*hash).vtmp.as_mut_ptr(), ptr::null_mut()) == 0 {
                    return 0;
                }
                ptr::copy_nonoverlapping((*hash).vtmp.as_ptr(), out, outlen);
                return 1;
            } else {
                if EVP_DigestFinal((*hash).ctx, out, ptr::null_mut()) == 0 {
                    return 0;
                }
                outlen -= (*hash).blocklen;
                if outlen == 0 {
                    break;
                }
                out = out.add((*hash).blocklen);
            }
            add_bytes(
                drbg,
                (*hash).vtmp.as_mut_ptr(),
                ptr::addr_of!(one).cast_mut(),
                1,
            );
        }
        1
    }
}

/// `static int drbg_hash_instantiate(PROV_DRBG *drbg, const unsigned char *ent, size_t ent_len,
/// const unsigned char *nonce, size_t nonce_len, const unsigned char *pstr, size_t pstr_len)`
/// — `drbg_hash.c:261-277`.
///
/// # Safety
/// `drbg` is live with a `ProvDrbgHash` in `data`.
unsafe extern "C" fn drbg_hash_instantiate(
    drbg: *mut ProvDrbg,
    ent: *const c_uchar,
    ent_len: usize,
    nonce: *const c_uchar,
    nonce_len: usize,
    pstr: *const c_uchar,
    pstr_len: usize,
) -> c_int {
    // SAFETY: `drbg` is live per the contract.
    unsafe {
        let hash = (*drbg).data.cast::<ProvDrbgHash>();
        EVP_MD_CTX_free((*hash).ctx);
        (*hash).ctx = EVP_MD_CTX_new();
        // (Step 1-3) V = Hash_df(entropy||nonce||pers, seedlen).
        if (*hash).ctx.is_null() {
            return 0;
        }
        if hash_df(
            drbg,
            (*hash).v.as_mut_ptr(),
            INBYTE_IGNORE,
            ent,
            ent_len,
            nonce,
            nonce_len,
            pstr,
            pstr_len,
        ) == 0
        {
            return 0;
        }
        // (Step 4) C = Hash_df(0x00||V, seedlen).
        hash_df1(
            drbg,
            (*hash).c.as_mut_ptr(),
            0x00,
            (*hash).v.as_ptr(),
            (*drbg).seedlen,
        )
    }
}

/// `static int drbg_hash_instantiate_wrapper(void *vdrbg, unsigned int strength, int
/// prediction_resistance, const unsigned char *pstr, size_t pstr_len, const OSSL_PARAM
/// params[])` — `drbg_hash.c:279-304`.
///
/// # Safety
/// The `OSSL_FUNC_rand_instantiate_fn` contract.
unsafe extern "C" fn drbg_hash_instantiate_wrapper(
    vdrbg: *mut c_void,
    strength: c_uint,
    prediction_resistance: c_int,
    pstr: *const c_uchar,
    pstr_len: usize,
    params: *const OsslParam,
) -> c_int {
    // SAFETY: the dispatch contract.
    unsafe {
        let drbg = vdrbg.cast::<ProvDrbg>();
        let mut p = DrbgSetCtxParams::EMPTY;
        if drbg.is_null() || drbg_hash_set_ctx_params_decoder(params, &mut p) == 0 {
            return 0;
        }
        if !(*drbg).lock.is_null() && CRYPTO_THREAD_write_lock((*drbg).lock) == 0 {
            return 0;
        }
        let mut ret = 0;
        if is_running() != 0 && drbg_hash_set_ctx_params_locked(drbg, &p) != 0 {
            ret = ossl_prov_drbg_instantiate(drbg, strength, prediction_resistance, pstr, pstr_len);
        }
        if !(*drbg).lock.is_null() {
            CRYPTO_THREAD_unlock((*drbg).lock);
        }
        ret
    }
}

/// `static int drbg_hash_reseed(PROV_DRBG *drbg, const unsigned char *ent, size_t ent_len, const
/// unsigned char *adin, size_t adin_len)` — `drbg_hash.c:314-328`.
///
/// # Safety
/// `drbg` is live with a `ProvDrbgHash` in `data`.
unsafe extern "C" fn drbg_hash_reseed(
    drbg: *mut ProvDrbg,
    ent: *const c_uchar,
    ent_len: usize,
    adin: *const c_uchar,
    adin_len: usize,
) -> c_int {
    // SAFETY: `drbg` is live per the contract.
    unsafe {
        let hash = (*drbg).data.cast::<ProvDrbgHash>();
        // (Step 1-2) V = Hash_df(0x01 || V || entropy_input || additional_input).
        if hash_df(
            drbg,
            (*hash).c.as_mut_ptr(),
            0x01,
            (*hash).v.as_ptr(),
            (*drbg).seedlen,
            ent,
            ent_len,
            adin,
            adin_len,
        ) == 0
        {
            return 0;
        }
        let seedlen = (*drbg).seedlen;
        ptr::copy_nonoverlapping((*hash).c.as_ptr(), (*hash).v.as_mut_ptr(), seedlen);
        // (Step 4) C = Hash_df(0x00||V, seedlen).
        hash_df1(
            drbg,
            (*hash).c.as_mut_ptr(),
            0x00,
            (*hash).v.as_ptr(),
            (*drbg).seedlen,
        )
    }
}

/// `static int drbg_hash_reseed_wrapper(void *vdrbg, int prediction_resistance, const unsigned
/// char *ent, size_t ent_len, const unsigned char *adin, size_t adin_len)`
/// — `drbg_hash.c:330-338`.
///
/// # Safety
/// The `OSSL_FUNC_rand_reseed_fn` contract.
unsafe extern "C" fn drbg_hash_reseed_wrapper(
    vdrbg: *mut c_void,
    prediction_resistance: c_int,
    ent: *const c_uchar,
    ent_len: usize,
    adin: *const c_uchar,
    adin_len: usize,
) -> c_int {
    // SAFETY: the dispatch contract.
    unsafe {
        ossl_prov_drbg_reseed(
            vdrbg.cast::<ProvDrbg>(),
            prediction_resistance,
            ent,
            ent_len,
            adin,
            adin_len,
        )
    }
}

/// `static int drbg_hash_generate(PROV_DRBG *drbg, unsigned char *out, size_t outlen, const
/// unsigned char *adin, size_t adin_len)` — `drbg_hash.c:349-376`.
///
/// # Safety
/// `drbg` is live with a `ProvDrbgHash` in `data`; `out` writable for `outlen`.
unsafe extern "C" fn drbg_hash_generate(
    drbg: *mut ProvDrbg,
    out: *mut c_uchar,
    outlen: usize,
    adin: *const c_uchar,
    adin_len: usize,
) -> c_int {
    // SAFETY: `drbg` is live per the contract.
    unsafe {
        let hash = (*drbg).data.cast::<ProvDrbgHash>();
        let mut counter = [0u8; 4];
        let reseed_counter = (*drbg).generate_counter;
        counter[0] = ((reseed_counter >> 24) & 0xff) as c_uchar;
        counter[1] = ((reseed_counter >> 16) & 0xff) as c_uchar;
        counter[2] = ((reseed_counter >> 8) & 0xff) as c_uchar;
        counter[3] = (reseed_counter & 0xff) as c_uchar;

        if (*hash).ctx.is_null() {
            return 0;
        }
        // (Step 2) if adin != NULL then V = V + Hash(0x02||V||adin).
        if !adin.is_null() && adin_len != 0 && add_hash_to_v(drbg, 0x02, adin, adin_len) == 0 {
            return 0;
        }
        // (Step 3) Hashgen(outlen, V).
        if hash_gen(drbg, out, outlen) == 0 {
            return 0;
        }
        // (Step 4/5) H = V = (V + Hash(0x03||V)) mod 2^seedlen_bits.
        if add_hash_to_v(drbg, 0x03, ptr::null(), 0) == 0 {
            return 0;
        }
        // (Step 5) V = (V + H + C + reseed_counter) mod 2^seedlen_bits.
        if add_bytes(
            drbg,
            (*hash).v.as_mut_ptr(),
            (*hash).c.as_mut_ptr(),
            (*drbg).seedlen,
        ) == 0
        {
            return 0;
        }
        add_bytes(drbg, (*hash).v.as_mut_ptr(), counter.as_mut_ptr(), 4)
    }
}

/// `static int drbg_hash_generate_wrapper(void *vdrbg, unsigned char *out, size_t outlen,
/// unsigned int strength, int prediction_resistance, const unsigned char *adin, size_t
/// adin_len)` — `drbg_hash.c:378-385`.
///
/// # Safety
/// The `OSSL_FUNC_rand_generate_fn` contract.
unsafe extern "C" fn drbg_hash_generate_wrapper(
    vdrbg: *mut c_void,
    out: *mut c_uchar,
    outlen: usize,
    strength: c_uint,
    prediction_resistance: c_int,
    adin: *const c_uchar,
    adin_len: usize,
) -> c_int {
    // SAFETY: the dispatch contract.
    unsafe {
        ossl_prov_drbg_generate(
            vdrbg.cast::<ProvDrbg>(),
            out,
            outlen,
            strength,
            prediction_resistance,
            adin,
            adin_len,
        )
    }
}

/// `static int drbg_hash_uninstantiate(PROV_DRBG *drbg)` — `drbg_hash.c:387-395`.
///
/// # Safety
/// `drbg` is live with a `ProvDrbgHash` in `data`.
unsafe extern "C" fn drbg_hash_uninstantiate(drbg: *mut ProvDrbg) -> c_int {
    // SAFETY: `drbg` is live per the contract.
    unsafe {
        let hash = (*drbg).data.cast::<ProvDrbgHash>();
        cleanse((*hash).v.as_mut_ptr().cast(), HASH_PRNG_MAX_SEEDLEN);
        cleanse((*hash).c.as_mut_ptr().cast(), HASH_PRNG_MAX_SEEDLEN);
        cleanse((*hash).vtmp.as_mut_ptr().cast(), HASH_PRNG_MAX_SEEDLEN);
        ossl_prov_drbg_uninstantiate(drbg)
    }
}

/// `static int drbg_hash_uninstantiate_wrapper(void *vdrbg)` — `drbg_hash.c:397-411`.
///
/// # Safety
/// The `OSSL_FUNC_rand_uninstantiate_fn` contract.
unsafe extern "C" fn drbg_hash_uninstantiate_wrapper(vdrbg: *mut c_void) -> c_int {
    // SAFETY: the dispatch contract.
    unsafe {
        let drbg = vdrbg.cast::<ProvDrbg>();
        if !(*drbg).lock.is_null() && CRYPTO_THREAD_write_lock((*drbg).lock) == 0 {
            return 0;
        }
        let ret = drbg_hash_uninstantiate(drbg);
        if !(*drbg).lock.is_null() {
            CRYPTO_THREAD_unlock((*drbg).lock);
        }
        ret
    }
}

/// `static int drbg_hash_verify_zeroization(void *vdrbg)` — `drbg_hash.c:413-431`.
///
/// # Safety
/// The `OSSL_FUNC_rand_verify_zeroization_fn` contract.
unsafe extern "C" fn drbg_hash_verify_zeroization(vdrbg: *mut c_void) -> c_int {
    // SAFETY: the dispatch contract.
    unsafe {
        let drbg = vdrbg.cast::<ProvDrbg>();
        let hash = (*drbg).data.cast::<ProvDrbgHash>();
        if !(*drbg).lock.is_null() && CRYPTO_THREAD_read_lock((*drbg).lock) == 0 {
            return 0;
        }
        let mut ret = 0;
        if (*hash).v.iter().all(|b| *b == 0)
            && (*hash).c.iter().all(|b| *b == 0)
            && (*hash).vtmp.iter().all(|b| *b == 0)
        {
            ret = 1;
        }
        if !(*drbg).lock.is_null() {
            CRYPTO_THREAD_unlock((*drbg).lock);
        }
        ret
    }
}

/// `static int drbg_hash_new(PROV_DRBG *ctx)` — `drbg_hash.c:433-453`.
///
/// # Safety
/// `ctx` must be live.
unsafe extern "C" fn drbg_hash_new(ctx: *mut ProvDrbg) -> c_int {
    // SAFETY: `ctx` is live per the contract.
    unsafe {
        let hash = CRYPTO_secure_zalloc(core::mem::size_of::<ProvDrbgHash>(), FILE_DRBG_HASH, LINE)
            .cast::<ProvDrbgHash>();
        if hash.is_null() {
            return 0;
        }
        // OSSL_FIPS_IND_INIT(ctx) is a no-op when FIPS_MODULE is undefined.
        (*ctx).data = hash.cast();
        (*ctx).seedlen = HASH_PRNG_MAX_SEEDLEN;
        (*ctx).max_entropylen = DRBG_MAX_LENGTH;
        (*ctx).max_noncelen = DRBG_MAX_LENGTH;
        (*ctx).max_perslen = DRBG_MAX_LENGTH;
        (*ctx).max_adinlen = DRBG_MAX_LENGTH;
        // Maximum number of bits per request = 2^19 = 2^16 bytes.
        (*ctx).max_request = 1 << 16;
        1
    }
}

/// `static void *drbg_hash_new_wrapper(void *provctx, void *parent, const OSSL_DISPATCH
/// *parent_dispatch)` — `drbg_hash.c:455-462`.
///
/// # Safety
/// The `OSSL_FUNC_rand_newctx_fn` contract.
unsafe extern "C" fn drbg_hash_new_wrapper(
    provctx: *mut c_void,
    parent: *mut c_void,
    parent_dispatch: *const OsslDispatch,
) -> *mut c_void {
    // SAFETY: the dispatch contract; the callback addresses are this module's.
    unsafe {
        ossl_rand_drbg_new(
            provctx.cast::<ProvCtx>(),
            parent,
            parent_dispatch,
            drbg_hash_new,
            drbg_hash_free,
            drbg_hash_instantiate,
            drbg_hash_uninstantiate,
            drbg_hash_reseed,
            drbg_hash_generate,
        )
        .cast()
    }
}

/// `static void drbg_hash_free(void *vdrbg)` — `drbg_hash.c:464-475`.
///
/// # Safety
/// `vdrbg` is NULL or what `drbg_hash_new_wrapper` returned.
unsafe extern "C" fn drbg_hash_free(vdrbg: *mut c_void) {
    // SAFETY: `vdrbg` is per the contract.
    unsafe {
        let drbg = vdrbg.cast::<ProvDrbg>();
        if !drbg.is_null() {
            let hash = (*drbg).data.cast::<ProvDrbgHash>();
            if !hash.is_null() {
                EVP_MD_CTX_free((*hash).ctx);
                ossl_prov_digest_reset(&mut (*hash).digest);
                CRYPTO_secure_clear_free(
                    hash.cast(),
                    core::mem::size_of::<ProvDrbgHash>(),
                    FILE_DRBG_HASH,
                    LINE,
                );
            }
        }
        ossl_rand_drbg_free(drbg);
    }
}

// ---- HASH generated get-ctx-params decoder --------------------------------------------------

/// The get-decoder's repeat raise sites, from the spec at `drbg_hash.c.in:480-496`: `digest`,
/// `state`, `str`, `maxreq`, `minentlen`, `maxentlen`, `minnonlen`, `maxnonlen`, `maxperlen`,
/// `maxadlen`, `reseed_cnt`, `reseed_time`, `reseed_req`, `reseed_int` (`ind` is absent).
const DRBG_HASH_GET_PARAMS_DECODER_KEYS: [(&err_sites::ErrSite, *const c_char); 14] = [
    (&err_sites::PROV_DRBG_HASH_540, OSSL_DRBG_PARAM_DIGEST),
    (&err_sites::PROV_DRBG_HASH_780, OSSL_RAND_PARAM_STATE),
    (&err_sites::PROV_DRBG_HASH_791, OSSL_RAND_PARAM_STRENGTH),
    (&err_sites::PROV_DRBG_HASH_624, OSSL_RAND_PARAM_MAX_REQUEST),
    (
        &err_sites::PROV_DRBG_HASH_650,
        OSSL_DRBG_PARAM_MIN_ENTROPYLEN,
    ),
    (
        &err_sites::PROV_DRBG_HASH_591,
        OSSL_DRBG_PARAM_MAX_ENTROPYLEN,
    ),
    (&err_sites::PROV_DRBG_HASH_661, OSSL_DRBG_PARAM_MIN_NONCELEN),
    (&err_sites::PROV_DRBG_HASH_602, OSSL_DRBG_PARAM_MAX_NONCELEN),
    (&err_sites::PROV_DRBG_HASH_613, OSSL_DRBG_PARAM_MAX_PERSLEN),
    (&err_sites::PROV_DRBG_HASH_580, OSSL_DRBG_PARAM_MAX_ADINLEN),
    (
        &err_sites::PROV_DRBG_HASH_704,
        OSSL_DRBG_PARAM_RESEED_COUNTER,
    ),
    (&err_sites::PROV_DRBG_HASH_751, OSSL_DRBG_PARAM_RESEED_TIME),
    (
        &err_sites::PROV_DRBG_HASH_715,
        OSSL_DRBG_PARAM_RESEED_REQUESTS,
    ),
    (
        &err_sites::PROV_DRBG_HASH_742,
        OSSL_DRBG_PARAM_RESEED_TIME_INTERVAL,
    ),
];

/// `drbg_hash_get_ctx_params_decoder` — generated at `drbg_hash.c.in:480-496`.
///
/// # Safety
/// `params` is NULL or key-terminated; `r` is writable.
unsafe fn drbg_hash_get_ctx_params_decoder(
    params: *const OsslParam,
    r: *mut DrbgGetCtxParams,
) -> c_int {
    // SAFETY: the arguments are per the contract.
    unsafe {
        ptr::write(r, DrbgGetCtxParams::EMPTY);
        if let Some(site) = repeated_param_site(params, &DRBG_HASH_GET_PARAMS_DECODER_KEYS) {
            return fail_at(site);
        }
        (*r).digest = OSSL_PARAM_locate_const(params, OSSL_DRBG_PARAM_DIGEST) as *mut OsslParam;
        (*r).state = OSSL_PARAM_locate_const(params, OSSL_RAND_PARAM_STATE) as *mut OsslParam;
        (*r).str = OSSL_PARAM_locate_const(params, OSSL_RAND_PARAM_STRENGTH) as *mut OsslParam;
        (*r).maxreq =
            OSSL_PARAM_locate_const(params, OSSL_RAND_PARAM_MAX_REQUEST) as *mut OsslParam;
        (*r).minentlen =
            OSSL_PARAM_locate_const(params, OSSL_DRBG_PARAM_MIN_ENTROPYLEN) as *mut OsslParam;
        (*r).maxentlen =
            OSSL_PARAM_locate_const(params, OSSL_DRBG_PARAM_MAX_ENTROPYLEN) as *mut OsslParam;
        (*r).minnonlen =
            OSSL_PARAM_locate_const(params, OSSL_DRBG_PARAM_MIN_NONCELEN) as *mut OsslParam;
        (*r).maxnonlen =
            OSSL_PARAM_locate_const(params, OSSL_DRBG_PARAM_MAX_NONCELEN) as *mut OsslParam;
        (*r).maxperlen =
            OSSL_PARAM_locate_const(params, OSSL_DRBG_PARAM_MAX_PERSLEN) as *mut OsslParam;
        (*r).maxadlen =
            OSSL_PARAM_locate_const(params, OSSL_DRBG_PARAM_MAX_ADINLEN) as *mut OsslParam;
        (*r).reseed_cnt =
            OSSL_PARAM_locate_const(params, OSSL_DRBG_PARAM_RESEED_COUNTER) as *mut OsslParam;
        (*r).reseed_time =
            OSSL_PARAM_locate_const(params, OSSL_DRBG_PARAM_RESEED_TIME) as *mut OsslParam;
        (*r).reseed_req =
            OSSL_PARAM_locate_const(params, OSSL_DRBG_PARAM_RESEED_REQUESTS) as *mut OsslParam;
        (*r).reseed_int =
            OSSL_PARAM_locate_const(params, OSSL_DRBG_PARAM_RESEED_TIME_INTERVAL) as *mut OsslParam;
        1
    }
}

/// `drbg_hash_get_ctx_params_list[]` — generated at `drbg_hash.c.in:480-496`.
static DRBG_HASH_GET_CTX_PARAMS_LIST: [OsslParam; 15] = [
    param_utf8_string(OSSL_DRBG_PARAM_DIGEST),
    param_int(OSSL_RAND_PARAM_STATE),
    param_uint(OSSL_RAND_PARAM_STRENGTH),
    param_size_t(OSSL_RAND_PARAM_MAX_REQUEST),
    param_size_t(OSSL_DRBG_PARAM_MIN_ENTROPYLEN),
    param_size_t(OSSL_DRBG_PARAM_MAX_ENTROPYLEN),
    param_size_t(OSSL_DRBG_PARAM_MIN_NONCELEN),
    param_size_t(OSSL_DRBG_PARAM_MAX_NONCELEN),
    param_size_t(OSSL_DRBG_PARAM_MAX_PERSLEN),
    param_size_t(OSSL_DRBG_PARAM_MAX_ADINLEN),
    param_uint(OSSL_DRBG_PARAM_RESEED_COUNTER),
    param_time_t(OSSL_DRBG_PARAM_RESEED_TIME),
    param_uint(OSSL_DRBG_PARAM_RESEED_REQUESTS),
    param_uint64(OSSL_DRBG_PARAM_RESEED_TIME_INTERVAL),
    END,
];

/// `static int drbg_hash_get_ctx_params(void *vdrbg, OSSL_PARAM params[])` — `drbg_hash.c:499-534`.
///
/// # Safety
/// The `OSSL_FUNC_rand_get_ctx_params_fn` contract.
unsafe extern "C" fn drbg_hash_get_ctx_params(vdrbg: *mut c_void, params: *mut OsslParam) -> c_int {
    // SAFETY: the dispatch contract.
    unsafe {
        let drbg = vdrbg.cast::<ProvDrbg>();
        let mut p = DrbgGetCtxParams::EMPTY;
        if drbg.is_null() || drbg_hash_get_ctx_params_decoder(params, &mut p) == 0 {
            return 0;
        }
        let mut complete: c_int = 0;
        if ossl_drbg_get_ctx_params_no_lock(drbg, &p, params, &mut complete) == 0 {
            return 0;
        }
        if complete != 0 {
            return 1;
        }
        let hash = (*drbg).data.cast::<ProvDrbgHash>();
        if !(*drbg).lock.is_null() && CRYPTO_THREAD_read_lock((*drbg).lock) == 0 {
            return 0;
        }
        let mut ret = 0;
        if !p.digest.is_null() {
            let md = ossl_prov_digest_md(&(*hash).digest);
            if md.is_null() || OSSL_PARAM_set_utf8_string(p.digest, EVP_MD_get0_name(md)) == 0 {
                if !(*drbg).lock.is_null() {
                    CRYPTO_THREAD_unlock((*drbg).lock);
                }
                return ret;
            }
        }
        ret = ossl_drbg_get_ctx_params(drbg, &p);
        if !(*drbg).lock.is_null() {
            CRYPTO_THREAD_unlock((*drbg).lock);
        }
        ret
    }
}

/// `static const OSSL_PARAM *drbg_hash_gettable_ctx_params(void *vctx, void *p_ctx)`
/// — `drbg_hash.c:536-540`.
///
/// # Safety
/// The `OSSL_FUNC_rand_gettable_ctx_params_fn` contract.
unsafe extern "C" fn drbg_hash_gettable_ctx_params(
    _vctx: *mut c_void,
    _p_ctx: *mut c_void,
) -> *const OsslParam {
    DRBG_HASH_GET_CTX_PARAMS_LIST.as_ptr()
}

/// `static int drbg_fetch_digest_from_prov(const struct drbg_set_ctx_params_st *p, OSSL_LIB_CTX
/// *libctx, EVP_MD **digest, const char *propq)` — `drbg_hash.c:542-577`.
///
/// # Safety
/// `p` is decoded and `digest` is writable.
unsafe fn drbg_fetch_digest_from_prov(
    p: *const DrbgSetCtxParams,
    libctx: *mut c_void,
    digest: *mut *mut EvpMd,
    propq: *const c_char,
) -> c_int {
    // SAFETY: the arguments are per the contract.
    unsafe {
        let mut ret = 0;
        // #ifndef FIPS_MODULE
        let propquery = if propq.is_null() {
            c"provider=default".as_ptr()
        } else {
            propq
        };
        // #endif

        if digest.is_null() {
            return 0;
        }
        if (*p).digest.is_null() {
            return 1;
        }
        if (*(*p).digest).data_type != crate::params::OSSL_PARAM_UTF8_STRING {
            return ret;
        }
        let md: *mut EvpMd = EVP_MD_fetch(libctx, (*(*p).digest).data.cast(), propquery);
        if !md.is_null() {
            EVP_MD_free(*digest);
            *digest = md;
            ret = 1;
        }
        ret
    }
}

/// `static int drbg_hash_set_ctx_params_locked(PROV_DRBG *ctx, const struct drbg_set_ctx_params_st
/// *p)` — `drbg_hash.c:579-629`.
///
/// # Safety
/// `ctx` is live and `p` is decoded.
unsafe fn drbg_hash_set_ctx_params_locked(ctx: *mut ProvDrbg, p: *const DrbgSetCtxParams) -> c_int {
    // SAFETY: `ctx` and `p` are per the contract.
    unsafe {
        let hash = (*ctx).data.cast::<ProvDrbgHash>();
        let libctx = prov_libctx_of((*ctx).provctx.cast());
        let mut prov_md: *mut EvpMd = ptr::null_mut();

        // OSSL_FIPS_IND_SET_CTX_FROM_PARAM(ctx, SETTABLE0, p->ind_d) is the literal 1 here.

        // Try to fetch the digest from the provider.
        let _ = crate::runtime::err::ERR_set_mark();
        let propq = if !(*p).propq.is_null()
            && (*(*p).propq).data_type == crate::params::OSSL_PARAM_UTF8_STRING
        {
            (*(*p).propq).data.cast()
        } else {
            ptr::null()
        };
        if drbg_fetch_digest_from_prov(p, libctx, &mut prov_md, propq) == 0 {
            let _ = crate::runtime::err::ERR_pop_to_mark();
            // Fall back to the full implementation search.
            if ossl_prov_digest_load(
                &mut (*hash).digest,
                (*p).digest,
                (*p).propq,
                (*p).engine,
                libctx,
            ) == 0
            {
                return 0;
            }
        } else {
            let _ = crate::runtime::err::ERR_clear_last_mark();
            if !prov_md.is_null() {
                ossl_prov_digest_set_md(&mut (*hash).digest, prov_md);
            }
        }

        let md = ossl_prov_digest_md(&(*hash).digest);
        if !md.is_null() {
            if ossl_drbg_verify_digest(ctx, libctx, md) == 0 {
                return 0; // Error already raised for us.
            }
            // These are taken from SP 800-90 10.1 Table 2.
            let md_size = EVP_MD_get_size(md);
            if md_size <= 0 {
                return 0;
            }
            (*hash).blocklen = md_size as usize;
            // See SP800-57 Part1 Rev4 5.6.1 Table 3.
            let mut strength = 64u32 * ((*hash).blocklen >> 3) as u32;
            if strength > 256 {
                strength = 256;
            }
            (*ctx).strength = strength;
            if (*hash).blocklen > MAX_BLOCKLEN_USING_SMALL_SEEDLEN {
                (*ctx).seedlen = HASH_PRNG_MAX_SEEDLEN;
            } else {
                (*ctx).seedlen = HASH_PRNG_SMALL_SEEDLEN;
            }
            (*ctx).min_entropylen = ((*ctx).strength / 8) as usize;
            (*ctx).min_noncelen = (*ctx).min_entropylen / 2;
        }

        ossl_drbg_set_ctx_params(ctx, p)
    }
}

/// The hash set-decoder's repeat raise sites, from the spec at `drbg_hash.c.in:634-642`: `propq`,
/// `engine` (hidden), `digest`, `prov`, `reseed_req`, `reseed_time` (`ind_d` is absent).
const DRBG_HASH_SET_PARAMS_DECODER_KEYS: [(&err_sites::ErrSite, *const c_char); 6] = [
    (&err_sites::PROV_DRBG_HASH_1060, OSSL_DRBG_PARAM_PROPERTIES),
    (&err_sites::PROV_DRBG_HASH_1037, OSSL_ALG_PARAM_ENGINE),
    (&err_sites::PROV_DRBG_HASH_1021, OSSL_DRBG_PARAM_DIGEST),
    (
        &err_sites::PROV_DRBG_HASH_1071,
        OSSL_PROV_PARAM_CORE_PROV_NAME,
    ),
    (
        &err_sites::PROV_DRBG_HASH_1113,
        OSSL_DRBG_PARAM_RESEED_REQUESTS,
    ),
    (
        &err_sites::PROV_DRBG_HASH_1124,
        OSSL_DRBG_PARAM_RESEED_TIME_INTERVAL,
    ),
];

/// `drbg_hash_set_ctx_params_decoder` — generated at `drbg_hash.c.in:634-642`.
///
/// # Safety
/// `params` is NULL or key-terminated; `r` is writable.
unsafe fn drbg_hash_set_ctx_params_decoder(
    params: *const OsslParam,
    r: *mut DrbgSetCtxParams,
) -> c_int {
    // SAFETY: the arguments are per the contract.
    unsafe {
        ptr::write(r, DrbgSetCtxParams::EMPTY);
        if let Some(site) = repeated_param_site(params, &DRBG_HASH_SET_PARAMS_DECODER_KEYS) {
            return fail_at(site);
        }
        (*r).propq = OSSL_PARAM_locate_const(params, OSSL_DRBG_PARAM_PROPERTIES);
        (*r).engine = OSSL_PARAM_locate_const(params, OSSL_ALG_PARAM_ENGINE);
        (*r).digest = OSSL_PARAM_locate_const(params, OSSL_DRBG_PARAM_DIGEST);
        (*r).prov = OSSL_PARAM_locate_const(params, OSSL_PROV_PARAM_CORE_PROV_NAME);
        (*r).reseed_req = OSSL_PARAM_locate_const(params, OSSL_DRBG_PARAM_RESEED_REQUESTS);
        (*r).reseed_time = OSSL_PARAM_locate_const(params, OSSL_DRBG_PARAM_RESEED_TIME_INTERVAL);
        1
    }
}

/// `drbg_hash_set_ctx_params_list[]` — generated at `drbg_hash.c.in:634-642`; `engine` is a
/// decoder-only `hidden` key and is absent here.
static DRBG_HASH_SET_CTX_PARAMS_LIST: [OsslParam; 6] = [
    param_utf8_string(OSSL_DRBG_PARAM_PROPERTIES),
    param_utf8_string(OSSL_DRBG_PARAM_DIGEST),
    param_utf8_string(OSSL_PROV_PARAM_CORE_PROV_NAME),
    param_uint(OSSL_DRBG_PARAM_RESEED_REQUESTS),
    param_uint64(OSSL_DRBG_PARAM_RESEED_TIME_INTERVAL),
    END,
];

/// `static int drbg_hash_set_ctx_params(void *vctx, const OSSL_PARAM params[])`
/// — `drbg_hash.c:645-663`.
///
/// # Safety
/// The `OSSL_FUNC_rand_set_ctx_params_fn` contract.
unsafe extern "C" fn drbg_hash_set_ctx_params(
    vctx: *mut c_void,
    params: *const OsslParam,
) -> c_int {
    // SAFETY: the dispatch contract.
    unsafe {
        let drbg = vctx.cast::<ProvDrbg>();
        let mut p = DrbgSetCtxParams::EMPTY;
        if drbg.is_null() || drbg_hash_set_ctx_params_decoder(params, &mut p) == 0 {
            return 0;
        }
        if !(*drbg).lock.is_null() && CRYPTO_THREAD_write_lock((*drbg).lock) == 0 {
            return 0;
        }
        let ret = drbg_hash_set_ctx_params_locked(drbg, &p);
        if !(*drbg).lock.is_null() {
            CRYPTO_THREAD_unlock((*drbg).lock);
        }
        ret
    }
}

/// `static const OSSL_PARAM *drbg_hash_settable_ctx_params(void *vctx, void *p_ctx)`
/// — `drbg_hash.c:665-669`.
///
/// # Safety
/// The `OSSL_FUNC_rand_settable_ctx_params_fn` contract.
unsafe extern "C" fn drbg_hash_settable_ctx_params(
    _vctx: *mut c_void,
    _p_ctx: *mut c_void,
) -> *const OsslParam {
    DRBG_HASH_SET_CTX_PARAMS_LIST.as_ptr()
}

/// `const OSSL_DISPATCH ossl_drbg_hash_functions[]` — `drbg_hash.c:671-694`, sixteen entries.
pub(crate) static DRBG_HASH_FUNCTIONS: [OsslDispatch; 17] = [
    OsslDispatch {
        function_id: OSSL_FUNC_RAND_NEWCTX,
        function: drbg_hash_new_wrapper as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_RAND_FREECTX,
        function: drbg_hash_free as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_RAND_INSTANTIATE,
        function: drbg_hash_instantiate_wrapper as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_RAND_UNINSTANTIATE,
        function: drbg_hash_uninstantiate_wrapper as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_RAND_GENERATE,
        function: drbg_hash_generate_wrapper as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_RAND_RESEED,
        function: drbg_hash_reseed_wrapper as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_RAND_ENABLE_LOCKING,
        function: ossl_drbg_enable_locking as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_RAND_LOCK,
        function: ossl_drbg_lock as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_RAND_UNLOCK,
        function: ossl_drbg_unlock as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_RAND_SETTABLE_CTX_PARAMS,
        function: drbg_hash_settable_ctx_params as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_RAND_SET_CTX_PARAMS,
        function: drbg_hash_set_ctx_params as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_RAND_GETTABLE_CTX_PARAMS,
        function: drbg_hash_gettable_ctx_params as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_RAND_GET_CTX_PARAMS,
        function: drbg_hash_get_ctx_params as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_RAND_VERIFY_ZEROIZATION,
        function: drbg_hash_verify_zeroization as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_RAND_GET_SEED,
        function: ossl_drbg_get_seed as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_RAND_CLEAR_SEED,
        function: ossl_drbg_clear_seed as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_DISPATCH_END,
        function: ptr::null_mut(),
    },
];

// =============================================================================================
// `drbg_hmac.c` — the HMAC-DRBG
// =============================================================================================

/// `struct drbg_hmac_st` — `prov/hmac_drbg.h:17-23`.
#[repr(C)]
pub(crate) struct ProvDrbgHmac {
    /// `EVP_MAC_CTX *ctx` — `H(x) = HMAC_hash` or `H(x) = KMAC`.
    pub ctx: *mut EvpMacCtx,
    /// `PROV_DIGEST digest` — `H(x) = hash(x)`.
    pub digest: ProvDigest,
    /// `size_t blocklen`.
    pub blocklen: usize,
    /// `unsigned char K[EVP_MAX_MD_SIZE]`.
    pub k: [c_uchar; EVP_MAX_MD_SIZE],
    /// `unsigned char V[EVP_MAX_MD_SIZE]`.
    pub v: [c_uchar; EVP_MAX_MD_SIZE],
}

/// `static int do_hmac(PROV_DRBG_HMAC *hmac, unsigned char inbyte, const unsigned char *in1,
/// size_t in1len, const unsigned char *in2, size_t in2len, const unsigned char *in3, size_t
/// in3len)` — `drbg_hmac.c:62-83`. Note `hmac->blocklen` is the MAC's *output* length here.
///
/// # Safety
/// `hmac` is live and the inputs are readable for their stated lengths (or NULL).
#[allow(clippy::too_many_arguments)] // mirrors the authority's signature exactly
unsafe fn do_hmac(
    hmac: *mut ProvDrbgHmac,
    inbyte: c_uchar,
    in1: *const c_uchar,
    in1len: usize,
    in2: *const c_uchar,
    in2len: usize,
    in3: *const c_uchar,
    in3len: usize,
) -> c_int {
    // SAFETY: `hmac` and the inputs are per the contract.
    unsafe {
        let ctx = (*hmac).ctx;
        let blocklen = (*hmac).blocklen;
        // K = HMAC(K, V || inbyte || [in1] || [in2] || [in3]).
        if EVP_MAC_init(ctx, (*hmac).k.as_ptr(), blocklen, ptr::null()) == 0
            || EVP_MAC_update(ctx, (*hmac).v.as_ptr(), blocklen) == 0
            || EVP_MAC_update(ctx, &inbyte, 1) == 0
            || !(in1.is_null() || in1len == 0 || EVP_MAC_update(ctx, in1, in1len) != 0)
            || !(in2.is_null() || in2len == 0 || EVP_MAC_update(ctx, in2, in2len) != 0)
            || !(in3.is_null() || in3len == 0 || EVP_MAC_update(ctx, in3, in3len) != 0)
            || EVP_MAC_final(
                ctx,
                (*hmac).k.as_mut_ptr(),
                ptr::null_mut(),
                EVP_MAX_MD_SIZE,
            ) == 0
        {
            return 0;
        }
        // V = HMAC(K, V).
        if EVP_MAC_init(ctx, (*hmac).k.as_ptr(), blocklen, ptr::null()) == 0
            || EVP_MAC_update(ctx, (*hmac).v.as_ptr(), blocklen) == 0
            || EVP_MAC_final(
                ctx,
                (*hmac).v.as_mut_ptr(),
                ptr::null_mut(),
                EVP_MAX_MD_SIZE,
            ) == 0
        {
            return 0;
        }
        1
    }
}

/// `static int drbg_hmac_update(PROV_DRBG_HMAC *hmac, const unsigned char *in1, size_t in1len,
/// const unsigned char *in2, size_t in2len, const unsigned char *in3, size_t in3len)`
/// — `drbg_hmac.c:99-112`.
///
/// # Safety
/// `hmac` is live and the inputs are readable for their stated lengths (or NULL).
unsafe fn drbg_hmac_update(
    hmac: *mut ProvDrbgHmac,
    in1: *const c_uchar,
    in1len: usize,
    in2: *const c_uchar,
    in2len: usize,
    in3: *const c_uchar,
    in3len: usize,
) -> c_int {
    // SAFETY: `hmac` and the inputs are per the contract.
    unsafe {
        // (Steps 1-2) K = HMAC(K, V||0x00||provided_data). V = HMAC(K,V).
        if do_hmac(hmac, 0x00, in1, in1len, in2, in2len, in3, in3len) == 0 {
            return 0;
        }
        // (Step 3) If provided_data == NULL then return (K,V).
        if in1len == 0 && in2len == 0 && in3len == 0 {
            return 1;
        }
        // (Steps 4-5) K = HMAC(K, V||0x01||provided_data). V = HMAC(K,V).
        do_hmac(hmac, 0x01, in1, in1len, in2, in2len, in3, in3len)
    }
}

/// `int ossl_drbg_hmac_init(PROV_DRBG_HMAC *hmac, const unsigned char *ent, size_t ent_len,
/// const unsigned char *nonce, size_t nonce_len, const unsigned char *pstr, size_t pstr_len)`
/// — `drbg_hmac.c:125-142`.
///
/// # Safety
/// `hmac` is live with a non-NULL `ctx`.
pub(crate) unsafe fn ossl_drbg_hmac_init(
    hmac: *mut ProvDrbgHmac,
    ent: *const c_uchar,
    ent_len: usize,
    nonce: *const c_uchar,
    nonce_len: usize,
    pstr: *const c_uchar,
    pstr_len: usize,
) -> c_int {
    // SAFETY: `hmac` is live per the contract.
    unsafe {
        if (*hmac).ctx.is_null() {
            raise_site(&err_sites::PROV_DRBG_HMAC_129);
            return 0;
        }
        // (Step 2) Key = 0x00 00...00.
        cleanse((*hmac).k.as_mut_ptr().cast(), (*hmac).blocklen);
        // (Step 3) V = 0x01 01...01.
        let blocklen = (*hmac).blocklen;
        for i in 0..blocklen {
            (*hmac).v[i] = 0x01;
        }
        // (Step 4) (K,V) = HMAC_DRBG_Update(entropy||nonce||pers string, K, V).
        drbg_hmac_update(hmac, ent, ent_len, nonce, nonce_len, pstr, pstr_len)
    }
}

/// `static int drbg_hmac_instantiate(PROV_DRBG *drbg, const unsigned char *ent, size_t ent_len,
/// const unsigned char *nonce, size_t nonce_len, const unsigned char *pstr, size_t pstr_len)`
/// — `drbg_hmac.c:143-150`.
///
/// # Safety
/// `drbg` is live with a `ProvDrbgHmac` in `data`.
unsafe extern "C" fn drbg_hmac_instantiate(
    drbg: *mut ProvDrbg,
    ent: *const c_uchar,
    ent_len: usize,
    nonce: *const c_uchar,
    nonce_len: usize,
    pstr: *const c_uchar,
    pstr_len: usize,
) -> c_int {
    // SAFETY: `drbg` is live per the contract.
    unsafe {
        ossl_drbg_hmac_init(
            (*drbg).data.cast::<ProvDrbgHmac>(),
            ent,
            ent_len,
            nonce,
            nonce_len,
            pstr,
            pstr_len,
        )
    }
}

/// `static int drbg_hmac_instantiate_wrapper(void *vdrbg, unsigned int strength, int
/// prediction_resistance, const unsigned char *pstr, size_t pstr_len, const OSSL_PARAM
/// params[])` — `drbg_hmac.c:152-177`.
///
/// # Safety
/// The `OSSL_FUNC_rand_instantiate_fn` contract.
unsafe extern "C" fn drbg_hmac_instantiate_wrapper(
    vdrbg: *mut c_void,
    strength: c_uint,
    prediction_resistance: c_int,
    pstr: *const c_uchar,
    pstr_len: usize,
    params: *const OsslParam,
) -> c_int {
    // SAFETY: the dispatch contract.
    unsafe {
        let drbg = vdrbg.cast::<ProvDrbg>();
        let mut p = DrbgSetCtxParams::EMPTY;
        if drbg.is_null() || drbg_hmac_set_ctx_params_decoder(params, &mut p) == 0 {
            return 0;
        }
        if !(*drbg).lock.is_null() && CRYPTO_THREAD_write_lock((*drbg).lock) == 0 {
            return 0;
        }
        let mut ret = 0;
        if is_running() != 0 && drbg_hmac_set_ctx_params_locked(drbg, &p) != 0 {
            ret = ossl_prov_drbg_instantiate(drbg, strength, prediction_resistance, pstr, pstr_len);
        }
        if !(*drbg).lock.is_null() {
            CRYPTO_THREAD_unlock((*drbg).lock);
        }
        ret
    }
}

/// `static int drbg_hmac_reseed(PROV_DRBG *drbg, const unsigned char *ent, size_t ent_len, const
/// unsigned char *adin, size_t adin_len)` — `drbg_hmac.c:189-197`.
///
/// # Safety
/// `drbg` is live with a `ProvDrbgHmac` in `data`.
unsafe extern "C" fn drbg_hmac_reseed(
    drbg: *mut ProvDrbg,
    ent: *const c_uchar,
    ent_len: usize,
    adin: *const c_uchar,
    adin_len: usize,
) -> c_int {
    // SAFETY: `drbg` is live per the contract.
    unsafe {
        // (Step 2) (K,V) = HMAC_DRBG_Update(entropy||additional_input, K, V).
        drbg_hmac_update(
            (*drbg).data.cast::<ProvDrbgHmac>(),
            ent,
            ent_len,
            adin,
            adin_len,
            ptr::null(),
            0,
        )
    }
}

/// `static int drbg_hmac_reseed_wrapper(void *vdrbg, int prediction_resistance, const unsigned
/// char *ent, size_t ent_len, const unsigned char *adin, size_t adin_len)`
/// — `drbg_hmac.c:199-207`.
///
/// # Safety
/// The `OSSL_FUNC_rand_reseed_fn` contract.
unsafe extern "C" fn drbg_hmac_reseed_wrapper(
    vdrbg: *mut c_void,
    prediction_resistance: c_int,
    ent: *const c_uchar,
    ent_len: usize,
    adin: *const c_uchar,
    adin_len: usize,
) -> c_int {
    // SAFETY: the dispatch contract.
    unsafe {
        ossl_prov_drbg_reseed(
            vdrbg.cast::<ProvDrbg>(),
            prediction_resistance,
            ent,
            ent_len,
            adin,
            adin_len,
        )
    }
}

/// `int ossl_drbg_hmac_generate(PROV_DRBG_HMAC *hmac, unsigned char *out, size_t outlen, const
/// unsigned char *adin, size_t adin_len)` — `drbg_hmac.c:218-261`.
///
/// # Safety
/// `hmac` is live with a non-NULL `ctx`; `out` writable for `outlen`.
pub(crate) unsafe fn ossl_drbg_hmac_generate(
    hmac: *mut ProvDrbgHmac,
    out: *mut c_uchar,
    outlen: usize,
    adin: *const c_uchar,
    adin_len: usize,
) -> c_int {
    // SAFETY: `hmac` is live per the contract.
    unsafe {
        let ctx = (*hmac).ctx;
        let blocklen = (*hmac).blocklen;
        let mut temp: *const c_uchar = (*hmac).v.as_ptr();
        let mut out = out;
        let mut outlen = outlen;

        // (Step 2) if adin != NULL then (K,V) = HMAC_DRBG_Update(adin, K, V).
        if !adin.is_null()
            && adin_len > 0
            && drbg_hmac_update(hmac, adin, adin_len, ptr::null(), 0, ptr::null(), 0) == 0
        {
            return 0;
        }

        // (Steps 3-5) temp = NULL; while (len(temp) < outlen) { V = HMAC(K,V); temp ||= V; }.
        loop {
            if EVP_MAC_init(ctx, (*hmac).k.as_ptr(), blocklen, ptr::null()) == 0
                || EVP_MAC_update(ctx, temp, blocklen) == 0
            {
                return 0;
            }
            if outlen > blocklen {
                if EVP_MAC_final(ctx, out, ptr::null_mut(), outlen) == 0 {
                    return 0;
                }
                temp = out;
            } else {
                if EVP_MAC_final(
                    ctx,
                    (*hmac).v.as_mut_ptr(),
                    ptr::null_mut(),
                    EVP_MAX_MD_SIZE,
                ) == 0
                {
                    return 0;
                }
                ptr::copy_nonoverlapping((*hmac).v.as_ptr(), out, outlen);
                break;
            }
            out = out.add(blocklen);
            outlen -= blocklen;
        }

        // (Step 6) (K,V) = HMAC_DRBG_Update(adin, K, V).
        if drbg_hmac_update(hmac, adin, adin_len, ptr::null(), 0, ptr::null(), 0) == 0 {
            return 0;
        }
        1
    }
}

/// `static int drbg_hmac_generate(PROV_DRBG *drbg, unsigned char *out, size_t outlen, const
/// unsigned char *adin, size_t adin_len)` — `drbg_hmac.c:263-269`.
///
/// # Safety
/// `drbg` is live with a `ProvDrbgHmac` in `data`.
unsafe extern "C" fn drbg_hmac_generate(
    drbg: *mut ProvDrbg,
    out: *mut c_uchar,
    outlen: usize,
    adin: *const c_uchar,
    adin_len: usize,
) -> c_int {
    // SAFETY: `drbg` is live per the contract.
    unsafe {
        ossl_drbg_hmac_generate(
            (*drbg).data.cast::<ProvDrbgHmac>(),
            out,
            outlen,
            adin,
            adin_len,
        )
    }
}

/// `static int drbg_hmac_generate_wrapper(void *vdrbg, unsigned char *out, size_t outlen,
/// unsigned int strength, int prediction_resistance, const unsigned char *adin, size_t
/// adin_len)` — `drbg_hmac.c:271-279`.
///
/// # Safety
/// The `OSSL_FUNC_rand_generate_fn` contract.
unsafe extern "C" fn drbg_hmac_generate_wrapper(
    vdrbg: *mut c_void,
    out: *mut c_uchar,
    outlen: usize,
    strength: c_uint,
    prediction_resistance: c_int,
    adin: *const c_uchar,
    adin_len: usize,
) -> c_int {
    // SAFETY: the dispatch contract.
    unsafe {
        ossl_prov_drbg_generate(
            vdrbg.cast::<ProvDrbg>(),
            out,
            outlen,
            strength,
            prediction_resistance,
            adin,
            adin_len,
        )
    }
}

/// `static int drbg_hmac_uninstantiate(PROV_DRBG *drbg)` — `drbg_hmac.c:281-288`.
///
/// # Safety
/// `drbg` is live with a `ProvDrbgHmac` in `data`.
unsafe extern "C" fn drbg_hmac_uninstantiate(drbg: *mut ProvDrbg) -> c_int {
    // SAFETY: `drbg` is live per the contract.
    unsafe {
        let hmac = (*drbg).data.cast::<ProvDrbgHmac>();
        cleanse((*hmac).k.as_mut_ptr().cast(), EVP_MAX_MD_SIZE);
        cleanse((*hmac).v.as_mut_ptr().cast(), EVP_MAX_MD_SIZE);
        ossl_prov_drbg_uninstantiate(drbg)
    }
}

/// `static int drbg_hmac_uninstantiate_wrapper(void *vdrbg)` — `drbg_hmac.c:290-304`.
///
/// # Safety
/// The `OSSL_FUNC_rand_uninstantiate_fn` contract.
unsafe extern "C" fn drbg_hmac_uninstantiate_wrapper(vdrbg: *mut c_void) -> c_int {
    // SAFETY: the dispatch contract.
    unsafe {
        let drbg = vdrbg.cast::<ProvDrbg>();
        if !(*drbg).lock.is_null() && CRYPTO_THREAD_write_lock((*drbg).lock) == 0 {
            return 0;
        }
        let ret = drbg_hmac_uninstantiate(drbg);
        if !(*drbg).lock.is_null() {
            CRYPTO_THREAD_unlock((*drbg).lock);
        }
        ret
    }
}

/// `static int drbg_hmac_verify_zeroization(void *vdrbg)` — `drbg_hmac.c:306-323`.
///
/// # Safety
/// The `OSSL_FUNC_rand_verify_zeroization_fn` contract.
unsafe extern "C" fn drbg_hmac_verify_zeroization(vdrbg: *mut c_void) -> c_int {
    // SAFETY: the dispatch contract.
    unsafe {
        let drbg = vdrbg.cast::<ProvDrbg>();
        let hmac = (*drbg).data.cast::<ProvDrbgHmac>();
        if !(*drbg).lock.is_null() && CRYPTO_THREAD_read_lock((*drbg).lock) == 0 {
            return 0;
        }
        let mut ret = 0;
        if (*hmac).k.iter().all(|b| *b == 0) && (*hmac).v.iter().all(|b| *b == 0) {
            ret = 1;
        }
        if !(*drbg).lock.is_null() {
            CRYPTO_THREAD_unlock((*drbg).lock);
        }
        ret
    }
}

/// `static int drbg_hmac_new(PROV_DRBG *drbg)` — `drbg_hmac.c:325-345`.
///
/// # Safety
/// `drbg` must be live.
unsafe extern "C" fn drbg_hmac_new(drbg: *mut ProvDrbg) -> c_int {
    // SAFETY: `drbg` is live per the contract.
    unsafe {
        let hmac = CRYPTO_secure_zalloc(core::mem::size_of::<ProvDrbgHmac>(), FILE_DRBG_HMAC, LINE)
            .cast::<ProvDrbgHmac>();
        if hmac.is_null() {
            return 0;
        }
        // OSSL_FIPS_IND_INIT(drbg) is a no-op when FIPS_MODULE is undefined.
        (*drbg).data = hmac.cast();
        // See SP800-57 Part1 Rev4 5.6.1 Table 3.
        (*drbg).max_entropylen = DRBG_MAX_LENGTH;
        (*drbg).max_noncelen = DRBG_MAX_LENGTH;
        (*drbg).max_perslen = DRBG_MAX_LENGTH;
        (*drbg).max_adinlen = DRBG_MAX_LENGTH;
        // Maximum number of bits per request = 2^19 = 2^16 bytes.
        (*drbg).max_request = 1 << 16;
        1
    }
}

/// `static void *drbg_hmac_new_wrapper(void *provctx, void *parent, const OSSL_DISPATCH
/// *parent_dispatch)` — `drbg_hmac.c:347-354`.
///
/// # Safety
/// The `OSSL_FUNC_rand_newctx_fn` contract.
unsafe extern "C" fn drbg_hmac_new_wrapper(
    provctx: *mut c_void,
    parent: *mut c_void,
    parent_dispatch: *const OsslDispatch,
) -> *mut c_void {
    // SAFETY: the dispatch contract; the callback addresses are this module's.
    unsafe {
        ossl_rand_drbg_new(
            provctx.cast::<ProvCtx>(),
            parent,
            parent_dispatch,
            drbg_hmac_new,
            drbg_hmac_free,
            drbg_hmac_instantiate,
            drbg_hmac_uninstantiate,
            drbg_hmac_reseed,
            drbg_hmac_generate,
        )
        .cast()
    }
}

/// `static void drbg_hmac_free(void *vdrbg)` — `drbg_hmac.c:356-367`.
///
/// # Safety
/// `vdrbg` is NULL or what `drbg_hmac_new_wrapper` returned.
unsafe extern "C" fn drbg_hmac_free(vdrbg: *mut c_void) {
    // SAFETY: `vdrbg` is per the contract.
    unsafe {
        let drbg = vdrbg.cast::<ProvDrbg>();
        if !drbg.is_null() {
            let hmac = (*drbg).data.cast::<ProvDrbgHmac>();
            if !hmac.is_null() {
                EVP_MAC_CTX_free((*hmac).ctx);
                ossl_prov_digest_reset(&mut (*hmac).digest);
                CRYPTO_secure_clear_free(
                    hmac.cast(),
                    core::mem::size_of::<ProvDrbgHmac>(),
                    FILE_DRBG_HMAC,
                    LINE,
                );
            }
        }
        ossl_rand_drbg_free(drbg);
    }
}

// ---- HMAC generated get-ctx-params decoder --------------------------------------------------

/// The get-decoder's repeat raise sites, from the spec at `drbg_hmac.c.in:372-389`: `mac`,
/// `digest`, `state`, `str`, `maxreq`, `minentlen`, `maxentlen`, `minnonlen`, `maxnonlen`,
/// `maxperlen`, `maxadlen`, `reseed_cnt`, `reseed_time`, `reseed_req`, `reseed_int`.
const DRBG_HMAC_GET_PARAMS_DECODER_KEYS: [(&err_sites::ErrSite, *const c_char); 15] = [
    (&err_sites::PROV_DRBG_HMAC_468, OSSL_DRBG_PARAM_MAC),
    (&err_sites::PROV_DRBG_HMAC_434, OSSL_DRBG_PARAM_DIGEST),
    (&err_sites::PROV_DRBG_HMAC_687, OSSL_RAND_PARAM_STATE),
    (&err_sites::PROV_DRBG_HMAC_698, OSSL_RAND_PARAM_STRENGTH),
    (&err_sites::PROV_DRBG_HMAC_531, OSSL_RAND_PARAM_MAX_REQUEST),
    (
        &err_sites::PROV_DRBG_HMAC_557,
        OSSL_DRBG_PARAM_MIN_ENTROPYLEN,
    ),
    (
        &err_sites::PROV_DRBG_HMAC_498,
        OSSL_DRBG_PARAM_MAX_ENTROPYLEN,
    ),
    (&err_sites::PROV_DRBG_HMAC_568, OSSL_DRBG_PARAM_MIN_NONCELEN),
    (&err_sites::PROV_DRBG_HMAC_509, OSSL_DRBG_PARAM_MAX_NONCELEN),
    (&err_sites::PROV_DRBG_HMAC_520, OSSL_DRBG_PARAM_MAX_PERSLEN),
    (&err_sites::PROV_DRBG_HMAC_487, OSSL_DRBG_PARAM_MAX_ADINLEN),
    (
        &err_sites::PROV_DRBG_HMAC_611,
        OSSL_DRBG_PARAM_RESEED_COUNTER,
    ),
    (&err_sites::PROV_DRBG_HMAC_658, OSSL_DRBG_PARAM_RESEED_TIME),
    (
        &err_sites::PROV_DRBG_HMAC_622,
        OSSL_DRBG_PARAM_RESEED_REQUESTS,
    ),
    (
        &err_sites::PROV_DRBG_HMAC_649,
        OSSL_DRBG_PARAM_RESEED_TIME_INTERVAL,
    ),
];

/// `drbg_hmac_get_ctx_params_decoder` — generated at `drbg_hmac.c.in:372-389`.
///
/// # Safety
/// `params` is NULL or key-terminated; `r` is writable.
unsafe fn drbg_hmac_get_ctx_params_decoder(
    params: *const OsslParam,
    r: *mut DrbgGetCtxParams,
) -> c_int {
    // SAFETY: the arguments are per the contract.
    unsafe {
        ptr::write(r, DrbgGetCtxParams::EMPTY);
        if let Some(site) = repeated_param_site(params, &DRBG_HMAC_GET_PARAMS_DECODER_KEYS) {
            return fail_at(site);
        }
        (*r).mac = OSSL_PARAM_locate_const(params, OSSL_DRBG_PARAM_MAC) as *mut OsslParam;
        (*r).digest = OSSL_PARAM_locate_const(params, OSSL_DRBG_PARAM_DIGEST) as *mut OsslParam;
        (*r).state = OSSL_PARAM_locate_const(params, OSSL_RAND_PARAM_STATE) as *mut OsslParam;
        (*r).str = OSSL_PARAM_locate_const(params, OSSL_RAND_PARAM_STRENGTH) as *mut OsslParam;
        (*r).maxreq =
            OSSL_PARAM_locate_const(params, OSSL_RAND_PARAM_MAX_REQUEST) as *mut OsslParam;
        (*r).minentlen =
            OSSL_PARAM_locate_const(params, OSSL_DRBG_PARAM_MIN_ENTROPYLEN) as *mut OsslParam;
        (*r).maxentlen =
            OSSL_PARAM_locate_const(params, OSSL_DRBG_PARAM_MAX_ENTROPYLEN) as *mut OsslParam;
        (*r).minnonlen =
            OSSL_PARAM_locate_const(params, OSSL_DRBG_PARAM_MIN_NONCELEN) as *mut OsslParam;
        (*r).maxnonlen =
            OSSL_PARAM_locate_const(params, OSSL_DRBG_PARAM_MAX_NONCELEN) as *mut OsslParam;
        (*r).maxperlen =
            OSSL_PARAM_locate_const(params, OSSL_DRBG_PARAM_MAX_PERSLEN) as *mut OsslParam;
        (*r).maxadlen =
            OSSL_PARAM_locate_const(params, OSSL_DRBG_PARAM_MAX_ADINLEN) as *mut OsslParam;
        (*r).reseed_cnt =
            OSSL_PARAM_locate_const(params, OSSL_DRBG_PARAM_RESEED_COUNTER) as *mut OsslParam;
        (*r).reseed_time =
            OSSL_PARAM_locate_const(params, OSSL_DRBG_PARAM_RESEED_TIME) as *mut OsslParam;
        (*r).reseed_req =
            OSSL_PARAM_locate_const(params, OSSL_DRBG_PARAM_RESEED_REQUESTS) as *mut OsslParam;
        (*r).reseed_int =
            OSSL_PARAM_locate_const(params, OSSL_DRBG_PARAM_RESEED_TIME_INTERVAL) as *mut OsslParam;
        1
    }
}

/// `drbg_hmac_get_ctx_params_list[]` — generated at `drbg_hmac.c.in:372-389`.
static DRBG_HMAC_GET_CTX_PARAMS_LIST: [OsslParam; 16] = [
    param_utf8_string(OSSL_DRBG_PARAM_MAC),
    param_utf8_string(OSSL_DRBG_PARAM_DIGEST),
    param_int(OSSL_RAND_PARAM_STATE),
    param_uint(OSSL_RAND_PARAM_STRENGTH),
    param_size_t(OSSL_RAND_PARAM_MAX_REQUEST),
    param_size_t(OSSL_DRBG_PARAM_MIN_ENTROPYLEN),
    param_size_t(OSSL_DRBG_PARAM_MAX_ENTROPYLEN),
    param_size_t(OSSL_DRBG_PARAM_MIN_NONCELEN),
    param_size_t(OSSL_DRBG_PARAM_MAX_NONCELEN),
    param_size_t(OSSL_DRBG_PARAM_MAX_PERSLEN),
    param_size_t(OSSL_DRBG_PARAM_MAX_ADINLEN),
    param_uint(OSSL_DRBG_PARAM_RESEED_COUNTER),
    param_time_t(OSSL_DRBG_PARAM_RESEED_TIME),
    param_uint(OSSL_DRBG_PARAM_RESEED_REQUESTS),
    param_uint64(OSSL_DRBG_PARAM_RESEED_TIME_INTERVAL),
    END,
];

/// `static int drbg_hmac_get_ctx_params(void *vdrbg, OSSL_PARAM params[])` — `drbg_hmac.c:392-436`.
///
/// # Safety
/// The `OSSL_FUNC_rand_get_ctx_params_fn` contract.
unsafe extern "C" fn drbg_hmac_get_ctx_params(vdrbg: *mut c_void, params: *mut OsslParam) -> c_int {
    // SAFETY: the dispatch contract.
    unsafe {
        let drbg = vdrbg.cast::<ProvDrbg>();
        let mut p = DrbgGetCtxParams::EMPTY;
        if drbg.is_null() || drbg_hmac_get_ctx_params_decoder(params, &mut p) == 0 {
            return 0;
        }
        let mut complete: c_int = 0;
        if ossl_drbg_get_ctx_params_no_lock(drbg, &p, params, &mut complete) == 0 {
            return 0;
        }
        if complete != 0 {
            return 1;
        }
        let hmac = (*drbg).data.cast::<ProvDrbgHmac>();
        if !(*drbg).lock.is_null() && CRYPTO_THREAD_read_lock((*drbg).lock) == 0 {
            return 0;
        }
        let mut ret = 0;
        if !p.mac.is_null() {
            if (*hmac).ctx.is_null() {
                if !(*drbg).lock.is_null() {
                    CRYPTO_THREAD_unlock((*drbg).lock);
                }
                return ret;
            }
            let name = EVP_MAC_get0_name(EVP_MAC_CTX_get0_mac((*hmac).ctx));
            if OSSL_PARAM_set_utf8_string(p.mac, name) == 0 {
                if !(*drbg).lock.is_null() {
                    CRYPTO_THREAD_unlock((*drbg).lock);
                }
                return ret;
            }
        }
        if !p.digest.is_null() {
            let md = ossl_prov_digest_md(&(*hmac).digest);
            if md.is_null() || OSSL_PARAM_set_utf8_string(p.digest, EVP_MD_get0_name(md)) == 0 {
                if !(*drbg).lock.is_null() {
                    CRYPTO_THREAD_unlock((*drbg).lock);
                }
                return ret;
            }
        }
        ret = ossl_drbg_get_ctx_params(drbg, &p);
        if !(*drbg).lock.is_null() {
            CRYPTO_THREAD_unlock((*drbg).lock);
        }
        ret
    }
}

/// `static const OSSL_PARAM *drbg_hmac_gettable_ctx_params(void *vctx, void *p_ctx)`
/// — `drbg_hmac.c:438-442`.
///
/// # Safety
/// The `OSSL_FUNC_rand_gettable_ctx_params_fn` contract.
unsafe extern "C" fn drbg_hmac_gettable_ctx_params(
    _vctx: *mut c_void,
    _p_ctx: *mut c_void,
) -> *const OsslParam {
    DRBG_HMAC_GET_CTX_PARAMS_LIST.as_ptr()
}

/// `static int drbg_fetch_algs_from_prov(const struct drbg_set_ctx_params_st *p, OSSL_LIB_CTX
/// *libctx, EVP_MAC_CTX **macctx, EVP_MD **digest, const char *propq)` — `drbg_hmac.c:444-497`.
///
/// # Safety
/// `p` is decoded, `macctx` and `digest` are writable.
unsafe fn drbg_fetch_algs_from_prov(
    p: *const DrbgSetCtxParams,
    libctx: *mut c_void,
    macctx: *mut *mut EvpMacCtx,
    digest: *mut *mut EvpMd,
    propq: *const c_char,
) -> c_int {
    // SAFETY: the arguments are per the contract.
    unsafe {
        let md: *mut EvpMd;
        let mut ret = 0;
        // #ifndef FIPS_MODULE
        let propquery = if propq.is_null() {
            c"provider=default".as_ptr()
        } else {
            propq
        };
        // #endif

        if macctx.is_null() || digest.is_null() {
            return 0;
        }
        if !(*p).digest.is_null() {
            if (*(*p).digest).data_type != crate::params::OSSL_PARAM_UTF8_STRING {
                return ret;
            }
            md = EVP_MD_fetch(libctx, (*(*p).digest).data.cast(), propquery);
            if !md.is_null() {
                EVP_MD_free(*digest);
                *digest = md;
            } else {
                return ret;
            }
        }
        if (*p).mac.is_null() {
            return 1;
        }
        if (*(*p).mac).data_type != crate::params::OSSL_PARAM_UTF8_STRING {
            return ret;
        }
        EVP_MAC_CTX_free(*macctx);
        *macctx = ptr::null_mut();
        let mac = EVP_MAC_fetch(libctx, (*(*p).mac).data.cast(), propquery);
        if !mac.is_null() {
            *macctx = EVP_MAC_CTX_new(mac);
            // The context holds on to the MAC.
            EVP_MAC_free(mac);
            ret = 1;
        }
        ret
    }
}

/// `static int drbg_hmac_set_ctx_params_locked(PROV_DRBG *ctx, const struct drbg_set_ctx_params_st
/// *p)` — `drbg_hmac.c:499-559`.
///
/// # Safety
/// `ctx` is live and `p` is decoded.
unsafe fn drbg_hmac_set_ctx_params_locked(ctx: *mut ProvDrbg, p: *const DrbgSetCtxParams) -> c_int {
    // SAFETY: `ctx` and `p` are per the contract.
    unsafe {
        let hmac = (*ctx).data.cast::<ProvDrbgHmac>();
        let libctx = prov_libctx_of((*ctx).provctx.cast());
        let mut prov_md: *mut EvpMd = ptr::null_mut();

        // OSSL_FIPS_IND_SET_CTX_FROM_PARAM(ctx, SETTABLE0, p->ind_d) is the literal 1 here.

        // Try to fetch the MAC and digest from the provider.
        let _ = crate::runtime::err::ERR_set_mark();
        let propq = if !(*p).propq.is_null()
            && (*(*p).propq).data_type == crate::params::OSSL_PARAM_UTF8_STRING
        {
            (*(*p).propq).data.cast()
        } else {
            ptr::null()
        };
        if drbg_fetch_algs_from_prov(p, libctx, &mut (*hmac).ctx, &mut prov_md, propq) == 0 {
            let _ = crate::runtime::err::ERR_pop_to_mark();
            // It is possible for drbg_fetch_algs_from_prov to return 0 and set prov_md, so it
            // must be released to stay leak-free.
            EVP_MD_free(prov_md);
            // Fall back to the full implementation search.
            if ossl_prov_digest_load(
                &mut (*hmac).digest,
                (*p).digest,
                (*p).propq,
                (*p).engine,
                libctx,
            ) == 0
            {
                return 0;
            }
            if ossl_prov_macctx_load(
                &mut (*hmac).ctx,
                (*p).mac,
                ptr::null(),
                (*p).digest,
                (*p).propq,
                (*p).engine,
                ptr::null(),
                ptr::null(),
                ptr::null(),
                libctx,
            ) == 0
            {
                return 0;
            }
        } else {
            let _ = crate::runtime::err::ERR_clear_last_mark();
            if !prov_md.is_null() {
                ossl_prov_digest_set_md(&mut (*hmac).digest, prov_md);
            }
            if ossl_prov_macctx_load(
                &mut (*hmac).ctx,
                (*p).mac,
                ptr::null(),
                (*p).digest,
                (*p).propq,
                (*p).engine,
                ptr::null(),
                ptr::null(),
                ptr::null(),
                libctx,
            ) == 0
            {
                return 0;
            }
        }

        let md = ossl_prov_digest_md(&(*hmac).digest);
        if !md.is_null() && ossl_drbg_verify_digest(ctx, libctx, md) == 0 {
            return 0; // Error already raised for us.
        }

        if !md.is_null() && !(*hmac).ctx.is_null() {
            // These are taken from SP 800-90 10.1 Table 2.
            let md_size = EVP_MD_get_size(md);
            if md_size <= 0 {
                return 0;
            }
            (*hmac).blocklen = md_size as usize;
            // See SP800-57 Part1 Rev4 5.6.1 Table 3.
            let mut strength = 64u32 * ((*hmac).blocklen >> 3) as u32;
            if strength > 256 {
                strength = 256;
            }
            (*ctx).strength = strength;
            (*ctx).seedlen = (*hmac).blocklen;
            (*ctx).min_entropylen = ((*ctx).strength / 8) as usize;
            (*ctx).min_noncelen = (*ctx).min_entropylen / 2;
        }

        ossl_drbg_set_ctx_params(ctx, p)
    }
}

/// The HMAC set-decoder's repeat raise sites, from the spec at `drbg_hmac.c.in:564-573`: `propq`,
/// `engine` (hidden), `digest`, `mac`, `prov`, `reseed_req`, `reseed_time` (`ind_d` absent).
const DRBG_HMAC_SET_PARAMS_DECODER_KEYS: [(&err_sites::ErrSite, *const c_char); 7] = [
    (&err_sites::PROV_DRBG_HMAC_1017, OSSL_DRBG_PARAM_PROPERTIES),
    (&err_sites::PROV_DRBG_HMAC_983, OSSL_ALG_PARAM_ENGINE),
    (&err_sites::PROV_DRBG_HMAC_967, OSSL_DRBG_PARAM_DIGEST),
    (&err_sites::PROV_DRBG_HMAC_994, OSSL_DRBG_PARAM_MAC),
    (
        &err_sites::PROV_DRBG_HMAC_1028,
        OSSL_PROV_PARAM_CORE_PROV_NAME,
    ),
    (
        &err_sites::PROV_DRBG_HMAC_1070,
        OSSL_DRBG_PARAM_RESEED_REQUESTS,
    ),
    (
        &err_sites::PROV_DRBG_HMAC_1081,
        OSSL_DRBG_PARAM_RESEED_TIME_INTERVAL,
    ),
];

/// `drbg_hmac_set_ctx_params_decoder` — generated at `drbg_hmac.c.in:564-573`.
///
/// # Safety
/// `params` is NULL or key-terminated; `r` is writable.
unsafe fn drbg_hmac_set_ctx_params_decoder(
    params: *const OsslParam,
    r: *mut DrbgSetCtxParams,
) -> c_int {
    // SAFETY: the arguments are per the contract.
    unsafe {
        ptr::write(r, DrbgSetCtxParams::EMPTY);
        if let Some(site) = repeated_param_site(params, &DRBG_HMAC_SET_PARAMS_DECODER_KEYS) {
            return fail_at(site);
        }
        (*r).propq = OSSL_PARAM_locate_const(params, OSSL_DRBG_PARAM_PROPERTIES);
        (*r).engine = OSSL_PARAM_locate_const(params, OSSL_ALG_PARAM_ENGINE);
        (*r).digest = OSSL_PARAM_locate_const(params, OSSL_DRBG_PARAM_DIGEST);
        (*r).mac = OSSL_PARAM_locate_const(params, OSSL_DRBG_PARAM_MAC);
        (*r).prov = OSSL_PARAM_locate_const(params, OSSL_PROV_PARAM_CORE_PROV_NAME);
        (*r).reseed_req = OSSL_PARAM_locate_const(params, OSSL_DRBG_PARAM_RESEED_REQUESTS);
        (*r).reseed_time = OSSL_PARAM_locate_const(params, OSSL_DRBG_PARAM_RESEED_TIME_INTERVAL);
        1
    }
}

/// `drbg_hmac_set_ctx_params_list[]` — generated at `drbg_hmac.c.in:564-573`; `engine` is a
/// decoder-only `hidden` key and is absent here.
static DRBG_HMAC_SET_CTX_PARAMS_LIST: [OsslParam; 7] = [
    param_utf8_string(OSSL_DRBG_PARAM_PROPERTIES),
    param_utf8_string(OSSL_DRBG_PARAM_DIGEST),
    param_utf8_string(OSSL_DRBG_PARAM_MAC),
    param_utf8_string(OSSL_PROV_PARAM_CORE_PROV_NAME),
    param_uint(OSSL_DRBG_PARAM_RESEED_REQUESTS),
    param_uint64(OSSL_DRBG_PARAM_RESEED_TIME_INTERVAL),
    END,
];

/// `static int drbg_hmac_set_ctx_params(void *vctx, const OSSL_PARAM params[])`
/// — `drbg_hmac.c:576-594`.
///
/// # Safety
/// The `OSSL_FUNC_rand_set_ctx_params_fn` contract.
unsafe extern "C" fn drbg_hmac_set_ctx_params(
    vctx: *mut c_void,
    params: *const OsslParam,
) -> c_int {
    // SAFETY: the dispatch contract.
    unsafe {
        let drbg = vctx.cast::<ProvDrbg>();
        let mut p = DrbgSetCtxParams::EMPTY;
        if drbg.is_null() || drbg_hmac_set_ctx_params_decoder(params, &mut p) == 0 {
            return 0;
        }
        if !(*drbg).lock.is_null() && CRYPTO_THREAD_write_lock((*drbg).lock) == 0 {
            return 0;
        }
        let ret = drbg_hmac_set_ctx_params_locked(drbg, &p);
        if !(*drbg).lock.is_null() {
            CRYPTO_THREAD_unlock((*drbg).lock);
        }
        ret
    }
}

/// `static const OSSL_PARAM *drbg_hmac_settable_ctx_params(void *vctx, void *p_ctx)`
/// — `drbg_hmac.c:596-600`.
///
/// # Safety
/// The `OSSL_FUNC_rand_settable_ctx_params_fn` contract.
unsafe extern "C" fn drbg_hmac_settable_ctx_params(
    _vctx: *mut c_void,
    _p_ctx: *mut c_void,
) -> *const OsslParam {
    DRBG_HMAC_SET_CTX_PARAMS_LIST.as_ptr()
}

/// `const OSSL_DISPATCH ossl_drbg_ossl_hmac_functions[]` — `drbg_hmac.c:602-625`, sixteen entries.
pub(crate) static DRBG_HMAC_FUNCTIONS: [OsslDispatch; 17] = [
    OsslDispatch {
        function_id: OSSL_FUNC_RAND_NEWCTX,
        function: drbg_hmac_new_wrapper as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_RAND_FREECTX,
        function: drbg_hmac_free as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_RAND_INSTANTIATE,
        function: drbg_hmac_instantiate_wrapper as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_RAND_UNINSTANTIATE,
        function: drbg_hmac_uninstantiate_wrapper as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_RAND_GENERATE,
        function: drbg_hmac_generate_wrapper as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_RAND_RESEED,
        function: drbg_hmac_reseed_wrapper as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_RAND_ENABLE_LOCKING,
        function: ossl_drbg_enable_locking as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_RAND_LOCK,
        function: ossl_drbg_lock as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_RAND_UNLOCK,
        function: ossl_drbg_unlock as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_RAND_SETTABLE_CTX_PARAMS,
        function: drbg_hmac_settable_ctx_params as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_RAND_SET_CTX_PARAMS,
        function: drbg_hmac_set_ctx_params as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_RAND_GETTABLE_CTX_PARAMS,
        function: drbg_hmac_gettable_ctx_params as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_RAND_GET_CTX_PARAMS,
        function: drbg_hmac_get_ctx_params as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_RAND_VERIFY_ZEROIZATION,
        function: drbg_hmac_verify_zeroization as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_RAND_GET_SEED,
        function: ossl_drbg_get_seed as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_RAND_CLEAR_SEED,
        function: ossl_drbg_clear_seed as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_DISPATCH_END,
        function: ptr::null_mut(),
    },
];

// =============================================================================================
// The alias rows — `providers/defltprov.c`'s `deflt_rands[]` (`defltprov.c:404-414`), restricted
// to the three rows this unit implements, **in the authority's order**.
//
// `deflt_rands[]` publishes six rows (CTR-DRBG, HASH-DRBG, HMAC-DRBG, SEED-SRC, JITTER,
// TEST-RAND), in that order, each with `"provider=default"`:
//
//     static const OSSL_ALGORITHM deflt_rands[] = {
//         { PROV_NAMES_CTR_DRBG,  "provider=default", ossl_drbg_ctr_functions },
//         { PROV_NAMES_HASH_DRBG, "provider=default", ossl_drbg_hash_functions },
//         { PROV_NAMES_HMAC_DRBG, "provider=default", ossl_drbg_ossl_hmac_functions },
//         { PROV_NAMES_SEED_SRC,  "provider=default", ossl_seed_src_functions },
//     #ifndef OPENSSL_NO_JITTER
//         { PROV_NAMES_JITTER,    "provider=default", ossl_jitter_functions },
//     #endif
//         { PROV_NAMES_TEST_RAND, "provider=default", ossl_test_rng_functions },
//         { NULL, NULL, NULL }
//     };
//
// SEED-SRC (`ossl_seed_src_functions`, `seed_src.c.in`), JITTER and TEST-RAND are the sibling
// agent's; they are named here rather than redefined. Integration must also add the
// `OSSL_OP_RAND` arm to `deflt_query()` (`src/provider/digest.rs:2099-2116`).
// =============================================================================================

/// `const OSSL_ALGORITHM deflt_rands[]` — the three rows this unit owns, plus the terminator.
///
/// The alias sequences are written inline, as `defltprov.c`'s `PROV_NAMES_*` expand to them and as
/// `DEFLT_DIGESTS`/`DEFLT_MACS` write them: the provider census reads a row's whole alias sequence
/// out of the table rather than trusting a primary name, and an indirection through a `const` it
/// cannot follow would read as a row-less table (D237's class, from the candidate side).
pub(crate) static DEFLT_RANDS: [OsslAlgorithm; 6] = [
    OsslAlgorithm {
        // `PROV_NAMES_CTR_DRBG` — `prov/names.h:330`. No alias and no OID.
        algorithm_names: c"CTR-DRBG".as_ptr(),
        property_definition: c"provider=default".as_ptr(),
        implementation: DRBG_CTR_FUNCTIONS.as_ptr().cast(),
        algorithm_description: ptr::null(),
    },
    OsslAlgorithm {
        // `PROV_NAMES_HASH_DRBG` — `prov/names.h:331`.
        algorithm_names: c"HASH-DRBG".as_ptr(),
        property_definition: c"provider=default".as_ptr(),
        implementation: DRBG_HASH_FUNCTIONS.as_ptr().cast(),
        algorithm_description: ptr::null(),
    },
    OsslAlgorithm {
        // `PROV_NAMES_HMAC_DRBG` — `prov/names.h:332`.
        algorithm_names: c"HMAC-DRBG".as_ptr(),
        property_definition: c"provider=default".as_ptr(),
        implementation: DRBG_HMAC_FUNCTIONS.as_ptr().cast(),
        algorithm_description: ptr::null(),
    },
    OsslAlgorithm {
        // `PROV_NAMES_SEED_SRC` — `prov/names.h:334`. The same row name the **base** provider
        // publishes (`baseprov.c:90-96`, `BASE_RANDS`); the default provider carries it too,
        // which is why the census has two rows for one algorithm.
        algorithm_names: c"SEED-SRC".as_ptr(),
        property_definition: c"provider=default".as_ptr(),
        implementation: SEED_SRC_FUNCTIONS.as_ptr().cast(),
        algorithm_description: ptr::null(),
    },
    OsslAlgorithm {
        // `PROV_NAMES_TEST_RAND` — `prov/names.h:333`. The macro is `PROV_NAMES_TEST_RAND`, not
        // `PROV_NAMES_TEST_RNG`. This is the row the plan's DRBG courts seed from: with
        // `test_entropy` and `test_nonce` set it is deterministic, which is what makes its bytes
        // an observable rather than a comparison of two pools.
        algorithm_names: c"TEST-RAND".as_ptr(),
        property_definition: c"provider=default".as_ptr(),
        implementation: TEST_RNG_FUNCTIONS.as_ptr().cast(),
        algorithm_description: ptr::null(),
    },
    OsslAlgorithm {
        algorithm_names: ptr::null(),
        property_definition: ptr::null(),
        implementation: ptr::null(),
        algorithm_description: ptr::null(),
    },
];
