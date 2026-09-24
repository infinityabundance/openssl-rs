//! Phase 9 — the default provider's two non-DRBG `OSSL_OP_RAND` rows: `SEED-SRC` and
//! `TEST-RAND`.
//!
//! # What is here, and where each row is published
//!
//! `providers/implementations/rands/seed_src.c` and `test_rng.c`, transcribed from their
//! generated forms. Both rows are published by **`DEFLT_RANDS` in `src/provider/rand.rs`**, which
//! is what `deflt_query`'s `OSSL_OP_RAND` arm answers and what the provider census reads them out
//! of; this module owns the dispatch tables and the bodies.
//!
//! `baseprov.c` also publishes `SEED-SRC` (`base_rands[]`), and that row is described here as
//! [`BASE_RANDS`] but **not published**, because this crate has no base-provider module — its
//! other rows (`base_encoder`/`base_decoder`/`base_store`) are Phase 10's and land with it. The
//! census therefore still records the *base* `SEED-SRC` row `unimplemented` while the default
//! one is `implemented`, which is the honest reading of "which provider publishes what".
//!
//! # What is deliberately not here
//!
//! * **`fips_crng_test.c`** (`CRNG-TEST`). `providers/implementations/rands/build.info` puts it in
//!   `libfips.a` and nowhere else, and this profile builds no FIPS module. Its only authority row
//!   is `fipsprov.c:445`'s, and `fipsprov.c` is not an admitted provider, so the provider census
//!   has no `CRNG-TEST` row for any of default/base/legacy/null and there is no observable for a
//!   transcription to be measured against. It is recorded rather than carried, the same treatment
//!   `#ifdef DSO_NONE`'s `dso_openssl.c` gets.
//! * **`seed_src_jitter.c`** (`JITTER`). The unit *is* in `libdefault.a`, but its row sits inside
//!   `#ifndef OPENSSL_NO_JITTER` and `OPENSSL_NO_JITTER` is defined (`configdata.pm:215`), so it
//!   publishes nothing.
//! * **`crypto/rand/rand_uniform.c`**, whose two range helpers draw through `RAND_bytes_ex`. That
//!   export is the RAND front's; the helpers land with it, in the commit that lands the front.
//!
//! # Discrepancies against the plan's own description, recorded not papered over
//!
//! * There is no `crngt.c` and no `ossl_crngt_*` in 3.6.4 — those are 3.0-era names. The
//!   continuous test is `fips_crng_test.c`, and a dead `extern const OSSL_DISPATCH
//!   crngt_functions[];` in `prov/implementations.h:316` is the only trace of the old name.
//! * There is no `seed_src_is_entropy`, no `seed_src_copy`, and no
//!   `ossl_prov_seed_src_{get,set}_ctx_params` in 3.6.4's `seed_src.c`: the unit publishes no
//!   settable keys at all, and its getter is the static `seed_src_get_ctx_params`.
//! * `test_rng.c` has no `ossl_test_rng_get_size` and no `ossl_test_rng_set_state`.
//! * The macro is `PROV_NAMES_TEST_RAND`, not `PROV_NAMES_TEST_RNG`.
//!
//! # Build facts this transcription depends on
//!
//! * `FIPS_MODULE` is undefined for the default provider, so every `#if defined(FIPS_MODULE)`
//!   arm is absent: `test_rng`'s `get_ctx_params` loses its `fips-indicator` key. The arms are
//!   kept in comments so a reader can see what is omitted.
//! * Neither `seed_src.c` nor `test_rng.c` is a `.c.in`-generated file with a `../../src/...`
//!   prefix in its `FILE`: both are generated *in the build tree*, so `__FILE__` is the
//!   build-relative path — the same finding `src/provider/mac.rs` records for `cmac_prov.c`
//!   (D235).
//!
//! SPDX-License-Identifier: Apache-2.0

#![allow(non_snake_case)]
// The authority's spellings survive transcription for the same reason `src/provider/rand.rs`'s
// do: an identifier the tooling cannot join to a C name is indistinguishable from an absent one.
// `type` aliases here are the authority's own (`RAND_POOL`) or its public types modelled as
// opaque handles; renaming either would break the join.
#![allow(non_camel_case_types)]

use core::ffi::{c_char, c_int, c_uchar, c_uint, c_void};
use core::ptr;

use crate::context::dispatch::{OsslDispatch, OSSL_DISPATCH_END};
use crate::params::{
    OSSL_PARAM_get_octet_string, OSSL_PARAM_get_size_t, OSSL_PARAM_get_uint, OSSL_PARAM_locate,
    OSSL_PARAM_locate_const, OSSL_PARAM_set_int, OSSL_PARAM_set_size_t, OSSL_PARAM_set_uint,
    OsslParam, END,
};
use crate::provider::activate::OsslAlgorithm;
use crate::provider::cipher::{
    param_int, param_octet_string, param_size_t, param_uint, repeated_param_site,
};
use crate::rand::pool::{
    ossl_rand_pool_adin_mix_in, ossl_rand_pool_buffer, ossl_rand_pool_detach, ossl_rand_pool_free,
    ossl_rand_pool_length, ossl_rand_pool_new, RandPool,
};
use crate::rand::unix::ossl_pool_acquire_entropy;
use crate::runtime::err::{err_sites, raise_site, raise_site_dynamic};
use crate::runtime::mem::{CRYPTO_free, CRYPTO_zalloc};
use crate::runtime::secure::CRYPTO_secure_clear_free;
use crate::runtime::thread::{
    CRYPTO_THREAD_lock_free, CRYPTO_THREAD_lock_new, CRYPTO_THREAD_unlock,
    CRYPTO_THREAD_write_lock, CryptoRwlock,
};

/// `RAND_POOL` — `include/crypto/rand_pool.h:61-82`. The crate's own type; this alias is the
/// authority's spelling, which the signatures below use.
type RAND_POOL = RandPool;

// ---------------------------------------------------------------------------------------------
// `core_names.h` RAND parameter keys
// =============================================================================================
// Shared RAND dispatch ids and parameter keys.
//
// The `OSSL_FUNC_RAND_*` ids live in `src/evp/rand.rs` and are `pub(crate)`; `OSSL_OP_RAND`,
// the three `EVP_RAND_STATE_*` values and the six `OSSL_RAND_PARAM_*` keys below are declared
// here because the crate carries no shared home for them yet and each is used only by this
// unit's rows. `src/provider/rand.rs` declares its own `OSSL_OP_RAND`/state spellings for the
// same reason.
// =============================================================================================

use crate::evp::rand::{
    OSSL_FUNC_RAND_CLEAR_SEED, OSSL_FUNC_RAND_ENABLE_LOCKING, OSSL_FUNC_RAND_FREECTX,
    OSSL_FUNC_RAND_GENERATE, OSSL_FUNC_RAND_GETTABLE_CTX_PARAMS, OSSL_FUNC_RAND_GET_CTX_PARAMS,
    OSSL_FUNC_RAND_GET_SEED, OSSL_FUNC_RAND_INSTANTIATE, OSSL_FUNC_RAND_LOCK,
    OSSL_FUNC_RAND_NEWCTX, OSSL_FUNC_RAND_NONCE, OSSL_FUNC_RAND_RESEED,
    OSSL_FUNC_RAND_SETTABLE_CTX_PARAMS, OSSL_FUNC_RAND_SET_CTX_PARAMS,
    OSSL_FUNC_RAND_UNINSTANTIATE, OSSL_FUNC_RAND_UNLOCK, OSSL_FUNC_RAND_VERIFY_ZEROIZATION,
};

/// `OSSL_OP_RAND` — `include/openssl/core_dispatch.h`.
const OSSL_OP_RAND: c_int = 5;

/// `EVP_RAND_STATE_UNINITIALISED` — `include/openssl/evp.h:1345`.
const EVP_RAND_STATE_UNINITIALISED: c_int = 0;
/// `EVP_RAND_STATE_READY` — `include/openssl/evp.h:1346`.
const EVP_RAND_STATE_READY: c_int = 1;
/// `EVP_RAND_STATE_ERROR` — `include/openssl/evp.h:1347`. Already present (private) at
/// `src/evp/rand.rs:89`; redeclared here for the same visibility reason.
const EVP_RAND_STATE_ERROR: c_int = 2;

// ---------------------------------------------------------------------------------------------
// `core_names.h` RAND parameter keys — `prefix/.../core_names.h:538-544`. Declared per-unit as
// `src/provider/mac.rs` declares its `OSSL_MAC_PARAM_*` strings; only `max_request`, `strength`
// and `state` exist (privately) in `src/evp/rand.rs`.
// ---------------------------------------------------------------------------------------------

/// `OSSL_RAND_PARAM_STATE` — `"state"`.
const OSSL_RAND_PARAM_STATE: *const c_char = c"state".as_ptr();
/// `OSSL_RAND_PARAM_STRENGTH` — `"strength"`.
const OSSL_RAND_PARAM_STRENGTH: *const c_char = c"strength".as_ptr();
/// `OSSL_RAND_PARAM_MAX_REQUEST` — `"max_request"`.
const OSSL_RAND_PARAM_MAX_REQUEST: *const c_char = c"max_request".as_ptr();
/// `OSSL_RAND_PARAM_GENERATE` — `"generate"`.
const OSSL_RAND_PARAM_GENERATE: *const c_char = c"generate".as_ptr();
/// `OSSL_RAND_PARAM_TEST_ENTROPY` — `"test_entropy"`.
const OSSL_RAND_PARAM_TEST_ENTROPY: *const c_char = c"test_entropy".as_ptr();
/// `OSSL_RAND_PARAM_TEST_NONCE` — `"test_nonce"`.
const OSSL_RAND_PARAM_TEST_NONCE: *const c_char = c"test_nonce".as_ptr();

// ---------------------------------------------------------------------------------------------
// `PROV_NAMES_*` — `providers/implementations/include/prov/names.h:329-335`. **No alias and no
// OID on any of the three.** These are what the `algorithm_names` fields below carry.
// ---------------------------------------------------------------------------------------------

/// `PROV_NAMES_SEED_SRC` — `names.h:334`, the primary name alone. The **default** provider's row
/// of this name is published by `DEFLT_RANDS` in `src/provider/rand.rs`; this constant is what
/// the base provider's row below carries.
pub(crate) const PROV_NAMES_SEED_SRC: *const c_char = c"SEED-SRC".as_ptr();

/// The authority's `ERR_raise(...); return 0;` pair, in one place — the shape
/// `src/provider/mac.rs:183-188` established.
#[inline]
fn fail_at(site: &err_sites::ErrSite) -> c_int {
    // SAFETY: `site` is a generated compile-time constant whose three string pointers are
    // `'static`; no caller state is touched.
    unsafe { raise_site(site) };
    0
}

/// `ossl_assert` — `include/internal/common.h:41`, which under this profile is
/// `ossl_likely((x) != 0)`: a plain check, **not** the `OPENSSL_die` form (`:52` is the
/// `NDEBUG`-less arm, and the build tree carries `-DNDEBUG`). `src/mac/ssl3_cbc.rs` carries the
/// same helper for the same reason, and `crypto/rand/rand_uniform.c`'s two range helpers — the
/// only callers in this stratum — land with `RAND_bytes_ex`.
#[inline]
#[allow(dead_code)] // the landing caller is `ossl_rand_uniform_uint32` (the RAND front)
fn ossl_assert(expr: bool) -> c_int {
    c_int::from(expr)
}

// =============================================================================================
// `providers/implementations/rands/seed_src.c`
// =============================================================================================

/// The authority's translation unit, for the allocation-tracking `file` argument. Generated
/// file, so build-relative (no `../../src/openssl-3.6.4/`).
const FILE_SEED_SRC: *const c_char = c"providers/implementations/rands/seed_src.c".as_ptr();
/// `seed_src_new`'s `OPENSSL_zalloc(sizeof(*s))` (generated line 61).
const LINE_SEED_SRC_ZALLOC: c_int = 61;
/// `seed_src_free`'s `OPENSSL_free(vseed)` (generated line 72).
const LINE_SEED_SRC_FREE: c_int = 72;

/// `typedef struct { void *provctx; int state; } PROV_SEED_SRC` — `seed_src.c:46-49`.
#[repr(C)]
pub(crate) struct ProvSeedSrc {
    /// `void *provctx` — the creating provider's context; unused by every arm of this unit.
    pub provctx: *mut c_void,
    /// `int state` — one of `EVP_RAND_STATE_*`.
    pub state: c_int,
}

/// `static void *seed_src_new(void *provctx, void *parent, const OSSL_DISPATCH
/// *parent_dispatch)` — `seed_src.c:51-68`.
///
/// **A seed source must not have a parent**, and the refusal is a *raised*
/// `PROV_R_SEED_SOURCES_MUST_NOT_HAVE_A_PARENT` before any allocation. The third argument is
/// part of the `newctx` contract and is ignored here.
///
/// # Safety
/// The dispatch contract.
unsafe extern "C" fn seed_src_new(
    provctx: *mut c_void,
    parent: *mut c_void,
    _parent_dispatch: *const OsslDispatch,
) -> *mut c_void {
    // SAFETY: the caller's contract; `parent` is NULL or the parent context the core supplied.
    unsafe {
        if !parent.is_null() {
            // site: `err_sites::PROV_SEED_SRC_55` (`seed_src.c:55`,
            // ERR_LIB_PROV / PROV_R_SEED_SOURCES_MUST_NOT_HAVE_A_PARENT).
            raise_site(&err_sites::PROV_SEED_SRC_55);
            return ptr::null_mut();
        }

        let s = CRYPTO_zalloc(
            core::mem::size_of::<ProvSeedSrc>(),
            FILE_SEED_SRC,
            LINE_SEED_SRC_ZALLOC,
        )
        .cast::<ProvSeedSrc>();
        if s.is_null() {
            return ptr::null_mut();
        }

        (*s).provctx = provctx;
        (*s).state = EVP_RAND_STATE_UNINITIALISED;
        s.cast()
    }
}

/// `static void seed_src_free(void *vseed)` — `seed_src.c:70-73`. `OPENSSL_free(vseed)` is
/// `CRYPTO_free(vseed, OPENSSL_FILE, OPENSSL_LINE)`; there is no other release.
///
/// # Safety
/// The dispatch contract; `vseed` is a context `seed_src_new` allocated or NULL.
unsafe extern "C" fn seed_src_free(vseed: *mut c_void) {
    // SAFETY: `vseed` is NULL or a live `ProvSeedSrc` per the contract.
    unsafe { CRYPTO_free(vseed, FILE_SEED_SRC, LINE_SEED_SRC_FREE) };
}

/// `static int seed_src_instantiate(void *vseed, unsigned int strength,
/// int prediction_resistance, const unsigned char *pstr, size_t pstr_len,
/// ossl_unused const OSSL_PARAM params[])` — `seed_src.c:75-84`.
///
/// Every argument but the context is unused: the state machine has exactly two states and the
/// instantiate arms the second. There is no raise and no allocation.
///
/// # Safety
/// The dispatch contract.
unsafe extern "C" fn seed_src_instantiate(
    vseed: *mut c_void,
    _strength: c_uint,
    _prediction_resistance: c_int,
    _pstr: *const c_uchar,
    _pstr_len: usize,
    _params: *const OsslParam,
) -> c_int {
    // SAFETY: `vseed` is a live `ProvSeedSrc` per the contract.
    unsafe {
        (*vseed.cast::<ProvSeedSrc>()).state = EVP_RAND_STATE_READY;
        1
    }
}

/// `static int seed_src_uninstantiate(void *vseed)` — `seed_src.c:86-92`.
///
/// # Safety
/// The dispatch contract.
unsafe extern "C" fn seed_src_uninstantiate(vseed: *mut c_void) -> c_int {
    // SAFETY: `vseed` is a live `ProvSeedSrc` per the contract.
    unsafe {
        (*vseed.cast::<ProvSeedSrc>()).state = EVP_RAND_STATE_UNINITIALISED;
        1
    }
}

/// `static int seed_src_generate(void *vseed, unsigned char *out, size_t outlen,
/// unsigned int strength, ossl_unused int prediction_resistance,
/// const unsigned char *adin, size_t adin_len)` — `seed_src.c:94-130`.
///
/// **The seed source's generate is a poll of the system entropy sources**, not a DRBG draw.
/// It is the one arm that reaches the `RAND_POOL` machinery: `ossl_rand_pool_new(strength, 1,
/// outlen, outlen)` asks for `outlen` bytes at `strength`, secure (`1`); `ossl_pool_acquire_entropy`
/// polls; a positive answer mixes `adin` in and copies the pool out. A *weak* pool
/// (`entropy_available == 0`) is **not** an error here — the function returns 0 without raising,
/// which is the shape the caller (`seed_get_seed`) then turns into a raise.
///
/// # Safety
/// The dispatch contract.
unsafe extern "C" fn seed_src_generate(
    vseed: *mut c_void,
    out: *mut c_uchar,
    outlen: usize,
    strength: c_uint,
    _prediction_resistance: c_int,
    adin: *const c_uchar,
    adin_len: usize,
) -> c_int {
    // SAFETY: `vseed` is a live `ProvSeedSrc` per the contract; `out` is writable for `outlen`.
    unsafe {
        let s = vseed.cast::<ProvSeedSrc>();

        if (*s).state != EVP_RAND_STATE_READY {
            // site: `err_sites::PROV_SEED_SRC_103` (`seed_src.c:103`), a
            // **dynamic-reason** site: PROV_R_IN_ERROR_STATE when `state == ERROR`, else
            // PROV_R_NOT_INSTANTIATED.
            let reason = if (*s).state == EVP_RAND_STATE_ERROR {
                crate::runtime::err::err_reasons::PROV_R_IN_ERROR_STATE
            } else {
                crate::runtime::err::err_reasons::PROV_R_NOT_INSTANTIATED
            };
            raise_site_dynamic(&err_sites::PROV_SEED_SRC_103, reason);
            return 0;
        }

        let pool: *mut RAND_POOL = ossl_rand_pool_new(strength as c_int, 1, outlen, outlen);
        if pool.is_null() {
            // site: `err_sites::PROV_SEED_SRC_111` (`seed_src.c:111`,
            // ERR_LIB_PROV / ERR_R_RAND_LIB).
            raise_site(&err_sites::PROV_SEED_SRC_111);
            return 0;
        }

        /* Get entropy by polling system entropy sources. */
        let entropy_available = ossl_pool_acquire_entropy(pool);

        if entropy_available > 0 {
            if ossl_rand_pool_adin_mix_in(pool, adin, adin_len) == 0 {
                ossl_rand_pool_free(pool);
                return 0;
            }
            ptr::copy_nonoverlapping(
                ossl_rand_pool_buffer(pool),
                out,
                ossl_rand_pool_length(pool),
            );
        }

        ossl_rand_pool_free(pool);
        c_int::from(entropy_available > 0)
    }
}

/// `static int seed_src_reseed(void *vseed, ossl_unused int prediction_resistance,
/// ossl_unused const unsigned char *ent, ossl_unused size_t ent_len,
/// ossl_unused const unsigned char *adin, ossl_unused size_t adin_len)` —
/// `seed_src.c:132-148`.
///
/// A reseed of a seed source does nothing but re-check the state; it does not poll.
///
/// # Safety
/// The dispatch contract.
unsafe extern "C" fn seed_src_reseed(
    vseed: *mut c_void,
    _prediction_resistance: c_int,
    _ent: *const c_uchar,
    _ent_len: usize,
    _adin: *const c_uchar,
    _adin_len: usize,
) -> c_int {
    // SAFETY: `vseed` is a live `ProvSeedSrc` per the contract.
    unsafe {
        let s = vseed.cast::<ProvSeedSrc>();
        if (*s).state != EVP_RAND_STATE_READY {
            // site: `err_sites::PROV_SEED_SRC_140` (`seed_src.c:140`), dynamic-reason
            // (PROV_R_IN_ERROR_STATE / PROV_R_NOT_INSTANTIATED).
            let reason = if (*s).state == EVP_RAND_STATE_ERROR {
                crate::runtime::err::err_reasons::PROV_R_IN_ERROR_STATE
            } else {
                crate::runtime::err::err_reasons::PROV_R_NOT_INSTANTIATED
            };
            raise_site_dynamic(&err_sites::PROV_SEED_SRC_140, reason);
            return 0;
        }
        1
    }
}

/* --------------------------------------------------------------------------------------------
 * clang-format off
 * Machine generated by util/perl/OpenSSL/paramnames.pm
 *
 * The authority's `seed_src_get_ctx_params_list` and its decoder. The decoder is a
 * character-by-character `strcmp` walk (`'m'` => `max_request`, `'s'`/`'t'`/`'a'` => `state`,
 * `'s'`/`'t'`/`'r'` => `strength`), raising `PROV_R_REPEATED_PARAMETER` on a second sighting.
 * `src/provider/mac.rs` replaces the generated decoder with `repeated_param_site` plus
 * `OSSL_PARAM_locate`, and that is the form used here — the decoder *key order* below is the
 * **switch** order (`max_request`, `state`, `strength`), not the list order.
 * ------------------------------------------------------------------------------------------- */

/// `static const OSSL_PARAM seed_src_get_ctx_params_list[]` — `seed_src.c:151-156`.
static SEED_SRC_GET_CTX_PARAMS_LIST: [OsslParam; 4] = [
    param_int(OSSL_RAND_PARAM_STATE),
    param_uint(OSSL_RAND_PARAM_STRENGTH),
    param_size_t(OSSL_RAND_PARAM_MAX_REQUEST),
    END,
];

/// The three keys `seed_src_get_ctx_params_decoder` locates, each with the site of its own
/// repeated-parameter raise (`seed_src.c:183`, `:202`, `:213`).
///
/// sites: `err_sites::PROV_SEED_SRC_183`, `PROV_SEED_SRC_202`, `PROV_SEED_SRC_213`.
const SEED_SRC_GET_CTX_PARAMS_DECODER_KEYS: [(&err_sites::ErrSite, *const c_char); 3] = [
    (&err_sites::PROV_SEED_SRC_183, OSSL_RAND_PARAM_MAX_REQUEST),
    (&err_sites::PROV_SEED_SRC_202, OSSL_RAND_PARAM_STATE),
    (&err_sites::PROV_SEED_SRC_213, OSSL_RAND_PARAM_STRENGTH),
];

/// `static int seed_src_get_ctx_params(void *vseed, OSSL_PARAM params[])` —
/// `seed_src.c:158-175`.
///
/// The answers are the authority's own constants: `strength` is **1024** and `max_request` is
/// **128**, neither of them derived from the context. Only `state` reads the context.
///
/// # Safety
/// The dispatch contract.
unsafe extern "C" fn seed_src_get_ctx_params(vseed: *mut c_void, params: *mut OsslParam) -> c_int {
    // SAFETY: the caller's contract; `vseed` is live and `params` is NULL or a key-terminated
    // array.
    unsafe {
        if vseed.is_null() {
            return 0;
        }
        if let Some(site) = repeated_param_site(params, &SEED_SRC_GET_CTX_PARAMS_DECODER_KEYS) {
            return fail_at(site);
        }

        let s = vseed.cast::<ProvSeedSrc>();

        let p = OSSL_PARAM_locate(params, OSSL_RAND_PARAM_STATE);
        if !p.is_null() && OSSL_PARAM_set_int(p, (*s).state) == 0 {
            return 0;
        }

        let p = OSSL_PARAM_locate(params, OSSL_RAND_PARAM_STRENGTH);
        if !p.is_null() && OSSL_PARAM_set_uint(p, 1024) == 0 {
            return 0;
        }

        let p = OSSL_PARAM_locate(params, OSSL_RAND_PARAM_MAX_REQUEST);
        if !p.is_null() && OSSL_PARAM_set_size_t(p, 128) == 0 {
            return 0;
        }
        1
    }
}

/// `static const OSSL_PARAM *seed_src_gettable_ctx_params(ossl_unused void *vseed,
/// ossl_unused void *provctx)` — `seed_src.c:177-181`. No `settable_ctx_params` exists.
///
/// # Safety
/// The dispatch contract.
unsafe extern "C" fn seed_src_gettable_ctx_params(
    _vseed: *mut c_void,
    _provctx: *mut c_void,
) -> *const OsslParam {
    SEED_SRC_GET_CTX_PARAMS_LIST.as_ptr()
}

/// `static int seed_src_verify_zeroization(ossl_unused void *vseed)` — `seed_src.c:183-186`.
/// The authority always answers 1; nothing is held that could be verified.
///
/// # Safety
/// The dispatch contract.
unsafe extern "C" fn seed_src_verify_zeroization(_vseed: *mut c_void) -> c_int {
    1
}

/// `static size_t seed_get_seed(void *vseed, unsigned char **pout, int entropy,
/// size_t min_len, size_t max_len, int prediction_resistance,
/// const unsigned char *adin, size_t adin_len)` — `seed_src.c:188-215`.
///
/// The seed-source *seed* path. It differs from `seed_src_generate` in one contract detail
/// that matters: the pool is sized `min_len..max_len`, and **both** a weak pool and a failed
/// `adin` mix-in raise `PROV_R_ENTROPY_SOURCE_STRENGTH_TOO_WEAK` before the pool is freed. The
/// answer is `ossl_rand_pool_length(pool)`, and the buffer is **detached** so the caller owns
/// it — the reason `seed_clear_seed` below is `OPENSSL_secure_clear_free`.
///
/// # Safety
/// The dispatch contract.
unsafe extern "C" fn seed_get_seed(
    _vseed: *mut c_void,
    pout: *mut *mut c_uchar,
    entropy: c_int,
    min_len: usize,
    max_len: usize,
    _prediction_resistance: c_int,
    adin: *const c_uchar,
    adin_len: usize,
) -> usize {
    // SAFETY: the caller's contract; `pout` is writable and `adin` is readable for `adin_len`.
    unsafe {
        let mut ret: usize = 0;

        let pool: *mut RAND_POOL = ossl_rand_pool_new(entropy, 1, min_len, max_len);
        if pool.is_null() {
            // site: `err_sites::PROV_SEED_SRC_269` (`seed_src.c:199`,
            // ERR_LIB_PROV / ERR_R_RAND_LIB).
            raise_site(&err_sites::PROV_SEED_SRC_269);
            return 0;
        }

        /* Get entropy by polling system entropy sources. */
        let entropy_available = ossl_pool_acquire_entropy(pool);

        if entropy_available > 0 && ossl_rand_pool_adin_mix_in(pool, adin, adin_len) != 0 {
            ret = ossl_rand_pool_length(pool);
            *pout = ossl_rand_pool_detach(pool);
        } else {
            // site: `err_sites::PROV_SEED_SRC_281` (`seed_src.c:211`,
            // ERR_LIB_PROV / PROV_R_ENTROPY_SOURCE_STRENGTH_TOO_WEAK).
            raise_site(&err_sites::PROV_SEED_SRC_281);
        }
        ossl_rand_pool_free(pool);
        ret
    }
}

/// `static void seed_clear_seed(ossl_unused void *vdrbg, unsigned char *out,
/// size_t outlen)` — `seed_src.c:217-221`.
///
/// `OPENSSL_secure_clear_free(out, outlen)` is `CRYPTO_secure_clear_free(out, outlen,
/// OPENSSL_FILE, OPENSSL_LINE)`, and that is a function this crate already has.
///
/// # Safety
/// The dispatch contract; `out` is a buffer `seed_get_seed` detached.
unsafe extern "C" fn seed_clear_seed(_vdrbg: *mut c_void, out: *mut c_uchar, outlen: usize) {
    // SAFETY: `out` is NULL or the secure allocation `seed_get_seed` handed the caller, and
    // `outlen` is its length.
    unsafe {
        CRYPTO_secure_clear_free(
            out.cast::<c_void>(),
            outlen,
            FILE_SEED_SRC,
            // seed_src.c:220 — the `OPENSSL_secure_clear_free` call's line.
            220,
        )
    };
}

/// `static int seed_src_enable_locking(ossl_unused void *vseed)` — `seed_src.c:223-226`.
///
/// # Safety
/// The dispatch contract.
unsafe extern "C" fn seed_src_enable_locking(_vseed: *mut c_void) -> c_int {
    1
}

/// `int seed_src_lock(ossl_unused void *vctx)` — `seed_src.c:228-231`. **Non-static** in the
/// authority (unusual for this class), so it is `pub(crate)` here rather than module-private.
///
/// # Safety
/// The dispatch contract.
pub(crate) unsafe extern "C" fn seed_src_lock(_vctx: *mut c_void) -> c_int {
    1
}

/// `void seed_src_unlock(ossl_unused void *vctx)` — `seed_src.c:233-235`. Non-static in the
/// authority.
///
/// # Safety
/// The dispatch contract.
pub(crate) unsafe extern "C" fn seed_src_unlock(_vctx: *mut c_void) {}

/// `const OSSL_DISPATCH ossl_seed_src_functions[]` — `seed_src.c:237-257`, fourteen entries.
///
/// Note the two **`GET_SEED`/`CLEAR_SEED`** entries: these are what the DRBG frame uses to pull
/// entropy from a seed source, and they are the reason this row is meaningful to the RAND layer
/// even though `generate` exists for callers that treat it as an ordinary RAND.
pub(crate) static SEED_SRC_FUNCTIONS: [OsslDispatch; 15] = [
    OsslDispatch {
        function_id: OSSL_FUNC_RAND_NEWCTX,
        function: seed_src_new as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_RAND_FREECTX,
        function: seed_src_free as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_RAND_INSTANTIATE,
        function: seed_src_instantiate as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_RAND_UNINSTANTIATE,
        function: seed_src_uninstantiate as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_RAND_GENERATE,
        function: seed_src_generate as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_RAND_RESEED,
        function: seed_src_reseed as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_RAND_ENABLE_LOCKING,
        function: seed_src_enable_locking as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_RAND_LOCK,
        function: seed_src_lock as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_RAND_UNLOCK,
        function: seed_src_unlock as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_RAND_GETTABLE_CTX_PARAMS,
        function: seed_src_gettable_ctx_params as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_RAND_GET_CTX_PARAMS,
        function: seed_src_get_ctx_params as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_RAND_VERIFY_ZEROIZATION,
        function: seed_src_verify_zeroization as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_RAND_GET_SEED,
        function: seed_get_seed as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_RAND_CLEAR_SEED,
        function: seed_clear_seed as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_DISPATCH_END,
        function: ptr::null_mut(),
    },
];

// =============================================================================================
// `providers/implementations/rands/test_rng.c`
// =============================================================================================

/// The authority's translation unit, for the allocation-tracking `file` argument.
const FILE_TEST_RNG: *const c_char = c"providers/implementations/rands/test_rng.c".as_ptr();
/// `test_rng_new`'s `OPENSSL_zalloc(sizeof(*t))` (generated line 64).
const LINE_TEST_RNG_ZALLOC: c_int = 64;
/// `test_rng_free`'s `OPENSSL_free(t->entropy)` (generated line 80).
const LINE_TEST_RNG_FREE_ENTROPY: c_int = 80;
/// `test_rng_free`'s `OPENSSL_free(t->nonce)` (generated line 81).
const LINE_TEST_RNG_FREE_NONCE: c_int = 81;
/// `test_rng_free`'s `OPENSSL_free(t)` (generated line 83).
const LINE_TEST_RNG_FREE: c_int = 83;
/// `test_rng_set_ctx_params`'s `OPENSSL_free(t->entropy)` (generated line 471).
const LINE_TEST_RNG_SET_FREE_ENTROPY: c_int = 471;
/// `test_rng_set_ctx_params`'s `OPENSSL_free(t->nonce)` (generated line 481).
const LINE_TEST_RNG_SET_FREE_NONCE: c_int = 481;

/// `INT_MAX`, the value `test_rng_new` writes into `max_request`.
const INT_MAX: usize = 2147483647;

/// `typedef struct { ... } PROV_TEST_RNG` — `test_rng.c:47-57`.
#[repr(C)]
pub(crate) struct ProvTestRng {
    /// `void *provctx`.
    pub provctx: *mut c_void,
    /// `unsigned int generate` — when non-zero, generate from the xorshift instead of the
    /// caller-supplied `entropy`.
    pub generate: c_uint,
    /// `int state`.
    pub state: c_int,
    /// `unsigned int strength` — the ceiling both `instantiate` and `generate` compare against.
    pub strength: c_uint,
    /// `size_t max_request`.
    pub max_request: usize,
    /// `unsigned char *entropy, *nonce` — owned buffers from `test_entropy`/`test_nonce`.
    pub entropy: *mut c_uchar,
    pub nonce: *mut c_uchar,
    /// `size_t entropy_len, entropy_pos, nonce_len`.
    pub entropy_len: usize,
    pub entropy_pos: usize,
    pub nonce_len: usize,
    /// `CRYPTO_RWLOCK *lock`.
    pub lock: *mut CryptoRwlock,
    /// `uint32_t seed` — the xorshift's state, reset by `instantiate` to a non-zero constant.
    pub seed: u32,
}

/// `static void *test_rng_new(void *provctx, void *parent,
/// const OSSL_DISPATCH *parent_dispatch)` — `test_rng.c:59-72`.
///
/// **The three-argument `newctx` and a test RNG that ignores the parent entirely.** Unlike
/// SEED-SRC it accepts a parent without inspecting it. `max_request` starts at `INT_MAX` and
/// `state` at `UNINITIALISED`; the `zalloc` is what makes every pointer field NULL.
///
/// # Safety
/// The dispatch contract.
unsafe extern "C" fn test_rng_new(
    provctx: *mut c_void,
    _parent: *mut c_void,
    _parent_dispatch: *const OsslDispatch,
) -> *mut c_void {
    // SAFETY: the caller's contract.
    unsafe {
        let t = CRYPTO_zalloc(
            core::mem::size_of::<ProvTestRng>(),
            FILE_TEST_RNG,
            LINE_TEST_RNG_ZALLOC,
        )
        .cast::<ProvTestRng>();
        if t.is_null() {
            return ptr::null_mut();
        }

        (*t).max_request = INT_MAX;
        (*t).provctx = provctx;
        (*t).state = EVP_RAND_STATE_UNINITIALISED;
        t.cast()
    }
}

/// `static void test_rng_free(void *vtest)` — `test_rng.c:74-84`.
///
/// The NULL arm is explicit in the authority (`if (t == NULL) return;`), which matters because
/// `CRYPTO_THREAD_lock_free` and `OPENSSL_free` are separately NULL-tolerant but the authority
/// still guards. `CRYPTO_THREAD_lock_free(t->lock)` precedes the context free even when the
/// lock is NULL.
///
/// # Safety
/// The dispatch contract; `vtest` is a context `test_rng_new` allocated or NULL.
unsafe extern "C" fn test_rng_free(vtest: *mut c_void) {
    // SAFETY: `vtest` is NULL or a live `ProvTestRng` per the contract.
    unsafe {
        if vtest.is_null() {
            return;
        }
        let t = vtest.cast::<ProvTestRng>();
        CRYPTO_free(
            (*t).entropy.cast(),
            FILE_TEST_RNG,
            LINE_TEST_RNG_FREE_ENTROPY,
        );
        CRYPTO_free((*t).nonce.cast(), FILE_TEST_RNG, LINE_TEST_RNG_FREE_NONCE);
        CRYPTO_THREAD_lock_free((*t).lock);
        CRYPTO_free(vtest, FILE_TEST_RNG, LINE_TEST_RNG_FREE);
    }
}

/// `static int test_rng_instantiate(void *vtest, unsigned int strength,
/// int prediction_resistance, const unsigned char *pstr, size_t pstr_len,
/// const OSSL_PARAM params[])` — `test_rng.c:86-101`.
///
/// **`set_ctx_params` runs first**, so `instantiate` is where the `strength` ceiling can be
/// raised by the caller's own parameters; the refusal is `strength > t->strength` *after* the
/// set. `entropy_pos` is rewound and `seed` is set to the authority's magic constant
/// `221953166` — "Value doesn't matter, so long as it isn't zero".
///
/// # Safety
/// The dispatch contract.
unsafe extern "C" fn test_rng_instantiate(
    vtest: *mut c_void,
    strength: c_uint,
    _prediction_resistance: c_int,
    _pstr: *const c_uchar,
    _pstr_len: usize,
    params: *const OsslParam,
) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        let t = vtest.cast::<ProvTestRng>();
        if test_rng_set_ctx_params(vtest, params) == 0 || strength > (*t).strength {
            return 0;
        }
        (*t).state = EVP_RAND_STATE_READY;
        (*t).entropy_pos = 0;
        (*t).seed = 221953166; /* Value doesn't matter, so long as it isn't zero */
        1
    }
}

/// `static int test_rng_uninstantiate(void *vtest)` — `test_rng.c:103-110`.
///
/// # Safety
/// The dispatch contract.
unsafe extern "C" fn test_rng_uninstantiate(vtest: *mut c_void) -> c_int {
    // SAFETY: `vtest` is a live `ProvTestRng` per the contract.
    unsafe {
        let t = vtest.cast::<ProvTestRng>();
        (*t).entropy_pos = 0;
        (*t).state = EVP_RAND_STATE_UNINITIALISED;
        1
    }
}

/// `static unsigned char gen_byte(PROV_TEST_RNG *t)` — `test_rng.c:112-130`.
///
/// The 32-bit xorshift of Marsaglia (JSS 8(14), 2008): `n ^= n << 13; n ^= n >> 17;
/// n ^= n << 5`, keeping the low byte. Every shift here is a *wrapping* shift on a `u32`
/// and must not be allowed to trip `overflow-checks`; the XOR-shift itself is bit-exact.
fn gen_byte(t: *mut ProvTestRng) -> c_uchar {
    // SAFETY: `t` is a live `ProvTestRng` per the caller's contract.
    let mut n = unsafe { (*t).seed };
    n ^= n << 13;
    n ^= n >> 17;
    n ^= n << 5;
    // SAFETY: as above.
    unsafe { (*t).seed = n };
    (n & 0xff) as c_uchar
}

/// `static int test_rng_generate(void *vtest, unsigned char *out, size_t outlen,
/// unsigned int strength, int prediction_resistance, const unsigned char *adin,
/// size_t adin_len)` — `test_rng.c:132-152`.
///
/// Two modes. With `generate` set, `outlen` xorshift bytes. Otherwise a **prefix of the stored
/// entropy**, refused when `entropy_len - entropy_pos < outlen` — a `size_t` subtraction that
/// in C is unsigned wraparound and therefore `wrapping_sub` here, because `entropy_pos` can
/// exceed `entropy_len` after a caller rewinds or re-instantiate. The refusal raises nothing.
///
/// # Safety
/// The dispatch contract.
unsafe extern "C" fn test_rng_generate(
    vtest: *mut c_void,
    out: *mut c_uchar,
    outlen: usize,
    strength: c_uint,
    _prediction_resistance: c_int,
    _adin: *const c_uchar,
    _adin_len: usize,
) -> c_int {
    // SAFETY: `vtest` is a live `ProvTestRng`; `out` is writable for `outlen`.
    unsafe {
        let t = vtest.cast::<ProvTestRng>();
        if strength > (*t).strength {
            return 0;
        }
        if (*t).generate != 0 {
            let mut i: usize = 0;
            while i < outlen {
                *out.add(i) = gen_byte(t);
                i += 1;
            }
        } else {
            if (*t).entropy_len.wrapping_sub((*t).entropy_pos) < outlen {
                return 0;
            }
            ptr::copy_nonoverlapping((*t).entropy.add((*t).entropy_pos), out, outlen);
            (*t).entropy_pos = (*t).entropy_pos.wrapping_add(outlen);
        }
        1
    }
}

/// `static int test_rng_reseed(ossl_unused void *vtest, ...)` — `test_rng.c:154-162`.
/// A test RNG reseed is a no-op that answers 1.
///
/// # Safety
/// The dispatch contract.
unsafe extern "C" fn test_rng_reseed(
    _vtest: *mut c_void,
    _prediction_resistance: c_int,
    _ent: *const c_uchar,
    _ent_len: usize,
    _adin: *const c_uchar,
    _adin_len: usize,
) -> c_int {
    1
}

/// `static size_t test_rng_nonce(void *vtest, unsigned char *out, unsigned int strength,
/// size_t min_noncelen, size_t max_noncelen)` — `test_rng.c:164-186`.
///
/// **The only `NONCE` entry in the RAND stratum.** It answers `min_noncelen` xorshift bytes in
/// generate mode; otherwise it copies `min(nonce_len, max_noncelen)` from the stored nonce and
/// answers 0 when none was set. In generate mode `out` is written for exactly
/// `min_noncelen` bytes — `max_noncelen` is not consulted.
///
/// # Safety
/// The dispatch contract.
unsafe extern "C" fn test_rng_nonce(
    vtest: *mut c_void,
    out: *mut c_uchar,
    strength: c_uint,
    min_noncelen: usize,
    max_noncelen: usize,
) -> usize {
    // SAFETY: `vtest` is a live `ProvTestRng`; `out` is NULL or writable for the length returned.
    unsafe {
        let t = vtest.cast::<ProvTestRng>();
        if strength > (*t).strength {
            return 0;
        }

        if (*t).generate != 0 {
            let mut i: usize = 0;
            while i < min_noncelen {
                *out.add(i) = gen_byte(t);
                i += 1;
            }
            return min_noncelen;
        }

        if (*t).nonce.is_null() {
            return 0;
        }
        let i = if (*t).nonce_len > max_noncelen {
            max_noncelen
        } else {
            (*t).nonce_len
        };
        if !out.is_null() {
            ptr::copy_nonoverlapping((*t).nonce, out, i);
        }
        i
    }
}

/* Machine generated by util/perl/OpenSSL/paramnames.pm — get side.
 * Switch order: 'g'enerate, 'm'ax_request, 's'tate, 's'trength. The `fips-indicator` arm is
 * `# if defined(FIPS_MODULE)` and absent in this profile. */

/// `static const OSSL_PARAM test_rng_get_ctx_params_list[]` — `test_rng.c:190-201`.
/// The `FIPS_APPROVED_INDICATOR` entry is guarded out in this build.
static TEST_RNG_GET_CTX_PARAMS_LIST: [OsslParam; 5] = [
    param_int(OSSL_RAND_PARAM_STATE),
    param_uint(OSSL_RAND_PARAM_STRENGTH),
    param_size_t(OSSL_RAND_PARAM_MAX_REQUEST),
    param_uint(OSSL_RAND_PARAM_GENERATE),
    // # if defined(FIPS_MODULE) OSSL_PARAM_int(OSSL_RAND_PARAM_FIPS_APPROVED_INDICATOR, NULL),
    END,
];

/// The four keys `test_rng_get_ctx_params_decoder` locates in this profile (switch order:
/// `generate`, `max_request`, `state`, `strength`), each with its repeated-raise site
/// (`test_rng.c:244`, `:255`, `:274`, `:286`). The fifth, `fips-indicator`, is FIPS-guarded.
const TEST_RNG_GET_CTX_PARAMS_DECODER_KEYS: [(&err_sites::ErrSite, *const c_char); 4] = [
    (&err_sites::PROV_TEST_RNG_244, OSSL_RAND_PARAM_GENERATE),
    (&err_sites::PROV_TEST_RNG_255, OSSL_RAND_PARAM_MAX_REQUEST),
    (&err_sites::PROV_TEST_RNG_274, OSSL_RAND_PARAM_STATE),
    (&err_sites::PROV_TEST_RNG_285, OSSL_RAND_PARAM_STRENGTH),
];

/// `static int test_rng_get_ctx_params(void *vtest, OSSL_PARAM params[])` —
/// `test_rng.c:300-326`, without its `#ifdef FIPS_MODULE` `ind` arm.
///
/// Unlike SEED-SRC, all four answers read the context, including `strength` and `max_request`.
///
/// # Safety
/// The dispatch contract.
unsafe extern "C" fn test_rng_get_ctx_params(vtest: *mut c_void, params: *mut OsslParam) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        if vtest.is_null() {
            return 0;
        }
        if let Some(site) = repeated_param_site(params, &TEST_RNG_GET_CTX_PARAMS_DECODER_KEYS) {
            return fail_at(site);
        }

        let t = vtest.cast::<ProvTestRng>();

        let p = OSSL_PARAM_locate(params, OSSL_RAND_PARAM_STATE);
        if !p.is_null() && OSSL_PARAM_set_int(p, (*t).state) == 0 {
            return 0;
        }

        let p = OSSL_PARAM_locate(params, OSSL_RAND_PARAM_STRENGTH);
        if !p.is_null() && OSSL_PARAM_set_uint(p, (*t).strength) == 0 {
            return 0;
        }

        let p = OSSL_PARAM_locate(params, OSSL_RAND_PARAM_MAX_REQUEST);
        if !p.is_null() && OSSL_PARAM_set_size_t(p, (*t).max_request) == 0 {
            return 0;
        }

        let p = OSSL_PARAM_locate(params, OSSL_RAND_PARAM_GENERATE);
        if !p.is_null() && OSSL_PARAM_set_uint(p, (*t).generate) == 0 {
            return 0;
        }

        // #ifdef FIPS_MODULE
        // if (p.ind != NULL && !OSSL_PARAM_set_int(p.ind, 0)) return 0;
        // #endif
        1
    }
}

/// `static const OSSL_PARAM *test_rng_gettable_ctx_params(ossl_unused void *vtest,
/// ossl_unused void *provctx)` — `test_rng.c:328-332`.
///
/// # Safety
/// The dispatch contract.
unsafe extern "C" fn test_rng_gettable_ctx_params(
    _vtest: *mut c_void,
    _provctx: *mut c_void,
) -> *const OsslParam {
    TEST_RNG_GET_CTX_PARAMS_LIST.as_ptr()
}

/* Machine generated — set side.
 * Switch order: 'g'enerate, 'm'ax_request, 's'trength, then the four-level 't'e's't'_'e'ntropy /
 * 't'e's't'_'n'once nest. Five keys, none FIPS-guarded. */

/// `static const OSSL_PARAM test_rng_set_ctx_params_list[]` — `test_rng.c:336-345`.
static TEST_RNG_SET_CTX_PARAMS_LIST: [OsslParam; 6] = [
    param_octet_string(OSSL_RAND_PARAM_TEST_ENTROPY),
    param_octet_string(OSSL_RAND_PARAM_TEST_NONCE),
    param_uint(OSSL_RAND_PARAM_STRENGTH),
    param_size_t(OSSL_RAND_PARAM_MAX_REQUEST),
    param_uint(OSSL_RAND_PARAM_GENERATE),
    END,
];

/// The five keys `test_rng_set_ctx_params_decoder` locates (switch order: `generate`,
/// `max_request`, `strength`, `test_entropy`, `test_nonce`), each with its raise site
/// (`test_rng.c:373`, `:384`, `:395`, `:426`, `:437`).
const TEST_RNG_SET_CTX_PARAMS_DECODER_KEYS: [(&err_sites::ErrSite, *const c_char); 5] = [
    (&err_sites::PROV_TEST_RNG_373, OSSL_RAND_PARAM_GENERATE),
    (&err_sites::PROV_TEST_RNG_384, OSSL_RAND_PARAM_MAX_REQUEST),
    (&err_sites::PROV_TEST_RNG_395, OSSL_RAND_PARAM_STRENGTH),
    (&err_sites::PROV_TEST_RNG_426, OSSL_RAND_PARAM_TEST_ENTROPY),
    (&err_sites::PROV_TEST_RNG_437, OSSL_RAND_PARAM_TEST_NONCE),
];

/// `static int test_rng_set_ctx_params(void *vtest, const OSSL_PARAM params[])` —
/// `test_rng.c:455-492`.
///
/// The ownership transfer is the contract here: `OSSL_PARAM_get_octet_string` **allocates** the
/// buffer it returns, the old field is `OPENSSL_free`d first, and `entropy_pos` is rewound to
/// 0. A wrong descriptor type is a bare `return 0` with no raise. `nonce` reuses the same
/// `ptr`/`size` temporaries without resetting `ptr` to NULL between the two arms, exactly as the
/// authority writes it — after the entropy arm `ptr` is explicitly re-NULLed, so the nonce arm
/// starts clean.
///
/// # Safety
/// The dispatch contract.
unsafe extern "C" fn test_rng_set_ctx_params(
    vtest: *mut c_void,
    params: *const OsslParam,
) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        if vtest.is_null() {
            return 0;
        }
        if let Some(site) = repeated_param_site(params, &TEST_RNG_SET_CTX_PARAMS_DECODER_KEYS) {
            return fail_at(site);
        }

        let t = vtest.cast::<ProvTestRng>();
        let mut ptr: *mut c_void = ptr::null_mut();
        let mut size: usize = 0;

        let p = OSSL_PARAM_locate_const(params, OSSL_RAND_PARAM_STRENGTH);
        if !p.is_null() && OSSL_PARAM_get_uint(p, ptr::addr_of_mut!((*t).strength)) == 0 {
            return 0;
        }

        let p = OSSL_PARAM_locate_const(params, OSSL_RAND_PARAM_TEST_ENTROPY);
        if !p.is_null() {
            if OSSL_PARAM_get_octet_string(p, &mut ptr, 0, &mut size) == 0 {
                return 0;
            }
            CRYPTO_free(
                (*t).entropy.cast(),
                FILE_TEST_RNG,
                LINE_TEST_RNG_SET_FREE_ENTROPY,
            );
            (*t).entropy = ptr.cast::<c_uchar>();
            (*t).entropy_len = size;
            (*t).entropy_pos = 0;
            ptr = ptr::null_mut();
        }

        let p = OSSL_PARAM_locate_const(params, OSSL_RAND_PARAM_TEST_NONCE);
        if !p.is_null() {
            if OSSL_PARAM_get_octet_string(p, &mut ptr, 0, &mut size) == 0 {
                return 0;
            }
            CRYPTO_free(
                (*t).nonce.cast(),
                FILE_TEST_RNG,
                LINE_TEST_RNG_SET_FREE_NONCE,
            );
            (*t).nonce = ptr.cast::<c_uchar>();
            (*t).nonce_len = size;
        }

        let p = OSSL_PARAM_locate_const(params, OSSL_RAND_PARAM_MAX_REQUEST);
        if !p.is_null() && OSSL_PARAM_get_size_t(p, ptr::addr_of_mut!((*t).max_request)) == 0 {
            return 0;
        }

        let p = OSSL_PARAM_locate_const(params, OSSL_RAND_PARAM_GENERATE);
        if !p.is_null() && OSSL_PARAM_get_uint(p, ptr::addr_of_mut!((*t).generate)) == 0 {
            return 0;
        }
        1
    }
}

/// `static const OSSL_PARAM *test_rng_settable_ctx_params(ossl_unused void *vtest,
/// ossl_unused void *provctx)` — `test_rng.c:494-498`.
///
/// # Safety
/// The dispatch contract.
unsafe extern "C" fn test_rng_settable_ctx_params(
    _vtest: *mut c_void,
    _provctx: *mut c_void,
) -> *const OsslParam {
    TEST_RNG_SET_CTX_PARAMS_LIST.as_ptr()
}

/// `static int test_rng_verify_zeroization(ossl_unused void *vtest)` — `test_rng.c:500-503`.
///
/// # Safety
/// The dispatch contract.
unsafe extern "C" fn test_rng_verify_zeroization(_vtest: *mut c_void) -> c_int {
    1
}

/// `static size_t test_rng_get_seed(void *vtest, unsigned char **pout, int entropy,
/// size_t min_len, size_t max_len, ossl_unused int prediction_resistance,
/// ossl_unused const unsigned char *adin, ossl_unused size_t adin_len)` —
/// `test_rng.c:505-515`.
///
/// **It does not allocate**: `*pout = t->entropy` hands the caller the context's own buffer,
/// and the return is `min(entropy_len, max_len)`. A subsequent `test_rng_clear_seed` is
/// therefore absent from this row's dispatch table — the caller must not free what it did not
/// receive.
///
/// # Safety
/// The dispatch contract.
unsafe extern "C" fn test_rng_get_seed(
    vtest: *mut c_void,
    pout: *mut *mut c_uchar,
    _entropy: c_int,
    _min_len: usize,
    max_len: usize,
    _prediction_resistance: c_int,
    _adin: *const c_uchar,
    _adin_len: usize,
) -> usize {
    // SAFETY: `vtest` is a live `ProvTestRng` and `pout` is writable per the contract.
    unsafe {
        let t = vtest.cast::<ProvTestRng>();
        *pout = (*t).entropy;
        if (*t).entropy_len > max_len {
            max_len
        } else {
            (*t).entropy_len
        }
    }
}

/// `static int test_rng_enable_locking(void *vtest)` — `test_rng.c:517-529`.
///
/// Lazily creates the lock, and a failed creation is the row's **only** raise:
/// `PROV_R_FAILED_TO_CREATE_LOCK`.
///
/// # Safety
/// The dispatch contract.
unsafe extern "C" fn test_rng_enable_locking(vtest: *mut c_void) -> c_int {
    // SAFETY: `vtest` is a live `ProvTestRng` per the contract.
    unsafe {
        let t = vtest.cast::<ProvTestRng>();
        if !t.is_null() && (*t).lock.is_null() {
            (*t).lock = CRYPTO_THREAD_lock_new();
            if (*t).lock.is_null() {
                // site: `err_sites::PROV_TEST_RNG_524` (`test_rng.c:524`,
                // ERR_LIB_PROV / PROV_R_FAILED_TO_CREATE_LOCK).
                raise_site(&err_sites::PROV_TEST_RNG_524);
                return 0;
            }
        }
        1
    }
}

/// `static int test_rng_lock(void *vtest)` — `test_rng.c:531-538`. A NULL context or a NULL
/// lock answers 1 without locking; otherwise it takes the **write** lock.
///
/// # Safety
/// The dispatch contract.
unsafe extern "C" fn test_rng_lock(vtest: *mut c_void) -> c_int {
    // SAFETY: `vtest` is a live `ProvTestRng` per the contract.
    unsafe {
        let t = vtest.cast::<ProvTestRng>();
        if t.is_null() || (*t).lock.is_null() {
            return 1;
        }
        CRYPTO_THREAD_write_lock((*t).lock)
    }
}

/// `static void test_rng_unlock(void *vtest)` — `test_rng.c:540-546`.
///
/// # Safety
/// The dispatch contract.
unsafe extern "C" fn test_rng_unlock(vtest: *mut c_void) {
    // SAFETY: `vtest` is a live `ProvTestRng` per the contract.
    unsafe {
        let t = vtest.cast::<ProvTestRng>();
        if !t.is_null() && !(*t).lock.is_null() {
            CRYPTO_THREAD_unlock((*t).lock);
        }
    }
}

/// `const OSSL_DISPATCH ossl_test_rng_functions[]` — `test_rng.c:548-571`, **sixteen** entries.
///
/// This is the one RAND row that publishes `NONCE`, `SETTABLE_CTX_PARAMS` **and**
/// `SET_CTX_PARAMS`, and it publishes no `CLEAR_SEED` to pair with its `GET_SEED`.
pub(crate) static TEST_RNG_FUNCTIONS: [OsslDispatch; 17] = [
    OsslDispatch {
        function_id: OSSL_FUNC_RAND_NEWCTX,
        function: test_rng_new as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_RAND_FREECTX,
        function: test_rng_free as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_RAND_INSTANTIATE,
        function: test_rng_instantiate as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_RAND_UNINSTANTIATE,
        function: test_rng_uninstantiate as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_RAND_GENERATE,
        function: test_rng_generate as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_RAND_RESEED,
        function: test_rng_reseed as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_RAND_NONCE,
        function: test_rng_nonce as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_RAND_ENABLE_LOCKING,
        function: test_rng_enable_locking as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_RAND_LOCK,
        function: test_rng_lock as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_RAND_UNLOCK,
        function: test_rng_unlock as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_RAND_SETTABLE_CTX_PARAMS,
        function: test_rng_settable_ctx_params as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_RAND_SET_CTX_PARAMS,
        function: test_rng_set_ctx_params as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_RAND_GETTABLE_CTX_PARAMS,
        function: test_rng_gettable_ctx_params as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_RAND_GET_CTX_PARAMS,
        function: test_rng_get_ctx_params as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_RAND_VERIFY_ZEROIZATION,
        function: test_rng_verify_zeroization as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_RAND_GET_SEED,
        function: test_rng_get_seed as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_DISPATCH_END,
        function: ptr::null_mut(),
    },
];

// =============================================================================================
// `providers/implementations/rands/fips_crng_test.c` — **not in this profile's build.**
//
// `providers/implementations/rands/build.info` puts the unit in `libfips.a` and nowhere else:
//
// ```text
// $RANDS_GOAL=../../libdefault.a ../../libfips.a
// SOURCE[$RANDS_GOAL]=drbg.c test_rng.c drbg_ctr.c drbg_hash.c drbg_hmac.c
// SOURCE[../../libdefault.a]=seed_src.c seed_src_jitter.c
// SOURCE[../../libfips.a]=fips_crng_test.c
// ```
//
// so the continuous RNG test is compiled into the FIPS module, which `configdata.pm`'s disabled
// list excludes from this profile. Its only authority row is `fipsprov.c:445`'s `CRNG-TEST`,
// and `fipsprov.c` is not an admitted provider: the provider census has no `CRNG-TEST` row for
// any of default/base/legacy/null, so there is no observable for a transcription to be measured
// against. It is therefore **recorded rather than transcribed**, which is the same treatment
// `#ifdef DSO_NONE`'s `dso_openssl.c` gets in `forensics/prerequisites.json`'s `units` block:
// a unit the profile does not build is a fact to state, not code to carry. `seed_src_jitter.c`
// is the neighbouring case -- it *is* in `libdefault.a`, but its row is inside
// `#ifndef OPENSSL_NO_JITTER` and `OPENSSL_NO_JITTER` is defined (`configdata.pm:215`), so it
// too publishes nothing.
// =============================================================================================

// =============================================================================================
// `crypto/rand/rand_uniform.c` — held back with the RAND front (D310).
//
// The staged transcription of `ossl_rand_uniform_uint32` and `ossl_rand_range_uint32` is
// **not here**, because both draw their bytes with `RAND_bytes_ex(NULL, ...)` and that export
// is `rand_lib.c`'s twenty-five, which have not landed. Writing the two helpers against a
// missing callee would be a stub wearing a name; they land in the commit that lands
// `RAND_bytes_ex`, and `forensics/prerequisites.json` records the unit as owed to it.
// =============================================================================================

// `providers/baseprov.c` — the RAND row only, as a Rust row description.
//
// The task asked for a TEST-RAND row in `baseprov.c`. **There is none.** The file's
// `base_rands[]` (`baseprov.c:90-96`) carries SEED-SRC and, guarded by `#ifndef
// OPENSSL_NO_JITTER`, JITTER — and `OPENSSL_NO_JITTER` is defined in this build
// (`configdata.pm:215`), so the published table is SEED-SRC alone. This is reproduced
// faithfully below. TEST-RAND is in the *default* provider's table instead:
// `defltprov.c:404-414` = CTR-DRBG, HASH-DRBG, HMAC-DRBG, SEED-SRC, TEST-RAND (no JITTER).
//
// The default provider's own module is not represented in this crate yet, so the row below is
// a description to be placed by the integration that lands `baseprov.c` and `defltprov.c`; it
// references `SEED_SRC_FUNCTIONS` above directly.
// =============================================================================================

/// `static const OSSL_ALGORITHM base_rands[]` — `providers/baseprov.c:90-96`, after the
/// `OPENSSL_NO_JITTER` guard is resolved for this build.
///
/// The authority's macro is `ALG(NAMES, FUNC) = { { NAMES, "provider=base", FUNC }, NULL }`,
/// i.e. a four-field [`OsslAlgorithm`] row with the property string **`"provider=base"`** and a
/// NULL description; the table is terminated by a row of NULLs (`providers/prov_running` reads
/// the first field to stop).
///
/// `algorithm_names` is `PROV_NAMES_SEED_SRC`, byte-for-byte `"SEED-SRC"`. The dispatch symbol
/// is `ossl_seed_src_functions[]` = [`SEED_SRC_FUNCTIONS`].
pub(crate) static BASE_RANDS: [OsslAlgorithm; 2] = [
    OsslAlgorithm {
        algorithm_names: PROV_NAMES_SEED_SRC,
        property_definition: c"provider=base".as_ptr(),
        implementation: SEED_SRC_FUNCTIONS.as_ptr().cast(),
        algorithm_description: ptr::null(),
    },
    // #ifndef OPENSSL_NO_JITTER
    // { PROV_NAMES_JITTER, "provider=base", ossl_jitter_functions },
    // #endif
    OsslAlgorithm {
        algorithm_names: ptr::null(),
        property_definition: ptr::null(),
        implementation: ptr::null(),
        algorithm_description: ptr::null(),
    },
];

/// `static const OSSL_ALGORITHM *base_query(void *provctx, int operation_id,
/// int *no_cache)` — `providers/baseprov.c:98-113`, with only the RAND arm relevant here.
///
/// The shape the integration must reproduce: `*no_cache` is set to 0 **before** the switch, so
/// the operation tables are cacheable; `OSSL_OP_RAND` selects `base_rands`; and every other
/// operation id — including the four baseprov.c handles (ENCODER, DECODER, STORE, RAND) — falls
/// through to NULL. This function is not provider-row data and is not transcribed as Rust here
/// because the base provider's module does not exist in this crate yet; the row above is the
/// part that belongs to this unit.
///
/// # Safety
/// `no_cache` must be writable; `provctx` is ignored by the RAND arm.
#[allow(dead_code)] // the base provider's module lands separately
unsafe extern "C" fn base_query(
    _provctx: *mut c_void,
    operation_id: c_int,
    no_cache: *mut c_int,
) -> *const OsslAlgorithm {
    // SAFETY: `no_cache` is writable per the contract.
    unsafe { *no_cache = 0 };
    match operation_id {
        OSSL_OP_RAND => BASE_RANDS.as_ptr(),
        _ => ptr::null(),
    }
}

// The **default** provider's RAND rows are not described here: they are published by
// `DEFLT_RANDS` in `src/provider/rand.rs`, which is where `deflt_query`'s `OSSL_OP_RAND` arm
// reads them, and the provider census reads them out of that table rather than out of prose.
// `providers/defltprov.c:404-414` is the authority's table and `src/provider/rand.rs` carries
// its five rows.
