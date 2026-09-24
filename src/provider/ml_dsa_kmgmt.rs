//! Phase 8 — `providers/implementations/keymgmt/ml_dsa_kmgmt.c.in`: the three ML-DSA keymgmt rows.
//!
//! Six hundred and sixteen template lines, three `produce_param_decoder` blocks expanded inline and
//! **one** body with three macro expansions, publishing the `ML-DSA-44`/`-65`/`-87` rows of
//! `deflt_keymgmt[]`. Every row's table is the same nineteen slots; only `NEW` and `GEN` differ,
//! because each carries its own `EVP_PKEY_ML_DSA_*` NID into `ossl_prov_ml_dsa_new`/`ml_dsa_gen`.
//!
//! ## The generated decoders are written the crate's way
//!
//! `util/perl/OpenSSL/paramnames.pm` emits, for each `produce_param_decoder` block, a
//! character-by-character `switch` trie over the parameter's key. Its whole observable content is
//! the **repeated-key refusal** — an `ERR_raise_data(..., PROV_R_REPEATED_PARAMETER, ...)` at the
//! parameter's own coordinate — plus the located pointer this unit's body reads. The three decoders
//! here are the repeated-key scan plus `OSSL_PARAM_locate_const` per key, the shape
//! `src/provider/ml_kem_kmgmt.rs` and `src/provider/slh_dsa_kmgmt.rs` already use for theirs. The
//! tuple order is not the site order: the generated trie emits each key's raise at its own leaf in
//! first-character order, so the pairing was read back from the authority's expanded
//! `build/openssl-3.6.4-production/.../ml_dsa_kmgmt.c` — `p`→`r`·`p`→`u` then `s` for the key-type
//! block; `b`·`m`→`a`→`n`·`m`→`a`→`x`·`p`→`r`·`p`→`u` then the `s` subtree's `security-bits`·
//! `security-category`·`seed` for get-params; and `p`·`s` for the gen-set block.
//!
//! ## The `FIPS_MODULE` arms are absent, the non-FIPS ones are not
//!
//! `ml_dsa_pairwise_test` (`:54-106`) and the `#ifdef FIPS_MODULE` self-test calls in
//! `ml_dsa_import` (`:301-307`) and `ml_dsa_gen` (`:511-514`) are inside `#ifdef FIPS_MODULE`, which
//! this profile does not define, so they are recorded with their coordinates and not written. The
//! `#ifndef FIPS_MODULE` `ml_dsa_load` **is** compiled — `DISPATCH_LOAD_FN` is the non-FIPS arm — so
//! the unit's `LOAD` slot is present and `ml_dsa_load` is written.
//!
//! SPDX-License-Identifier: Apache-2.0

#![allow(unreachable_pub)]

use core::ffi::{c_char, c_int, c_void, CStr};
use core::ptr;

use crate::context::dispatch::{OsslDispatch, OSSL_DISPATCH_END};
use crate::evp::keymgmt::{
    OSSL_FUNC_KEYMGMT_DUP, OSSL_FUNC_KEYMGMT_EXPORT, OSSL_FUNC_KEYMGMT_EXPORT_TYPES,
    OSSL_FUNC_KEYMGMT_FREE, OSSL_FUNC_KEYMGMT_GEN, OSSL_FUNC_KEYMGMT_GEN_CLEANUP,
    OSSL_FUNC_KEYMGMT_GEN_INIT, OSSL_FUNC_KEYMGMT_GEN_SETTABLE_PARAMS,
    OSSL_FUNC_KEYMGMT_GEN_SET_PARAMS, OSSL_FUNC_KEYMGMT_GETTABLE_PARAMS,
    OSSL_FUNC_KEYMGMT_GET_PARAMS, OSSL_FUNC_KEYMGMT_HAS, OSSL_FUNC_KEYMGMT_IMPORT,
    OSSL_FUNC_KEYMGMT_IMPORT_TYPES, OSSL_FUNC_KEYMGMT_LOAD, OSSL_FUNC_KEYMGMT_MATCH,
    OSSL_FUNC_KEYMGMT_NEW, OSSL_FUNC_KEYMGMT_VALIDATE,
};
use crate::evp::pkey::{OSSL_KEYMGMT_SELECT_PRIVATE_KEY, OSSL_KEYMGMT_SELECT_PUBLIC_KEY};
use crate::ml_dsa::encoders::{ossl_ml_dsa_pk_decode, ossl_ml_dsa_sk_decode};
use crate::ml_dsa::key::{
    ossl_ml_dsa_generate_key, ossl_ml_dsa_key_dup, ossl_ml_dsa_key_equal, ossl_ml_dsa_key_free,
    ossl_ml_dsa_key_get_collision_strength_bits, ossl_ml_dsa_key_get_priv,
    ossl_ml_dsa_key_get_priv_len, ossl_ml_dsa_key_get_prov_flags, ossl_ml_dsa_key_get_pub,
    ossl_ml_dsa_key_get_pub_len, ossl_ml_dsa_key_get_security_category, ossl_ml_dsa_key_get_seed,
    ossl_ml_dsa_key_get_sig_len, ossl_ml_dsa_key_has, ossl_ml_dsa_key_new,
    ossl_ml_dsa_key_pairwise_check, ossl_ml_dsa_key_params, ossl_ml_dsa_key_reset,
    ossl_ml_dsa_set_prekey,
};
use crate::ml_dsa::{
    MlDsaKey, EVP_PKEY_ML_DSA_44, EVP_PKEY_ML_DSA_65, EVP_PKEY_ML_DSA_87, ML_DSA_ENTROPY_LEN,
    ML_DSA_KEY_PREFER_SEED, ML_DSA_KEY_RETAIN_SEED, ML_DSA_SEED_BYTES,
};
use crate::params::{
    OSSL_PARAM_construct_end, OSSL_PARAM_construct_octet_string, OSSL_PARAM_get_octet_string,
    OSSL_PARAM_get_octet_string_ptr, OSSL_PARAM_get_utf8_string, OSSL_PARAM_locate_const,
    OSSL_PARAM_set_int, OSSL_PARAM_set_octet_string, OSSL_PARAM_set_size_t,
    OSSL_PARAM_set_utf8_string, OsslParam, END,
};
use crate::provider::cipher::{param_int, param_octet_string, param_utf8_string};
use crate::provider::ctx::{ossl_prov_ctx_get_bool_param, prov_libctx_of, ProvCtx};
use crate::runtime::err::err_sites;
use crate::runtime::err::{raise_site, raise_site_data};
use crate::runtime::mem::{CRYPTO_free, CRYPTO_zalloc, OPENSSL_cleanse};
use crate::selftest::OsslCallback;

extern "C" {
    /// `int memcmp(const void *, const void *, size_t)` — the authority's own comparison, reached at
    /// `ml_dsa_kmgmt.c`'s `ml_dsa_key_fromdata`.
    fn memcmp(a: *const c_void, b: *const c_void, n: usize) -> c_int;
}

/// `OSSL_KEYMGMT_SELECT_KEYPAIR` — `core_dispatch.h:649-650`, `PRIVATE_KEY | PUBLIC_KEY`.
///
/// The pair is **imported** from `src/evp/pkey.rs` rather than re-spelled, the same union
/// `src/provider/ml_kem_kmgmt.rs` and `src/provider/slh_dsa_kmgmt.rs` build.
const OSSL_KEYMGMT_SELECT_KEYPAIR: c_int =
    OSSL_KEYMGMT_SELECT_PRIVATE_KEY | OSSL_KEYMGMT_SELECT_PUBLIC_KEY;

/// `OSSL_PKEY_PARAM_BITS` — `core_names.h` (spelled `OSSL_ALG_PARAM_BITS` there).
const OSSL_PKEY_PARAM_BITS: *const c_char = c"bits".as_ptr();
/// `OSSL_PKEY_PARAM_SECURITY_BITS` — `core_names.h`.
const OSSL_PKEY_PARAM_SECURITY_BITS: *const c_char = c"security-bits".as_ptr();
/// `OSSL_PKEY_PARAM_MAX_SIZE` — `core_names.h`.
const OSSL_PKEY_PARAM_MAX_SIZE: *const c_char = c"max-size".as_ptr();
/// `OSSL_PKEY_PARAM_SECURITY_CATEGORY` — `core_names.h`, spelled `OSSL_ALG_PARAM_SECURITY_CATEGORY`.
const OSSL_PKEY_PARAM_SECURITY_CATEGORY: *const c_char = c"security-category".as_ptr();
/// `OSSL_PKEY_PARAM_MANDATORY_DIGEST` — `core_names.h:422`.
const OSSL_PKEY_PARAM_MANDATORY_DIGEST: *const c_char = c"mandatory-digest".as_ptr();
/// `OSSL_PKEY_PARAM_ML_DSA_SEED` — `core_names.h:431`, `"seed"`.
const OSSL_PKEY_PARAM_ML_DSA_SEED: *const c_char = c"seed".as_ptr();
/// `OSSL_PKEY_PARAM_PRIV_KEY` — `core_names.h:439`.
const OSSL_PKEY_PARAM_PRIV_KEY: *const c_char = c"priv".as_ptr();
/// `OSSL_PKEY_PARAM_PUB_KEY` — `core_names.h:441`.
const OSSL_PKEY_PARAM_PUB_KEY: *const c_char = c"pub".as_ptr();
/// `OSSL_PKEY_PARAM_PROPERTIES` — `core_names.h:440`, `OSSL_ALG_PARAM_PROPERTIES`.
const OSSL_PKEY_PARAM_PROPERTIES: *const c_char = c"properties".as_ptr();
/// `OSSL_PKEY_PARAM_ML_DSA_RETAIN_SEED` — `core_names.h:430`.
const OSSL_PKEY_PARAM_ML_DSA_RETAIN_SEED: *const c_char = c"ml-dsa.retain_seed".as_ptr();
/// `OSSL_PKEY_PARAM_ML_DSA_PREFER_SEED` — `core_names.h:429`.
const OSSL_PKEY_PARAM_ML_DSA_PREFER_SEED: *const c_char = c"ml-dsa.prefer_seed".as_ptr();

/// The unit's own `__FILE__`. `.c.in`-generated, so the bare build-relative path.
const FILE: *const c_char = c"providers/implementations/keymgmt/ml_dsa_kmgmt.c".as_ptr();
/// `ml_dsa_kmgmt.c:730`, `ml_dsa_gen_init`'s `OPENSSL_zalloc(sizeof(*gctx))`.
const LINE_GEN_ZALLOC: c_int = 730;
/// `ml_dsa_kmgmt.c:733`, `ml_dsa_gen_init`'s `OPENSSL_free(gctx)` failure path.
const LINE_GEN_FREE_GCTX: c_int = 733;
/// `ml_dsa_kmgmt.c:844`, `ml_dsa_gen_set_params`'s `OPENSSL_free(gctx->propq)`.
const LINE_GEN_SET_FREE_PROPQ: c_int = 844;
/// `ml_dsa_kmgmt.c:866`, `ml_dsa_gen_cleanup`'s `OPENSSL_free(gctx->propq)`.
const LINE_GEN_CLEANUP_PROPQ: c_int = 866;
/// `ml_dsa_kmgmt.c:867`, `ml_dsa_gen_cleanup`'s `OPENSSL_free(gctx)`.
const LINE_GEN_CLEANUP_CTX: c_int = 867;

/// `ossl_prov_is_running()` — the literal 1 on this build.
#[inline]
fn is_running() -> c_int {
    1
}

/// `struct ml_dsa_gen_ctx` — `ml_dsa_kmgmt.c.in:47-52`.
#[repr(C)]
struct MlDsaGenCtx {
    /// `PROV_CTX *provctx` — borrowed.
    provctx: *mut ProvCtx,
    /// `char *propq` — owned.
    propq: *mut c_char,
    /// `uint8_t entropy[32]` — the caller-supplied keygen seed.
    entropy: [u8; ML_DSA_ENTROPY_LEN],
    /// `size_t entropy_len`.
    entropy_len: usize,
}

/// Raise a message of the form `prefix || algorithm_name || suffix`.
///
/// # Safety
/// `alg` must be a NUL-terminated C string.
unsafe fn raise_with_alg(
    site: &err_sites::ErrSite,
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

/// `ML_DSA_KEY *ossl_prov_ml_dsa_new(PROV_CTX *ctx, const char *propq, int evp_type)` —
/// `ml_dsa_kmgmt.c.in:108-140`.
///
/// # Safety
/// `ctx` is the provider context; `propq` is NULL or NUL-terminated.
pub(crate) unsafe fn ossl_prov_ml_dsa_new(
    ctx: *mut ProvCtx,
    propq: *const c_char,
    evp_type: c_int,
) -> *mut MlDsaKey {
    if is_running() == 0 {
        return ptr::null_mut();
    }

    // SAFETY: `ctx` is the caller's context; `propq` is NUL-terminated.
    unsafe {
        let key = ossl_ml_dsa_key_new(prov_libctx_of(ctx.cast()), propq, evp_type);
        /*
         * When decoding, if the key ends up "loaded" into the same provider, these are the correct
         * config settings, otherwise, new values will be assigned on import into a different
         * provider. The "load" API does not pass along the provider context.
         */
        if !key.is_null() {
            let mut flags_set: c_int = 0;
            let mut flags_clr: c_int = 0;

            if ossl_prov_ctx_get_bool_param(ctx, OSSL_PKEY_PARAM_ML_DSA_RETAIN_SEED, 1) != 0 {
                flags_set |= ML_DSA_KEY_RETAIN_SEED;
            } else {
                flags_clr = ML_DSA_KEY_RETAIN_SEED;
            }

            if ossl_prov_ctx_get_bool_param(ctx, OSSL_PKEY_PARAM_ML_DSA_PREFER_SEED, 1) != 0 {
                flags_set |= ML_DSA_KEY_PREFER_SEED;
            } else {
                flags_clr |= ML_DSA_KEY_PREFER_SEED;
            }

            ossl_ml_dsa_set_prekey(key, flags_set, flags_clr, ptr::null(), 0, ptr::null(), 0);
        }
        key
    }
}

/// `static void ml_dsa_free_key(void *keydata)` — `ml_dsa_kmgmt.c.in:142-145`.
///
/// # Safety
/// The keymgmt `free` dispatch contract.
unsafe extern "C" fn ml_dsa_free_key(keydata: *mut c_void) {
    // SAFETY: `keydata` is NULL or the caller's key.
    unsafe { ossl_ml_dsa_key_free(keydata.cast::<MlDsaKey>()) };
}

/// `static void *ml_dsa_dup_key(const void *keydata_from, int selection)` —
/// `ml_dsa_kmgmt.c.in:147-152`.
///
/// # Safety
/// The keymgmt `dup` dispatch contract.
unsafe extern "C" fn ml_dsa_dup_key(keydata_from: *const c_void, selection: c_int) -> *mut c_void {
    if is_running() != 0 {
        // SAFETY: the caller's contract, forwarded.
        return unsafe { ossl_ml_dsa_key_dup(keydata_from.cast::<MlDsaKey>(), selection) }.cast();
    }
    ptr::null_mut()
}

/// `static int ml_dsa_has(const void *keydata, int selection)` — `ml_dsa_kmgmt.c.in:154-164`.
///
/// # Safety
/// The keymgmt `has` dispatch contract.
unsafe extern "C" fn ml_dsa_has(keydata: *const c_void, selection: c_int) -> c_int {
    let key = keydata.cast::<MlDsaKey>();

    if is_running() == 0 || key.is_null() {
        return 0;
    }
    if (selection & OSSL_KEYMGMT_SELECT_KEYPAIR) == 0 {
        return 1; /* the selection is not missing */
    }
    // SAFETY: `key` is non-NULL past the guard.
    unsafe { ossl_ml_dsa_key_has(key, selection) }
}

/// `static int ml_dsa_match(const void *keydata1, const void *keydata2, int selection)` —
/// `ml_dsa_kmgmt.c.in:166-176`.
///
/// # Safety
/// The keymgmt `match` dispatch contract.
unsafe extern "C" fn ml_dsa_match(
    keydata1: *const c_void,
    keydata2: *const c_void,
    selection: c_int,
) -> c_int {
    if is_running() == 0 {
        return 0;
    }
    if keydata1.is_null() || keydata2.is_null() {
        return 0;
    }
    // SAFETY: both keys are the caller's and non-NULL past the guard.
    unsafe {
        ossl_ml_dsa_key_equal(
            keydata1.cast::<MlDsaKey>(),
            keydata2.cast::<MlDsaKey>(),
            selection,
        )
    }
}

/// `static int ml_dsa_validate(const void *key_data, int selection, int check_type)` —
/// `ml_dsa_kmgmt.c.in:178-188`.
///
/// `check_type` is unused by the authority.
///
/// # Safety
/// The keymgmt `validate` dispatch contract.
unsafe extern "C" fn ml_dsa_validate(
    key_data: *const c_void,
    selection: c_int,
    _check_type: c_int,
) -> c_int {
    // SAFETY: `key_data` is the caller's key.
    unsafe {
        if ml_dsa_has(key_data, selection) == 0 {
            return 0;
        }

        if (selection & OSSL_KEYMGMT_SELECT_KEYPAIR) == OSSL_KEYMGMT_SELECT_KEYPAIR {
            return ossl_ml_dsa_key_pairwise_check(key_data.cast::<MlDsaKey>());
        }
    }
    1
}

// ---------------------------------------------------------------------------------------------
// The generated decoders — `paramnames.pm`'s repeated-key walk, written the crate's way.
// ---------------------------------------------------------------------------------------------

/// The repeated-key scan the three generated decoders share — the observable content of
/// `paramnames.pm`'s nested key walk.
///
/// # Safety
/// `params` is NULL or a key-terminated array.
unsafe fn ml_dsa_repeated_param_site(
    params: *const OsslParam,
    keys: &[(&'static err_sites::ErrSite, *const c_char)],
) -> Option<&'static err_sites::ErrSite> {
    if params.is_null() {
        return None;
    }
    // SAFETY: the array is key-terminated per the contract; the walk stops at the NULL key.
    unsafe {
        let mut seen: u32 = 0;
        let mut p = params;
        while !(*p).key.is_null() {
            let k = CStr::from_ptr((*p).key).to_bytes();
            for (i, (site, name)) in keys.iter().enumerate() {
                if CStr::from_ptr(*name).to_bytes() == k {
                    let bit = 1u32 << i;
                    if seen & bit != 0 {
                        return Some(site);
                    }
                    seen |= bit;
                    break;
                }
            }
            p = p.add(1);
        }
    }
    None
}

/// `static const OSSL_PARAM ml_dsa_key_type_params_list[]` — generated `ml_dsa_kmgmt.c`.
static ML_DSA_KEY_TYPE_PARAMS_LIST: [OsslParam; 4] = [
    param_octet_string(OSSL_PKEY_PARAM_ML_DSA_SEED),
    param_octet_string(OSSL_PKEY_PARAM_PUB_KEY),
    param_octet_string(OSSL_PKEY_PARAM_PRIV_KEY),
    END,
];

/// `struct ml_dsa_key_type_params_st` — generated `ml_dsa_kmgmt.c`.
struct KeyTypeParams {
    seed: *const OsslParam,
    privkey: *const OsslParam,
    pubkey: *const OsslParam,
}

/// The `ml_dsa_key_type_params` decoder's coordinates, in the trie's own leaf order.
///
/// Read back from the generated unit: `p`→`r` (`priv`), `p`→`u` (`pub`), then `s` (`seed`).
const KEY_TYPE_DECODER_KEYS: [(&err_sites::ErrSite, *const c_char); 3] = [
    (&err_sites::PROV_ML_DSA_KMGMT_227, OSSL_PKEY_PARAM_PRIV_KEY),
    (&err_sites::PROV_ML_DSA_KMGMT_238, OSSL_PKEY_PARAM_PUB_KEY),
    (
        &err_sites::PROV_ML_DSA_KMGMT_250,
        OSSL_PKEY_PARAM_ML_DSA_SEED,
    ),
];

/// `ml_dsa_key_type_params_decoder` — generated `ml_dsa_kmgmt.c`.
///
/// # Safety
/// `params` is NULL or key-terminated; `r` is writable.
unsafe fn key_type_params_decoder(params: *const OsslParam, r: &mut KeyTypeParams) -> c_int {
    // SAFETY: the arguments are per the contract.
    unsafe {
        if let Some(site) = ml_dsa_repeated_param_site(params, &KEY_TYPE_DECODER_KEYS) {
            raise_site(site);
            return 0;
        }
        r.seed = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_ML_DSA_SEED);
        r.privkey = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_PRIV_KEY);
        r.pubkey = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_PUB_KEY);
    }
    1
}

/// `static int ml_dsa_key_fromdata(ML_DSA_KEY *key, const OSSL_PARAM params[],`
/// `int include_private)` — `ml_dsa_kmgmt.c.in:207-285`.
///
/// # Safety
/// `key` is live and has no key material yet.
unsafe fn ml_dsa_key_fromdata(
    key: *mut MlDsaKey,
    params: *const OsslParam,
    include_private: c_int,
) -> c_int {
    let mut p = KeyTypeParams {
        seed: ptr::null(),
        privkey: ptr::null(),
        pubkey: ptr::null(),
    };
    let mut pk: *const c_void = ptr::null();
    let mut sk: *const c_void = ptr::null();
    let mut seed: *const c_void = ptr::null();
    let mut pk_len = 0usize;
    let mut sk_len = 0usize;
    let mut seed_len = 0usize;

    // SAFETY: the arguments are per the contract.
    unsafe {
        let key_params = ossl_ml_dsa_key_params(key);

        if key_type_params_decoder(params, &mut p) == 0 {
            return 0;
        }

        if !p.pubkey.is_null() {
            if OSSL_PARAM_get_octet_string_ptr(p.pubkey, &mut pk, &mut pk_len) == 0 {
                return 0;
            }
            if !pk.is_null() && pk_len != (*key_params).pk_len {
                raise_with_alg(
                    &err_sites::PROV_ML_DSA_KMGMT_287,
                    "Invalid ",
                    (*key_params).alg,
                    " public key length",
                );
                return 0;
            }
        }

        /* Private key seed is optional */
        if !p.seed.is_null() && include_private != 0 {
            if OSSL_PARAM_get_octet_string_ptr(p.seed, &mut seed, &mut seed_len) == 0 {
                return 0;
            }
            if !seed.is_null() && seed_len != ML_DSA_SEED_BYTES {
                raise_site(&err_sites::PROV_ML_DSA_KMGMT_299);
                return 0;
            }
        }

        /* Private key is optional */
        if !p.privkey.is_null() && include_private != 0 {
            if OSSL_PARAM_get_octet_string_ptr(p.privkey, &mut sk, &mut sk_len) == 0 {
                return 0;
            }
            if !sk.is_null() && sk_len != (*key_params).sk_len {
                raise_with_alg(
                    &err_sites::PROV_ML_DSA_KMGMT_310,
                    "Invalid ",
                    (*key_params).alg,
                    " private key length",
                );
                return 0;
            }
        }

        /* The caller MUST specify at least one of seed, private or public keys. */
        if seed_len == 0 && pk_len == 0 && sk_len == 0 {
            raise_site(&err_sites::PROV_ML_DSA_KMGMT_319);
            return 0;
        }

        if seed_len != 0
            && (sk_len == 0 || (ossl_ml_dsa_key_get_prov_flags(key) & ML_DSA_KEY_PREFER_SEED) != 0)
        {
            if ossl_ml_dsa_set_prekey(key, 0, 0, seed.cast(), seed_len, sk.cast(), sk_len) == 0 {
                return 0;
            }
            if ossl_ml_dsa_generate_key(key) == 0 {
                raise_site(&err_sites::PROV_ML_DSA_KMGMT_329);
                return 0;
            }
        } else if sk_len > 0 {
            if ossl_ml_dsa_sk_decode(key, sk.cast(), sk_len) == 0 {
                return 0;
            }
        } else if pk_len > 0 && ossl_ml_dsa_pk_decode(key, pk.cast(), pk_len) == 0 {
            return 0;
        }

        /* Error if the supplied public key does not match the generated key */
        if pk_len == 0
            || seed_len + sk_len == 0
            || memcmp(ossl_ml_dsa_key_get_pub(key).cast(), pk, pk_len) == 0
        {
            return 1;
        }
        raise_with_alg(
            &err_sites::PROV_ML_DSA_KMGMT_345,
            "explicit ",
            (*key_params).alg,
            " public key does not match private",
        );
        ossl_ml_dsa_key_reset(key);
    }
    0
}

/// `static int ml_dsa_import(void *keydata, int selection, const OSSL_PARAM params[])` —
/// `ml_dsa_kmgmt.c.in:287-309`.
///
/// The `FIPS_MODULE` pairwise-test block (`:301-307`) is absent on this profile.
///
/// # Safety
/// The keymgmt `import` dispatch contract.
unsafe extern "C" fn ml_dsa_import(
    keydata: *mut c_void,
    selection: c_int,
    params: *const OsslParam,
) -> c_int {
    let key = keydata.cast::<MlDsaKey>();

    if is_running() == 0 || key.is_null() {
        return 0;
    }
    if (selection & OSSL_KEYMGMT_SELECT_KEYPAIR) == 0 {
        return 0;
    }

    let include_priv = c_int::from((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0);
    // SAFETY: `key` is live per the contract.
    unsafe { ml_dsa_key_fromdata(key, params, include_priv) }
}

/// `static const OSSL_PARAM *ml_dsa_imexport_types(int selection)` —
/// `ml_dsa_kmgmt.c.in:311-316`.
///
/// # Safety
/// The keymgmt `import_types`/`export_types` dispatch contract.
unsafe extern "C" fn ml_dsa_imexport_types(selection: c_int) -> *const OsslParam {
    if (selection & OSSL_KEYMGMT_SELECT_KEYPAIR) == 0 {
        return ptr::null();
    }
    ML_DSA_KEY_TYPE_PARAMS_LIST.as_ptr()
}

/// `static const OSSL_PARAM ml_dsa_get_params_list[]` — generated `ml_dsa_kmgmt.c`.
static ML_DSA_GET_PARAMS_LIST: [OsslParam; 9] = [
    param_int(OSSL_PKEY_PARAM_BITS),
    param_int(OSSL_PKEY_PARAM_SECURITY_BITS),
    param_int(OSSL_PKEY_PARAM_MAX_SIZE),
    param_int(OSSL_PKEY_PARAM_SECURITY_CATEGORY),
    param_utf8_string(OSSL_PKEY_PARAM_MANDATORY_DIGEST),
    param_octet_string(OSSL_PKEY_PARAM_ML_DSA_SEED),
    param_octet_string(OSSL_PKEY_PARAM_PUB_KEY),
    param_octet_string(OSSL_PKEY_PARAM_PRIV_KEY),
    END,
];

/// `struct ml_dsa_get_params_st` — generated `ml_dsa_kmgmt.c`.
struct GetParams {
    bits: *mut OsslParam,
    dgstp: *mut OsslParam,
    maxsize: *mut OsslParam,
    privkey: *mut OsslParam,
    pubkey: *mut OsslParam,
    secbits: *mut OsslParam,
    seccat: *mut OsslParam,
    seed: *mut OsslParam,
}

/// The `ml_dsa_get_params` decoder's eight coordinates, in the trie's own leaf order:
/// `b`·`m`→`a`→`n`·`m`→`a`→`x`·`p`→`r`·`p`→`u`, then the `s` subtree's three.
const GET_PARAMS_DECODER_KEYS: [(&err_sites::ErrSite, *const c_char); 8] = [
    (&err_sites::PROV_ML_DSA_KMGMT_428, OSSL_PKEY_PARAM_BITS),
    (
        &err_sites::PROV_ML_DSA_KMGMT_447,
        OSSL_PKEY_PARAM_MANDATORY_DIGEST,
    ),
    (&err_sites::PROV_ML_DSA_KMGMT_458, OSSL_PKEY_PARAM_MAX_SIZE),
    (&err_sites::PROV_ML_DSA_KMGMT_475, OSSL_PKEY_PARAM_PRIV_KEY),
    (&err_sites::PROV_ML_DSA_KMGMT_486, OSSL_PKEY_PARAM_PUB_KEY),
    (
        &err_sites::PROV_ML_DSA_KMGMT_534,
        OSSL_PKEY_PARAM_SECURITY_BITS,
    ),
    (
        &err_sites::PROV_ML_DSA_KMGMT_545,
        OSSL_PKEY_PARAM_SECURITY_CATEGORY,
    ),
    (
        &err_sites::PROV_ML_DSA_KMGMT_563,
        OSSL_PKEY_PARAM_ML_DSA_SEED,
    ),
];

/// `ml_dsa_get_params_decoder` — generated `ml_dsa_kmgmt.c`.
///
/// # Safety
/// `params` is NULL or key-terminated; `r` is writable.
unsafe fn get_params_decoder(params: *const OsslParam, r: &mut GetParams) -> c_int {
    // SAFETY: the arguments are per the contract.
    unsafe {
        if let Some(site) = ml_dsa_repeated_param_site(params, &GET_PARAMS_DECODER_KEYS) {
            raise_site(site);
            return 0;
        }
        r.bits = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_BITS).cast_mut();
        r.secbits = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_SECURITY_BITS).cast_mut();
        r.maxsize = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_MAX_SIZE).cast_mut();
        r.seccat = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_SECURITY_CATEGORY).cast_mut();
        r.dgstp = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_MANDATORY_DIGEST).cast_mut();
        r.seed = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_ML_DSA_SEED).cast_mut();
        r.pubkey = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_PUB_KEY).cast_mut();
        r.privkey = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_PRIV_KEY).cast_mut();
    }
    1
}

/// `static const OSSL_PARAM *ml_dsa_gettable_params(void *provctx)` —
/// `ml_dsa_kmgmt.c.in:331-334`.
///
/// `provctx` is unused by the authority.
///
/// # Safety
/// Takes no live pointers it reads.
unsafe extern "C" fn ml_dsa_gettable_params(_provctx: *mut c_void) -> *const OsslParam {
    ML_DSA_GET_PARAMS_LIST.as_ptr()
}

/// `static int ml_dsa_get_params(void *keydata, OSSL_PARAM params[])` —
/// `ml_dsa_kmgmt.c.in:336-393`.
///
/// # Safety
/// The keymgmt `get_params` dispatch contract.
unsafe extern "C" fn ml_dsa_get_params(keydata: *mut c_void, params: *mut OsslParam) -> c_int {
    let key = keydata.cast::<MlDsaKey>();
    let mut p = GetParams {
        bits: ptr::null_mut(),
        dgstp: ptr::null_mut(),
        maxsize: ptr::null_mut(),
        privkey: ptr::null_mut(),
        pubkey: ptr::null_mut(),
        secbits: ptr::null_mut(),
        seccat: ptr::null_mut(),
        seed: ptr::null_mut(),
    };

    // SAFETY: `key` and `params` are the caller's.
    unsafe {
        if key.is_null() || get_params_decoder(params, &mut p) == 0 {
            return 0;
        }

        if !p.bits.is_null()
            && OSSL_PARAM_set_size_t(p.bits, 8 * ossl_ml_dsa_key_get_pub_len(key)) == 0
        {
            return 0;
        }

        if !p.secbits.is_null()
            && OSSL_PARAM_set_size_t(p.secbits, ossl_ml_dsa_key_get_collision_strength_bits(key))
                == 0
        {
            return 0;
        }

        if !p.maxsize.is_null()
            && OSSL_PARAM_set_size_t(p.maxsize, ossl_ml_dsa_key_get_sig_len(key)) == 0
        {
            return 0;
        }

        if !p.seccat.is_null()
            && OSSL_PARAM_set_int(p.seccat, ossl_ml_dsa_key_get_security_category(key)) == 0
        {
            return 0;
        }

        if !p.seed.is_null() {
            let d = ossl_ml_dsa_key_get_seed(key);
            if !d.is_null() && OSSL_PARAM_set_octet_string(p.seed, d.cast(), ML_DSA_SEED_BYTES) == 0
            {
                return 0;
            }
        }

        if !p.privkey.is_null() {
            let d = ossl_ml_dsa_key_get_priv(key);
            if !d.is_null() {
                let len = ossl_ml_dsa_key_get_priv_len(key);
                if OSSL_PARAM_set_octet_string(p.privkey, d.cast(), len) == 0 {
                    return 0;
                }
            }
        }

        if !p.pubkey.is_null() {
            let d = ossl_ml_dsa_key_get_pub(key);
            if !d.is_null() {
                let len = ossl_ml_dsa_key_get_pub_len(key);
                if OSSL_PARAM_set_octet_string(p.pubkey, d.cast(), len) == 0 {
                    return 0;
                }
            }
        }

        /*
         * This allows apps to use an empty digest, so that the old API for digest signing can be
         * used.
         */
        if !p.dgstp.is_null() && OSSL_PARAM_set_utf8_string(p.dgstp, c"".as_ptr()) == 0 {
            return 0;
        }
    }
    1
}

/// `static int ml_dsa_export(void *keydata, int selection, OSSL_CALLBACK *param_cb, void *cbarg)` —
/// `ml_dsa_kmgmt.c.in:395-433`.
///
/// # Safety
/// The keymgmt `export` dispatch contract.
unsafe extern "C" fn ml_dsa_export(
    keydata: *mut c_void,
    selection: c_int,
    param_cb: Option<OsslCallback>,
    cbarg: *mut c_void,
) -> c_int {
    let key = keydata.cast::<MlDsaKey>();
    let mut params = [END; 4];
    let mut pnum = 0usize;

    if is_running() == 0 || key.is_null() {
        return 0;
    }
    if (selection & OSSL_KEYMGMT_SELECT_KEYPAIR) == 0 {
        return 0;
    }

    let include_private = (selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0;

    // SAFETY: `key` is live per the contract; the descriptors point at the key's own buffers.
    unsafe {
        /*
         * Note that if the seed is present, both the seed and the private key are exported. The
         * recipient will have a choice.
         */
        if include_private {
            let buf = ossl_ml_dsa_key_get_seed(key);
            if !buf.is_null() {
                params[pnum] = OSSL_PARAM_construct_octet_string(
                    OSSL_PKEY_PARAM_ML_DSA_SEED,
                    buf.cast_mut().cast(),
                    ML_DSA_SEED_BYTES,
                );
                pnum += 1;
            }
            let buf = ossl_ml_dsa_key_get_priv(key);
            if !buf.is_null() {
                params[pnum] = OSSL_PARAM_construct_octet_string(
                    OSSL_PKEY_PARAM_PRIV_KEY,
                    buf.cast_mut().cast(),
                    ossl_ml_dsa_key_get_priv_len(key),
                );
                pnum += 1;
            }
        }
        if (selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0 {
            let buf = ossl_ml_dsa_key_get_pub(key);
            if !buf.is_null() {
                params[pnum] = OSSL_PARAM_construct_octet_string(
                    OSSL_PKEY_PARAM_PUB_KEY,
                    buf.cast_mut().cast(),
                    ossl_ml_dsa_key_get_pub_len(key),
                );
                pnum += 1;
            }
        }
        if pnum == 0 {
            return 0;
        }
        params[pnum] = OSSL_PARAM_construct_end();
    }

    // SAFETY: `params` is a local, key-terminated array; `cbarg` is the caller's.
    unsafe {
        match param_cb {
            Some(cb) => cb(params.as_ptr(), cbarg),
            None => 0,
        }
    }
}

/// `static void *ml_dsa_load(const void *reference, size_t reference_sz)` —
/// `ml_dsa_kmgmt.c.in:436-472`.
///
/// The `#ifndef FIPS_MODULE` arm of `DISPATCH_LOAD_FN`, so it is present on this profile.
///
/// # Safety
/// The keymgmt `load` dispatch contract.
unsafe extern "C" fn ml_dsa_load(reference: *const c_void, reference_sz: usize) -> *mut c_void {
    let mut key: *mut MlDsaKey = ptr::null_mut();

    // SAFETY: `reference` names a pointer-sized slot per the size check below.
    unsafe {
        if is_running() != 0 && reference_sz == core::mem::size_of::<*mut MlDsaKey>() {
            /* The contents of the reference is the address to our object */
            let slot = reference as *mut *mut MlDsaKey;
            key = *slot;
            /* We grabbed, so we detach it */
            *slot = ptr::null_mut();
            /* All done, if the pubkey is present. */
            if key.is_null() || !ossl_ml_dsa_key_get_pub(key).is_null() {
                return key.cast();
            }
            /* Handle private prekey inputs. */
            let sk = ossl_ml_dsa_key_get_priv(key);
            let seed = ossl_ml_dsa_key_get_seed(key);
            if !seed.is_null()
                && (sk.is_null()
                    || (ossl_ml_dsa_key_get_prov_flags(key) & ML_DSA_KEY_PREFER_SEED) != 0)
            {
                if ossl_ml_dsa_generate_key(key) != 0 {
                    return key.cast();
                }
            } else if !sk.is_null() {
                if ossl_ml_dsa_sk_decode(key, sk, ossl_ml_dsa_key_get_priv_len(key)) != 0 {
                    return key.cast();
                }
                let key_params = ossl_ml_dsa_key_params(key);
                raise_with_alg(
                    &err_sites::PROV_ML_DSA_KMGMT_709,
                    "error parsing ",
                    (*key_params).alg,
                    " private key",
                );
            } else {
                return key.cast();
            }
        }

        ossl_ml_dsa_key_free(key);
    }
    ptr::null_mut()
}

/// `static void *ml_dsa_gen_init(void *provctx, int selection, const OSSL_PARAM params[])` —
/// `ml_dsa_kmgmt.c.in:475-491`.
///
/// `selection` is unused by the authority.
///
/// # Safety
/// The keymgmt `gen_init` dispatch contract.
unsafe fn ml_dsa_gen_init(
    provctx: *mut c_void,
    _selection: c_int,
    params: *const OsslParam,
) -> *mut c_void {
    if is_running() == 0 {
        return ptr::null_mut();
    }

    let gctx = CRYPTO_zalloc(core::mem::size_of::<MlDsaGenCtx>(), FILE, LINE_GEN_ZALLOC)
        .cast::<MlDsaGenCtx>();
    if !gctx.is_null() {
        // SAFETY: `gctx` is a fresh allocation; `provctx` is the caller's context.
        unsafe {
            (*gctx).provctx = provctx.cast();
            if ml_dsa_gen_set_params(gctx.cast(), params) == 0 {
                CRYPTO_free(gctx.cast(), FILE, LINE_GEN_FREE_GCTX);
                return ptr::null_mut();
            }
        }
    }
    gctx.cast()
}

/// `static void *ml_dsa_gen(void *genctx, int evp_type)` — `ml_dsa_kmgmt.c.in:493-519`.
///
/// The `FIPS_MODULE` pairwise-test block (`:511-514`) is absent on this profile.
///
/// # Safety
/// `genctx` is a live `struct ml_dsa_gen_ctx`.
unsafe fn ml_dsa_gen(genctx: *mut c_void, evp_type: c_int) -> *mut c_void {
    let gctx = genctx.cast::<MlDsaGenCtx>();

    if is_running() == 0 || gctx.is_null() {
        return ptr::null_mut();
    }

    // SAFETY: `gctx` is live per the contract.
    unsafe {
        let key = ossl_prov_ml_dsa_new((*gctx).provctx, (*gctx).propq, evp_type);
        if key.is_null() {
            return ptr::null_mut();
        }
        if (*gctx).entropy_len != 0
            && ossl_ml_dsa_set_prekey(
                key,
                0,
                0,
                (*gctx).entropy.as_ptr(),
                (*gctx).entropy_len,
                ptr::null(),
                0,
            ) == 0
        {
            ossl_ml_dsa_key_free(key);
            return ptr::null_mut();
        }
        if ossl_ml_dsa_generate_key(key) == 0 {
            raise_site(&err_sites::PROV_ML_DSA_KMGMT_755);
            ossl_ml_dsa_key_free(key);
            return ptr::null_mut();
        }
        key.cast()
    }
}

/// `static const OSSL_PARAM ml_dsa_gen_set_params_list[]` — generated `ml_dsa_kmgmt.c`.
static ML_DSA_GEN_SET_PARAMS_LIST: [OsslParam; 3] = [
    param_octet_string(OSSL_PKEY_PARAM_ML_DSA_SEED),
    param_utf8_string(OSSL_PKEY_PARAM_PROPERTIES),
    END,
];

/// `struct ml_dsa_gen_set_params_st` — generated `ml_dsa_kmgmt.c`.
struct GenSetParams {
    propq: *const OsslParam,
    seed: *const OsslParam,
}

/// The `ml_dsa_gen_set_params` decoder's two coordinates, in the trie's own leaf order:
/// `p` (`properties`), then `s` (`seed`).
const GEN_SET_PARAMS_DECODER_KEYS: [(&err_sites::ErrSite, *const c_char); 2] = [
    (
        &err_sites::PROV_ML_DSA_KMGMT_801,
        OSSL_PKEY_PARAM_PROPERTIES,
    ),
    (
        &err_sites::PROV_ML_DSA_KMGMT_812,
        OSSL_PKEY_PARAM_ML_DSA_SEED,
    ),
];

/// `ml_dsa_gen_set_params_decoder` — generated `ml_dsa_kmgmt.c`.
///
/// # Safety
/// `params` is NULL or key-terminated; `r` is writable.
unsafe fn gen_set_params_decoder(params: *const OsslParam, r: &mut GenSetParams) -> c_int {
    // SAFETY: the arguments are per the contract.
    unsafe {
        if let Some(site) = ml_dsa_repeated_param_site(params, &GEN_SET_PARAMS_DECODER_KEYS) {
            raise_site(site);
            return 0;
        }
        r.seed = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_ML_DSA_SEED);
        r.propq = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_PROPERTIES);
    }
    1
}

/// `static int ml_dsa_gen_set_params(void *genctx, const OSSL_PARAM params[])` —
/// `ml_dsa_kmgmt.c.in:528-553`.
///
/// # Safety
/// The keymgmt `gen_set_params` dispatch contract.
unsafe extern "C" fn ml_dsa_gen_set_params(genctx: *mut c_void, params: *const OsslParam) -> c_int {
    let gctx = genctx.cast::<MlDsaGenCtx>();
    let mut p = GenSetParams {
        propq: ptr::null(),
        seed: ptr::null(),
    };

    // SAFETY: `gctx` and `params` are the caller's; `p` is this call's own decoder result.
    unsafe {
        if gctx.is_null() || gen_set_params_decoder(params, &mut p) == 0 {
            return 0;
        }

        if !p.seed.is_null() {
            let mut vp: *mut c_void = (*gctx).entropy.as_mut_ptr().cast();
            let len = (*gctx).entropy.len();

            if OSSL_PARAM_get_octet_string(p.seed, &mut vp, len, &mut (*gctx).entropy_len) == 0 {
                (*gctx).entropy_len = 0;
                return 0;
            }
        }

        if !p.propq.is_null() {
            CRYPTO_free((*gctx).propq.cast(), FILE, LINE_GEN_SET_FREE_PROPQ);
            (*gctx).propq = ptr::null_mut();
            if OSSL_PARAM_get_utf8_string(p.propq, &mut (*gctx).propq, 0) == 0 {
                return 0;
            }
        }
    }
    1
}

/// `static const OSSL_PARAM *ml_dsa_gen_settable_params(void *genctx, void *provctx)` —
/// `ml_dsa_kmgmt.c.in:555-559`.
///
/// Both arguments are unused by the authority.
///
/// # Safety
/// Takes no live pointers it reads.
unsafe extern "C" fn ml_dsa_gen_settable_params(
    _genctx: *mut c_void,
    _provctx: *mut c_void,
) -> *const OsslParam {
    ML_DSA_GEN_SET_PARAMS_LIST.as_ptr()
}

/// `static void ml_dsa_gen_cleanup(void *genctx)` — `ml_dsa_kmgmt.c.in:561-571`.
///
/// # Safety
/// The keymgmt `gen_cleanup` dispatch contract.
unsafe extern "C" fn ml_dsa_gen_cleanup(genctx: *mut c_void) {
    let gctx = genctx.cast::<MlDsaGenCtx>();

    if gctx.is_null() {
        return;
    }

    // SAFETY: `gctx` is the caller's live context.
    unsafe {
        OPENSSL_cleanse((*gctx).entropy.as_mut_ptr().cast(), (*gctx).entropy.len());
        CRYPTO_free((*gctx).propq.cast(), FILE, LINE_GEN_CLEANUP_PROPQ);
        CRYPTO_free(gctx.cast(), FILE, LINE_GEN_CLEANUP_CTX);
    }
}

/// `MAKE_KEYMGMT_FUNCTIONS(alg)` — `ml_dsa_kmgmt.c.in:580-612`, once per parameter set.
///
/// Each expansion differs in the `EVP_PKEY_ML_DSA_*` NID it carries into `ossl_prov_ml_dsa_new`
/// (`NEW`) and `ml_dsa_gen` (`GEN`); every other slot is one of the shared functions above. The
/// table order is the authority's: `NEW`, `FREE`, `HAS`, `MATCH`, `IMPORT`, `IMPORT_TYPES`,
/// `EXPORT`, `EXPORT_TYPES`, the non-FIPS `LOAD`, `GET_PARAMS`, `GETTABLE_PARAMS`, `VALIDATE`,
/// `GEN_INIT`, `GEN`, `GEN_CLEANUP`, `GEN_SET_PARAMS`, `GEN_SETTABLE_PARAMS`, `DUP`, terminator.
macro_rules! make_ml_dsa_keymgmt_functions {
    ($table:ident, $fn_new:ident, $fn_gen:ident, $evp_type:expr) => {
        /// `static void *ml_dsa_<alg>_new_key(void *provctx)` — one expansion's `NEW`.
        ///
        /// # Safety
        /// The keymgmt `new` dispatch contract.
        unsafe extern "C" fn $fn_new(provctx: *mut c_void) -> *mut c_void {
            // SAFETY: `provctx` is the caller's context; NULL is the authority's own `propq`.
            unsafe { ossl_prov_ml_dsa_new(provctx.cast(), ptr::null(), $evp_type).cast() }
        }

        /// `static void *ml_dsa_<alg>_gen(void *genctx, OSSL_CALLBACK *osslcb, void *cbarg)` —
        /// one expansion's `GEN`.
        ///
        /// # Safety
        /// The keymgmt `gen` dispatch contract.
        unsafe extern "C" fn $fn_gen(
            genctx: *mut c_void,
            _osslcb: Option<OsslCallback>,
            _cbarg: *mut c_void,
        ) -> *mut c_void {
            // SAFETY: forwarded with this expansion's own `EVP_PKEY_ML_DSA_*` type.
            unsafe { ml_dsa_gen(genctx, $evp_type) }
        }

        /// `const OSSL_DISPATCH ossl_ml_dsa_<alg>_keymgmt_functions[]` — one expansion's table.
        pub(crate) static $table: [OsslDispatch; 19] = [
            OsslDispatch {
                function_id: OSSL_FUNC_KEYMGMT_NEW,
                function: $fn_new as *mut c_void,
            },
            OsslDispatch {
                function_id: OSSL_FUNC_KEYMGMT_FREE,
                function: ml_dsa_free_key as *mut c_void,
            },
            OsslDispatch {
                function_id: OSSL_FUNC_KEYMGMT_HAS,
                function: ml_dsa_has as *mut c_void,
            },
            OsslDispatch {
                function_id: OSSL_FUNC_KEYMGMT_MATCH,
                function: ml_dsa_match as *mut c_void,
            },
            OsslDispatch {
                function_id: OSSL_FUNC_KEYMGMT_IMPORT,
                function: ml_dsa_import as *mut c_void,
            },
            OsslDispatch {
                function_id: OSSL_FUNC_KEYMGMT_IMPORT_TYPES,
                function: ml_dsa_imexport_types as *mut c_void,
            },
            OsslDispatch {
                function_id: OSSL_FUNC_KEYMGMT_EXPORT,
                function: ml_dsa_export as *mut c_void,
            },
            OsslDispatch {
                function_id: OSSL_FUNC_KEYMGMT_EXPORT_TYPES,
                function: ml_dsa_imexport_types as *mut c_void,
            },
            // `DISPATCH_LOAD_FN` — non-FIPS, so `OSSL_FUNC_KEYMGMT_LOAD` is present.
            OsslDispatch {
                function_id: OSSL_FUNC_KEYMGMT_LOAD,
                function: ml_dsa_load as *mut c_void,
            },
            OsslDispatch {
                function_id: OSSL_FUNC_KEYMGMT_GET_PARAMS,
                function: ml_dsa_get_params as *mut c_void,
            },
            OsslDispatch {
                function_id: OSSL_FUNC_KEYMGMT_GETTABLE_PARAMS,
                function: ml_dsa_gettable_params as *mut c_void,
            },
            OsslDispatch {
                function_id: OSSL_FUNC_KEYMGMT_VALIDATE,
                function: ml_dsa_validate as *mut c_void,
            },
            OsslDispatch {
                function_id: OSSL_FUNC_KEYMGMT_GEN_INIT,
                function: ml_dsa_gen_init as *mut c_void,
            },
            OsslDispatch {
                function_id: OSSL_FUNC_KEYMGMT_GEN,
                function: $fn_gen as *mut c_void,
            },
            OsslDispatch {
                function_id: OSSL_FUNC_KEYMGMT_GEN_CLEANUP,
                function: ml_dsa_gen_cleanup as *mut c_void,
            },
            OsslDispatch {
                function_id: OSSL_FUNC_KEYMGMT_GEN_SET_PARAMS,
                function: ml_dsa_gen_set_params as *mut c_void,
            },
            OsslDispatch {
                function_id: OSSL_FUNC_KEYMGMT_GEN_SETTABLE_PARAMS,
                function: ml_dsa_gen_settable_params as *mut c_void,
            },
            OsslDispatch {
                function_id: OSSL_FUNC_KEYMGMT_DUP,
                function: ml_dsa_dup_key as *mut c_void,
            },
            OsslDispatch {
                function_id: OSSL_DISPATCH_END,
                function: ptr::null_mut(),
            },
        ];
    };
}

make_ml_dsa_keymgmt_functions!(
    ML_DSA_44_KEYMGMT_FUNCTIONS,
    ml_dsa_44_new_key,
    ml_dsa_44_gen,
    EVP_PKEY_ML_DSA_44
);
make_ml_dsa_keymgmt_functions!(
    ML_DSA_65_KEYMGMT_FUNCTIONS,
    ml_dsa_65_new_key,
    ml_dsa_65_gen,
    EVP_PKEY_ML_DSA_65
);
make_ml_dsa_keymgmt_functions!(
    ML_DSA_87_KEYMGMT_FUNCTIONS,
    ml_dsa_87_new_key,
    ml_dsa_87_gen,
    EVP_PKEY_ML_DSA_87
);
