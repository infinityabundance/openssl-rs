//! Phase 8 — `providers/implementations/keymgmt/ml_kem_kmgmt.c.in`: the three ML-KEM keymgmt rows.
//!
//! Nine hundred and two template lines — about eleven hundred expanded, because four
//! `produce_param_decoder` blocks are generated inline — and **one** body with three macro
//! expansions. Every row's table is the same twenty slots; only `NEW` and `GEN_INIT` differ,
//! because each carries its own variant's `EVP_PKEY_ML_KEM_*` NID.
//!
//! ## The generated decoders are written the crate's way
//!
//! `util/perl/OpenSSL/paramnames.pm` emits, for each `produce_param_decoder` block, a
//! character-by-character `switch` trie over the parameter's key. Its whole observable content is
//! the **repeated-key refusal** — an `ERR_raise_data(..., PROV_R_REPEATED_PARAMETER, ...)` at the
//! parameter's own coordinate — plus the located pointer this unit's body reads. The four decoders
//! here are the repeated-key scan plus `OSSL_PARAM_locate_const` per key, the shape
//! `src/provider/ecx_kem.rs`, `src/provider/exchange.rs` and `src/provider/slh_dsa_kmgmt.rs`
//! already use for theirs. **The site is not guessed from the tuple's order**: the generated trie
//! emits each key's raise at its own leaf, in first-character order, so the pairing was read back
//! from `build/openssl-3.6.4-production/.../ml_kem_kmgmt.c` -- `b`·`e`·`k`·`m`·`p`→`r`·`p`→`u`·`r`
//! then the `s` subtree's `security-bits`·`security-category`·`seed`.
//!
//! ## The `FIPS_MODULE` arms are absent, the CMS arm is not
//!
//! `ml_kem_pairwise_test`'s self-test block (`:78-113`, `:134-136`, `:145-148`) and `ml_kem_gen`'s
//! fixed-PCT block (`:817-822`) are inside `#ifdef FIPS_MODULE`, which this profile does not
//! define, so they are recorded with their coordinates and not written; the non-FIPS `err:` arm
//! that raises `PROV_R_INVALID_KEY` is. The `#ifndef OPENSSL_NO_CMS` block of `ml_kem_get_params`
//! **is** compiled: `OPENSSL_NO_CMS` is not in the admitted profile, so `ri_type` and
//! `kemri_kdf_alg` are both written, and the latter is a DER `AlgorithmIdentifier` built with the
//! packet writer. `ossl_der_oid_id_alg_hkdf_with_sha256` is read back from the authority's own
//! generated `der_hkdf_gen.h` (`DER_OID_V_...` = `DER_P_OBJECT, 11, 0x2A, 0x86, ...`), which is
//! `{ id-alg 28 }` = `1.2.840.113549.1.9.16.3.28`.
//!
//! SPDX-License-Identifier: Apache-2.0

#![allow(unreachable_pub)]
// The three tables share one body; each is a transcription of the same authority macro expansion.
#![allow(clippy::too_many_arguments)]

use core::ffi::{c_char, c_int, c_void, CStr};
use core::ptr;

use crate::context::dispatch::{OsslDispatch, OSSL_DISPATCH_END};
use crate::der_writer::{
    ossl_DER_w_begin_sequence, ossl_DER_w_end_sequence, ossl_DER_w_precompiled,
};
use crate::evp::keymgmt::{
    OSSL_FUNC_KEYMGMT_DUP, OSSL_FUNC_KEYMGMT_EXPORT, OSSL_FUNC_KEYMGMT_EXPORT_TYPES,
    OSSL_FUNC_KEYMGMT_FREE, OSSL_FUNC_KEYMGMT_GEN, OSSL_FUNC_KEYMGMT_GEN_CLEANUP,
    OSSL_FUNC_KEYMGMT_GEN_INIT, OSSL_FUNC_KEYMGMT_GEN_SETTABLE_PARAMS,
    OSSL_FUNC_KEYMGMT_GEN_SET_PARAMS, OSSL_FUNC_KEYMGMT_GETTABLE_PARAMS,
    OSSL_FUNC_KEYMGMT_GET_PARAMS, OSSL_FUNC_KEYMGMT_HAS, OSSL_FUNC_KEYMGMT_IMPORT,
    OSSL_FUNC_KEYMGMT_IMPORT_TYPES, OSSL_FUNC_KEYMGMT_LOAD, OSSL_FUNC_KEYMGMT_MATCH,
    OSSL_FUNC_KEYMGMT_NEW, OSSL_FUNC_KEYMGMT_SETTABLE_PARAMS, OSSL_FUNC_KEYMGMT_SET_PARAMS,
    OSSL_FUNC_KEYMGMT_VALIDATE,
};
use crate::evp::pkey::{
    OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS, OSSL_KEYMGMT_SELECT_PRIVATE_KEY,
    OSSL_KEYMGMT_SELECT_PUBLIC_KEY,
};
use crate::ml_kem::key::{
    ossl_ml_kem_decap, ossl_ml_kem_encap_rand, ossl_ml_kem_encap_seed,
    ossl_ml_kem_encode_private_key, ossl_ml_kem_encode_public_key, ossl_ml_kem_encode_seed,
    ossl_ml_kem_genkey, ossl_ml_kem_key_dup, ossl_ml_kem_key_free, ossl_ml_kem_key_new,
    ossl_ml_kem_key_reset, ossl_ml_kem_parse_private_key, ossl_ml_kem_parse_public_key,
    ossl_ml_kem_pubkey_cmp, ossl_ml_kem_set_seed,
};
use crate::ml_kem::{
    ossl_ml_kem_decoded_key, ossl_ml_kem_have_dkenc, ossl_ml_kem_have_prvkey,
    ossl_ml_kem_have_pubkey, ossl_ml_kem_have_seed, ossl_ml_kem_key_vinfo, MlKemKey,
    ML_KEM_KEY_FIXED_PCT, ML_KEM_KEY_PCT_TYPE, ML_KEM_KEY_PREFER_SEED, ML_KEM_KEY_RANDOM_PCT,
    ML_KEM_KEY_RETAIN_SEED, ML_KEM_PKHASH_BYTES, ML_KEM_RANDOM_BYTES, ML_KEM_SEED_BYTES,
    ML_KEM_SHARED_SECRET_BYTES,
};
use crate::packet::{
    WPACKET_cleanup, WPACKET_finish, WPACKET_get_curr, WPACKET_get_total_written, WPACKET_init_der,
    Wpacket,
};
use crate::param_build_set::ossl_param_build_set_octet_string;
use crate::params::build::{
    OSSL_PARAM_BLD_free, OSSL_PARAM_BLD_new, OSSL_PARAM_BLD_to_param, OSSL_PARAM_BLD,
};
use crate::params::dup::OSSL_PARAM_free;
use crate::params::{
    OSSL_PARAM_get_octet_string, OSSL_PARAM_get_octet_string_ptr, OSSL_PARAM_locate_const,
    OSSL_PARAM_set_int, OSSL_PARAM_set_octet_string, OSSL_PARAM_set_size_t, OsslParam, END,
    OSSL_PARAM_OCTET_STRING, OSSL_PARAM_UTF8_STRING,
};
use crate::provider::cipher::{param_int, param_octet_string, param_utf8_string};
use crate::provider::ctx::{ossl_prov_ctx_get_bool_param, ossl_prov_ctx_get_param, prov_libctx_of};
use crate::runtime::err::err_sites;
use crate::runtime::err::{raise_site, raise_site_data};
use crate::runtime::mem::{
    CRYPTO_clear_free, CRYPTO_free, CRYPTO_malloc, CRYPTO_strdup, CRYPTO_zalloc, OPENSSL_cleanse,
};
use crate::runtime::secure::{CRYPTO_secure_clear_free, CRYPTO_secure_zalloc};
use crate::runtime::str::OPENSSL_strcasecmp;
use crate::selftest::OsslCallback;

/// `OSSL_KEYMGMT_SELECT_KEYPAIR` — `core_dispatch.h:649-650`, `PRIVATE_KEY | PUBLIC_KEY`.
///
/// `src/evp/pkey.rs` keeps its own copy private, so the union is spelled here from the two
/// **imported** bits rather than from a second copy of either (D402).
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
/// `OSSL_PKEY_PARAM_ML_KEM_SEED` — `core_names.h:437`, `"seed"`.
const OSSL_PKEY_PARAM_ML_KEM_SEED: *const c_char = c"seed".as_ptr();
/// `OSSL_PKEY_PARAM_ML_DSA_SEED` — `core_names.h:431`, the same spelling, which is what
/// `ml_kem_gen_set_params`'s decoder block names.
const OSSL_PKEY_PARAM_ML_DSA_SEED: *const c_char = c"seed".as_ptr();
/// `OSSL_PKEY_PARAM_PRIV_KEY` — `core_names.h`.
const OSSL_PKEY_PARAM_PRIV_KEY: *const c_char = c"priv".as_ptr();
/// `OSSL_PKEY_PARAM_PUB_KEY` — `core_names.h`.
const OSSL_PKEY_PARAM_PUB_KEY: *const c_char = c"pub".as_ptr();
/// `OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY` — `core_names.h:398`.
const OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY: *const c_char = c"encoded-pub-key".as_ptr();
/// `OSSL_PKEY_PARAM_CMS_RI_TYPE` — `core_names.h:369`.
const OSSL_PKEY_PARAM_CMS_RI_TYPE: *const c_char = c"ri-type".as_ptr();
/// `OSSL_PKEY_PARAM_CMS_KEMRI_KDF_ALGORITHM` — `core_names.h:368`.
const OSSL_PKEY_PARAM_CMS_KEMRI_KDF_ALGORITHM: *const c_char = c"kemri-kdf-alg".as_ptr();
/// `OSSL_PKEY_PARAM_PROPERTIES` — `core_names.h`.
const OSSL_PKEY_PARAM_PROPERTIES: *const c_char = c"properties".as_ptr();
/// `OSSL_PKEY_PARAM_ML_KEM_IMPORT_PCT_TYPE` — `core_names.h:432`.
const OSSL_PKEY_PARAM_ML_KEM_IMPORT_PCT_TYPE: *const c_char = c"ml-kem.import_pct_type".as_ptr();
/// `OSSL_PKEY_PARAM_ML_KEM_RETAIN_SEED` — `core_names.h:436`.
const OSSL_PKEY_PARAM_ML_KEM_RETAIN_SEED: *const c_char = c"ml-kem.retain_seed".as_ptr();
/// `OSSL_PKEY_PARAM_ML_KEM_PREFER_SEED` — `core_names.h:435`.
const OSSL_PKEY_PARAM_ML_KEM_PREFER_SEED: *const c_char = c"ml-kem.prefer_seed".as_ptr();

/// `CMS_RECIPINFO_KEM` — `include/openssl/cms.h.in:77`.
const CMS_RECIPINFO_KEM: c_int = 5;

/// `OSSL_MAX_ALGORITHM_ID_SIZE` — `include/internal/sizes.h:20`.
const OSSL_MAX_ALGORITHM_ID_SIZE: usize = 256;

/// `ossl_der_oid_id_alg_hkdf_with_sha256` — the authority's generated `prov/der_hkdf_gen.h:21`,
/// `DER_OID_V_id_alg_hkdf_with_sha256` = `DER_P_OBJECT, 11, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D,
/// 0x01, 0x09, 0x10, 0x03, 0x1C`. That is `{ id-alg 28 }` = `1.2.840.113549.1.9.16.3.28`, the same
/// OID `DEFLT_KDFS` publishes as `id-alg-hkdf-with-sha256`.
const OSSL_DER_OID_ID_ALG_HKDF_WITH_SHA256: [u8; 13] = [
    0x06, 0x0b, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x10, 0x03, 0x1c,
];

/// The generated unit's own `__FILE__`. `.c.in`-generated, so the bare build-relative path.
const FILE: *const c_char = c"providers/implementations/keymgmt/ml_kem_kmgmt.c".as_ptr();

/// `ml_kem_kmgmt.c:115`, `ml_kem_pairwise_test`'s `OPENSSL_malloc(v->ctext_bytes)`.
const LINE_PCT_CTEXT: c_int = 115;
/// `ml_kem_kmgmt.c:162`, `ossl_prov_ml_kem_new`'s `ossl_ml_kem_key_new` line -- not an allocation.
/// `ml_kem_kmgmt.c:269`, `ml_kem_export`'s `OPENSSL_malloc(v->pubkey_bytes)`.
const LINE_EXPORT_PUB: c_int = 269;
/// `ml_kem_kmgmt.c:283`/`289`/`294`, `ml_kem_export`'s three `OPENSSL_secure_zalloc` calls.
const LINE_EXPORT_SEED: c_int = 283;
/// `ml_kem_kmgmt.c:289`.
const LINE_EXPORT_PRV: c_int = 289;
/// `ml_kem_kmgmt.c:294`.
const LINE_EXPORT_DKENC: c_int = 294;
/// `ml_kem_kmgmt.c:377`, `check_prvenc`'s `OPENSSL_malloc(len)`.
const LINE_CHECK_PRVENC: c_int = 377;
/// `ml_kem_kmgmt.c:535`, `ml_kem_load`'s `OPENSSL_secure_clear_free`.
const LINE_LOAD_CLEAR: c_int = 535;
/// `ml_kem_kmgmt.c:734`, `ml_kem_gen_set_params`'s `OPENSSL_free(gctx->propq)`.
const LINE_GEN_FREE_PROPQ: c_int = 734;
/// `ml_kem_kmgmt.c:767`, `ml_kem_gen_init`'s `OPENSSL_zalloc(sizeof(*gctx))`.
const LINE_GEN_ZALLOC: c_int = 767;
/// `ml_kem_kmgmt.c:839`/`840`, `ml_kem_gen_cleanup`'s two frees.
const LINE_GEN_CLEANUP_PROPQ: c_int = 839;
/// `ml_kem_kmgmt.c:840`.
const LINE_GEN_CLEANUP_CTX: c_int = 840;

/// `ossl_prov_is_running()` — the literal 1 on this build.
#[inline]
fn is_running() -> c_int {
    1
}

/// `minimal_selection` — `ml_kem_kmgmt.c:64-65`.
const MINIMAL_SELECTION: c_int =
    OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS | OSSL_KEYMGMT_SELECT_PRIVATE_KEY;

/// `PROV_ML_KEM_GEN_CTX` — `ml_kem_kmgmt.c:67-74`.
#[repr(C)]
struct ProvMlKemGenCtx {
    /// `PROV_CTX *provctx` — borrowed.
    provctx: *mut crate::provider::ctx::ProvCtx,
    /// `char *propq` — owned.
    propq: *mut c_char,
    /// `int selection`.
    selection: c_int,
    /// `int evp_type`.
    evp_type: c_int,
    /// `uint8_t seedbuf[ML_KEM_SEED_BYTES]` — the built-in one-shot seed buffer.
    seedbuf: [u8; ML_KEM_SEED_BYTES],
    /// `uint8_t *seed` — NULL, or `seedbuf`, or a caller-supplied seed.
    seed: *mut u8,
}

/// Raise a fixed message through a site, the `ERR_raise_data` form.
///
/// # Safety
/// Nothing: the message is a NUL-terminated literal built here.
unsafe fn raise_fixed(site: &err_sites::ErrSite, msg: &str) {
    let mut buf = msg.as_bytes().to_vec();
    buf.push(0);
    // SAFETY: `buf` is NUL-terminated just above.
    unsafe { raise_site_data(site, buf.as_ptr().cast()) };
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

/// `static int ml_kem_pairwise_test(const ML_KEM_KEY *key, int key_flags)` —
/// `ml_kem_kmgmt.c:76-160`.
///
/// The `FIPS_MODULE` arms are absent: the self-test bracket (`:78-113`, `:134-136`, `:145-148`).
/// What remains is the profile's own body -- an encapsulate/decapsulate round trip, random or
/// fixed-entropy by flag, with the non-FIPS `err:` raise.
///
/// # Safety
/// `key` is live.
unsafe fn ml_kem_pairwise_test(key: *const MlKemKey, key_flags: c_int) -> c_int {
    // SAFETY: `key` is live per the contract.
    unsafe {
        let v = ossl_ml_kem_key_vinfo(key);
        let mut entropy = [0u8; ML_KEM_RANDOM_BYTES];
        let mut secret = [0u8; ML_KEM_SHARED_SECRET_BYTES];
        let mut out = [0u8; ML_KEM_SHARED_SECRET_BYTES];
        let ctext: *mut u8;
        let mut ret = 0;

        // Unless we have both a public and private key, we can't do the test
        if !ossl_ml_kem_have_prvkey(key)
            || !ossl_ml_kem_have_pubkey(key)
            || (key_flags & ML_KEM_KEY_PCT_TYPE) == 0
        {
            return 1;
        }

        // The authority's `err:` label, as one labelled block.
        'err: {
            ctext = CRYPTO_malloc((*v).ctext_bytes, FILE, LINE_PCT_CTEXT).cast::<u8>();
            if ctext.is_null() {
                break 'err;
            }

            ptr::write_bytes(out.as_mut_ptr(), 0, out.len());

            let operation_result = if key_flags & ML_KEM_KEY_RANDOM_PCT != 0 {
                ossl_ml_kem_encap_rand(
                    ctext,
                    (*v).ctext_bytes,
                    secret.as_mut_ptr(),
                    secret.len(),
                    key,
                )
            } else {
                // The authority's `memset(entropy, 0125, sizeof(entropy))` -- octal 0125 is 'U'.
                ptr::write_bytes(entropy.as_mut_ptr(), 0o125u8, entropy.len());
                ossl_ml_kem_encap_seed(
                    ctext,
                    (*v).ctext_bytes,
                    secret.as_mut_ptr(),
                    secret.len(),
                    entropy.as_ptr(),
                    entropy.len(),
                    key,
                )
            };
            if operation_result != 1 {
                break 'err;
            }

            let operation_result =
                ossl_ml_kem_decap(out.as_mut_ptr(), out.len(), ctext, (*v).ctext_bytes, key);
            if operation_result != 1
                || crate::runtime::mem::CRYPTO_memcmp(
                    out.as_ptr().cast(),
                    secret.as_ptr().cast(),
                    out.len(),
                ) != 0
            {
                break 'err;
            }

            ret = 1;
        }

        // The `err:` tail, non-FIPS side: the raise fires exactly when `ret == 0`.
        if ret == 0 {
            raise_with_alg(
                &err_sites::PROV_ML_KEM_KMGMT_148,
                "public part of ",
                (*v).algorithm_name,
                " private key fails to match private",
            );
        }
        make_clean(&mut entropy, &mut secret, &mut out);
        CRYPTO_clear_free(ctext.cast(), (*v).ctext_bytes, FILE, LINE_PCT_CTEXT);
        ret
    }
}

/// The three `OPENSSL_cleanse` calls `ml_kem_pairwise_test` makes on every exit.
fn make_clean(entropy: &mut [u8], secret: &mut [u8], out: &mut [u8]) {
    // SAFETY: each slice is a live local with its own length.
    unsafe {
        OPENSSL_cleanse(entropy.as_mut_ptr().cast(), entropy.len());
        OPENSSL_cleanse(secret.as_mut_ptr().cast(), secret.len());
        OPENSSL_cleanse(out.as_mut_ptr().cast(), out.len());
    }
}

/// `ML_KEM_KEY *ossl_prov_ml_kem_new(PROV_CTX *ctx, const char *propq, int evp_type)` —
/// `ml_kem_kmgmt.c:162-196`.
///
/// # Safety
/// `ctx` is the provider context; `propq` is NULL or NUL-terminated.
pub(crate) unsafe fn ossl_prov_ml_kem_new(
    ctx: *mut crate::provider::ctx::ProvCtx,
    propq: *const c_char,
    evp_type: c_int,
) -> *mut MlKemKey {
    if is_running() == 0 {
        return ptr::null_mut();
    }

    // SAFETY: `ctx` is the caller's context; `propq` is NUL-terminated.
    unsafe {
        let key = ossl_ml_kem_key_new(prov_libctx_of(ctx.cast()), propq, evp_type);
        if !key.is_null() {
            let pct_type = ossl_prov_ctx_get_param(
                ctx,
                OSSL_PKEY_PARAM_ML_KEM_IMPORT_PCT_TYPE,
                c"random".as_ptr(),
            );

            if ossl_prov_ctx_get_bool_param(ctx, OSSL_PKEY_PARAM_ML_KEM_RETAIN_SEED, 1) != 0 {
                (*key).prov_flags |= ML_KEM_KEY_RETAIN_SEED;
            } else {
                (*key).prov_flags &= !ML_KEM_KEY_RETAIN_SEED;
            }
            if ossl_prov_ctx_get_bool_param(ctx, OSSL_PKEY_PARAM_ML_KEM_PREFER_SEED, 1) != 0 {
                (*key).prov_flags |= ML_KEM_KEY_PREFER_SEED;
            } else {
                (*key).prov_flags &= !ML_KEM_KEY_PREFER_SEED;
            }
            if OPENSSL_strcasecmp(pct_type, c"random".as_ptr()) == 0 {
                (*key).prov_flags |= ML_KEM_KEY_RANDOM_PCT;
            } else if OPENSSL_strcasecmp(pct_type, c"fixed".as_ptr()) == 0 {
                (*key).prov_flags |= ML_KEM_KEY_FIXED_PCT;
            } else {
                (*key).prov_flags &= !ML_KEM_KEY_PCT_TYPE;
            }
        }
        key
    }
}

/// `static int ml_kem_has(const void *vkey, int selection)` — `ml_kem_kmgmt.c:198-214`.
///
/// # Safety
/// The keymgmt `has` dispatch contract.
unsafe extern "C" fn ml_kem_has(vkey: *const c_void, selection: c_int) -> c_int {
    let key = vkey.cast::<MlKemKey>();

    if is_running() == 0 || key.is_null() {
        return 0;
    }

    // SAFETY: `key` is non-NULL past the guard.
    unsafe {
        match selection & OSSL_KEYMGMT_SELECT_KEYPAIR {
            0 => 1,
            OSSL_KEYMGMT_SELECT_PUBLIC_KEY => c_int::from(ossl_ml_kem_have_pubkey(key)),
            _ => c_int::from(ossl_ml_kem_have_prvkey(key)),
        }
    }
}

/// `static int ml_kem_match(const void *vkey1, const void *vkey2, int selection)` —
/// `ml_kem_kmgmt.c:216-229`.
///
/// # Safety
/// The keymgmt `match` dispatch contract.
unsafe extern "C" fn ml_kem_match(
    vkey1: *const c_void,
    vkey2: *const c_void,
    selection: c_int,
) -> c_int {
    if is_running() == 0 {
        return 0;
    }

    // All we have that can be compared is key material
    if selection & OSSL_KEYMGMT_SELECT_KEYPAIR == 0 {
        return 1;
    }

    // SAFETY: both keys are the caller's.
    unsafe { ossl_ml_kem_pubkey_cmp(vkey1.cast(), vkey2.cast()) }
}

/// `static int ml_kem_validate(const void *vkey, int selection, int check_type)` —
/// `ml_kem_kmgmt.c:231-241`.
///
/// # Safety
/// The keymgmt `validate` dispatch contract.
unsafe extern "C" fn ml_kem_validate(
    vkey: *const c_void,
    selection: c_int,
    _check_type: c_int,
) -> c_int {
    let key = vkey.cast::<MlKemKey>();

    // SAFETY: the forwarded contract.
    if unsafe { ml_kem_has(vkey, selection) } == 0 {
        return 0;
    }

    if selection & OSSL_KEYMGMT_SELECT_KEYPAIR == OSSL_KEYMGMT_SELECT_KEYPAIR {
        // SAFETY: `key` is live per the contract.
        return unsafe { ml_kem_pairwise_test(key, ML_KEM_KEY_RANDOM_PCT) };
    }
    1
}

/// `static int ml_kem_export(void *vkey, int selection, OSSL_CALLBACK *param_cb, void *cbarg)` —
/// `ml_kem_kmgmt.c:243-341`.
///
/// # Safety
/// The keymgmt `export` dispatch contract.
unsafe extern "C" fn ml_kem_export(
    vkey: *mut c_void,
    selection: c_int,
    param_cb: Option<OsslCallback>,
    cbarg: *mut c_void,
) -> c_int {
    let key = vkey.cast::<MlKemKey>();

    if is_running() == 0 || key.is_null() {
        return 0;
    }
    if selection & OSSL_KEYMGMT_SELECT_KEYPAIR == 0 {
        return 0;
    }

    // SAFETY: `key` is live per the contract.
    unsafe {
        let v = ossl_ml_kem_key_vinfo(key);
        let mut pubenc: *mut u8 = ptr::null_mut();
        let mut prvenc: *mut u8 = ptr::null_mut();
        let mut seedenc: *mut u8 = ptr::null_mut();
        let mut prvlen = 0usize;
        let mut seedlen = 0usize;

        if !ossl_ml_kem_have_pubkey(key) {
            // Fail when no key material can be returned
            if selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY == 0 || !ossl_ml_kem_decoded_key(key) {
                raise_site(&err_sites::PROV_ML_KEM_KMGMT_263);
                return 0;
            }
        } else if selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY != 0 {
            pubenc = CRYPTO_malloc((*v).pubkey_bytes, FILE, LINE_EXPORT_PUB).cast::<u8>();
            if pubenc.is_null()
                || ossl_ml_kem_encode_public_key(pubenc, (*v).pubkey_bytes, key) == 0
            {
                export_tail(
                    ptr::null_mut(),
                    seedenc,
                    seedlen,
                    prvenc,
                    prvlen,
                    pubenc,
                    (*v).pubkey_bytes,
                );
                return 0;
            }
        }

        if selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY != 0 {
            // The seed and/or private key material are allocated on the secure heap if
            // configured; `ossl_param_build_set_octet_string` will then use it too.
            if ossl_ml_kem_have_seed(key) {
                seedlen = ML_KEM_SEED_BYTES;
                seedenc = CRYPTO_secure_zalloc(seedlen, FILE, LINE_EXPORT_SEED).cast::<u8>();
                if seedenc.is_null() || ossl_ml_kem_encode_seed(seedenc, seedlen, key) == 0 {
                    export_tail(
                        ptr::null_mut(),
                        seedenc,
                        seedlen,
                        prvenc,
                        prvlen,
                        pubenc,
                        (*v).pubkey_bytes,
                    );
                    return 0;
                }
            }
            if ossl_ml_kem_have_prvkey(key) {
                prvlen = (*v).prvkey_bytes;
                prvenc = CRYPTO_secure_zalloc(prvlen, FILE, LINE_EXPORT_PRV).cast::<u8>();
                if prvenc.is_null() || ossl_ml_kem_encode_private_key(prvenc, prvlen, key) == 0 {
                    export_tail(
                        ptr::null_mut(),
                        seedenc,
                        seedlen,
                        prvenc,
                        prvlen,
                        pubenc,
                        (*v).pubkey_bytes,
                    );
                    return 0;
                }
            } else if ossl_ml_kem_have_dkenc(key) {
                prvlen = (*v).prvkey_bytes;
                prvenc = CRYPTO_secure_zalloc(prvlen, FILE, LINE_EXPORT_DKENC).cast::<u8>();
                if prvenc.is_null() {
                    export_tail(
                        ptr::null_mut(),
                        seedenc,
                        seedlen,
                        prvenc,
                        prvlen,
                        pubenc,
                        (*v).pubkey_bytes,
                    );
                    return 0;
                }
                ptr::copy_nonoverlapping((*key).encoded_dk, prvenc, prvlen);
            }
        }

        let tmpl = OSSL_PARAM_BLD_new();
        if tmpl.is_null() {
            export_tail(
                ptr::null_mut(),
                seedenc,
                seedlen,
                prvenc,
                prvlen,
                pubenc,
                (*v).pubkey_bytes,
            );
            return 0;
        }

        // The (d, z) seed, when available and private keys are requested.
        if !seedenc.is_null()
            && ossl_param_build_set_octet_string(
                tmpl,
                ptr::null_mut(),
                OSSL_PKEY_PARAM_ML_KEM_SEED,
                seedenc,
                seedlen,
            ) == 0
        {
            export_tail(
                tmpl,
                seedenc,
                seedlen,
                prvenc,
                prvlen,
                pubenc,
                (*v).pubkey_bytes,
            );
            return 0;
        }

        // The private key in the FIPS 203 |dk| format, when requested.
        if !prvenc.is_null()
            && ossl_param_build_set_octet_string(
                tmpl,
                ptr::null_mut(),
                OSSL_PKEY_PARAM_PRIV_KEY,
                prvenc,
                prvlen,
            ) == 0
        {
            export_tail(
                tmpl,
                seedenc,
                seedlen,
                prvenc,
                prvlen,
                pubenc,
                (*v).pubkey_bytes,
            );
            return 0;
        }

        // The public key on request; it is always available when either is.
        if !pubenc.is_null()
            && ossl_param_build_set_octet_string(
                tmpl,
                ptr::null_mut(),
                OSSL_PKEY_PARAM_PUB_KEY,
                pubenc,
                (*v).pubkey_bytes,
            ) == 0
        {
            export_tail(
                tmpl,
                seedenc,
                seedlen,
                prvenc,
                prvlen,
                pubenc,
                (*v).pubkey_bytes,
            );
            return 0;
        }

        let params = OSSL_PARAM_BLD_to_param(tmpl);
        if params.is_null() {
            export_tail(
                tmpl,
                seedenc,
                seedlen,
                prvenc,
                prvlen,
                pubenc,
                (*v).pubkey_bytes,
            );
            return 0;
        }

        let ret: c_int = match param_cb {
            Some(cb) => cb(params, cbarg),
            None => 0,
        };
        // `OSSL_PARAM_free()` only wipes the secure-heap data block, so wipe the key material
        // copies held in the params first.
        let mut p = params;
        while !(*p).key.is_null() {
            OPENSSL_cleanse((*p).data, (*p).data_size);
            p = p.add(1);
        }
        OSSL_PARAM_free(params);

        export_tail(
            tmpl,
            seedenc,
            seedlen,
            prvenc,
            prvlen,
            pubenc,
            (*v).pubkey_bytes,
        );
        ret
    }
}

/// The `err:` label of `ml_kem_export` — `ml_kem_kmgmt.c:335-340`.
///
/// `tmpl` is NULL until the builder exists, which the authority's bare `OSSL_PARAM_BLD_free`
/// accepts; the three buffers are freed with their **own** recorded lengths.
///
/// # Safety
/// `tmpl` and the three buffers are this call's own or NULL.
unsafe fn export_tail(
    tmpl: *mut OSSL_PARAM_BLD,
    seedenc: *mut u8,
    seedlen: usize,
    prvenc: *mut u8,
    prvlen: usize,
    pubenc: *mut u8,
    pub_bytes: usize,
) {
    // SAFETY: `tmpl` is this call's own builder and NULL is accepted.
    unsafe { OSSL_PARAM_BLD_free(tmpl) };
    // SAFETY: the three pointers are this call's own or NULL, which both free functions accept.
    unsafe {
        CRYPTO_secure_clear_free(seedenc.cast(), seedlen, FILE, LINE_EXPORT_SEED);
        CRYPTO_secure_clear_free(prvenc.cast(), prvlen, FILE, LINE_EXPORT_PRV);
        CRYPTO_clear_free(pubenc.cast(), pub_bytes, FILE, LINE_EXPORT_PUB);
    }
}

/// The repeated-key scan a generated decoder is.
///
/// # Safety
/// `params` is NULL or a key-terminated array.
unsafe fn repeated_param_site(
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

/// `static const OSSL_PARAM ml_kem_key_type_params_list[]` — generated `ml_kem_kmgmt.c`.
static ML_KEM_KEY_TYPE_PARAMS_LIST: [OsslParam; 4] = [
    param_octet_string(OSSL_PKEY_PARAM_ML_KEM_SEED),
    param_octet_string(OSSL_PKEY_PARAM_PRIV_KEY),
    param_octet_string(OSSL_PKEY_PARAM_PUB_KEY),
    END,
];

/// `static const OSSL_PARAM ml_kem_get_params_list[]` — generated `ml_kem_kmgmt.c`.
static ML_KEM_GET_PARAMS_LIST: [OsslParam; 11] = [
    param_int(OSSL_PKEY_PARAM_BITS),
    param_int(OSSL_PKEY_PARAM_SECURITY_BITS),
    param_int(OSSL_PKEY_PARAM_MAX_SIZE),
    param_int(OSSL_PKEY_PARAM_SECURITY_CATEGORY),
    param_octet_string(OSSL_PKEY_PARAM_ML_KEM_SEED),
    param_octet_string(OSSL_PKEY_PARAM_PRIV_KEY),
    param_octet_string(OSSL_PKEY_PARAM_PUB_KEY),
    param_octet_string(OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY),
    param_int(OSSL_PKEY_PARAM_CMS_RI_TYPE),
    param_octet_string(OSSL_PKEY_PARAM_CMS_KEMRI_KDF_ALGORITHM),
    END,
];

/// `static const OSSL_PARAM ml_kem_set_params_list[]` — generated `ml_kem_kmgmt.c`.
static ML_KEM_SET_PARAMS_LIST: [OsslParam; 2] =
    [param_octet_string(OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY), END];

/// `static const OSSL_PARAM ml_kem_gen_set_params_list[]` — generated `ml_kem_kmgmt.c`.
static ML_KEM_GEN_SET_PARAMS_LIST: [OsslParam; 3] = [
    param_octet_string(OSSL_PKEY_PARAM_ML_DSA_SEED),
    param_utf8_string(OSSL_PKEY_PARAM_PROPERTIES),
    END,
];

/// `struct ml_kem_key_type_params_st` — generated `ml_kem_kmgmt.c`.
struct KeyTypeParams {
    seed: *const OsslParam,
    privkey: *const OsslParam,
    pubkey: *const OsslParam,
}

/// `struct ml_kem_get_params_st` — generated `ml_kem_kmgmt.c`.
struct GetParams {
    bits: *mut OsslParam,
    secbits: *mut OsslParam,
    maxsize: *mut OsslParam,
    seccat: *mut OsslParam,
    seed: *mut OsslParam,
    privkey: *mut OsslParam,
    pubkey: *mut OsslParam,
    encpubkey: *mut OsslParam,
    ri_type: *mut OsslParam,
    kemri_kdf_alg: *mut OsslParam,
}

/// `struct ml_kem_set_params_st` — generated `ml_kem_kmgmt.c`.
struct SetParams {
    pubparam: *mut OsslParam,
}

/// `struct ml_kem_gen_set_params_st` — generated `ml_kem_kmgmt.c`.
struct GenSetParams {
    seed: *const OsslParam,
    propq: *const OsslParam,
}

/// The `ml_kem_key_type_params` decoder's coordinates, in the trie's own leaf order.
///
/// Read back from the generated unit: `p`→`r` (`priv`), `p`→`u` (`pub`), then `s` (`seed`).
const KEY_TYPE_DECODER_KEYS: [(&err_sites::ErrSite, *const c_char); 3] = [
    (&err_sites::PROV_ML_KEM_KMGMT_380, OSSL_PKEY_PARAM_PRIV_KEY),
    (&err_sites::PROV_ML_KEM_KMGMT_391, OSSL_PKEY_PARAM_PUB_KEY),
    (
        &err_sites::PROV_ML_KEM_KMGMT_403,
        OSSL_PKEY_PARAM_ML_KEM_SEED,
    ),
];

/// The `ml_kem_get_params` decoder's ten coordinates, in the trie's own leaf order:
/// `b`·`e`·`k`·`m`, `p`→`r`, `p`→`u`, `r`, then the `s` subtree's three.
const GET_PARAMS_DECODER_KEYS: [(&err_sites::ErrSite, *const c_char); 10] = [
    (&err_sites::PROV_ML_KEM_KMGMT_616, OSSL_PKEY_PARAM_BITS),
    (
        &err_sites::PROV_ML_KEM_KMGMT_627,
        OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY,
    ),
    (
        &err_sites::PROV_ML_KEM_KMGMT_638,
        OSSL_PKEY_PARAM_CMS_KEMRI_KDF_ALGORITHM,
    ),
    (&err_sites::PROV_ML_KEM_KMGMT_649, OSSL_PKEY_PARAM_MAX_SIZE),
    (&err_sites::PROV_ML_KEM_KMGMT_664, OSSL_PKEY_PARAM_PRIV_KEY),
    (&err_sites::PROV_ML_KEM_KMGMT_675, OSSL_PKEY_PARAM_PUB_KEY),
    (
        &err_sites::PROV_ML_KEM_KMGMT_687,
        OSSL_PKEY_PARAM_CMS_RI_TYPE,
    ),
    (
        &err_sites::PROV_ML_KEM_KMGMT_734,
        OSSL_PKEY_PARAM_SECURITY_BITS,
    ),
    (
        &err_sites::PROV_ML_KEM_KMGMT_745,
        OSSL_PKEY_PARAM_SECURITY_CATEGORY,
    ),
    (
        &err_sites::PROV_ML_KEM_KMGMT_763,
        OSSL_PKEY_PARAM_ML_KEM_SEED,
    ),
];

/// The `ml_kem_set_params` decoder's one coordinate.
const SET_PARAMS_DECODER_KEYS: [(&err_sites::ErrSite, *const c_char); 1] = [(
    &err_sites::PROV_ML_KEM_KMGMT_960,
    OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY,
)];

/// The `ml_kem_gen_set_params` decoder's two coordinates: `p` (`properties`), then `s` (`seed`).
const GEN_SET_PARAMS_DECODER_KEYS: [(&err_sites::ErrSite, *const c_char); 2] = [
    (
        &err_sites::PROV_ML_KEM_KMGMT_1042,
        OSSL_PKEY_PARAM_PROPERTIES,
    ),
    (
        &err_sites::PROV_ML_KEM_KMGMT_1053,
        OSSL_PKEY_PARAM_ML_DSA_SEED,
    ),
];

/// `ml_kem_key_type_params_decoder` — generated `ml_kem_kmgmt.c`.
///
/// # Safety
/// `params` is NULL or key-terminated; `r` is writable.
unsafe fn key_type_params_decoder(params: *const OsslParam, r: &mut KeyTypeParams) -> c_int {
    // SAFETY: the arguments are per the contract.
    unsafe {
        if let Some(site) = repeated_param_site(params, &KEY_TYPE_DECODER_KEYS) {
            raise_site(site);
            return 0;
        }
        r.seed = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_ML_KEM_SEED) as *mut OsslParam;
        r.privkey = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_PRIV_KEY) as *mut OsslParam;
        r.pubkey = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_PUB_KEY) as *mut OsslParam;
    }
    1
}

/// `ml_kem_get_params_decoder` — generated `ml_kem_kmgmt.c`.
///
/// # Safety
/// `params` is NULL or key-terminated; `r` is writable.
unsafe fn get_params_decoder(params: *const OsslParam, r: &mut GetParams) -> c_int {
    // SAFETY: the arguments are per the contract.
    unsafe {
        if let Some(site) = repeated_param_site(params, &GET_PARAMS_DECODER_KEYS) {
            raise_site(site);
            return 0;
        }
        r.bits = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_BITS) as *mut OsslParam;
        r.secbits =
            OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_SECURITY_BITS) as *mut OsslParam;
        r.maxsize = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_MAX_SIZE) as *mut OsslParam;
        r.seccat =
            OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_SECURITY_CATEGORY) as *mut OsslParam;
        r.seed = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_ML_KEM_SEED) as *mut OsslParam;
        r.privkey = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_PRIV_KEY) as *mut OsslParam;
        r.pubkey = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_PUB_KEY) as *mut OsslParam;
        r.encpubkey =
            OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY) as *mut OsslParam;
        r.ri_type = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_CMS_RI_TYPE) as *mut OsslParam;
        r.kemri_kdf_alg = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_CMS_KEMRI_KDF_ALGORITHM)
            as *mut OsslParam;
    }
    1
}

/// `ml_kem_set_params_decoder` — generated `ml_kem_kmgmt.c`.
///
/// # Safety
/// `params` is NULL or key-terminated; `r` is writable.
unsafe fn set_params_decoder(params: *const OsslParam, r: &mut SetParams) -> c_int {
    // SAFETY: the arguments are per the contract.
    unsafe {
        if let Some(site) = repeated_param_site(params, &SET_PARAMS_DECODER_KEYS) {
            raise_site(site);
            return 0;
        }
        r.pubparam =
            OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY) as *mut OsslParam;
    }
    1
}

/// `ml_kem_gen_set_params_decoder` — generated `ml_kem_kmgmt.c`.
///
/// # Safety
/// `params` is NULL or key-terminated; `r` is writable.
unsafe fn gen_set_params_decoder(params: *const OsslParam, r: &mut GenSetParams) -> c_int {
    // SAFETY: the arguments are per the contract.
    unsafe {
        if let Some(site) = repeated_param_site(params, &GEN_SET_PARAMS_DECODER_KEYS) {
            raise_site(site);
            return 0;
        }
        r.seed = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_ML_DSA_SEED);
        r.propq = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_PROPERTIES);
    }
    1
}

/// `static const OSSL_PARAM *ml_kem_imexport_types(int selection)` — `ml_kem_kmgmt.c:351-356`.
///
/// # Safety
/// The keymgmt `import_types`/`export_types` dispatch contract.
unsafe extern "C" fn ml_kem_imexport_types(selection: c_int) -> *const OsslParam {
    if selection & OSSL_KEYMGMT_SELECT_KEYPAIR != 0 {
        return ML_KEM_KEY_TYPE_PARAMS_LIST.as_ptr();
    }
    ptr::null()
}

/// `static int check_seed(const uint8_t *seed, const uint8_t *prvenc, ML_KEM_KEY *key)` —
/// `ml_kem_kmgmt.c:358-372`.
///
/// # Safety
/// Both buffers are readable for the lengths the key's variant implies.
unsafe fn check_seed(seed: *const u8, prvenc: *const u8, key: *mut MlKemKey) -> c_int {
    let zlen = ML_KEM_RANDOM_BYTES;

    // SAFETY: the buffers are readable per the contract.
    unsafe {
        if crate::runtime::mem::CRYPTO_memcmp(
            seed.add(ML_KEM_SEED_BYTES - zlen).cast(),
            prvenc.add((*(*key).vinfo).prvkey_bytes - zlen).cast(),
            zlen,
        ) == 0
        {
            return 1;
        }
        raise_with_alg(
            &err_sites::PROV_ML_KEM_KMGMT_432,
            "private ",
            (*(*key).vinfo).algorithm_name,
            " key implicit rejection secret does not match seed",
        );
    }
    0
}

/// `static int check_prvenc(const uint8_t *prvenc, ML_KEM_KEY *key)` —
/// `ml_kem_kmgmt.c:374-393`.
///
/// # Safety
/// `prvenc` is readable for the key's `prvkey_bytes`.
unsafe fn check_prvenc(prvenc: *const u8, key: *mut MlKemKey) -> c_int {
    // SAFETY: `key` and its vinfo are live per the contract.
    let len = unsafe { (*(*key).vinfo).prvkey_bytes };

    // SAFETY: `key` is live per the contract.
    unsafe {
        let buf = CRYPTO_malloc(len, FILE, LINE_CHECK_PRVENC).cast::<u8>();
        let mut ret = 0;
        if !buf.is_null() && ossl_ml_kem_encode_private_key(buf, len, key) != 0 {
            ret = c_int::from(
                crate::runtime::mem::CRYPTO_memcmp(buf.cast(), prvenc.cast(), len) == 0,
            );
        }
        CRYPTO_clear_free(buf.cast(), len, FILE, LINE_CHECK_PRVENC);
        if ret != 0 {
            return 1;
        }

        if !buf.is_null() {
            raise_with_alg(
                &err_sites::PROV_ML_KEM_KMGMT_453,
                "explicit ",
                (*(*key).vinfo).algorithm_name,
                " private key does not match seed",
            );
        }
        ossl_ml_kem_key_reset(key);
    }
    0
}

/// `static int ml_kem_key_fromdata(ML_KEM_KEY *key, const OSSL_PARAM params[],`
/// `int include_private)` — `ml_kem_kmgmt.c:395-478`.
///
/// # Safety
/// `key` is live and has no key material yet.
unsafe fn ml_kem_key_fromdata(
    key: *mut MlKemKey,
    params: *const OsslParam,
    include_private: c_int,
) -> c_int {
    let mut p = KeyTypeParams {
        seed: ptr::null(),
        privkey: ptr::null(),
        pubkey: ptr::null(),
    };
    let mut pubenc: *const c_void = ptr::null();
    let mut prvenc: *const c_void = ptr::null();
    let mut seedenc: *const c_void = ptr::null();
    let mut publen = 0usize;
    let mut prvlen = 0usize;
    let mut seedlen = 0usize;

    // SAFETY: the arguments are per the contract.
    unsafe {
        // Invalid attempt to mutate a key, what is the right error to report?
        if key.is_null()
            || ossl_ml_kem_have_pubkey(key)
            || key_type_params_decoder(params, &mut p) == 0
        {
            return 0;
        }
        let v = ossl_ml_kem_key_vinfo(key);

        if !p.seed.is_null() && include_private != 0 {
            if OSSL_PARAM_get_octet_string_ptr(p.seed, &mut seedenc, &mut seedlen) != 1 {
                return 0;
            }
            if seedlen != 0 && seedlen != ML_KEM_SEED_BYTES {
                raise_site(&err_sites::PROV_ML_KEM_KMGMT_489);
                return 0;
            }
        }

        if !p.privkey.is_null() && include_private != 0 {
            if OSSL_PARAM_get_octet_string_ptr(p.privkey, &mut prvenc, &mut prvlen) != 1 {
                return 0;
            }
            if prvlen != 0 && prvlen != (*v).prvkey_bytes {
                raise_site(&err_sites::PROV_ML_KEM_KMGMT_498);
                return 0;
            }
        }

        // Used only when no seed or private key is provided.
        if !p.pubkey.is_null() {
            if OSSL_PARAM_get_octet_string_ptr(p.pubkey, &mut pubenc, &mut publen) != 1 {
                return 0;
            }
            if publen != 0 && publen != (*v).pubkey_bytes {
                raise_site(&err_sites::PROV_ML_KEM_KMGMT_508);
                return 0;
            }
        }

        // The caller MUST specify at least one of seed, private or public keys.
        if seedlen == 0 && publen == 0 && prvlen == 0 {
            raise_site(&err_sites::PROV_ML_KEM_KMGMT_515);
            return 0;
        }

        // Check any explicit public key against embedded value in private key
        if publen > 0 && prvlen > 0 {
            // point to the ek offset in dk = DKpke||ek||H(ek)||z
            let puboff = prvlen - ML_KEM_RANDOM_BYTES - ML_KEM_PKHASH_BYTES - publen;
            if crate::runtime::mem::CRYPTO_memcmp(
                pubenc,
                prvenc.cast::<u8>().add(puboff).cast(),
                publen,
            ) != 0
            {
                raise_with_alg(
                    &err_sites::PROV_ML_KEM_KMGMT_524,
                    "explicit ",
                    (*v).algorithm_name,
                    " public key does not match private",
                );
                return 0;
            }
        }

        if seedlen != 0 && (prvlen == 0 || (*key).prov_flags & ML_KEM_KEY_PREFER_SEED != 0) {
            if prvlen != 0 && check_seed(seedenc.cast(), prvenc.cast(), key) == 0 {
                return 0;
            }
            if ossl_ml_kem_set_seed(seedenc.cast(), seedlen, key).is_null()
                || ossl_ml_kem_genkey(ptr::null_mut(), 0, key) == 0
            {
                return 0;
            }
            return c_int::from(prvlen == 0 || check_prvenc(prvenc.cast(), key) != 0);
        } else if prvlen != 0 {
            return ossl_ml_kem_parse_private_key(prvenc.cast(), prvlen, key);
        }
        ossl_ml_kem_parse_public_key(pubenc.cast(), publen, key)
    }
}

/// `static int ml_kem_import(void *vkey, int selection, const OSSL_PARAM params[])` —
/// `ml_kem_kmgmt.c:480-500`.
///
/// # Safety
/// The keymgmt `import` dispatch contract.
unsafe extern "C" fn ml_kem_import(
    vkey: *mut c_void,
    selection: c_int,
    params: *const OsslParam,
) -> c_int {
    let key = vkey.cast::<MlKemKey>();

    if is_running() == 0 || key.is_null() {
        return 0;
    }
    if selection & OSSL_KEYMGMT_SELECT_KEYPAIR == 0 {
        return 0;
    }

    let include_private = c_int::from(selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY != 0);
    // SAFETY: `key` is live per the contract.
    unsafe {
        let mut res = ml_kem_key_fromdata(key, params, include_private);
        if res > 0 && include_private != 0 && ml_kem_pairwise_test(key, (*key).prov_flags) == 0 {
            ossl_ml_kem_key_reset(key);
            res = 0;
        }
        res
    }
}

/// `static const OSSL_PARAM *ml_kem_gettable_params(void *provctx)` — `ml_kem_kmgmt.c:517-520`.
///
/// # Safety
/// The keymgmt `gettable_params` dispatch contract.
unsafe extern "C" fn ml_kem_gettable_params(_provctx: *mut c_void) -> *const OsslParam {
    ML_KEM_GET_PARAMS_LIST.as_ptr()
}

/// `static void *ml_kem_load(const void *reference, size_t reference_sz)` —
/// `ml_kem_kmgmt.c:523-569`.
///
/// # Safety
/// The keymgmt `load` dispatch contract.
unsafe extern "C" fn ml_kem_load(reference: *const c_void, reference_sz: usize) -> *mut c_void {
    if is_running() == 0 || reference_sz != core::mem::size_of::<*mut MlKemKey>() {
        return ptr::null_mut();
    }

    // SAFETY: `reference` names a pointer-sized slot per the size check above.
    unsafe {
        let slot = reference as *mut *mut MlKemKey;
        let key = *slot;
        if key.is_null() {
            return ptr::null_mut();
        }
        let encoded_dk = (*key).encoded_dk;
        (*key).encoded_dk = ptr::null_mut();
        // We grabbed, so we detach it
        *slot = ptr::null_mut();

        let mut seed = [0u8; ML_KEM_SEED_BYTES];
        let prvkey_bytes = (*(*key).vinfo).prvkey_bytes;

        if !encoded_dk.is_null()
            && ossl_ml_kem_encode_seed(seed.as_mut_ptr(), seed.len(), key) != 0
            && check_seed(seed.as_ptr(), encoded_dk, key) == 0
        {
            return load_err(key, encoded_dk, &mut seed, prvkey_bytes);
        }
        // Generate the key now, if it holds only a stashed seed.
        if ossl_ml_kem_have_seed(key)
            && (encoded_dk.is_null() || (*key).prov_flags & ML_KEM_KEY_PREFER_SEED != 0)
        {
            if ossl_ml_kem_genkey(ptr::null_mut(), 0, key) == 0
                || (!encoded_dk.is_null() && check_prvenc(encoded_dk, key) == 0)
            {
                return load_err(key, encoded_dk, &mut seed, prvkey_bytes);
            }
        } else if !encoded_dk.is_null() {
            if ossl_ml_kem_parse_private_key(encoded_dk, prvkey_bytes, key) == 0 {
                raise_with_alg(
                    &err_sites::PROV_ML_KEM_KMGMT_811,
                    "error parsing ",
                    (*(*key).vinfo).algorithm_name,
                    " private key",
                );
                return load_err(key, encoded_dk, &mut seed, prvkey_bytes);
            }
            if ml_kem_pairwise_test(key, (*key).prov_flags) == 0 {
                return load_err(key, encoded_dk, &mut seed, prvkey_bytes);
            }
        }
        CRYPTO_secure_clear_free(encoded_dk.cast(), prvkey_bytes, FILE, LINE_LOAD_CLEAR);
        OPENSSL_cleanse(seed.as_mut_ptr().cast(), seed.len());
        key.cast()
    }
}

/// The `err:` label of `ml_kem_load` — `ml_kem_kmgmt.c:563-568`.
///
/// # Safety
/// `key` is this call's own.
unsafe fn load_err(
    key: *mut MlKemKey,
    encoded_dk: *mut u8,
    seed: &mut [u8; ML_KEM_SEED_BYTES],
    prvkey_bytes: usize,
) -> *mut c_void {
    // SAFETY: `key` is this call's own and NULL is accepted by both free functions.
    unsafe {
        if !key.is_null() && !(*key).vinfo.is_null() {
            CRYPTO_secure_clear_free(encoded_dk.cast(), prvkey_bytes, FILE, LINE_LOAD_CLEAR);
        }
        OPENSSL_cleanse(seed.as_mut_ptr().cast(), seed.len());
        ossl_ml_kem_key_free(key);
    }
    ptr::null_mut()
}

/// `static int ml_kem_get_key_param(const ML_KEM_KEY *key, OSSL_PARAM *p, size_t bytes,`
/// `int (*get_f)(uint8_t *out, size_t len, const ML_KEM_KEY *key))` — `ml_kem_kmgmt.c:572-585`.
///
/// # Safety
/// `p` is live and `key` is live.
unsafe fn ml_kem_get_key_param(
    key: *const MlKemKey,
    p: *mut OsslParam,
    bytes: usize,
    get_f: unsafe fn(*mut u8, usize, *const MlKemKey) -> c_int,
) -> c_int {
    // SAFETY: `p` and `key` are live per the contract.
    unsafe {
        if (*p).data_type != OSSL_PARAM_OCTET_STRING {
            return 0;
        }
        (*p).return_size = bytes;
        if !(*p).data.is_null()
            && ((*p).data_size < (*p).return_size
                || get_f((*p).data.cast::<u8>(), (*p).return_size, key) == 0)
        {
            return 0;
        }
    }
    1
}

/// `static int ml_kem_get_params(void *vkey, OSSL_PARAM params[])` — `ml_kem_kmgmt.c:590-670`.
///
/// # Safety
/// The keymgmt `get_params` dispatch contract.
unsafe extern "C" fn ml_kem_get_params(vkey: *mut c_void, params: *mut OsslParam) -> c_int {
    let key = vkey.cast::<MlKemKey>();
    let mut p = GetParams {
        bits: ptr::null_mut(),
        secbits: ptr::null_mut(),
        maxsize: ptr::null_mut(),
        seccat: ptr::null_mut(),
        seed: ptr::null_mut(),
        privkey: ptr::null_mut(),
        pubkey: ptr::null_mut(),
        encpubkey: ptr::null_mut(),
        ri_type: ptr::null_mut(),
        kemri_kdf_alg: ptr::null_mut(),
    };

    // SAFETY: `key` and `params` are the caller's.
    unsafe {
        if key.is_null() || get_params_decoder(params, &mut p) == 0 {
            return 0;
        }
        let v = ossl_ml_kem_key_vinfo(key);

        if !p.bits.is_null() && OSSL_PARAM_set_size_t(p.bits, (*v).bits as usize) == 0 {
            return 0;
        }
        if !p.secbits.is_null() && OSSL_PARAM_set_size_t(p.secbits, (*v).secbits as usize) == 0 {
            return 0;
        }
        if !p.maxsize.is_null() && OSSL_PARAM_set_size_t(p.maxsize, (*v).ctext_bytes) == 0 {
            return 0;
        }
        if !p.seccat.is_null() && OSSL_PARAM_set_int(p.seccat, (*v).security_category) == 0 {
            return 0;
        }

        if !p.pubkey.is_null() && ossl_ml_kem_have_pubkey(key) {
            // Exported to EVP_PKEY_get_raw_public_key()
            if ml_kem_get_key_param(
                key,
                p.pubkey,
                (*v).pubkey_bytes,
                ossl_ml_kem_encode_public_key,
            ) == 0
            {
                return 0;
            }
        }
        if !p.encpubkey.is_null() && ossl_ml_kem_have_pubkey(key) {
            // Needed by EVP_PKEY_get1_encoded_public_key()
            if ml_kem_get_key_param(
                key,
                p.encpubkey,
                (*v).pubkey_bytes,
                ossl_ml_kem_encode_public_key,
            ) == 0
            {
                return 0;
            }
        }
        if !p.privkey.is_null() && ossl_ml_kem_have_prvkey(key) {
            // Exported to EVP_PKEY_get_raw_private_key()
            if ml_kem_get_key_param(
                key,
                p.privkey,
                (*v).prvkey_bytes,
                ossl_ml_kem_encode_private_key,
            ) == 0
            {
                return 0;
            }
        }
        if !p.seed.is_null() && ossl_ml_kem_have_seed(key) {
            // Exported for import
            if ml_kem_get_key_param(key, p.seed, ML_KEM_SEED_BYTES, ossl_ml_kem_encode_seed) == 0 {
                return 0;
            }
        }

        // `#ifndef OPENSSL_NO_CMS` -- `OPENSSL_NO_CMS` is not in the admitted profile, so both
        // of these are compiled, which is why `CMS_RECIPINFO_KEM` and the HKDF OID are here.
        if !p.ri_type.is_null() && OSSL_PARAM_set_int(p.ri_type, CMS_RECIPINFO_KEM) == 0 {
            return 0;
        }

        if !p.kemri_kdf_alg.is_null() {
            let mut aid_buf = [0u8; OSSL_MAX_ALGORITHM_ID_SIZE];
            let mut aid_len = 0usize;
            let mut pkt = core::mem::MaybeUninit::<Wpacket>::uninit();

            let mut ret = WPACKET_init_der(pkt.as_mut_ptr(), aid_buf.as_mut_ptr(), aid_buf.len());
            ret &= c_int::from(
                ossl_DER_w_begin_sequence(pkt.as_mut_ptr(), -1) != 0
                    && ossl_DER_w_precompiled(
                        pkt.as_mut_ptr(),
                        -1,
                        OSSL_DER_OID_ID_ALG_HKDF_WITH_SHA256.as_ptr(),
                        OSSL_DER_OID_ID_ALG_HKDF_WITH_SHA256.len(),
                    ) != 0
                    && ossl_DER_w_end_sequence(pkt.as_mut_ptr(), -1) != 0,
            );
            let mut aid: *mut u8 = ptr::null_mut();
            if ret != 0 && WPACKET_finish(pkt.as_mut_ptr()) != 0 {
                WPACKET_get_total_written(pkt.as_mut_ptr(), &mut aid_len);
                aid = WPACKET_get_curr(pkt.as_mut_ptr());
            }
            WPACKET_cleanup(pkt.as_mut_ptr());
            if ret == 0 {
                return 0;
            }
            if !aid.is_null()
                && aid_len != 0
                && OSSL_PARAM_set_octet_string(p.kemri_kdf_alg, aid.cast(), aid_len) == 0
            {
                return 0;
            }
        }
    }
    1
}

/// `static const OSSL_PARAM *ml_kem_settable_params(void *provctx)` — `ml_kem_kmgmt.c:678-681`.
///
/// # Safety
/// The keymgmt `settable_params` dispatch contract.
unsafe extern "C" fn ml_kem_settable_params(_provctx: *mut c_void) -> *const OsslParam {
    ML_KEM_SET_PARAMS_LIST.as_ptr()
}

/// `static int ml_kem_set_params(void *vkey, const OSSL_PARAM params[])` —
/// `ml_kem_kmgmt.c:683-713`.
///
/// # Safety
/// The keymgmt `set_params` dispatch contract.
unsafe extern "C" fn ml_kem_set_params(vkey: *mut c_void, params: *const OsslParam) -> c_int {
    let key = vkey.cast::<MlKemKey>();
    let mut p = SetParams {
        pubparam: ptr::null_mut(),
    };
    let mut pubenc: *const c_void = ptr::null();
    let mut publen = 0usize;

    // SAFETY: `key` and `params` are the caller's.
    unsafe {
        if key.is_null() || set_params_decoder(params, &mut p) == 0 {
            return 0;
        }

        // Used in TLS via EVP_PKEY_set1_encoded_public_key().
        if !p.pubparam.is_null()
            && (OSSL_PARAM_get_octet_string_ptr(p.pubparam, &mut pubenc, &mut publen) != 1
                || publen != (*(*key).vinfo).pubkey_bytes)
        {
            raise_site(&err_sites::PROV_ML_KEM_KMGMT_991);
            return 0;
        }

        if publen == 0 {
            return 1;
        }

        // Key mutation is reportedly generally not allowed
        if ossl_ml_kem_have_pubkey(key) {
            raise_fixed(
                &err_sites::PROV_ML_KEM_KMGMT_1000,
                "ML-KEM keys cannot be mutated",
            );
            return 0;
        }

        ossl_ml_kem_parse_public_key(pubenc.cast(), publen, key)
    }
}

/// `static int ml_kem_gen_set_params(void *vgctx, const OSSL_PARAM params[])` —
/// `ml_kem_kmgmt.c:722-754`.
///
/// # Safety
/// The keymgmt `gen_set_params` dispatch contract.
unsafe extern "C" fn ml_kem_gen_set_params(vgctx: *mut c_void, params: *const OsslParam) -> c_int {
    let gctx = vgctx.cast::<ProvMlKemGenCtx>();
    let mut p = GenSetParams {
        seed: ptr::null(),
        propq: ptr::null(),
    };

    // SAFETY: `gctx` and `params` are the caller's.
    unsafe {
        if gctx.is_null() || gen_set_params_decoder(params, &mut p) == 0 {
            return 0;
        }

        if !p.propq.is_null() {
            if (*p.propq).data_type != OSSL_PARAM_UTF8_STRING {
                return 0;
            }
            CRYPTO_free((*gctx).propq.cast(), FILE, LINE_GEN_FREE_PROPQ);
            (*gctx).propq = CRYPTO_strdup((*p.propq).data.cast(), FILE, LINE_GEN_FREE_PROPQ);
            if (*gctx).propq.is_null() {
                return 0;
            }
        }

        if !p.seed.is_null() {
            let mut len = ML_KEM_SEED_BYTES;

            (*gctx).seed = (*gctx).seedbuf.as_mut_ptr();
            let mut sp: *mut c_void = (*gctx).seed.cast();
            let ok = OSSL_PARAM_get_octet_string(p.seed, &mut sp, len, &mut len);
            (*gctx).seed = sp.cast::<u8>();
            if ok != 0 && len == ML_KEM_SEED_BYTES {
                return 1;
            }

            // Possibly, but less likely wrong data type
            raise_site(&err_sites::PROV_ML_KEM_KMGMT_1091);
            OPENSSL_cleanse((*gctx).seedbuf.as_mut_ptr().cast(), ML_KEM_SEED_BYTES);
            (*gctx).seed = ptr::null_mut();
            return 0;
        }
    }
    1
}

/// `static void *ml_kem_gen_init(void *provctx, int selection, const OSSL_PARAM params[],`
/// `int evp_type)` — `ml_kem_kmgmt.c:756-778`.
///
/// # Safety
/// The keymgmt `gen_init` dispatch contract.
unsafe fn ml_kem_gen_init(
    provctx: *mut c_void,
    selection: c_int,
    params: *const OsslParam,
    evp_type: c_int,
) -> *mut c_void {
    if is_running() == 0 || selection & MINIMAL_SELECTION == 0 {
        return ptr::null_mut();
    }
    // SAFETY: `CRYPTO_zalloc` answers NULL on failure, which is checked.
    let gctx = CRYPTO_zalloc(
        core::mem::size_of::<ProvMlKemGenCtx>(),
        FILE,
        LINE_GEN_ZALLOC,
    )
    .cast::<ProvMlKemGenCtx>();
    if gctx.is_null() {
        return ptr::null_mut();
    }

    // SAFETY: `gctx` is a fresh allocation; every field is written below.
    unsafe {
        (*gctx).selection = selection;
        (*gctx).evp_type = evp_type;
        (*gctx).provctx = provctx.cast();
        if ml_kem_gen_set_params(gctx.cast(), params) != 0 {
            return gctx.cast();
        }
        ml_kem_gen_cleanup(gctx.cast());
    }
    ptr::null_mut()
}

/// `static const OSSL_PARAM *ml_kem_gen_settable_params(void *vgctx, void *provctx)` —
/// `ml_kem_kmgmt.c:780-784`.
///
/// # Safety
/// The keymgmt `gen_settable_params` dispatch contract.
unsafe extern "C" fn ml_kem_gen_settable_params(
    _vgctx: *mut c_void,
    _provctx: *mut c_void,
) -> *const OsslParam {
    ML_KEM_GEN_SET_PARAMS_LIST.as_ptr()
}

/// `static void *ml_kem_gen(void *vgctx, OSSL_CALLBACK *osslcb, void *cbarg)` —
/// `ml_kem_kmgmt.c:786-828`.
///
/// The `FIPS_MODULE` fixed-PCT block (`:817-822`) is absent on this profile.
///
/// # Safety
/// The keymgmt `gen` dispatch contract.
unsafe extern "C" fn ml_kem_gen(
    vgctx: *mut c_void,
    _osslcb: Option<OsslCallback>,
    _cbarg: *mut c_void,
) -> *mut c_void {
    let gctx = vgctx.cast::<ProvMlKemGenCtx>();

    if gctx.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: `gctx` is live per the contract.
    unsafe {
        if (*gctx).selection & OSSL_KEYMGMT_SELECT_KEYPAIR == OSSL_KEYMGMT_SELECT_PUBLIC_KEY {
            return ptr::null_mut();
        }
        let seed = (*gctx).seed;
        let key = ossl_prov_ml_kem_new((*gctx).provctx, (*gctx).propq, (*gctx).evp_type);
        if key.is_null() {
            return ptr::null_mut();
        }

        if (*gctx).selection & OSSL_KEYMGMT_SELECT_KEYPAIR == 0 {
            return key.cast();
        }

        if !seed.is_null() && ossl_ml_kem_set_seed(seed, ML_KEM_SEED_BYTES, key).is_null() {
            ossl_ml_kem_key_free(key);
            return ptr::null_mut();
        }
        let genok = ossl_ml_kem_genkey(ptr::null_mut(), 0, key);

        // Erase the single-use seed
        if !seed.is_null() {
            OPENSSL_cleanse(seed.cast(), ML_KEM_SEED_BYTES);
        }
        (*gctx).seed = ptr::null_mut();

        if genok != 0 {
            return key.cast();
        }

        ossl_ml_kem_key_free(key);
    }
    ptr::null_mut()
}

/// `static void ml_kem_gen_cleanup(void *vgctx)` — `ml_kem_kmgmt.c:830-841`.
///
/// # Safety
/// The keymgmt `gen_cleanup` dispatch contract.
unsafe extern "C" fn ml_kem_gen_cleanup(vgctx: *mut c_void) {
    let gctx = vgctx.cast::<ProvMlKemGenCtx>();

    if gctx.is_null() {
        return;
    }
    // SAFETY: `gctx` is live per the contract.
    unsafe {
        if !(*gctx).seed.is_null() {
            OPENSSL_cleanse((*gctx).seed.cast(), ML_KEM_SEED_BYTES);
        }
        CRYPTO_free((*gctx).propq.cast(), FILE, LINE_GEN_CLEANUP_PROPQ);
        CRYPTO_free(gctx.cast(), FILE, LINE_GEN_CLEANUP_CTX);
    }
}

/// `static void *ml_kem_dup(const void *vkey, int selection)` — `ml_kem_kmgmt.c:843-851`.
///
/// # Safety
/// The keymgmt `dup` dispatch contract.
unsafe extern "C" fn ml_kem_dup(vkey: *const c_void, selection: c_int) -> *mut c_void {
    if is_running() == 0 {
        return ptr::null_mut();
    }
    // SAFETY: `vkey` is the caller's.
    unsafe { ossl_ml_kem_key_dup(vkey.cast(), selection).cast() }
}

/// `static void ml_kem_free_key(void *keydata)` — `ml_kem_kmgmt.c:853-856`.
///
/// # Safety
/// The keymgmt `free` dispatch contract.
unsafe extern "C" fn ml_kem_free_key(keydata: *mut c_void) {
    // SAFETY: `keydata` is the caller's, and NULL is accepted.
    unsafe { ossl_ml_kem_key_free(keydata.cast()) };
}

/// One `DECLARE_VARIANT(bits)` expansion — `ml_kem_kmgmt.c:865-899`.
///
/// The two differing columns are `NEW` and `GEN_INIT`; every other slot is the shared body. The
/// algorithm name each expansion carries is an `EVP_PKEY_ML_KEM_*` **NID**, not a string, so the
/// name a row answers to comes from `DEFLT_KEYMGMT`'s `algorithm_names`, exactly as the
/// authority's `defltprov.c` pairs them.
macro_rules! declare_variant {
    ($fn_new:ident, $fn_gen_init:ident, $table:ident, $evp_type:expr) => {
        /// `static void *ml_kem_<bits>_new(void *provctx)` — one expansion's `NEW`.
        ///
        /// # Safety
        /// The keymgmt `new` dispatch contract.
        unsafe extern "C" fn $fn_new(provctx: *mut c_void) -> *mut c_void {
            // SAFETY: `provctx` is the caller's context; NULL is the authority's own `propq`.
            unsafe { ossl_prov_ml_kem_new(provctx.cast(), ptr::null(), $evp_type).cast() }
        }

        /// `static void *ml_kem_<bits>_gen_init(void *provctx, int selection,`
        /// `const OSSL_PARAM params[])` — one expansion's `GEN_INIT`.
        ///
        /// # Safety
        /// The keymgmt `gen_init` dispatch contract.
        unsafe extern "C" fn $fn_gen_init(
            provctx: *mut c_void,
            selection: c_int,
            params: *const OsslParam,
        ) -> *mut c_void {
            // SAFETY: forwarded with this expansion's own variant.
            unsafe { ml_kem_gen_init(provctx, selection, params, $evp_type) }
        }

        /// `const OSSL_DISPATCH ossl_ml_kem_<bits>_keymgmt_functions[]` — one expansion's table.
        pub(crate) static $table: [OsslDispatch; 21] = [
            OsslDispatch {
                function_id: OSSL_FUNC_KEYMGMT_NEW,
                function: $fn_new as *mut c_void,
            },
            OsslDispatch {
                function_id: OSSL_FUNC_KEYMGMT_FREE,
                function: ml_kem_free_key as *mut c_void,
            },
            OsslDispatch {
                function_id: OSSL_FUNC_KEYMGMT_GET_PARAMS,
                function: ml_kem_get_params as *mut c_void,
            },
            OsslDispatch {
                function_id: OSSL_FUNC_KEYMGMT_GETTABLE_PARAMS,
                function: ml_kem_gettable_params as *mut c_void,
            },
            OsslDispatch {
                function_id: OSSL_FUNC_KEYMGMT_SET_PARAMS,
                function: ml_kem_set_params as *mut c_void,
            },
            OsslDispatch {
                function_id: OSSL_FUNC_KEYMGMT_SETTABLE_PARAMS,
                function: ml_kem_settable_params as *mut c_void,
            },
            OsslDispatch {
                function_id: OSSL_FUNC_KEYMGMT_HAS,
                function: ml_kem_has as *mut c_void,
            },
            OsslDispatch {
                function_id: OSSL_FUNC_KEYMGMT_MATCH,
                function: ml_kem_match as *mut c_void,
            },
            OsslDispatch {
                function_id: OSSL_FUNC_KEYMGMT_VALIDATE,
                function: ml_kem_validate as *mut c_void,
            },
            OsslDispatch {
                function_id: OSSL_FUNC_KEYMGMT_GEN_INIT,
                function: $fn_gen_init as *mut c_void,
            },
            OsslDispatch {
                function_id: OSSL_FUNC_KEYMGMT_GEN_SET_PARAMS,
                function: ml_kem_gen_set_params as *mut c_void,
            },
            OsslDispatch {
                function_id: OSSL_FUNC_KEYMGMT_GEN_SETTABLE_PARAMS,
                function: ml_kem_gen_settable_params as *mut c_void,
            },
            OsslDispatch {
                function_id: OSSL_FUNC_KEYMGMT_GEN,
                function: ml_kem_gen as *mut c_void,
            },
            OsslDispatch {
                function_id: OSSL_FUNC_KEYMGMT_GEN_CLEANUP,
                function: ml_kem_gen_cleanup as *mut c_void,
            },
            // `DISPATCH_LOAD_FN` — non-FIPS, so `OSSL_FUNC_KEYMGMT_LOAD` is present.
            OsslDispatch {
                function_id: OSSL_FUNC_KEYMGMT_LOAD,
                function: ml_kem_load as *mut c_void,
            },
            OsslDispatch {
                function_id: OSSL_FUNC_KEYMGMT_DUP,
                function: ml_kem_dup as *mut c_void,
            },
            OsslDispatch {
                function_id: OSSL_FUNC_KEYMGMT_IMPORT,
                function: ml_kem_import as *mut c_void,
            },
            OsslDispatch {
                function_id: OSSL_FUNC_KEYMGMT_IMPORT_TYPES,
                function: ml_kem_imexport_types as *mut c_void,
            },
            OsslDispatch {
                function_id: OSSL_FUNC_KEYMGMT_EXPORT,
                function: ml_kem_export as *mut c_void,
            },
            OsslDispatch {
                function_id: OSSL_FUNC_KEYMGMT_EXPORT_TYPES,
                function: ml_kem_imexport_types as *mut c_void,
            },
            OsslDispatch {
                function_id: OSSL_DISPATCH_END,
                function: ptr::null_mut(),
            },
        ];
    };
}

declare_variant!(
    ml_kem_512_new,
    ml_kem_512_gen_init,
    ML_KEM_512_KEYMGMT_FUNCTIONS,
    crate::ml_kem::EVP_PKEY_ML_KEM_512
);
declare_variant!(
    ml_kem_768_new,
    ml_kem_768_gen_init,
    ML_KEM_768_KEYMGMT_FUNCTIONS,
    crate::ml_kem::EVP_PKEY_ML_KEM_768
);
declare_variant!(
    ml_kem_1024_new,
    ml_kem_1024_gen_init,
    ML_KEM_1024_KEYMGMT_FUNCTIONS,
    crate::ml_kem::EVP_PKEY_ML_KEM_1024
);
