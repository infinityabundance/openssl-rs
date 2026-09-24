//! Phase 8.5 — `crypto/dh/dh_kdf.c`: the X9.42 KDF wrapper and its ASN.1 entry point.
//!
//! The unit is fifty-six lines and defines **two functions and no internals beyond them**:
//! `ossl_dh_kdf_X9_42_asn1`, the `OSSL_KDF_PARAM`-building body the provider's DH exchange row
//! reaches, and `DH_KDF_X9_42` (`dh.h:258`), the deprecated wrapper that turns an
//! `ASN1_OBJECT` into the `cekalg` name the KDF wants. Neither computes a KDF: both fetch
//! `OSSL_KDF_NAME_X942KDF_ASN1` and drive it, which is why the row
//! [`crate::provider::kdf`] publishes is what makes them answer (`docs/DECISIONS.md` D296,
//! D346).
//!
//! **The whole body is inside `#if !defined(FIPS_MODULE)`** (`dh_kdf.c:47-56`), and
//! `FIPS_MODULE` is undefined on this profile, so `DH_KDF_X9_42` is compiled here.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_char, c_int, c_void};
use core::ptr;

use crate::evp::digest::{EVP_MD_get0_name, EVP_MD_get0_provider, EvpMd};
use crate::evp::kdf::{
    EVP_KDF_CTX_free, EVP_KDF_CTX_new, EVP_KDF_derive, EVP_KDF_fetch, EVP_KDF_free, EvpKdf,
    EvpKdfCtx,
};
use crate::params::{
    OSSL_PARAM_construct_end, OSSL_PARAM_construct_octet_string, OSSL_PARAM_construct_utf8_string,
    OsslParam, END,
};
use crate::provider::ossl_provider_libctx;
use crate::runtime::obj::{Asn1Object, OBJ_obj2txt};

/// `OSSL_MAX_NAME_SIZE` — `include/internal/../openssl/core_names.h`'s bound on an algorithm
/// name, as `src/evp/kdf.rs` and `src/evp/pkey_ctx.rs` each spell it.
const OSSL_MAX_NAME_SIZE: usize = 50;

/// `OSSL_KDF_NAME_X942KDF_ASN1` — `core_names.h:80` (`"X942KDF-ASN1"`).
const OSSL_KDF_NAME_X942KDF_ASN1: *const c_char = c"X942KDF-ASN1".as_ptr();
/// `OSSL_KDF_PARAM_DIGEST` — `core_names.h:281`, aliased from `OSSL_ALG_PARAM_DIGEST`.
const OSSL_KDF_PARAM_DIGEST: *const c_char = c"digest".as_ptr();
/// `OSSL_KDF_PARAM_KEY` — `core_names.h:294`.
const OSSL_KDF_PARAM_KEY: *const c_char = c"key".as_ptr();
/// `OSSL_KDF_PARAM_UKM` — `core_names.h:316`.
const OSSL_KDF_PARAM_UKM: *const c_char = c"ukm".as_ptr();
/// `OSSL_KDF_PARAM_CEK_ALG` — `core_names.h:277`.
const OSSL_KDF_PARAM_CEK_ALG: *const c_char = c"cekalg".as_ptr();

/// `int ossl_dh_kdf_X9_42_asn1(unsigned char *out, size_t outlen, const unsigned char *Z,
/// size_t Zlen, const char *cek_alg, const unsigned char *ukm, size_t ukmlen,
/// const EVP_MD *md, OSSL_LIB_CTX *libctx, const char *propq)` — `dh_kdf.c:27-56`.
///
/// The `OSSL_PARAM` array is `params[5]`: `digest`, `key`, the optional `ukm`, `cekalg` and the
/// terminator, so the UKM's presence is what keeps the array at its largest. The `kctx` is
/// released whether the fetch answered or not; only the derive's verdict is returned.
///
/// # Safety
/// `out` writable for `outlen` bytes; `Z`/`ukm` readable for their lengths; `cek_alg` a
/// NUL-terminated C string; `md` live.
#[allow(clippy::too_many_arguments)] // the authority's own signature has ten parameters.
#[allow(non_snake_case)] // the authority's own symbol name
pub(crate) unsafe fn ossl_dh_kdf_X9_42_asn1(
    out: *mut u8,
    outlen: usize,
    z: *const u8,
    z_len: usize,
    cek_alg: *const c_char,
    ukm: *const u8,
    ukm_len: usize,
    md: *const EvpMd,
    libctx: *mut c_void,
    propq: *const c_char,
) -> c_int {
    let mut params: [OsslParam; 5] = [END; 5];
    let mut n = 0usize;

    // SAFETY: `md` is live per the contract.
    let mdname = unsafe { EVP_MD_get0_name(md) };

    // SAFETY: `libctx`/`propq` are per the contract.
    let kdf: *mut EvpKdf = unsafe { EVP_KDF_fetch(libctx, OSSL_KDF_NAME_X942KDF_ASN1, propq) };
    if kdf.is_null() {
        return 0;
    }
    // SAFETY: `kdf` is live.
    let kctx: *mut EvpKdfCtx = unsafe { EVP_KDF_CTX_new(kdf) };
    if kctx.is_null() {
        // SAFETY: `kdf` is live.
        unsafe { EVP_KDF_free(kdf) };
        return 0;
    }
    let ret;

    // SAFETY: the descriptors borrow live data and `n` stays below the array's length.
    unsafe {
        params[n] = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST, mdname.cast_mut(), 0);
        n += 1;
        params[n] =
            OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_KEY, z.cast_mut().cast(), z_len);
        n += 1;
        if !ukm.is_null() {
            params[n] = OSSL_PARAM_construct_octet_string(
                OSSL_KDF_PARAM_UKM,
                ukm.cast_mut().cast(),
                ukm_len,
            );
            n += 1;
        }
        params[n] = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_CEK_ALG, cek_alg.cast_mut(), 0);
        n += 1;
        params[n] = OSSL_PARAM_construct_end();

        ret = (EVP_KDF_derive(kctx, out, outlen, params.as_ptr()) > 0) as c_int;

        EVP_KDF_CTX_free(kctx);
        EVP_KDF_free(kdf);
    }
    ret
}

/// `int DH_KDF_X9_42(unsigned char *out, size_t outlen, const unsigned char *Z, size_t Zlen,
/// ASN1_OBJECT *key_oid, const unsigned char *ukm, size_t ukmlen, const EVP_MD *md)` —
/// `dh_kdf.c:58-73`.
///
/// The ASN.1 object is rendered as its **text** form (`OBJ_obj2txt(..., no_name = 0)`), which is
/// the `cekalg` name the `X942KDF-ASN1` row's `find_alg_id` compares against `kek_algs[]`. A
/// non-positive length is the one refusal.
///
/// # Safety
/// `out` writable for `outlen` bytes; `Z`/`ukm` readable for their lengths; `key_oid` live;
/// `md` live.
#[no_mangle]
pub unsafe extern "C" fn DH_KDF_X9_42(
    out: *mut u8,
    outlen: usize,
    z: *const u8,
    z_len: usize,
    key_oid: *mut Asn1Object,
    ukm: *const u8,
    ukm_len: usize,
    md: *const EvpMd,
) -> c_int {
    let mut key_alg = [0 as c_char; OSSL_MAX_NAME_SIZE];

    // SAFETY: `md` is live per the contract.
    let prov = unsafe { EVP_MD_get0_provider(md) };
    // SAFETY: `prov` is live (or NULL, which `ossl_provider_libctx` answers NULL for).
    let libctx = unsafe { ossl_provider_libctx(prov) };

    // SAFETY: `key_alg` is a live buffer of the size passed, and `key_oid` is live.
    if unsafe {
        OBJ_obj2txt(
            key_alg.as_mut_ptr(),
            OSSL_MAX_NAME_SIZE as c_int,
            key_oid,
            0,
        )
    } <= 0
    {
        return 0;
    }

    // SAFETY: every pointer is per this function's contract.
    unsafe {
        ossl_dh_kdf_X9_42_asn1(
            out,
            outlen,
            z,
            z_len,
            key_alg.as_ptr(),
            ukm,
            ukm_len,
            md,
            libctx,
            ptr::null(),
        )
    }
}
