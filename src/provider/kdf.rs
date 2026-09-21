//! Phase 8 — the default provider's `OSSL_OP_KDF` rows, and the two algorithm units behind
//! them.
//!
//! Three registration rows of `providers/defltprov.c`'s `deflt_kdfs[]` are published here:
//! `SSKDF` and `X963KDF`, whose units are `providers/implementations/kdfs/sskdf.c`, and
//! `X942KDF-ASN1`, whose unit is `providers/implementations/kdfs/x942kdf.c`. Both units are
//! transcribed **whole** (D327's rule) and the two rows `DH_KDF_X9_42` and `ECDH_KDF_X9_62`
//! fetch are among them: `DH_KDF_X9_42` reaches `X942KDF-ASN1` and `ECDH_KDF_X9_62` reaches
//! `X963KDF`, so with this module both wrappers have a real provider row to fetch
//! (`docs/DECISIONS.md` D296, D346).
//!
//! ## The provider rows, and the census's order
//!
//! `deflt_kdfs[]` carries nineteen rows on this profile and the three published here are its
//! sixth (`SSKDF`), tenth (`X963KDF`) and thirteenth (`X942KDF-ASN1`) — so the table below is
//! the authority's order and a **subsequence** of it, which `gen_provider_algorithms.py`
//! checks (D244). Each row's alias sequence is `prov/names.h`'s: `SSKDF` carries no alias,
//! `X963KDF` carries `X942KDF-CONCAT` and `X942KDF-ASN1` carries `X942KDF`.
//!
//! ## What is modelled, and what is not
//!
//! `KDF_SSKDF` and `KDF_X942` are internal structures, so there is no ABI obligation; their
//! fields are the authority's and `OSSL_FIPS_IND_DECLARE` contributes nothing on this profile.
//! The `produce_param_decoder` output is **not** transcribed switch-for-switch: the crate's
//! established reading of a generated decoder is `repeated_param_site` over the keys and their
//! raise sites (D305's `hmac_prov.c`, D241's `cmac_prov.c`). One difference is measured rather
//! than glossed: `sskdf.c`'s and `x942kdf.c`'s decoders map **two** key names onto a single
//! field (`secret`/`key`, and `ukm`/`partyu-info`), and the generated code raises at the second
//! occurrence of either. [`repeated_param_site_by_field`] reproduces that by keying the
//! seen-set on the field rather than the name.
//!
//! The FIPS arms are all `#ifdef FIPS_MODULE` and are absent, exactly as the profile's
//! `configuration.h` has it. `EVP_MD_CTX_create`/`_destroy` are the authority's macros for
//! `EVP_MD_CTX_new`/`_free`.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_char, c_int, c_void, CStr};
use core::ptr;

use crate::context::dispatch::{OsslDispatch, OSSL_DISPATCH_END};
use crate::der_writer::{
    ossl_DER_w_begin_sequence, ossl_DER_w_end_sequence, ossl_DER_w_octet_string,
    ossl_DER_w_octet_string_uint32, ossl_DER_w_precompiled,
};
use crate::evp::cipher::{EVP_CIPHER_fetch, EVP_CIPHER_free, EVP_CIPHER_is_a};
use crate::evp::digest::{
    EVP_DigestFinal_ex, EVP_DigestInit, EVP_DigestUpdate, EVP_MD_CTX_copy_ex, EVP_MD_CTX_free,
    EVP_MD_CTX_new, EVP_MD_get_size, EVP_MD_xof,
};
use crate::evp::kdf::{
    OSSL_FUNC_KDF_DERIVE, OSSL_FUNC_KDF_DUPCTX, OSSL_FUNC_KDF_FREECTX,
    OSSL_FUNC_KDF_GETTABLE_CTX_PARAMS, OSSL_FUNC_KDF_GET_CTX_PARAMS, OSSL_FUNC_KDF_NEWCTX,
    OSSL_FUNC_KDF_RESET, OSSL_FUNC_KDF_SETTABLE_CTX_PARAMS, OSSL_FUNC_KDF_SET_CTX_PARAMS,
};
use crate::evp::mac::{
    EVP_MAC_CTX_dup, EVP_MAC_CTX_free, EVP_MAC_CTX_get0_mac, EVP_MAC_CTX_get_mac_size,
    EVP_MAC_CTX_set_params, EVP_MAC_final, EVP_MAC_init, EVP_MAC_is_a, EVP_MAC_update, EvpMacCtx,
};
use crate::packet::{
    WPACKET_cleanup, WPACKET_finish, WPACKET_get_curr, WPACKET_get_total_written, WPACKET_init_der,
    WPACKET_init_null_der, Wpacket,
};
use crate::params::{
    ossl_param_get1_concat_octet_string, ossl_param_get1_octet_string_from_param,
    OSSL_PARAM_construct_end, OSSL_PARAM_construct_octet_string, OSSL_PARAM_construct_size_t,
    OSSL_PARAM_get_int, OSSL_PARAM_get_octet_string, OSSL_PARAM_get_size_t,
    OSSL_PARAM_get_utf8_string_ptr, OSSL_PARAM_set_size_t, OsslParam, END,
};
use crate::provider::activate::OsslAlgorithm;
use crate::provider::cipher::{param_int, param_octet_string, param_size_t, param_utf8_string};
use crate::provider::ctx::prov_libctx_of;
use crate::provider::util::prov_digest::{
    ossl_prov_digest_copy, ossl_prov_digest_load, ossl_prov_digest_md, ossl_prov_digest_reset,
    ProvDigest,
};
use crate::provider::util::{ossl_prov_macctx_load, ossl_prov_memdup};
use crate::runtime::err::{err_sites, raise_site};
use crate::runtime::mem::{cleanse, CRYPTO_clear_free, CRYPTO_free, CRYPTO_zalloc};

/// `OSSL_OP_KDF` — `include/openssl/core_dispatch.h`.
pub(crate) const OSSL_OP_KDF: c_int = 4;

/// `SSKDF_MAX_INLEN` — `sskdf.c:49`.
const SSKDF_MAX_INLEN: usize = 1 << 30;
/// `SSKDF_KMAC128_DEFAULT_SALT_SIZE` — `sskdf.c:50`.
const SSKDF_KMAC128_DEFAULT_SALT_SIZE: usize = 168 - 4;
/// `SSKDF_KMAC256_DEFAULT_SALT_SIZE` — `sskdf.c:51`.
const SSKDF_KMAC256_DEFAULT_SALT_SIZE: usize = 136 - 4;
/// `SSKDF_MAX_INFOS` — `sskdf.c:53`.
const SSKDF_MAX_INFOS: usize = 5;
/// `X942KDF_MAX_INLEN` — `x942kdf.c:34`.
const X942KDF_MAX_INLEN: usize = 1 << 30;
/// `EVP_MAX_MD_SIZE` — `include/openssl/evp.h:637`.
const EVP_MAX_MD_SIZE: usize = 64;
/// `kmac_custom_str[]` — `sskdf.c:56`, the three bytes `'K' 'D' 'F'`.
const KMAC_CUSTOM_STR: [u8; 3] = [0x4B, 0x44, 0x46];
/// `OSSL_MAC_NAME_HMAC` — `core_names.h:62`.
const OSSL_MAC_NAME_HMAC: *const c_char = c"HMAC".as_ptr();
/// `OSSL_MAC_NAME_KMAC128` — `core_names.h:63`.
const OSSL_MAC_NAME_KMAC128: *const c_char = c"KMAC128".as_ptr();
/// `OSSL_MAC_NAME_KMAC256` — `core_names.h:64`.
const OSSL_MAC_NAME_KMAC256: *const c_char = c"KMAC256".as_ptr();
/// `OSSL_MAC_PARAM_CUSTOM` — `core_names.h:357` (`"custom"`).
const OSSL_MAC_PARAM_CUSTOM: *const c_char = c"custom".as_ptr();
/// `OSSL_MAC_PARAM_SIZE` — `core_names.h:353` (`"size"`).
const OSSL_MAC_PARAM_SIZE: *const c_char = c"size".as_ptr();
/// `OSSL_KDF_PARAM_SECRET` — `core_names.h:309`.
const OSSL_KDF_PARAM_SECRET: *const c_char = c"secret".as_ptr();
/// `OSSL_KDF_PARAM_KEY` — `core_names.h:294`.
const OSSL_KDF_PARAM_KEY: *const c_char = c"key".as_ptr();
/// `OSSL_KDF_PARAM_INFO` — `core_names.h:289`.
const OSSL_KDF_PARAM_INFO: *const c_char = c"info".as_ptr();
/// `OSSL_KDF_PARAM_DIGEST` — `core_names.h:281`, aliased from `OSSL_ALG_PARAM_DIGEST`.
const OSSL_KDF_PARAM_DIGEST: *const c_char = c"digest".as_ptr();
/// `OSSL_KDF_PARAM_MAC` — `core_names.h:296`, aliased from `OSSL_ALG_PARAM_MAC`.
const OSSL_KDF_PARAM_MAC: *const c_char = c"mac".as_ptr();
/// `OSSL_KDF_PARAM_PROPERTIES` — `core_names.h:303`, aliased from `OSSL_ALG_PARAM_PROPERTIES`.
const OSSL_KDF_PARAM_PROPERTIES: *const c_char = c"properties".as_ptr();
/// `OSSL_KDF_PARAM_SALT` — `core_names.h:304`.
const OSSL_KDF_PARAM_SALT: *const c_char = c"salt".as_ptr();
/// `OSSL_KDF_PARAM_MAC_SIZE` — `core_names.h:297` (`"maclen"`).
const OSSL_KDF_PARAM_MAC_SIZE: *const c_char = c"maclen".as_ptr();
/// `OSSL_KDF_PARAM_SIZE` — `core_names.h:311`.
const OSSL_KDF_PARAM_SIZE: *const c_char = c"size".as_ptr();
/// `OSSL_KDF_PARAM_UKM` — `core_names.h:316`.
const OSSL_KDF_PARAM_UKM: *const c_char = c"ukm".as_ptr();
/// `OSSL_KDF_PARAM_CEK_ALG` — `core_names.h:277`.
const OSSL_KDF_PARAM_CEK_ALG: *const c_char = c"cekalg".as_ptr();
/// `OSSL_KDF_PARAM_X942_ACVPINFO` — `core_names.h:317`.
const OSSL_KDF_PARAM_X942_ACVPINFO: *const c_char = c"acvp-info".as_ptr();
/// `OSSL_KDF_PARAM_X942_PARTYUINFO` — `core_names.h:318`.
const OSSL_KDF_PARAM_X942_PARTYUINFO: *const c_char = c"partyu-info".as_ptr();
/// `OSSL_KDF_PARAM_X942_PARTYVINFO` — `core_names.h:319`.
const OSSL_KDF_PARAM_X942_PARTYVINFO: *const c_char = c"partyv-info".as_ptr();
/// `OSSL_KDF_PARAM_X942_SUPP_PRIVINFO` — `core_names.h:320`.
const OSSL_KDF_PARAM_X942_SUPP_PRIVINFO: *const c_char = c"supp-privinfo".as_ptr();
/// `OSSL_KDF_PARAM_X942_SUPP_PUBINFO` — `core_names.h:321`.
const OSSL_KDF_PARAM_X942_SUPP_PUBINFO: *const c_char = c"supp-pubinfo".as_ptr();
/// `OSSL_KDF_PARAM_X942_USE_KEYBITS` — `core_names.h:322`.
const OSSL_KDF_PARAM_X942_USE_KEYBITS: *const c_char = c"use-keybits".as_ptr();
/// `OSSL_ALG_PARAM_ENGINE` — `core_names.h:129`, a decoder key and deliberately not a
/// settable-list entry (`provider_util.h`'s `hidden` form in the generation spec).
const OSSL_ALG_PARAM_ENGINE: *const c_char = c"engine".as_ptr();
/// `OSSL_ALG_PARAM_PROPERTIES` — `core_names.h` (`"properties"`).
const OSSL_ALG_PARAM_PROPERTIES: *const c_char = c"properties".as_ptr();

/// `__FILE__` for `sskdf.c`, as the default provider's object carries it: the unit is
/// `.c.in`-generated, so the spelling is the bare build-relative path (D235's finding,
/// confirmed by `strings` on `providers/implementations/kdfs/libdefault-lib-sskdf.o`).
const FILE_SSKDF: *const c_char = c"providers/implementations/kdfs/sskdf.c".as_ptr();
/// `__FILE__` for `x942kdf.c`, measured the same way.
const FILE_X942: *const c_char = c"providers/implementations/kdfs/x942kdf.c".as_ptr();
/// `__LINE__`, inert under `OPENSSL_NO_CRYPTO_MDEBUG`.
const LINE: c_int = 0;

/// `int ossl_prov_is_running(void)` — `providers/prov_running.c`, as the MAC half spells it: the
/// default provider is always in a happy state on this build.
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

/// `struct sskdf_all_set_ctx_params_st` — `sskdf.c:540-554`, without its two FIPS fields.
#[derive(Default)]
struct SskdfSetCtxParams {
    secret: *const OsslParam,
    propq: *const OsslParam,
    engine: *const OsslParam,
    digest: *const OsslParam,
    mac: *const OsslParam,
    salt: *const OsslParam,
    size: *const OsslParam,
    info: [*const OsslParam; SSKDF_MAX_INFOS],
    num_info: c_int,
}

/// `struct sshkdf_set_ctx_params_st` — `x942kdf.c`'s generated set decoder's target, without
/// `ind_k` (the FIPS `key-check` key).
#[derive(Default)]
struct X942SetCtxParams {
    propq: *const OsslParam,
    engine: *const OsslParam,
    digest: *const OsslParam,
    secret: *const OsslParam,
    uinfo: *const OsslParam,
    acvp: *const OsslParam,
    vinfo: *const OsslParam,
    pub_: *const OsslParam,
    priv_: *const OsslParam,
    kbits: *const OsslParam,
    cekalg: *const OsslParam,
}

/// The authority's `OSSL_PARAM_locate_const`, spelled once so the two decoders' field routing
/// reads like the generated switch's `r->field = (OSSL_PARAM *)p` assignments.
///
/// # Safety
/// `p` is NULL or a key-terminated array; `key` is NUL-terminated.
unsafe fn locate_const(p: *const OsslParam, key: *const c_char) -> *const OsslParam {
    // SAFETY: the two pointers are per the caller's contract.
    unsafe { crate::params::OSSL_PARAM_locate_const(p, key) }
}

/// The authority's decoder's **field**-keyed repeat check.
///
/// `repeated_param_site` in [`crate::provider::cipher`] keys its seen-set on the array index, so
/// it detects the same *name* twice. Two of these decoders are not like that: `sskdf.c`'s and
/// `x942kdf.c`'s generated switches route `secret` and `key` (and `ukm` and `partyu-info`) into
/// **one** field each and raise at the second occurrence of *either* spelling. The `field` id is
/// what the authority's `r->secret != NULL` test really compares, so it is what the seen-set is
/// keyed on here.
///
/// # Safety
/// `params` is NULL or a key-terminated array; each `name` is NULL or NUL-terminated.
unsafe fn repeated_param_site_by_field(
    params: *const OsslParam,
    keys: &[(&'static err_sites::ErrSite, *const c_char, u32)],
) -> Option<&'static err_sites::ErrSite> {
    if params.is_null() {
        return None;
    }
    // SAFETY: the caller guarantees a key-terminated array; the walk stops at the NULL key.
    unsafe {
        let mut seen: u32 = 0;
        let mut p = params;
        while !(*p).key.is_null() {
            let k = CStr::from_ptr((*p).key).to_bytes();
            for (site, name, field) in keys {
                if !name.is_null() && CStr::from_ptr(*name).to_bytes() == k {
                    let bit = 1u32 << *field;
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

// =============================================================================================
// `providers/implementations/kdfs/sskdf.c` — SSKDF and X963KDF
// =============================================================================================

/// `struct KDF_SSKDF` — `sskdf.c:59-71`, without its FIPS indicator field.
#[repr(C)]
pub(crate) struct KdfSskdf {
    /// `void *provctx`.
    pub provctx: *mut c_void,
    /// `EVP_MAC_CTX *macctx` — `H(x) = HMAC_hash` or `H(x) = KMAC`.
    pub macctx: *mut EvpMacCtx,
    /// `PROV_DIGEST digest`.
    pub digest: ProvDigest,
    /// `unsigned char *secret` / `size_t secret_len`.
    pub secret: *mut u8,
    pub secret_len: usize,
    /// `unsigned char *info` / `size_t info_len`.
    pub info: *mut u8,
    pub info_len: usize,
    /// `unsigned char *salt` / `size_t salt_len`.
    pub salt: *mut u8,
    pub salt_len: usize,
    /// `size_t out_len` — the optional KMAC parameter.
    pub out_len: usize,
    /// `int is_kmac`.
    pub is_kmac: c_int,
}

/// `OSSL_KDF_PARAM_FIPS_*` are all FIPS-only; the `sskdf_set_ctx_params_decoder` keys this
/// profile's generated switch raises for, each with its (field id, raise site).
///
/// Field ids: 0 `digest`, 1 `engine`, 2 `secret` (shared by `secret` and `key`), 3 `mac`,
/// 4 `size`, 5 `propq`, 6 `salt`. `info` is absent because the generated decoder does **not**
/// treat its repetition as an error — it counts up to `SSKDF_MAX_INFOS` and raises
/// `PROV_R_TOO_MANY_RECORDS` on the sixth.
const SSKDF_SET_DECODER_KEYS: [(&err_sites::ErrSite, *const c_char, u32); 8] = [
    (&err_sites::PROV_SSKDF_666, OSSL_KDF_PARAM_DIGEST, 0),
    (&err_sites::PROV_SSKDF_677, OSSL_ALG_PARAM_ENGINE, 1),
    (&err_sites::PROV_SSKDF_722, OSSL_KDF_PARAM_KEY, 2),
    (&err_sites::PROV_SSKDF_756, OSSL_KDF_PARAM_MAC, 3),
    (&err_sites::PROV_SSKDF_747, OSSL_KDF_PARAM_MAC_SIZE, 4),
    (&err_sites::PROV_SSKDF_769, OSSL_KDF_PARAM_PROPERTIES, 5),
    (&err_sites::PROV_SSKDF_784, OSSL_KDF_PARAM_SALT, 6),
    (&err_sites::PROV_SSKDF_795, OSSL_KDF_PARAM_SECRET, 2),
];

/// The same list for `x963kdf_set_ctx_params_decoder`. Its `secret`/`key` share field 2 exactly
/// as SSKDF's do, and its generated text puts `digest` at `:1020` and `secret` at `:1154`.
const X963KDF_SET_DECODER_KEYS: [(&err_sites::ErrSite, *const c_char, u32); 8] = [
    (&err_sites::PROV_SSKDF_1020, OSSL_KDF_PARAM_DIGEST, 0),
    (&err_sites::PROV_SSKDF_1036, OSSL_ALG_PARAM_ENGINE, 1),
    (&err_sites::PROV_SSKDF_1081, OSSL_KDF_PARAM_KEY, 2),
    (&err_sites::PROV_SSKDF_1115, OSSL_KDF_PARAM_MAC, 3),
    (&err_sites::PROV_SSKDF_1106, OSSL_KDF_PARAM_MAC_SIZE, 4),
    (&err_sites::PROV_SSKDF_1128, OSSL_KDF_PARAM_PROPERTIES, 5),
    (&err_sites::PROV_SSKDF_1143, OSSL_KDF_PARAM_SALT, 6),
    (&err_sites::PROV_SSKDF_1154, OSSL_KDF_PARAM_SECRET, 2),
];

/// `static const OSSL_PARAM sskdf_set_ctx_params_list[]` — `sskdf.c:617-630`, without the FIPS
/// `key-check` entry.
static SSKDF_SETTABLE_CTX_PARAMS: [OsslParam; 9] = [
    param_octet_string(OSSL_KDF_PARAM_SECRET),
    param_octet_string(OSSL_KDF_PARAM_KEY),
    param_octet_string(OSSL_KDF_PARAM_INFO),
    param_utf8_string(OSSL_KDF_PARAM_PROPERTIES),
    param_utf8_string(OSSL_KDF_PARAM_DIGEST),
    param_utf8_string(OSSL_KDF_PARAM_MAC),
    param_octet_string(OSSL_KDF_PARAM_SALT),
    param_size_t(OSSL_KDF_PARAM_MAC_SIZE),
    END,
];

/// The X963 settable list, which carries the same eight entries (its extra FIPS
/// `digest-check` key is compiled out).
static X963KDF_SETTABLE_CTX_PARAMS: [OsslParam; 9] = [
    param_octet_string(OSSL_KDF_PARAM_SECRET),
    param_octet_string(OSSL_KDF_PARAM_KEY),
    param_octet_string(OSSL_KDF_PARAM_INFO),
    param_utf8_string(OSSL_KDF_PARAM_PROPERTIES),
    param_utf8_string(OSSL_KDF_PARAM_DIGEST),
    param_utf8_string(OSSL_KDF_PARAM_MAC),
    param_octet_string(OSSL_KDF_PARAM_SALT),
    param_size_t(OSSL_KDF_PARAM_MAC_SIZE),
    END,
];

/// `static const OSSL_PARAM sskdf_get_ctx_params_list[]` — `sskdf.c`'s generated get list, the
/// `size` entry alone on this profile.
static SSKDF_GETTABLE_CTX_PARAMS: [OsslParam; 2] = [param_size_t(OSSL_KDF_PARAM_SIZE), END];

/// `static int SSKDF_hash_kdm(...)` — `sskdf.c:76-170`.
///
/// `append_ctr` is the whole difference between SSKDF and X9.63: the counter goes *after* `Z`
/// for X9.63 and *before* it otherwise. `out_len` is the digest size and `len` the requested
/// key, so the last block is truncated with `memcpy`.
///
/// # Safety
/// `kdf_md` is a live digest; `z`/`info` readable for their lengths; `derived_key` writable for
/// `derived_key_len` bytes.
#[allow(clippy::too_many_arguments)] // the authority's own signature has eight parameters.
unsafe fn sskdf_hash_kdm(
    kdf_md: *const crate::evp::digest::EvpMd,
    z: *const u8,
    z_len: usize,
    info: *const u8,
    info_len: usize,
    append_ctr: c_int,
    derived_key: *mut u8,
    derived_key_len: usize,
) -> c_int {
    let mut ret = 0;
    let mut c = [0u8; 4];
    let mut mac = [0u8; EVP_MAX_MD_SIZE];
    let mut out = derived_key;
    let mut len = derived_key_len;

    if z_len > SSKDF_MAX_INLEN
        || info_len > SSKDF_MAX_INLEN
        || derived_key_len > SSKDF_MAX_INLEN
        || derived_key_len == 0
    {
        return 0;
    }

    // SAFETY: `kdf_md` is live per the contract.
    let hlen = unsafe { EVP_MD_get_size(kdf_md) };
    if hlen <= 0 {
        return 0;
    }
    let out_len = hlen as usize;

    // SAFETY: `EVP_MD_CTX_create` is `EVP_MD_CTX_new`.
    let ctx = EVP_MD_CTX_new();
    let ctx_init = EVP_MD_CTX_new();
    if ctx.is_null() || ctx_init.is_null() {
        // SAFETY: both are NULL or live contexts.
        unsafe {
            EVP_MD_CTX_free(ctx);
            EVP_MD_CTX_free(ctx_init);
        }
        return 0;
    }

    // SAFETY: `ctx_init` and `kdf_md` are live.
    if unsafe { EVP_DigestInit(ctx_init, kdf_md) } == 0 {
        // SAFETY: both are live contexts.
        unsafe {
            EVP_MD_CTX_free(ctx);
            EVP_MD_CTX_free(ctx_init);
        }
        return 0;
    }

    let mut counter: u64 = 1;
    loop {
        c[0] = ((counter >> 24) & 0xff) as u8;
        c[1] = ((counter >> 16) & 0xff) as u8;
        c[2] = ((counter >> 8) & 0xff) as u8;
        c[3] = (counter & 0xff) as u8;

        // SAFETY: the two contexts are live and the buffers are readable for their lengths.
        let ok = unsafe {
            EVP_MD_CTX_copy_ex(ctx, ctx_init) != 0
                && (append_ctr != 0 || EVP_DigestUpdate(ctx, c.as_ptr().cast(), c.len()) != 0)
                && EVP_DigestUpdate(ctx, z.cast(), z_len) != 0
                && (append_ctr == 0 || EVP_DigestUpdate(ctx, c.as_ptr().cast(), c.len()) != 0)
                && EVP_DigestUpdate(ctx, info.cast(), info_len) != 0
        };
        if !ok {
            break;
        }
        if len >= out_len {
            // SAFETY: `out` is writable for `out_len` bytes.
            if unsafe { EVP_DigestFinal_ex(ctx, out, ptr::null_mut()) } == 0 {
                break;
            }
            // SAFETY: the pointer arithmetic stays inside the caller's buffer.
            out = unsafe { out.add(out_len) };
            len -= out_len;
            if len == 0 {
                ret = 1;
                break;
            }
        } else {
            // SAFETY: `mac` is `EVP_MAX_MD_SIZE` bytes.
            if unsafe { EVP_DigestFinal_ex(ctx, mac.as_mut_ptr(), ptr::null_mut()) } == 0 {
                break;
            }
            // SAFETY: `out` is writable for `len` bytes and `mac` readable for the same.
            unsafe { ptr::copy_nonoverlapping(mac.as_ptr(), out, len) };
            ret = 1;
            break;
        }
        counter += 1;
    }

    // SAFETY: both are live contexts; `mac` is a live local.
    unsafe {
        EVP_MD_CTX_free(ctx);
        EVP_MD_CTX_free(ctx_init);
        cleanse(mac.as_mut_ptr(), mac.len());
    }
    ret
}

/// `static int kmac_init(EVP_MAC_CTX *ctx, const unsigned char *custom, size_t custom_len,
/// size_t kmac_out_len, size_t derived_key_len, unsigned char **out)` — `sskdf.c:172-217`.
///
/// A `custom == NULL` means "not KMAC" and answers 1 without touching the context. The output
/// buffer is allocated only when KMAC's requested size exceeds a digest block.
///
/// # Safety
/// `ctx` live; `custom` NULL or readable for `custom_len`; `out` writable.
unsafe fn kmac_init(
    ctx: *mut EvpMacCtx,
    custom: *const u8,
    custom_len: usize,
    mut kmac_out_len: usize,
    derived_key_len: usize,
    out: *mut *mut u8,
) -> c_int {
    if custom.is_null() {
        return 1;
    }

    let mut params: [OsslParam; 2] = [END; 2];
    // SAFETY: `ctx` is live and the descriptors borrow live data.
    unsafe {
        params[0] = OSSL_PARAM_construct_octet_string(
            OSSL_MAC_PARAM_CUSTOM,
            custom.cast_mut().cast(),
            custom_len,
        );
        params[1] = OSSL_PARAM_construct_end();

        if EVP_MAC_CTX_set_params(ctx, params.as_ptr()) == 0 {
            return 0;
        }
    }

    if kmac_out_len == 0 {
        kmac_out_len = derived_key_len;
    } else if !(kmac_out_len == derived_key_len
        || kmac_out_len == 20
        || kmac_out_len == 28
        || kmac_out_len == 32
        || kmac_out_len == 48
        || kmac_out_len == 64)
    {
        return 0;
    }

    // SAFETY: the descriptor borrows the live local `kmac_out_len`.
    unsafe {
        params[0] = OSSL_PARAM_construct_size_t(OSSL_MAC_PARAM_SIZE, &mut kmac_out_len);

        if EVP_MAC_CTX_set_params(ctx, params.as_ptr()) <= 0 {
            return 0;
        }

        if kmac_out_len > EVP_MAX_MD_SIZE {
            *out = CRYPTO_zalloc(kmac_out_len, FILE_SSKDF, LINE).cast::<u8>();
            if (*out).is_null() {
                return 0;
            }
        }
    }
    1
}

/// `static int SSKDF_mac_kdm(...)` — `sskdf.c:225-297`.
///
/// The counter is prepended to `Z` here (never appended), and each iteration duplicates the
/// initialised context rather than copying into one, so the MAC's own state is re-derived.
///
/// # Safety
/// `ctx_init` live; the four buffers readable/writable for their lengths.
#[allow(clippy::too_many_arguments)] // the authority's own signature has ten parameters.
unsafe fn sskdf_mac_kdm(
    ctx_init: *mut EvpMacCtx,
    kmac_custom: *const u8,
    kmac_custom_len: usize,
    kmac_out_len: usize,
    salt: *const u8,
    salt_len: usize,
    z: *const u8,
    z_len: usize,
    info: *const u8,
    info_len: usize,
    derived_key: *mut u8,
    derived_key_len: usize,
) -> c_int {
    let mut ret = 0;
    let mut c = [0u8; 4];
    let mut mac_buf = [0u8; EVP_MAX_MD_SIZE];
    let mut out = derived_key;
    let mut mac: *mut u8 = mac_buf.as_mut_ptr();
    let mut kmac_buffer: *mut u8 = ptr::null_mut();

    if z_len > SSKDF_MAX_INLEN
        || info_len > SSKDF_MAX_INLEN
        || derived_key_len > SSKDF_MAX_INLEN
        || derived_key_len == 0
    {
        return 0;
    }

    // SAFETY: `ctx_init` is live; the out-pointer is this frame's local.
    if unsafe {
        kmac_init(
            ctx_init,
            kmac_custom,
            kmac_custom_len,
            kmac_out_len,
            derived_key_len,
            &mut kmac_buffer,
        )
    } == 0
    {
        // SAFETY: the locals are this frame's.
        unsafe {
            if !kmac_buffer.is_null() {
                CRYPTO_clear_free(kmac_buffer.cast(), derived_key_len, FILE_SSKDF, LINE);
            }
        }
        return 0;
    }
    if !kmac_buffer.is_null() {
        mac = kmac_buffer;
    }

    // SAFETY: `ctx_init` is live and `salt` is readable for `salt_len`.
    if unsafe { EVP_MAC_init(ctx_init, salt, salt_len, ptr::null()) } == 0 {
        // SAFETY: the two locals are this frame's.
        return unsafe {
            sskdf_mac_kdm_cleanup(ret, kmac_buffer, kmac_out_len, mac_buf.as_mut_ptr())
        };
    }

    // SAFETY: `ctx_init` is live.
    let out_len = unsafe { EVP_MAC_CTX_get_mac_size(ctx_init) };
    let mut len = derived_key_len;
    if out_len == 0 || (mac == mac_buf.as_mut_ptr() && out_len > mac_buf.len()) {
        // SAFETY: the two locals are this frame's.
        return unsafe {
            sskdf_mac_kdm_cleanup(ret, kmac_buffer, kmac_out_len, mac_buf.as_mut_ptr())
        };
    }

    let mut counter: u64 = 1;
    loop {
        c[0] = ((counter >> 24) & 0xff) as u8;
        c[1] = ((counter >> 16) & 0xff) as u8;
        c[2] = ((counter >> 8) & 0xff) as u8;
        c[3] = (counter & 0xff) as u8;

        // SAFETY: `ctx_init` is live; `ctx` is a fresh duplicate owned by this arm.
        let ctx = unsafe { EVP_MAC_CTX_dup(ctx_init) };
        // SAFETY: `ctx` is NULL or a live duplicate and each buffer is per the contract.
        let ok = unsafe {
            !ctx.is_null()
                && EVP_MAC_update(ctx, c.as_ptr(), c.len()) != 0
                && EVP_MAC_update(ctx, z, z_len) != 0
                && EVP_MAC_update(ctx, info, info_len) != 0
        };
        if !ok {
            // SAFETY: `ctx` is NULL or a live duplicate.
            unsafe { EVP_MAC_CTX_free(ctx) };
            break;
        }
        if len >= out_len {
            // SAFETY: `ctx` is live and `out` is writable for `len` bytes.
            if unsafe { EVP_MAC_final(ctx, out, ptr::null_mut(), len) } == 0 {
                // SAFETY: `ctx` is a live duplicate.
                unsafe { EVP_MAC_CTX_free(ctx) };
                break;
            }
            // SAFETY: the pointer arithmetic stays inside the caller's buffer.
            out = unsafe { out.add(out_len) };
            len -= out_len;
            if len == 0 {
                ret = 1;
                // SAFETY: `ctx` is a live duplicate.
                unsafe { EVP_MAC_CTX_free(ctx) };
                break;
            }
        } else {
            // SAFETY: `ctx` is live and `mac` is writable for `out_len` bytes.
            if unsafe { EVP_MAC_final(ctx, mac, ptr::null_mut(), out_len) } == 0 {
                // SAFETY: `ctx` is a live duplicate.
                unsafe { EVP_MAC_CTX_free(ctx) };
                break;
            }
            // SAFETY: `out` is writable for `len` bytes and `mac` readable for the same.
            unsafe { ptr::copy_nonoverlapping(mac, out, len) };
            ret = 1;
            // SAFETY: `ctx` is a live duplicate.
            unsafe { EVP_MAC_CTX_free(ctx) };
            break;
        }
        // SAFETY: `ctx` is a live duplicate and is not reused.
        unsafe { EVP_MAC_CTX_free(ctx) };
        counter += 1;
    }

    // SAFETY: the two locals are this frame's.
    unsafe { sskdf_mac_kdm_cleanup(ret, kmac_buffer, kmac_out_len, mac_buf.as_mut_ptr()) }
}

/// The `end:` label of `sskdf.c`'s `SSKDF_mac_kdm`: release the KMAC buffer if one was taken,
/// otherwise cleanse the stack buffer, and answer `ret`.
///
/// # Safety
/// `kmac_buffer` NULL or an allocation this crate owns; `mac_buf` a live 64-byte buffer.
unsafe fn sskdf_mac_kdm_cleanup(
    ret: c_int,
    kmac_buffer: *mut u8,
    kmac_out_len: usize,
    mac_buf: *mut u8,
) -> c_int {
    // SAFETY: the two pointers are per the contract.
    unsafe {
        if !kmac_buffer.is_null() {
            CRYPTO_clear_free(kmac_buffer.cast(), kmac_out_len, FILE_SSKDF, LINE);
        } else {
            cleanse(mac_buf, EVP_MAX_MD_SIZE);
        }
    }
    ret
}

/// `static void *sskdf_new(void *provctx)` — `sskdf.c:299-311`.
///
/// # Safety
/// The dispatch contract.
unsafe extern "C" fn sskdf_new(provctx: *mut c_void) -> *mut c_void {
    // SAFETY: the caller's contract.
    unsafe {
        if is_running() == 0 {
            return ptr::null_mut();
        }
        let ctx =
            CRYPTO_zalloc(core::mem::size_of::<KdfSskdf>(), FILE_SSKDF, LINE).cast::<KdfSskdf>();
        if !ctx.is_null() {
            (*ctx).provctx = provctx;
        }
        ctx.cast()
    }
}

/// `static void sskdf_reset(void *vctx)` — `sskdf.c:313-325`.
///
/// The `provctx` is saved across the `memset`, because the whole struct is cleared.
///
/// # Safety
/// `vctx` is a context `sskdf_new` allocated.
unsafe fn sskdf_reset(vctx: *mut c_void) {
    // SAFETY: `vctx` is a live context per the contract.
    unsafe {
        let ctx = vctx.cast::<KdfSskdf>();
        let provctx = (*ctx).provctx;

        EVP_MAC_CTX_free((*ctx).macctx);
        ossl_prov_digest_reset(ptr::addr_of_mut!((*ctx).digest));
        CRYPTO_clear_free((*ctx).secret.cast(), (*ctx).secret_len, FILE_SSKDF, LINE);
        CRYPTO_clear_free((*ctx).info.cast(), (*ctx).info_len, FILE_SSKDF, LINE);
        CRYPTO_clear_free((*ctx).salt.cast(), (*ctx).salt_len, FILE_SSKDF, LINE);
        ptr::write_bytes(vctx.cast::<u8>(), 0, core::mem::size_of::<KdfSskdf>());
        (*ctx).provctx = provctx;
    }
}

/// `static void sskdf_free(void *vctx)` — `sskdf.c:327-335`.
///
/// # Safety
/// The dispatch contract.
unsafe extern "C" fn sskdf_free(vctx: *mut c_void) {
    // SAFETY: `vctx` is NULL or a live context.
    unsafe {
        if !vctx.is_null() {
            sskdf_reset(vctx);
            CRYPTO_free(vctx, FILE_SSKDF, LINE);
        }
    }
}

/// `static void *sskdf_dup(void *vctx)` — `sskdf.c:337-366`.
///
/// # Safety
/// The dispatch contract.
unsafe extern "C" fn sskdf_dup(vctx: *mut c_void) -> *mut c_void {
    // SAFETY: the caller's contract.
    unsafe {
        let src = vctx.cast::<KdfSskdf>();
        let dest = sskdf_new((*src).provctx).cast::<KdfSskdf>();
        if dest.is_null() {
            return ptr::null_mut();
        }
        if !(*src).macctx.is_null() {
            (*dest).macctx = EVP_MAC_CTX_dup((*src).macctx);
            if (*dest).macctx.is_null() {
                sskdf_free(dest.cast());
                return ptr::null_mut();
            }
        }
        if ossl_prov_memdup(
            (*src).info.cast(),
            (*src).info_len,
            ptr::addr_of_mut!((*dest).info),
            ptr::addr_of_mut!((*dest).info_len),
        ) == 0
            || ossl_prov_memdup(
                (*src).salt.cast(),
                (*src).salt_len,
                ptr::addr_of_mut!((*dest).salt),
                ptr::addr_of_mut!((*dest).salt_len),
            ) == 0
            || ossl_prov_memdup(
                (*src).secret.cast(),
                (*src).secret_len,
                ptr::addr_of_mut!((*dest).secret),
                ptr::addr_of_mut!((*dest).secret_len),
            ) == 0
            || ossl_prov_digest_copy(
                ptr::addr_of_mut!((*dest).digest),
                ptr::addr_of!((*src).digest),
            ) == 0
        {
            sskdf_free(dest.cast());
            return ptr::null_mut();
        }
        (*dest).out_len = (*src).out_len;
        (*dest).is_kmac = (*src).is_kmac;
        dest.cast()
    }
}

/// `static size_t sskdf_size(KDF_SSKDF *ctx)` — `sskdf.c:368-383`.
///
/// # Safety
/// `ctx` live.
unsafe fn sskdf_size(ctx: *mut KdfSskdf) -> usize {
    // SAFETY: `ctx` is live per the contract.
    unsafe {
        if (*ctx).is_kmac != 0 {
            return usize::MAX;
        }
        let md = ossl_prov_digest_md(ptr::addr_of!((*ctx).digest));
        if md.is_null() {
            raise_site(&err_sites::PROV_SSKDF_376);
            return 0;
        }
        let len = EVP_MD_get_size(md);
        if len <= 0 {
            0
        } else {
            len as usize
        }
    }
}

/// `static int sskdf_derive(void *vctx, unsigned char *key, size_t keylen,
/// const OSSL_PARAM params[])` — `sskdf.c:403-469`.
///
/// # Safety
/// The dispatch contract.
unsafe extern "C" fn sskdf_derive(
    vctx: *mut c_void,
    key: *mut u8,
    keylen: usize,
    params: *const OsslParam,
) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        let ctx = vctx.cast::<KdfSskdf>();
        if is_running() == 0 || sskdf_set_ctx_params(vctx, params) == 0 {
            return 0;
        }
        if (*ctx).secret.is_null() {
            return fail_at(&err_sites::PROV_SSKDF_410);
        }

        let md = ossl_prov_digest_md(ptr::addr_of!((*ctx).digest));

        if !(*ctx).macctx.is_null() {
            // H(x) = KMAC or H(x) = HMAC.
            let custom: *const u8;
            let mut custom_len = 0usize;
            let default_salt_len: usize;
            let mac = EVP_MAC_CTX_get0_mac((*ctx).macctx);

            if EVP_MAC_is_a(mac, OSSL_MAC_NAME_HMAC) != 0 {
                if md.is_null() {
                    return fail_at(&err_sites::PROV_SSKDF_427);
                }
                let n = EVP_MD_get_size(md);
                if n <= 0 {
                    return 0;
                }
                default_salt_len = n as usize;
                custom = ptr::null();
            } else if (*ctx).is_kmac != 0 {
                custom = KMAC_CUSTOM_STR.as_ptr();
                custom_len = KMAC_CUSTOM_STR.len();
                if EVP_MAC_is_a(mac, OSSL_MAC_NAME_KMAC128) != 0 {
                    default_salt_len = SSKDF_KMAC128_DEFAULT_SALT_SIZE;
                } else {
                    default_salt_len = SSKDF_KMAC256_DEFAULT_SALT_SIZE;
                }
            } else {
                return fail_at(&err_sites::PROV_SSKDF_442);
            }
            // If no salt is set then use a default salt of zeros.
            if (*ctx).salt.is_null() || (*ctx).salt_len == 0 {
                (*ctx).salt = CRYPTO_zalloc(default_salt_len, FILE_SSKDF, LINE).cast::<u8>();
                if (*ctx).salt.is_null() {
                    return 0;
                }
                (*ctx).salt_len = default_salt_len;
            }
            return sskdf_mac_kdm(
                (*ctx).macctx,
                custom,
                custom_len,
                (*ctx).out_len,
                (*ctx).salt,
                (*ctx).salt_len,
                (*ctx).secret,
                (*ctx).secret_len,
                (*ctx).info,
                (*ctx).info_len,
                key,
                keylen,
            );
        }

        // H(x) = hash.
        if md.is_null() {
            return fail_at(&err_sites::PROV_SSKDF_461);
        }
        sskdf_hash_kdm(
            md,
            (*ctx).secret,
            (*ctx).secret_len,
            (*ctx).info,
            (*ctx).info_len,
            0,
            key,
            keylen,
        )
    }
}

/// `static int x963kdf_derive(void *vctx, unsigned char *key, size_t keylen,
/// const OSSL_PARAM params[])` — `sskdf.c:510-538`.
///
/// # Safety
/// The dispatch contract.
unsafe extern "C" fn x963kdf_derive(
    vctx: *mut c_void,
    key: *mut u8,
    keylen: usize,
    params: *const OsslParam,
) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        let ctx = vctx.cast::<KdfSskdf>();
        if is_running() == 0 || x963kdf_set_ctx_params(vctx, params) == 0 {
            return 0;
        }
        if (*ctx).secret.is_null() {
            return fail_at(&err_sites::PROV_SSKDF_520);
        }
        if !(*ctx).macctx.is_null() {
            // X963KDF has no MAC form.
            return fail_at(&err_sites::PROV_SSKDF_525);
        }
        let md = ossl_prov_digest_md(ptr::addr_of!((*ctx).digest));
        if md.is_null() {
            return fail_at(&err_sites::PROV_SSKDF_532);
        }
        sskdf_hash_kdm(
            md,
            (*ctx).secret,
            (*ctx).secret_len,
            (*ctx).info,
            (*ctx).info_len,
            1,
            key,
            keylen,
        )
    }
}

/// `static int sskdf_common_set_ctx_params(KDF_SSKDF *ctx, struct ... *p,
/// const OSSL_PARAM *params)` — `sskdf.c:556-610`, without its FIPS arm.
///
/// The `params` argument is the decoder's, and this body does not read it; it is kept in the
/// signature because the authority's has it and both call sites pass it.
///
/// # Safety
/// `ctx` live; `p` this frame's; `params` the caller's array.
unsafe fn sskdf_common_set_ctx_params(
    ctx: *mut KdfSskdf,
    p: *const SskdfSetCtxParams,
    _params: *const OsslParam,
) -> c_int {
    // SAFETY: `ctx` is live per the contract.
    let libctx = unsafe { prov_libctx_of((*ctx).provctx) };
    let mut sz: usize = 0;

    // SAFETY: the descriptors are NULL or live and the out-pointer is this frame's own.
    unsafe {
        if ossl_prov_macctx_load(
            ptr::addr_of_mut!((*ctx).macctx),
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
        if !(*ctx).macctx.is_null() {
            let mac = EVP_MAC_CTX_get0_mac((*ctx).macctx);
            if EVP_MAC_is_a(mac, OSSL_MAC_NAME_KMAC128) != 0
                || EVP_MAC_is_a(mac, OSSL_MAC_NAME_KMAC256) != 0
            {
                (*ctx).is_kmac = 1;
            }
        }

        if !(*p).digest.is_null() {
            if ossl_prov_digest_load(
                ptr::addr_of_mut!((*ctx).digest),
                (*p).digest,
                (*p).propq,
                (*p).engine,
                libctx,
            ) == 0
            {
                return 0;
            }
            let md = ossl_prov_digest_md(ptr::addr_of!((*ctx).digest));
            if EVP_MD_xof(md) != 0 {
                raise_site(&err_sites::PROV_SSKDF_584);
                return 0;
            }
        }

        let r = ossl_param_get1_octet_string_from_param(
            (*p).secret,
            ptr::addr_of_mut!((*ctx).secret),
            ptr::addr_of_mut!((*ctx).secret_len),
        );
        if r == 0 {
            return 0;
        }

        let infos: [*const OsslParam; SSKDF_MAX_INFOS] = (*p).info;
        if ossl_param_get1_concat_octet_string(
            (*p).num_info as usize,
            infos.as_ptr(),
            ptr::addr_of_mut!((*ctx).info),
            ptr::addr_of_mut!((*ctx).info_len),
        ) == 0
        {
            return 0;
        }

        if ossl_param_get1_octet_string_from_param(
            (*p).salt,
            ptr::addr_of_mut!((*ctx).salt),
            ptr::addr_of_mut!((*ctx).salt_len),
        ) == 0
        {
            return 0;
        }

        if !(*p).size.is_null() {
            if OSSL_PARAM_get_size_t((*p).size, &mut sz) == 0 || sz == 0 {
                return 0;
            }
            (*ctx).out_len = sz;
        }
    }
    // `params` is read by the decoder only; the authority passes it on unused.
    1
}

/// `static int sskdf_set_ctx_params(void *vctx, const OSSL_PARAM params[])` —
/// `sskdf.c:631-652`, without its FIPS arm.
///
/// # Safety
/// The dispatch contract.
unsafe extern "C" fn sskdf_set_ctx_params(vctx: *mut c_void, params: *const OsslParam) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        if vctx.is_null() {
            return 0;
        }
        let ctx = vctx.cast::<KdfSskdf>();
        if let Some(site) = repeated_param_site_by_field(params, &SSKDF_SET_DECODER_KEYS) {
            return fail_at(site);
        }
        let mut p = SskdfSetCtxParams::default();
        if sskdf_set_ctx_params_decode(params, &mut p) == 0 {
            return 0;
        }
        sskdf_common_set_ctx_params(ctx, &p, params)
    }
}

/// The generated `sskdf_set_ctx_params_decoder`'s non-FIPS behaviour: locate each key with
/// `OSSL_PARAM_locate_const`, count the `info` records against `SSKDF_MAX_INFOS`.
///
/// The `info` count is the one rule `repeated_param_site_by_field` cannot express: five `info`
/// entries are legal and a sixth raises `PROV_R_TOO_MANY_RECORDS` at `sskdf.c:688`, the site the
/// generated decoder's own counter test carries.
///
/// # Safety
/// `params` NULL or a key-terminated array; `r` writable.
unsafe fn sskdf_set_ctx_params_decode(
    params: *const OsslParam,
    r: &mut SskdfSetCtxParams,
) -> c_int {
    // SAFETY: the walk stops at the NULL key; every located descriptor is live.
    unsafe {
        r.digest = crate::params::OSSL_PARAM_locate_const(params, OSSL_KDF_PARAM_DIGEST);
        r.engine = crate::params::OSSL_PARAM_locate_const(params, OSSL_ALG_PARAM_ENGINE);
        r.mac = crate::params::OSSL_PARAM_locate_const(params, OSSL_KDF_PARAM_MAC);
        r.size = crate::params::OSSL_PARAM_locate_const(params, OSSL_KDF_PARAM_MAC_SIZE);
        r.propq = crate::params::OSSL_PARAM_locate_const(params, OSSL_ALG_PARAM_PROPERTIES);
        r.salt = crate::params::OSSL_PARAM_locate_const(params, OSSL_KDF_PARAM_SALT);
        r.secret = crate::params::OSSL_PARAM_locate_const(params, OSSL_KDF_PARAM_SECRET);
        if r.secret.is_null() {
            r.secret = crate::params::OSSL_PARAM_locate_const(params, OSSL_KDF_PARAM_KEY);
        }

        if !params.is_null() {
            let mut p = params;
            while !(*p).key.is_null() {
                if CStr::from_ptr((*p).key).to_bytes() == OSSL_KDF_PARAM_INFO_CSTR.to_bytes() {
                    if r.num_info as usize >= SSKDF_MAX_INFOS {
                        raise_site(&err_sites::PROV_SSKDF_688);
                        return 0;
                    }
                    r.info[r.num_info as usize] = p;
                    r.num_info += 1;
                }
                p = p.add(1);
            }
        }
    }
    1
}

/// `static int sskdf_common_get_ctx_params(void *vctx, OSSL_PARAM params[])` —
/// `sskdf.c:667-684`, without its FIPS arm.
///
/// # Safety
/// The dispatch contract.
unsafe extern "C" fn sskdf_common_get_ctx_params(
    vctx: *mut c_void,
    params: *mut OsslParam,
) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        if vctx.is_null() {
            return 0;
        }
        // The get decoder's one key is `size`; a repeat raises at its own site.
        if let Some(site) = repeated_param_site_by_field(params, &SSKDF_GET_DECODER_KEYS_BY_FIELD) {
            return fail_at(site);
        }
        let ctx = vctx.cast::<KdfSskdf>();

        let p = crate::params::OSSL_PARAM_locate_const(params, OSSL_KDF_PARAM_SIZE);
        if !p.is_null() && OSSL_PARAM_set_size_t(p.cast_mut(), sskdf_size(ctx)) == 0 {
            return 0;
        }
    }
    1
}

/// The two keys `sskdf_get_ctx_params_decoder` locates: `size` only, the FIPS indicator being
/// compiled out.
const SSKDF_GET_DECODER_KEYS_BY_FIELD: [(&err_sites::ErrSite, *const c_char, u32); 1] =
    [(&err_sites::PROV_SSKDF_888, OSSL_KDF_PARAM_SIZE, 0)];

/// `static int x963kdf_set_ctx_params(void *vctx, const OSSL_PARAM params[])` —
/// `sskdf.c:709-739`, without its FIPS arm.
///
/// # Safety
/// The dispatch contract.
unsafe extern "C" fn x963kdf_set_ctx_params(vctx: *mut c_void, params: *const OsslParam) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        if vctx.is_null() {
            return 0;
        }
        let ctx = vctx.cast::<KdfSskdf>();
        if let Some(site) = repeated_param_site_by_field(params, &X963KDF_SET_DECODER_KEYS) {
            return fail_at(site);
        }
        let mut p = SskdfSetCtxParams::default();
        if sskdf_set_ctx_params_decode(params, &mut p) == 0 {
            return 0;
        }
        sskdf_common_set_ctx_params(ctx, &p, params)
    }
}

/// `static const OSSL_PARAM *sskdf_settable_ctx_params(void *ctx, void *provctx)` —
/// `sskdf.c:654-658`.
///
/// # Safety
/// The dispatch contract.
unsafe extern "C" fn sskdf_settable_ctx_params(
    _ctx: *mut c_void,
    _provctx: *mut c_void,
) -> *const OsslParam {
    SSKDF_SETTABLE_CTX_PARAMS.as_ptr()
}

/// `static const OSSL_PARAM *sskdf_common_gettable_ctx_params(void *ctx, void *provctx)` —
/// `sskdf.c:686-689`.
///
/// # Safety
/// The dispatch contract.
unsafe extern "C" fn sskdf_common_gettable_ctx_params(
    _ctx: *mut c_void,
    _provctx: *mut c_void,
) -> *const OsslParam {
    SSKDF_GETTABLE_CTX_PARAMS.as_ptr()
}

/// `static const OSSL_PARAM *x963kdf_settable_ctx_params(void *ctx, void *provctx)` —
/// `sskdf.c:741-745`.
///
/// # Safety
/// The dispatch contract.
unsafe extern "C" fn x963kdf_settable_ctx_params(
    _ctx: *mut c_void,
    _provctx: *mut c_void,
) -> *const OsslParam {
    X963KDF_SETTABLE_CTX_PARAMS.as_ptr()
}

/// `const OSSL_DISPATCH ossl_kdf_sskdf_functions[]` — `sskdf.c:747-760`, ten entries (the FIPS
/// build has the same ten).
pub(crate) static SSKDF_FUNCTIONS: [OsslDispatch; 10] = [
    OsslDispatch {
        function_id: OSSL_FUNC_KDF_NEWCTX,
        function: sskdf_new as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KDF_DUPCTX,
        function: sskdf_dup as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KDF_FREECTX,
        function: sskdf_free as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KDF_RESET,
        function: sskdf_reset as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KDF_DERIVE,
        function: sskdf_derive as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KDF_SETTABLE_CTX_PARAMS,
        function: sskdf_settable_ctx_params as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KDF_SET_CTX_PARAMS,
        function: sskdf_set_ctx_params as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KDF_GETTABLE_CTX_PARAMS,
        function: sskdf_common_gettable_ctx_params as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KDF_GET_CTX_PARAMS,
        function: sskdf_common_get_ctx_params as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_DISPATCH_END,
        function: ptr::null_mut(),
    },
];

/// `const OSSL_DISPATCH ossl_kdf_x963_kdf_functions[]` — `sskdf.c:762-775`. The derive callback
/// is the only entry that differs from the SSKDF table.
pub(crate) static X963KDF_FUNCTIONS: [OsslDispatch; 10] = [
    OsslDispatch {
        function_id: OSSL_FUNC_KDF_NEWCTX,
        function: sskdf_new as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KDF_DUPCTX,
        function: sskdf_dup as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KDF_FREECTX,
        function: sskdf_free as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KDF_RESET,
        function: sskdf_reset as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KDF_DERIVE,
        function: x963kdf_derive as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KDF_SETTABLE_CTX_PARAMS,
        function: x963kdf_settable_ctx_params as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KDF_SET_CTX_PARAMS,
        function: x963kdf_set_ctx_params as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KDF_GETTABLE_CTX_PARAMS,
        function: sskdf_common_gettable_ctx_params as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KDF_GET_CTX_PARAMS,
        function: sskdf_common_get_ctx_params as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_DISPATCH_END,
        function: ptr::null_mut(),
    },
];

/// `"info"`, as a `&CStr` for the decoder's count test.
const OSSL_KDF_PARAM_INFO_CSTR: &CStr = c"info";

// =============================================================================================
// `providers/implementations/kdfs/x942kdf.c` — X942KDF-ASN1
// =============================================================================================

/// `struct KDF_X942` — `x942kdf.c:46-60`, without its FIPS indicator field.
#[repr(C)]
pub(crate) struct KdfX942 {
    /// `void *provctx`.
    pub provctx: *mut c_void,
    /// `PROV_DIGEST digest`.
    pub digest: ProvDigest,
    /// `unsigned char *secret` / `size_t secret_len`.
    pub secret: *mut u8,
    pub secret_len: usize,
    /// `unsigned char *acvpinfo` / `size_t acvpinfo_len`.
    pub acvpinfo: *mut u8,
    pub acvpinfo_len: usize,
    /// `unsigned char *partyuinfo, *partyvinfo, *supp_pubinfo, *supp_privinfo`.
    pub partyuinfo: *mut u8,
    pub partyvinfo: *mut u8,
    pub supp_pubinfo: *mut u8,
    pub supp_privinfo: *mut u8,
    /// The four lengths, in the authority's declared order.
    pub partyuinfo_len: usize,
    pub partyvinfo_len: usize,
    pub supp_pubinfo_len: usize,
    pub supp_privinfo_len: usize,
    /// `size_t dkm_len`.
    pub dkm_len: usize,
    /// `const unsigned char *cek_oid` / `size_t cek_oid_len`.
    pub cek_oid: *const u8,
    pub cek_oid_len: usize,
    /// `int use_keybits`.
    pub use_keybits: c_int,
}

/// `ossl_der_oid_id_aes128_wrap` — `providers/common/der/der_wrap_gen.c`, eleven bytes:
/// `06 09 60 86 48 01 65 03 04 01 05`.
const OID_AES128_WRAP: [u8; 11] = [
    0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x01, 0x05,
];
/// `ossl_der_oid_id_aes192_wrap` — the same with `0x19` for the last arc.
const OID_AES192_WRAP: [u8; 11] = [
    0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x01, 0x19,
];
/// `ossl_der_oid_id_aes256_wrap` — the same with `0x2D`.
const OID_AES256_WRAP: [u8; 11] = [
    0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x01, 0x2D,
];
/// `ossl_der_oid_id_alg_CMS3DESwrap` — thirteen bytes, `06 0B 2A 86 48 86 F7 0D 01 09 10 03 06`.
const OID_CMS3DES_WRAP: [u8; 13] = [
    0x06, 0x0B, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x10, 0x03, 0x06,
];

/// `static const struct { ... } kek_algs[]` — `x942kdf.c:68-84`, with `DES3-WRAP` present
/// because `FIPS_MODULE` is undefined.
static KEK_ALGS: [(&CStr, &[u8], usize); 4] = [
    (c"AES-128-WRAP", &OID_AES128_WRAP, 16),
    (c"AES-192-WRAP", &OID_AES192_WRAP, 24),
    (c"AES-256-WRAP", &OID_AES256_WRAP, 32),
    // `#ifndef FIPS_MODULE`.
    (c"DES3-WRAP", &OID_CMS3DES_WRAP, 24),
];

/// `x942kdf_set_ctx_params_decoder`'s keys, each with its (field id, raise site).
///
/// Field ids: 0 `propq`, 1 `engine`, 2 `digest`, 3 `secret` (`secret` and `key`), 4 `uinfo`
/// (`ukm` and `partyu-info`), 5 `acvp`, 6 `vinfo`, 7 `pub`, 8 `priv`, 9 `kbits`, 10 `cekalg`.
const X942_SET_DECODER_KEYS: [(&err_sites::ErrSite, *const c_char, u32); 11] = [
    (&err_sites::PROV_X942KDF_715, OSSL_KDF_PARAM_PROPERTIES, 0),
    (&err_sites::PROV_X942KDF_622, OSSL_ALG_PARAM_ENGINE, 1),
    (&err_sites::PROV_X942KDF_611, OSSL_KDF_PARAM_DIGEST, 2),
    (&err_sites::PROV_X942KDF_656, OSSL_KDF_PARAM_KEY, 3),
    (&err_sites::PROV_X942KDF_731, OSSL_KDF_PARAM_SECRET, 3),
    (
        &err_sites::PROV_X942KDF_689,
        OSSL_KDF_PARAM_X942_PARTYUINFO,
        4,
    ),
    (&err_sites::PROV_X942KDF_794, OSSL_KDF_PARAM_UKM, 4),
    (
        &err_sites::PROV_X942KDF_589,
        OSSL_KDF_PARAM_X942_ACVPINFO,
        5,
    ),
    (
        &err_sites::PROV_X942KDF_700,
        OSSL_KDF_PARAM_X942_PARTYVINFO,
        6,
    ),
    (
        &err_sites::PROV_X942KDF_773,
        OSSL_KDF_PARAM_X942_SUPP_PUBINFO,
        7,
    ),
    (
        &err_sites::PROV_X942KDF_762,
        OSSL_KDF_PARAM_X942_SUPP_PRIVINFO,
        8,
    ),
];

/// The two keys the field-keyed check above does not cover, because the generated decoder
/// gives each its own field: `use-keybits` and `cekalg`. They are checked in the same walk by
/// [`X942_SET_DECODER_KEYS_TAIL`].
const X942_SET_DECODER_KEYS_TAIL: [(&err_sites::ErrSite, *const c_char, u32); 2] = [
    (
        &err_sites::PROV_X942KDF_805,
        OSSL_KDF_PARAM_X942_USE_KEYBITS,
        9,
    ),
    (&err_sites::PROV_X942KDF_600, OSSL_KDF_PARAM_CEK_ALG, 10),
];

/// `static const OSSL_PARAM sshkdf_set_ctx_params_list[]` — `x942kdf.c`'s generated set list
/// (the generated identifier keeps the SHHKDF typo), without the FIPS `key-check` entry.
static X942_SETTABLE_CTX_PARAMS: [OsslParam; 13] = [
    param_utf8_string(OSSL_KDF_PARAM_PROPERTIES),
    param_utf8_string(OSSL_KDF_PARAM_DIGEST),
    param_octet_string(OSSL_KDF_PARAM_SECRET),
    param_octet_string(OSSL_KDF_PARAM_KEY),
    param_octet_string(OSSL_KDF_PARAM_UKM),
    param_octet_string(OSSL_KDF_PARAM_X942_ACVPINFO),
    param_octet_string(OSSL_KDF_PARAM_X942_PARTYUINFO),
    param_octet_string(OSSL_KDF_PARAM_X942_PARTYVINFO),
    param_octet_string(OSSL_KDF_PARAM_X942_SUPP_PUBINFO),
    param_octet_string(OSSL_KDF_PARAM_X942_SUPP_PRIVINFO),
    param_int(OSSL_KDF_PARAM_X942_USE_KEYBITS),
    param_utf8_string(OSSL_KDF_PARAM_CEK_ALG),
    END,
];

/// The one key `x942kdf`'s generated get decoder locates: `size`.
const X942_GET_DECODER_KEYS: [(&err_sites::ErrSite, *const c_char, u32); 1] =
    [(&err_sites::PROV_X942KDF_951, OSSL_KDF_PARAM_SIZE, 0)];

/// `static const OSSL_PARAM sshkdf_get_ctx_params_list[]` — the `size` entry alone.
static X942_GETTABLE_CTX_PARAMS: [OsslParam; 2] = [param_size_t(OSSL_KDF_PARAM_SIZE), END];

/// `static int find_alg_id(OSSL_LIB_CTX *libctx, const char *algname, const char *propq,
/// size_t *id)` — `x942kdf.c:86-107`.
///
/// # Safety
/// `libctx` NULL or live; `algname`/`propq` NULL or NUL-terminated; `id` writable.
unsafe fn find_alg_id(
    libctx: *mut c_void,
    algname: *const c_char,
    propq: *const c_char,
    id: *mut usize,
) -> c_int {
    // SAFETY: `libctx`/`algname`/`propq` are per the contract.
    let cipher = unsafe { EVP_CIPHER_fetch(libctx, algname, propq) };
    let mut ret = 0;
    if !cipher.is_null() {
        for (i, (name, _oid, _keklen)) in KEK_ALGS.iter().enumerate() {
            // SAFETY: `cipher` is live and `name` is a NUL-terminated static.
            if unsafe { EVP_CIPHER_is_a(cipher, name.as_ptr()) } != 0 {
                // SAFETY: `id` is writable per the contract.
                unsafe { *id = i };
                ret = 1;
                break;
            }
        }
    }
    if ret == 0 {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::PROV_X942KDF_101) };
    }
    // SAFETY: `cipher` is NULL or a fetched reference.
    unsafe { EVP_CIPHER_free(cipher) };
    ret
}

/// `static int DER_w_keyinfo(WPACKET *pkt, const unsigned char *der_oid, size_t der_oidlen,
/// unsigned char **pcounter)` — `x942kdf.c:109-121`.
///
/// # Safety
/// `pkt` live; `der_oid` readable for `der_oidlen`; `pcounter` NULL or writable.
unsafe fn der_w_keyinfo(
    pkt: *mut Wpacket,
    der_oid: *const u8,
    der_oidlen: usize,
    pcounter: *mut *mut u8,
) -> c_int {
    // SAFETY: `pkt` is live per the contract; the rest is this program's own.
    unsafe {
        (ossl_DER_w_begin_sequence(pkt, -1) != 0
            && ossl_DER_w_octet_string_uint32(pkt, -1, 1) != 0
            && (pcounter.is_null() || {
                *pcounter = WPACKET_get_curr(pkt);
                !(*pcounter).is_null()
            })
            && ossl_DER_w_precompiled(pkt, -1, der_oid, der_oidlen) != 0
            && ossl_DER_w_end_sequence(pkt, -1) != 0) as c_int
    }
}

/// `static int der_encode_sharedinfo(...)` — `x942kdf.c:123-146`.
///
/// The tagged fields are written in the authority's **descending** tag order (`[3]`, `[2]`,
/// `[1]`, `[0]`) because the DER writer constructs backwards; and the `keylen_bits` `[2]` field
/// shares a tag with `supp_pub` because exactly one of them is set.
///
/// # Safety
/// `pkt` live; each buffer readable for its length; `pcounter` NULL or writable.
#[allow(clippy::too_many_arguments)] // the authority's own signature has fourteen parameters.
unsafe fn der_encode_sharedinfo(
    pkt: *mut Wpacket,
    buf: *mut u8,
    buflen: usize,
    der_oid: *const u8,
    der_oidlen: usize,
    acvp: *const u8,
    acvplen: usize,
    partyu: *const u8,
    partyulen: usize,
    partyv: *const u8,
    partyvlen: usize,
    supp_pub: *const u8,
    supp_publen: usize,
    supp_priv: *const u8,
    supp_privlen: usize,
    keylen_bits: u32,
    pcounter: *mut *mut u8,
) -> c_int {
    // SAFETY: `pkt` is live and the buffers are per the contract.
    unsafe {
        ((if !buf.is_null() {
            WPACKET_init_der(pkt, buf, buflen)
        } else {
            WPACKET_init_null_der(pkt)
        }) != 0
            && ossl_DER_w_begin_sequence(pkt, -1) != 0
            && (supp_priv.is_null()
                || ossl_DER_w_octet_string(pkt, 3, supp_priv, supp_privlen) != 0)
            && (supp_pub.is_null() || ossl_DER_w_octet_string(pkt, 2, supp_pub, supp_publen) != 0)
            && (keylen_bits == 0 || ossl_DER_w_octet_string_uint32(pkt, 2, keylen_bits) != 0)
            && (partyv.is_null() || ossl_DER_w_octet_string(pkt, 1, partyv, partyvlen) != 0)
            && (partyu.is_null() || ossl_DER_w_octet_string(pkt, 0, partyu, partyulen) != 0)
            && (acvp.is_null() || ossl_DER_w_precompiled(pkt, -1, acvp, acvplen) != 0)
            && der_w_keyinfo(pkt, der_oid, der_oidlen, pcounter) != 0
            && ossl_DER_w_end_sequence(pkt, -1) != 0
            && WPACKET_finish(pkt) != 0) as c_int
    }
}

/// `static int x942_encode_otherinfo(...)` — `x942kdf.c:205-271`.
///
/// Two passes: a NULL-buffer sizing pass (`WPACKET_init_null_der`) and then the real encode into
/// a buffer of exactly that size. The counter's position is remembered across both so the
/// derivation loop can increment it in place, and the `04 04` header of the initial `1` is the
/// assertion that the field really is a four-byte octet string.
///
/// # Safety
/// The buffers are readable for their lengths; `der`/`der_len`/`out_ctr` writable.
#[allow(clippy::too_many_arguments)] // the authority's own signature has twelve parameters.
unsafe fn x942_encode_otherinfo(
    keylen: usize,
    cek_oid: *const u8,
    cek_oid_len: usize,
    acvp: *const u8,
    acvp_len: usize,
    partyu: *const u8,
    partyu_len: usize,
    partyv: *const u8,
    partyv_len: usize,
    supp_pub: *const u8,
    supp_pub_len: usize,
    supp_priv: *const u8,
    supp_priv_len: usize,
    der: *mut *mut u8,
    der_len: *mut usize,
    out_ctr: *mut *mut u8,
) -> c_int {
    let mut pkt = core::mem::MaybeUninit::<Wpacket>::uninit();
    let mut pcounter: *mut u8 = ptr::null_mut();
    let der_buf: *mut u8;
    let ret;

    // keylen_bits must fit into 4 bytes.
    if keylen > 0xFFFFFF {
        return 0;
    }
    let keylen_bits = (8 * keylen) as u32;
    let pkt = pkt.as_mut_ptr();

    // SAFETY: `pkt` is this frame's own storage and the buffers are per the contract.
    unsafe {
        let mut der_buflen: usize = 0;
        if der_encode_sharedinfo(
            pkt,
            ptr::null_mut(),
            0,
            cek_oid,
            cek_oid_len,
            acvp,
            acvp_len,
            partyu,
            partyu_len,
            partyv,
            partyv_len,
            supp_pub,
            supp_pub_len,
            supp_priv,
            supp_priv_len,
            keylen_bits,
            ptr::null_mut(),
        ) == 0
            || WPACKET_get_total_written(pkt, &mut der_buflen) == 0
        {
            WPACKET_cleanup(pkt);
            return 0;
        }
        WPACKET_cleanup(pkt);

        der_buf = CRYPTO_zalloc(der_buflen, FILE_X942, LINE).cast::<u8>();
        if der_buf.is_null() {
            WPACKET_cleanup(pkt);
            return 0;
        }
        if der_encode_sharedinfo(
            pkt,
            der_buf,
            der_buflen,
            cek_oid,
            cek_oid_len,
            acvp,
            acvp_len,
            partyu,
            partyu_len,
            partyv,
            partyv_len,
            supp_pub,
            supp_pub_len,
            supp_priv,
            supp_priv_len,
            keylen_bits,
            &mut pcounter,
        ) == 0
        {
            WPACKET_cleanup(pkt);
            CRYPTO_free(der_buf.cast(), FILE_X942, LINE);
            return 0;
        }

        // The buffer is exactly the size required, so the write cursor is back at its start.
        if WPACKET_get_curr(pkt) != der_buf {
            WPACKET_cleanup(pkt);
            CRYPTO_free(der_buf.cast(), FILE_X942, LINE);
            return 0;
        }

        // `04 04 00 00 00 01`: check the octet-string header and skip it.
        if pcounter.is_null() || *pcounter != 0x04 || *(pcounter.add(1)) != 0x04 {
            WPACKET_cleanup(pkt);
            CRYPTO_free(der_buf.cast(), FILE_X942, LINE);
            return 0;
        }
        *out_ctr = pcounter.add(2);
        *der = der_buf;
        *der_len = der_buflen;
        WPACKET_cleanup(pkt);
        ret = 1;
    }
    ret
}

/// `static int x942kdf_hash_kdm(...)` — `x942kdf.c:273-337`.
///
/// # Safety
/// `kdf_md` live; the buffers readable/writable for their lengths; `ctr` is the live counter
/// inside `other`.
#[allow(clippy::too_many_arguments)] // the authority's own signature has eight parameters.
unsafe fn x942kdf_hash_kdm(
    kdf_md: *const crate::evp::digest::EvpMd,
    z: *const u8,
    z_len: usize,
    other: *const u8,
    other_len: usize,
    ctr: *mut u8,
    derived_key: *mut u8,
    derived_key_len: usize,
) -> c_int {
    let mut ret = 0;
    let mut mac = [0u8; EVP_MAX_MD_SIZE];
    let mut out = derived_key;
    let mut len = derived_key_len;

    if z_len > X942KDF_MAX_INLEN
        || other_len > X942KDF_MAX_INLEN
        || derived_key_len > X942KDF_MAX_INLEN
        || derived_key_len == 0
    {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::PROV_X942KDF_287) };
        return 0;
    }

    // SAFETY: `kdf_md` is live per the contract.
    let hlen = unsafe { EVP_MD_get_size(kdf_md) };
    if hlen <= 0 {
        return 0;
    }
    let out_len = hlen as usize;

    // SAFETY: `EVP_MD_CTX_create` is `EVP_MD_CTX_new`.
    let ctx = EVP_MD_CTX_new();
    let ctx_init = EVP_MD_CTX_new();
    if ctx.is_null() || ctx_init.is_null() {
        // SAFETY: both are NULL or live contexts.
        unsafe {
            EVP_MD_CTX_free(ctx);
            EVP_MD_CTX_free(ctx_init);
        }
        return 0;
    }

    // SAFETY: the contexts and `kdf_md` are live.
    if unsafe { EVP_DigestInit(ctx_init, kdf_md) } == 0 {
        // SAFETY: both are NULL or live contexts.
        unsafe {
            EVP_MD_CTX_free(ctx);
            EVP_MD_CTX_free(ctx_init);
        }
        return 0;
    }

    // `EVP_MD_CTX_free` is `EVP_MD_CTX_destroy`; the loop writes the live counter in `other`.
    let mut counter: u64 = 1;
    loop {
        // SAFETY: `ctr` points at the four-byte counter field inside the caller's `other`
        // buffer, which the caller keeps live for the whole call.
        unsafe {
            *ctr = ((counter >> 24) & 0xff) as u8;
            *ctr.add(1) = ((counter >> 16) & 0xff) as u8;
            *ctr.add(2) = ((counter >> 8) & 0xff) as u8;
            *ctr.add(3) = (counter & 0xff) as u8;
        }

        // SAFETY: the contexts are live and the buffers readable.
        let ok = unsafe {
            EVP_MD_CTX_copy_ex(ctx, ctx_init) != 0
                && EVP_DigestUpdate(ctx, z.cast(), z_len) != 0
                && EVP_DigestUpdate(ctx, other.cast(), other_len) != 0
        };
        if !ok {
            break;
        }
        if len >= out_len {
            // SAFETY: `out` is writable for `out_len` bytes.
            if unsafe { EVP_DigestFinal_ex(ctx, out, ptr::null_mut()) } == 0 {
                break;
            }
            // SAFETY: the arithmetic stays inside the caller's buffer.
            out = unsafe { out.add(out_len) };
            len -= out_len;
            if len == 0 {
                ret = 1;
                break;
            }
        } else {
            // SAFETY: `mac` is `EVP_MAX_MD_SIZE` bytes.
            if unsafe { EVP_DigestFinal_ex(ctx, mac.as_mut_ptr(), ptr::null_mut()) } == 0 {
                break;
            }
            // SAFETY: `out` is writable for `len` and `mac` readable for the same.
            unsafe { ptr::copy_nonoverlapping(mac.as_ptr(), out, len) };
            ret = 1;
            break;
        }
        counter += 1;
    }

    // SAFETY: both contexts are live; `mac` is a live local.
    unsafe {
        EVP_MD_CTX_free(ctx);
        EVP_MD_CTX_free(ctx_init);
        cleanse(mac.as_mut_ptr(), mac.len());
    }
    ret
}

/// `static void *x942kdf_new(void *provctx)` — `x942kdf.c:339-354`.
///
/// # Safety
/// The dispatch contract.
unsafe extern "C" fn x942kdf_new(provctx: *mut c_void) -> *mut c_void {
    // SAFETY: the caller's contract.
    unsafe {
        if is_running() == 0 {
            return ptr::null_mut();
        }
        let ctx = CRYPTO_zalloc(core::mem::size_of::<KdfX942>(), FILE_X942, LINE).cast::<KdfX942>();
        if ctx.is_null() {
            return ptr::null_mut();
        }
        (*ctx).provctx = provctx;
        (*ctx).use_keybits = 1;
        ctx.cast()
    }
}

/// `static void x942kdf_reset(void *vctx)` — `x942kdf.c:356-371`.
///
/// # Safety
/// `vctx` is a context `x942kdf_new` allocated.
unsafe fn x942kdf_reset(vctx: *mut c_void) {
    // SAFETY: `vctx` is a live context per the contract.
    unsafe {
        let ctx = vctx.cast::<KdfX942>();
        let provctx = (*ctx).provctx;

        ossl_prov_digest_reset(ptr::addr_of_mut!((*ctx).digest));
        CRYPTO_clear_free((*ctx).secret.cast(), (*ctx).secret_len, FILE_X942, LINE);
        CRYPTO_clear_free((*ctx).acvpinfo.cast(), (*ctx).acvpinfo_len, FILE_X942, LINE);
        CRYPTO_clear_free(
            (*ctx).partyuinfo.cast(),
            (*ctx).partyuinfo_len,
            FILE_X942,
            LINE,
        );
        CRYPTO_clear_free(
            (*ctx).partyvinfo.cast(),
            (*ctx).partyvinfo_len,
            FILE_X942,
            LINE,
        );
        CRYPTO_clear_free(
            (*ctx).supp_pubinfo.cast(),
            (*ctx).supp_pubinfo_len,
            FILE_X942,
            LINE,
        );
        CRYPTO_clear_free(
            (*ctx).supp_privinfo.cast(),
            (*ctx).supp_privinfo_len,
            FILE_X942,
            LINE,
        );
        ptr::write_bytes(vctx.cast::<u8>(), 0, core::mem::size_of::<KdfX942>());
        (*ctx).provctx = provctx;
        (*ctx).use_keybits = 1;
    }
}

/// `static void x942kdf_free(void *vctx)` — `x942kdf.c:373-381`.
///
/// # Safety
/// The dispatch contract.
unsafe extern "C" fn x942kdf_free(vctx: *mut c_void) {
    // SAFETY: `vctx` is NULL or a live context.
    unsafe {
        if !vctx.is_null() {
            x942kdf_reset(vctx);
            CRYPTO_free(vctx, FILE_X942, LINE);
        }
    }
}

/// `static void *x942kdf_dup(void *vctx)` — `x942kdf.c:383-417`.
///
/// # Safety
/// The dispatch contract.
unsafe extern "C" fn x942kdf_dup(vctx: *mut c_void) -> *mut c_void {
    // SAFETY: the caller's contract.
    unsafe {
        let src = vctx.cast::<KdfX942>();
        let dest = x942kdf_new((*src).provctx).cast::<KdfX942>();
        if dest.is_null() {
            return ptr::null_mut();
        }
        if ossl_prov_memdup(
            (*src).secret.cast(),
            (*src).secret_len,
            ptr::addr_of_mut!((*dest).secret),
            ptr::addr_of_mut!((*dest).secret_len),
        ) == 0
            || ossl_prov_memdup(
                (*src).acvpinfo.cast(),
                (*src).acvpinfo_len,
                ptr::addr_of_mut!((*dest).acvpinfo),
                ptr::addr_of_mut!((*dest).acvpinfo_len),
            ) == 0
            || ossl_prov_memdup(
                (*src).partyuinfo.cast(),
                (*src).partyuinfo_len,
                ptr::addr_of_mut!((*dest).partyuinfo),
                ptr::addr_of_mut!((*dest).partyuinfo_len),
            ) == 0
            || ossl_prov_memdup(
                (*src).partyvinfo.cast(),
                (*src).partyvinfo_len,
                ptr::addr_of_mut!((*dest).partyvinfo),
                ptr::addr_of_mut!((*dest).partyvinfo_len),
            ) == 0
            || ossl_prov_memdup(
                (*src).supp_pubinfo.cast(),
                (*src).supp_pubinfo_len,
                ptr::addr_of_mut!((*dest).supp_pubinfo),
                ptr::addr_of_mut!((*dest).supp_pubinfo_len),
            ) == 0
            || ossl_prov_memdup(
                (*src).supp_privinfo.cast(),
                (*src).supp_privinfo_len,
                ptr::addr_of_mut!((*dest).supp_privinfo),
                ptr::addr_of_mut!((*dest).supp_privinfo_len),
            ) == 0
            || ossl_prov_digest_copy(
                ptr::addr_of_mut!((*dest).digest),
                ptr::addr_of!((*src).digest),
            ) == 0
        {
            x942kdf_free(dest.cast());
            return ptr::null_mut();
        }
        (*dest).cek_oid = (*src).cek_oid;
        (*dest).cek_oid_len = (*src).cek_oid_len;
        (*dest).dkm_len = (*src).dkm_len;
        (*dest).use_keybits = (*src).use_keybits;
        dest.cast()
    }
}

/// `static int x942kdf_set_buffer(unsigned char **out, size_t *out_len,
/// const OSSL_PARAM *p)` — `x942kdf.c:419-428`.
///
/// # Safety
/// `out`/`out_len` writable; `p` live.
unsafe fn x942kdf_set_buffer(out: *mut *mut u8, out_len: *mut usize, p: *const OsslParam) -> c_int {
    // SAFETY: `p` is live per the contract.
    unsafe {
        if (*p).data_size == 0 || (*p).data.is_null() {
            return 1;
        }
        CRYPTO_free((*out).cast(), FILE_X942, LINE);
        *out = ptr::null_mut();
        OSSL_PARAM_get_octet_string(p, out.cast::<*mut c_void>(), 0, out_len)
    }
}

/// `static size_t x942kdf_size(KDF_X942 *ctx)` — `x942kdf.c:430-441`.
///
/// # Safety
/// `ctx` live.
unsafe fn x942kdf_size(ctx: *mut KdfX942) -> usize {
    // SAFETY: `ctx` is live per the contract.
    unsafe {
        let md = ossl_prov_digest_md(ptr::addr_of!((*ctx).digest));
        if md.is_null() {
            raise_site(&err_sites::PROV_X942KDF_434);
            return 0;
        }
        let len = EVP_MD_get_size(md);
        if len <= 0 {
            0
        } else {
            len as usize
        }
    }
}

/// `static int x942kdf_derive(void *vctx, unsigned char *key, size_t keylen,
/// const OSSL_PARAM params[])` — `x942kdf.c:461-531`.
///
/// # Safety
/// The dispatch contract.
unsafe extern "C" fn x942kdf_derive(
    vctx: *mut c_void,
    key: *mut u8,
    keylen: usize,
    params: *const OsslParam,
) -> c_int {
    let mut der: *mut u8 = ptr::null_mut();
    let mut der_len: usize = 0;
    let mut ctr: *mut u8 = ptr::null_mut();

    // SAFETY: the caller's contract.
    unsafe {
        let ctx = vctx.cast::<KdfX942>();
        if is_running() == 0 || x942kdf_set_ctx_params(vctx, params) == 0 {
            return 0;
        }
        if (*ctx).use_keybits != 0 && !(*ctx).supp_pubinfo.is_null() {
            return fail_at(&err_sites::PROV_X942KDF_477);
        }
        if !(*ctx).acvpinfo.is_null()
            && (!(*ctx).partyuinfo.is_null()
                || !(*ctx).partyvinfo.is_null()
                || !(*ctx).supp_pubinfo.is_null()
                || !(*ctx).supp_privinfo.is_null())
        {
            return fail_at(&err_sites::PROV_X942KDF_489);
        }
        if (*ctx).secret.is_null() {
            return fail_at(&err_sites::PROV_X942KDF_493);
        }
        let md = ossl_prov_digest_md(ptr::addr_of!((*ctx).digest));
        if md.is_null() {
            return fail_at(&err_sites::PROV_X942KDF_498);
        }
        if (*ctx).cek_oid.is_null() || (*ctx).cek_oid_len == 0 {
            return fail_at(&err_sites::PROV_X942KDF_502);
        }
        if !(*ctx).partyuinfo.is_null() && (*ctx).partyuinfo_len >= X942KDF_MAX_INLEN {
            return fail_at(&err_sites::PROV_X942KDF_510);
        }
        if x942_encode_otherinfo(
            if (*ctx).use_keybits != 0 {
                (*ctx).dkm_len
            } else {
                0
            },
            (*ctx).cek_oid,
            (*ctx).cek_oid_len,
            (*ctx).acvpinfo,
            (*ctx).acvpinfo_len,
            (*ctx).partyuinfo,
            (*ctx).partyuinfo_len,
            (*ctx).partyvinfo,
            (*ctx).partyvinfo_len,
            (*ctx).supp_pubinfo,
            (*ctx).supp_pubinfo_len,
            (*ctx).supp_privinfo,
            (*ctx).supp_privinfo_len,
            &mut der,
            &mut der_len,
            &mut ctr,
        ) == 0
        {
            return fail_at(&err_sites::PROV_X942KDF_522);
        }
        let ret = x942kdf_hash_kdm(
            md,
            (*ctx).secret,
            (*ctx).secret_len,
            der,
            der_len,
            ctr,
            key,
            keylen,
        );
        CRYPTO_free(der.cast(), FILE_X942, LINE);
        ret
    }
}

/// `static int x942kdf_set_ctx_params(void *vctx, const OSSL_PARAM params[])` —
/// `x942kdf.c:552-626`, without its FIPS arm.
///
/// # Safety
/// The dispatch contract.
unsafe extern "C" fn x942kdf_set_ctx_params(vctx: *mut c_void, params: *const OsslParam) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        if vctx.is_null() {
            return 0;
        }
        let ctx = vctx.cast::<KdfX942>();
        if let Some(site) = repeated_param_site_by_field(params, &X942_SET_DECODER_KEYS) {
            return fail_at(site);
        }
        if let Some(site) = repeated_param_site_by_field(params, &X942_SET_DECODER_KEYS_TAIL) {
            return fail_at(site);
        }

        let p = X942SetCtxParams {
            propq: locate_const(params, OSSL_ALG_PARAM_PROPERTIES),
            engine: locate_const(params, OSSL_ALG_PARAM_ENGINE),
            digest: locate_const(params, OSSL_KDF_PARAM_DIGEST),
            // The generated decoder routes `secret` and `key` into one field, so the first
            // present spelling wins and the other is the fallback.
            secret: {
                let s = locate_const(params, OSSL_KDF_PARAM_SECRET);
                if s.is_null() {
                    locate_const(params, OSSL_KDF_PARAM_KEY)
                } else {
                    s
                }
            },
            // And `partyu-info` and `ukm` into another, the same way.
            uinfo: {
                let u = locate_const(params, OSSL_KDF_PARAM_X942_PARTYUINFO);
                if u.is_null() {
                    locate_const(params, OSSL_KDF_PARAM_UKM)
                } else {
                    u
                }
            },
            acvp: locate_const(params, OSSL_KDF_PARAM_X942_ACVPINFO),
            vinfo: locate_const(params, OSSL_KDF_PARAM_X942_PARTYVINFO),
            pub_: locate_const(params, OSSL_KDF_PARAM_X942_SUPP_PUBINFO),
            priv_: locate_const(params, OSSL_KDF_PARAM_X942_SUPP_PRIVINFO),
            kbits: locate_const(params, OSSL_KDF_PARAM_X942_USE_KEYBITS),
            cekalg: locate_const(params, OSSL_KDF_PARAM_CEK_ALG),
        };

        let provctx = prov_libctx_of((*ctx).provctx);

        if !p.digest.is_null() {
            if ossl_prov_digest_load(
                ptr::addr_of_mut!((*ctx).digest),
                p.digest,
                p.propq,
                p.engine,
                provctx,
            ) == 0
            {
                return 0;
            }
            let md = ossl_prov_digest_md(ptr::addr_of!((*ctx).digest));
            if EVP_MD_xof(md) != 0 {
                raise_site(&err_sites::PROV_X942KDF_842);
                return 0;
            }
        }

        if !p.secret.is_null()
            && x942kdf_set_buffer(
                ptr::addr_of_mut!((*ctx).secret),
                ptr::addr_of_mut!((*ctx).secret_len),
                p.secret,
            ) == 0
        {
            return 0;
        }
        if !p.acvp.is_null()
            && x942kdf_set_buffer(
                ptr::addr_of_mut!((*ctx).acvpinfo),
                ptr::addr_of_mut!((*ctx).acvpinfo_len),
                p.acvp,
            ) == 0
        {
            return 0;
        }
        if !p.uinfo.is_null()
            && x942kdf_set_buffer(
                ptr::addr_of_mut!((*ctx).partyuinfo),
                ptr::addr_of_mut!((*ctx).partyuinfo_len),
                p.uinfo,
            ) == 0
        {
            return 0;
        }
        if !p.vinfo.is_null()
            && x942kdf_set_buffer(
                ptr::addr_of_mut!((*ctx).partyvinfo),
                ptr::addr_of_mut!((*ctx).partyvinfo_len),
                p.vinfo,
            ) == 0
        {
            return 0;
        }
        if !p.kbits.is_null()
            && OSSL_PARAM_get_int(p.kbits, ptr::addr_of_mut!((*ctx).use_keybits)) == 0
        {
            return 0;
        }
        if !p.pub_.is_null() {
            if x942kdf_set_buffer(
                ptr::addr_of_mut!((*ctx).supp_pubinfo),
                ptr::addr_of_mut!((*ctx).supp_pubinfo_len),
                p.pub_,
            ) == 0
            {
                return 0;
            }
            (*ctx).use_keybits = 0;
        }
        if !p.priv_.is_null()
            && x942kdf_set_buffer(
                ptr::addr_of_mut!((*ctx).supp_privinfo),
                ptr::addr_of_mut!((*ctx).supp_privinfo_len),
                p.priv_,
            ) == 0
        {
            return 0;
        }
        if !p.cekalg.is_null() {
            let mut cekalg: *const c_char = ptr::null();
            let mut propq: *const c_char = ptr::null();
            if OSSL_PARAM_get_utf8_string_ptr(p.cekalg, &mut cekalg) == 0 {
                return 0;
            }
            if !p.propq.is_null() && OSSL_PARAM_get_utf8_string_ptr(p.propq, &mut propq) == 0 {
                return 0;
            }
            let mut id: usize = 0;
            if find_alg_id(provctx, cekalg, propq, &mut id) == 0 {
                return 0;
            }
            (*ctx).cek_oid = KEK_ALGS[id].1.as_ptr();
            (*ctx).cek_oid_len = KEK_ALGS[id].1.len();
            (*ctx).dkm_len = KEK_ALGS[id].2;
        }
    }
    1
}

/// `static int x942kdf_get_ctx_params(void *vctx, OSSL_PARAM params[])` —
/// `x942kdf.c:641-655`, without its FIPS arm.
///
/// # Safety
/// The dispatch contract.
unsafe extern "C" fn x942kdf_get_ctx_params(vctx: *mut c_void, params: *mut OsslParam) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        if vctx.is_null() {
            return 0;
        }
        if let Some(site) = repeated_param_site_by_field(params, &X942_GET_DECODER_KEYS) {
            return fail_at(site);
        }
        let ctx = vctx.cast::<KdfX942>();
        let p = crate::params::OSSL_PARAM_locate_const(params, OSSL_KDF_PARAM_SIZE);
        if !p.is_null() && OSSL_PARAM_set_size_t(p.cast_mut(), x942kdf_size(ctx)) == 0 {
            return 0;
        }
    }
    1
}

/// `static const OSSL_PARAM *x942kdf_settable_ctx_params(void *ctx, void *provctx)` —
/// `x942kdf.c:628-632`.
///
/// # Safety
/// The dispatch contract.
unsafe extern "C" fn x942kdf_settable_ctx_params(
    _ctx: *mut c_void,
    _provctx: *mut c_void,
) -> *const OsslParam {
    X942_SETTABLE_CTX_PARAMS.as_ptr()
}

/// `static const OSSL_PARAM *x942kdf_gettable_ctx_params(void *ctx, void *provctx)` —
/// `x942kdf.c:657-661`.
///
/// # Safety
/// The dispatch contract.
unsafe extern "C" fn x942kdf_gettable_ctx_params(
    _ctx: *mut c_void,
    _provctx: *mut c_void,
) -> *const OsslParam {
    X942_GETTABLE_CTX_PARAMS.as_ptr()
}

/// `const OSSL_DISPATCH ossl_kdf_x942_kdf_functions[]` — `x942kdf.c:663-676`.
pub(crate) static X942KDF_FUNCTIONS: [OsslDispatch; 10] = [
    OsslDispatch {
        function_id: OSSL_FUNC_KDF_NEWCTX,
        function: x942kdf_new as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KDF_DUPCTX,
        function: x942kdf_dup as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KDF_FREECTX,
        function: x942kdf_free as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KDF_RESET,
        function: x942kdf_reset as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KDF_DERIVE,
        function: x942kdf_derive as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KDF_SETTABLE_CTX_PARAMS,
        function: x942kdf_settable_ctx_params as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KDF_SET_CTX_PARAMS,
        function: x942kdf_set_ctx_params as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KDF_GETTABLE_CTX_PARAMS,
        function: x942kdf_gettable_ctx_params as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KDF_GET_CTX_PARAMS,
        function: x942kdf_get_ctx_params as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_DISPATCH_END,
        function: ptr::null_mut(),
    },
];

/// `static const OSSL_ALGORITHM deflt_kdfs[]` — `providers/defltprov.c:355-375`, restricted to
/// the rows this module implements, **in the authority's order**: `SSKDF` is row 5,
/// `X963KDF` row 9 and `X942KDF-ASN1` row 12, so the table is a subsequence (D244).
///
/// **The property definition is `"provider=default"` on every row**, which is `defltprov.c`'s
/// `ALG` macro (D247).
pub(crate) static DEFLT_KDFS: [OsslAlgorithm; 4] = [
    OsslAlgorithm {
        // `PROV_NAMES_SSKDF` — `prov/names.h`, the primary name alone.
        algorithm_names: c"SSKDF".as_ptr(),
        property_definition: c"provider=default".as_ptr(),
        implementation: SSKDF_FUNCTIONS.as_ptr().cast(),
        algorithm_description: ptr::null(),
    },
    OsslAlgorithm {
        // `PROV_NAMES_X963KDF` — the alias `X942KDF-CONCAT` is part of the row.
        algorithm_names: c"X963KDF:X942KDF-CONCAT".as_ptr(),
        property_definition: c"provider=default".as_ptr(),
        implementation: X963KDF_FUNCTIONS.as_ptr().cast(),
        algorithm_description: ptr::null(),
    },
    OsslAlgorithm {
        // `PROV_NAMES_X942KDF_ASN1` — the alias `X942KDF` is part of the row.
        algorithm_names: c"X942KDF-ASN1:X942KDF".as_ptr(),
        property_definition: c"provider=default".as_ptr(),
        implementation: X942KDF_FUNCTIONS.as_ptr().cast(),
        algorithm_description: ptr::null(),
    },
    OsslAlgorithm {
        algorithm_names: ptr::null(),
        property_definition: ptr::null(),
        implementation: ptr::null(),
        algorithm_description: ptr::null(),
    },
];

#[cfg(test)]
mod tests {
    use super::*;

    /// `defltprov.c:355-375` lists SSKDF 6th, X963KDF 10th and X942KDF-ASN1 13th of its nineteen
    /// rows, so the crate's three are a **subsequence** in that order and a test that asserted the
    /// crate's own array would stay green while the census failed (D244). The expected names below
    /// are `prov/names.h`'s expansions, checked against the census rather than this file.
    #[test]
    fn the_kdf_table_names_its_rows_in_the_authoritys_order() {
        assert_eq!(DEFLT_KDFS.len(), 4);
        // SAFETY: the terminator's fields are NULL by construction and each landed row's name is a
        // `'static` C string.
        unsafe {
            assert!(DEFLT_KDFS[3].algorithm_names.is_null());
            for (row, want) in [
                (&DEFLT_KDFS[0], b"SSKDF".as_slice()),
                (&DEFLT_KDFS[1], b"X963KDF:X942KDF-CONCAT"),
                (&DEFLT_KDFS[2], b"X942KDF-ASN1:X942KDF"),
            ] {
                assert_eq!(
                    core::ffi::CStr::from_ptr(row.algorithm_names).to_bytes(),
                    want
                );
                assert_eq!(
                    core::ffi::CStr::from_ptr(row.property_definition).to_bytes(),
                    b"provider=default"
                );
                assert!(!row.implementation.is_null());
                assert!(row.algorithm_description.is_null());
            }
        }
    }

    /// Each dispatch table is the authority's nine entries plus the terminator, and the two SSKDF
    /// tables differ in exactly the derive slot — `sskdf.c:747-775`.
    #[test]
    fn the_three_dispatch_tables_carry_nine_entries_and_terminate() {
        for table in [&SSKDF_FUNCTIONS, &X963KDF_FUNCTIONS, &X942KDF_FUNCTIONS] {
            assert_eq!(table.len(), 10);
            assert_eq!(
                table[9].function_id,
                crate::context::dispatch::OSSL_DISPATCH_END
            );
            assert!(table[9].function.is_null());
            for entry in &table[..9] {
                assert!(!entry.function.is_null());
            }
        }
        assert_eq!(SSKDF_FUNCTIONS[4].function_id, OSSL_FUNC_KDF_DERIVE);
        assert_eq!(X963KDF_FUNCTIONS[4].function_id, OSSL_FUNC_KDF_DERIVE);
        // The two tables share all but the derive and settable/gettable callbacks, so the derive
        // function must differ while the newctx one is the same.
        assert_ne!(SSKDF_FUNCTIONS[4].function, X963KDF_FUNCTIONS[4].function);
        assert_eq!(SSKDF_FUNCTIONS[0].function, X963KDF_FUNCTIONS[0].function);
    }

    /// `providers/common/der/der_wrap_gen.c`'s four precompiled OIDs, each the header's own byte
    /// array: `DER_P_OBJECT` (6), the content length, then the arcs.
    #[test]
    fn the_wrap_oids_are_the_generated_headers_own_bytes() {
        assert_eq!(
            OID_AES128_WRAP,
            [0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x01, 0x05]
        );
        assert_eq!(OID_AES192_WRAP[10], 0x19);
        assert_eq!(OID_AES256_WRAP[10], 0x2D);
        assert_eq!(OID_CMS3DES_WRAP.len(), 13);
        assert_eq!(OID_CMS3DES_WRAP[1], 0x0B);
        assert_eq!(KEK_ALGS.len(), 4);
        assert_eq!(KEK_ALGS[0].1, OID_AES128_WRAP.as_slice());
        assert_eq!(KEK_ALGS[3].1.len(), 13);
    }

    /// The one thing the crate's `repeated_param_site` cannot express, and the reason the KDF
    /// decoders use a field-keyed variant: `sskdf.c`'s and `x942kdf.c`'s generated switches route
    /// two *names* onto one field and raise at the second occurrence of **either**.
    #[test]
    fn the_repeated_check_is_keyed_on_the_field_and_not_the_name() {
        let mut a: u32 = 1;
        let mut b: u32 = 2;
        let mut params: [OsslParam; 3] = [END; 3];
        // SAFETY: the descriptors borrow two live locals and the array holds one descriptor plus
        // the terminator.
        unsafe {
            params[0] = OSSL_PARAM_construct_octet_string(
                OSSL_KDF_PARAM_KEY,
                ptr::addr_of_mut!(a).cast(),
                4,
            );
            params[1] = OSSL_PARAM_construct_octet_string(
                OSSL_KDF_PARAM_SECRET,
                ptr::addr_of_mut!(b).cast(),
                4,
            );
            params[2] = OSSL_PARAM_construct_end();
            // `secret` follows `key`, so the raise is `secret`'s own site.
            let site = repeated_param_site_by_field(params.as_ptr(), &SSKDF_SET_DECODER_KEYS);
            assert_eq!(site.map(|s| s.line), Some(795));

            // Reversed, it is `key`'s site.
            params[0] = OSSL_PARAM_construct_octet_string(
                OSSL_KDF_PARAM_SECRET,
                ptr::addr_of_mut!(a).cast(),
                4,
            );
            params[1] = OSSL_PARAM_construct_octet_string(
                OSSL_KDF_PARAM_KEY,
                ptr::addr_of_mut!(b).cast(),
                4,
            );
            let site = repeated_param_site_by_field(params.as_ptr(), &SSKDF_SET_DECODER_KEYS);
            assert_eq!(site.map(|s| s.line), Some(722));

            // `info` may repeat: the generated decoder counts up to `SSKDF_MAX_INFOS` and raises
            // `PROV_R_TOO_MANY_RECORDS` on the sixth, which the field check must not pre-empt.
            params[0] = OSSL_PARAM_construct_octet_string(
                OSSL_KDF_PARAM_INFO,
                ptr::addr_of_mut!(a).cast(),
                4,
            );
            params[1] = OSSL_PARAM_construct_octet_string(
                OSSL_KDF_PARAM_INFO,
                ptr::addr_of_mut!(b).cast(),
                4,
            );
            assert!(
                repeated_param_site_by_field(params.as_ptr(), &SSKDF_SET_DECODER_KEYS).is_none()
            );
        }
    }

    /// The settable lists are the generated ones minus their `# if defined(FIPS_MODULE)` entries.
    #[test]
    fn the_settable_lists_are_the_generated_lists_without_their_fips_entries() {
        // SAFETY: every entry is a compile-time constant with a `'static` key.
        unsafe {
            for (list, want) in [
                (
                    &SSKDF_SETTABLE_CTX_PARAMS[..],
                    [
                        b"secret".as_slice(),
                        b"key",
                        b"info",
                        b"properties",
                        b"digest",
                        b"mac",
                        b"salt",
                        b"maclen",
                    ],
                ),
                (
                    &X963KDF_SETTABLE_CTX_PARAMS[..],
                    [
                        b"secret".as_slice(),
                        b"key",
                        b"info",
                        b"properties",
                        b"digest",
                        b"mac",
                        b"salt",
                        b"maclen",
                    ],
                ),
            ] {
                assert_eq!(list.len(), 9);
                assert!(list[8].key.is_null());
                for (entry, key) in list[..8].iter().zip(want) {
                    assert_eq!(core::ffi::CStr::from_ptr(entry.key).to_bytes(), key);
                }
            }
        }
    }
}
