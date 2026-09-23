//! Phase 8 — the default provider's `OSSL_OP_KDF` rows, and the algorithm units behind them.
//!
//! Sixteen registration rows of `providers/defltprov.c`'s `deflt_kdfs[]` are published here:
//! `HKDF`, `HKDF-SHA256`, `HKDF-SHA384`, `HKDF-SHA512` and `TLS13-KDF`, whose unit is
//! `providers/implementations/kdfs/hkdf.c` (D376); `SSKDF` and `X963KDF`, whose unit is
//! `providers/implementations/kdfs/sskdf.c`; `X942KDF-ASN1`, whose unit is
//! `providers/implementations/kdfs/x942kdf.c`; `PKCS12KDF`, whose unit is
//! `providers/implementations/kdfs/pkcs12kdf.c` (`docs/DECISIONS.md` D373); `SSHKDF`, whose unit
//! is `providers/implementations/kdfs/sshkdf.c` (D374); `PBKDF2`, whose unit is
//! `providers/implementations/kdfs/pbkdf2.c` (D375); `TLS1-PRF`, whose unit is
//! `providers/implementations/kdfs/tls1_prf.c`; `KBKDF`, whose unit is
//! `providers/implementations/kdfs/kbkdf.c`; `SCRYPT`, whose unit is
//! `providers/implementations/kdfs/scrypt.c`; `KRB5KDF`, whose unit is
//! `providers/implementations/kdfs/krb5kdf.c`; and `HMAC-DRBG-KDF`, whose unit is
//! `providers/implementations/kdfs/hmacdrbg_kdf.c`. Each unit is transcribed **whole** (D327's
//! rule), and the two rows `DH_KDF_X9_42` and `ECDH_KDF_X9_62` fetch are among them:
//! `DH_KDF_X9_42` reaches `X942KDF-ASN1` and `ECDH_KDF_X9_62` reaches `X963KDF`, so with this
//! module both wrappers have a real provider row to fetch (`docs/DECISIONS.md` D296, D346).
//!
//! ## The provider rows, and the census's order
//!
//! `deflt_kdfs[]` carries nineteen rows on this profile and the sixteen published here are its
//! first five (`HKDF`, `HKDF-SHA256`, `HKDF-SHA384`, `HKDF-SHA512`, `TLS13-KDF`), then its sixth
//! (`SSKDF`), seventh (`PBKDF2`), eighth (`PKCS12KDF`), ninth (`SSHKDF`), tenth (`X963KDF`),
//! eleventh (`TLS1-PRF`), twelfth (`KBKDF`), thirteenth (`X942KDF-ASN1`), fourteenth (`SCRYPT`),
//! fifteenth (`KRB5KDF`) and sixteenth (`HMAC-DRBG-KDF`) — so the table below is the authority's
//! order and a **subsequence** of it, which `gen_provider_algorithms.py` checks (D244). Each
//! row's alias sequence is `prov/names.h`'s.
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

use core::ffi::{c_char, c_int, c_uchar, c_uint, c_ulong, c_void, CStr};
use core::ptr;

use crate::context::dispatch::{OsslDispatch, OSSL_DISPATCH_END};
// The per-context thread pool D397 landed (`crypto/thread/internal.c` + `crypto/thread/arch.c`).
// Argon2's threaded fill is their first caller: `ossl_get_avail_threads` is what
// `kdf_argon2_derive`'s thread-pool bound reads, and the trio drive `fill_segment_thr`.
use crate::context::thread_data::{
    ossl_crypto_thread_clean, ossl_crypto_thread_join, ossl_crypto_thread_start,
    ossl_get_avail_threads,
};
use crate::der_writer::{
    ossl_DER_w_begin_sequence, ossl_DER_w_end_sequence, ossl_DER_w_octet_string,
    ossl_DER_w_octet_string_uint32, ossl_DER_w_precompiled,
};
use crate::des::DES_set_odd_parity;
use crate::evp::cipher::{
    EVP_CIPHER_fetch, EVP_CIPHER_free, EVP_CIPHER_get_key_length, EVP_CIPHER_get_nid,
    EVP_CIPHER_is_a, EvpCipher,
};
use crate::evp::cipher_ctx::{
    EVP_CIPHER_CTX_free, EVP_CIPHER_CTX_get_block_size, EVP_CIPHER_CTX_get_key_length,
    EVP_CIPHER_CTX_new, EVP_CIPHER_CTX_reset, EVP_CIPHER_CTX_set_key_length,
    EVP_CIPHER_CTX_set_padding, EVP_EncryptFinal_ex, EVP_EncryptInit_ex, EVP_EncryptUpdate,
    EvpCipherCtx,
};
use crate::evp::digest::{
    EVP_DigestFinal_ex, EVP_DigestInit, EVP_DigestInit_ex, EVP_DigestInit_ex2, EVP_DigestUpdate,
    EVP_MD_CTX_copy_ex, EVP_MD_CTX_free, EVP_MD_CTX_new, EVP_MD_fetch, EVP_MD_free,
    EVP_MD_get0_name, EVP_MD_get_block_size, EVP_MD_get_size, EVP_MD_up_ref, EVP_MD_xof,
};
use crate::evp::kdf::{
    OSSL_FUNC_KDF_DERIVE, OSSL_FUNC_KDF_DUPCTX, OSSL_FUNC_KDF_FREECTX,
    OSSL_FUNC_KDF_GETTABLE_CTX_PARAMS, OSSL_FUNC_KDF_GET_CTX_PARAMS, OSSL_FUNC_KDF_NEWCTX,
    OSSL_FUNC_KDF_RESET, OSSL_FUNC_KDF_SETTABLE_CTX_PARAMS, OSSL_FUNC_KDF_SET_CTX_PARAMS,
};
use crate::evp::mac::{
    EVP_MAC_CTX_dup, EVP_MAC_CTX_free, EVP_MAC_CTX_get0_mac, EVP_MAC_CTX_get_mac_size,
    EVP_MAC_CTX_new, EVP_MAC_CTX_set_params, EVP_MAC_fetch, EVP_MAC_final, EVP_MAC_free,
    EVP_MAC_get0_name, EVP_MAC_init, EVP_MAC_is_a, EVP_MAC_update, EVP_Q_mac, EvpMacCtx,
};
use crate::evp::p5_crpt2::ossl_pkcs5_pbkdf2_hmac_ex;
use crate::evp::pbe::{
    OSSL_KDF_PARAM_SCRYPT_MAXMEM, OSSL_KDF_PARAM_SCRYPT_N, OSSL_KDF_PARAM_SCRYPT_P,
    OSSL_KDF_PARAM_SCRYPT_R,
};
use crate::evp::pkey_ctx::{
    EVP_KDF_HKDF_MODE_EXPAND_ONLY, EVP_KDF_HKDF_MODE_EXTRACT_AND_EXPAND,
    EVP_KDF_HKDF_MODE_EXTRACT_ONLY,
};
use crate::mac::hmac::{
    HMAC_CTX_copy, HMAC_CTX_free, HMAC_CTX_new, HMAC_Final, HMAC_Init_ex, HMAC_Update, HmacCtx,
};
use crate::packet::{
    WPACKET_cleanup, WPACKET_close, WPACKET_finish, WPACKET_get_curr, WPACKET_get_total_written,
    WPACKET_init_der, WPACKET_init_null_der, WPACKET_init_static_len, WPACKET_memcpy,
    WPACKET_put_bytes_u16, WPACKET_start_sub_packet_len__, WPACKET_sub_memcpy__, Wpacket,
};
use crate::params::{
    ossl_param_get1_concat_octet_string, ossl_param_get1_octet_string_from_param,
    OSSL_PARAM_construct_end, OSSL_PARAM_construct_octet_string, OSSL_PARAM_construct_size_t,
    OSSL_PARAM_construct_utf8_string, OSSL_PARAM_get_int, OSSL_PARAM_get_octet_string,
    OSSL_PARAM_get_octet_string_ptr, OSSL_PARAM_get_size_t, OSSL_PARAM_get_uint32,
    OSSL_PARAM_get_uint64, OSSL_PARAM_get_utf8_string_ptr, OSSL_PARAM_set_int,
    OSSL_PARAM_set_octet_string, OSSL_PARAM_set_size_t, OSSL_PARAM_set_utf8_string, OsslParam, END,
    OSSL_PARAM_UTF8_STRING,
};
use crate::provider::activate::OsslAlgorithm;
use crate::provider::cipher::{
    param_int, param_octet_string, param_size_t, param_uint32, param_uint64, param_utf8_string,
};
use crate::provider::ctx::prov_libctx_of;
use crate::provider::rand::{ossl_drbg_hmac_generate, ossl_drbg_hmac_init, ProvDrbgHmac};
use crate::provider::util::prov_digest::{
    ossl_prov_digest_copy, ossl_prov_digest_load, ossl_prov_digest_load_from_params,
    ossl_prov_digest_md, ossl_prov_digest_reset, ProvDigest,
};
use crate::provider::util::{
    ossl_prov_cipher_cipher, ossl_prov_cipher_copy, ossl_prov_cipher_engine, ossl_prov_cipher_load,
    ossl_prov_cipher_reset, ossl_prov_macctx_load, ossl_prov_memdup, ProvCipher,
};
use crate::runtime::bio::print::BIO_snprintf;
use crate::runtime::err::err_reasons;
use crate::runtime::err::{err_sites, raise_site, raise_site_data, raise_site_dynamic};
use crate::runtime::mem::{
    cleanse, CRYPTO_calloc, CRYPTO_clear_free, CRYPTO_clear_realloc, CRYPTO_free, CRYPTO_malloc,
    CRYPTO_memcmp, CRYPTO_strdup, CRYPTO_zalloc,
};
use crate::runtime::obj::NID_des_ede3_cbc;
use crate::runtime::secure::{CRYPTO_secure_calloc, CRYPTO_secure_clear_free};
use crate::runtime::str::{OPENSSL_strcasecmp, OPENSSL_strncasecmp};
use crate::runtime::thread_arch::{CryptoThreadRetval, CryptoThreadRoutine};

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
/// `OSSL_KDF_PARAM_PASSWORD` — `core_names.h:299` (`"pass"`).
const OSSL_KDF_PARAM_PASSWORD: *const c_char = c"pass".as_ptr();
/// `OSSL_KDF_PARAM_ITER` — `core_names.h:290` (`"iter"`).
const OSSL_KDF_PARAM_ITER: *const c_char = c"iter".as_ptr();
/// `OSSL_KDF_PARAM_THREADS` — `core_names.h:315` (`"threads"`), one of Argon2's six keys.
const OSSL_KDF_PARAM_THREADS: *const c_char = c"threads".as_ptr();
/// `OSSL_KDF_PARAM_EARLY_CLEAN` — `core_names.h:282` (`"early_clean"`).
const OSSL_KDF_PARAM_EARLY_CLEAN: *const c_char = c"early_clean".as_ptr();
/// `OSSL_KDF_PARAM_ARGON2_AD` — `core_names.h:273` (`"ad"`).
const OSSL_KDF_PARAM_ARGON2_AD: *const c_char = c"ad".as_ptr();
/// `OSSL_KDF_PARAM_ARGON2_LANES` — `core_names.h:274` (`"lanes"`).
const OSSL_KDF_PARAM_ARGON2_LANES: *const c_char = c"lanes".as_ptr();
/// `OSSL_KDF_PARAM_ARGON2_MEMCOST` — `core_names.h:275` (`"memcost"`).
const OSSL_KDF_PARAM_ARGON2_MEMCOST: *const c_char = c"memcost".as_ptr();
/// `OSSL_KDF_PARAM_ARGON2_VERSION` — `core_names.h:276` (`"version"`).
const OSSL_KDF_PARAM_ARGON2_VERSION: *const c_char = c"version".as_ptr();
/// `OSSL_MAC_PARAM_KEY` — `core_names.h:350` (`"key"`), the key `blake2b_mac` sets.
const OSSL_MAC_PARAM_KEY: *const c_char = c"key".as_ptr();
/// `OSSL_KDF_PARAM_PKCS12_ID` — `core_names.h:300` (`"id"`).
const OSSL_KDF_PARAM_PKCS12_ID: *const c_char = c"id".as_ptr();
/// `OSSL_KDF_PARAM_SSHKDF_XCGHASH` — `core_names.h:314`.
const OSSL_KDF_PARAM_SSHKDF_XCGHASH: *const c_char = c"xcghash".as_ptr();
/// `OSSL_KDF_PARAM_SSHKDF_SESSION_ID` — `core_names.h:312`.
const OSSL_KDF_PARAM_SSHKDF_SESSION_ID: *const c_char = c"session_id".as_ptr();
/// `OSSL_KDF_PARAM_SSHKDF_TYPE` — `core_names.h:313`.
const OSSL_KDF_PARAM_SSHKDF_TYPE: *const c_char = c"type".as_ptr();
/// `OSSL_KDF_PARAM_PKCS5` — `core_names.h:301` (`"pkcs5"`).
const OSSL_KDF_PARAM_PKCS5: *const c_char = c"pkcs5".as_ptr();
/// `SN_sha1` — `include/openssl/obj_mac.h`, the short name `ossl_prov_digest_load_from_params`
/// is asked for. The authority spells it `"SHA1"`, not `"SHA-1"` or `"sha1"`.
const SN_SHA1: *const c_char = c"SHA1".as_ptr();
/// `PKCS5_DEFAULT_ITER` — `include/openssl/evp.h:45`.
const PKCS5_DEFAULT_ITER: u64 = 2048;
/// `KDF_PBKDF2_MIN_KEY_LEN_BITS` — `pbkdf2.c:39`.
const KDF_PBKDF2_MIN_KEY_LEN_BITS: usize = 112;
/// `KDF_PBKDF2_MAX_KEY_LEN_DIGEST_RATIO` — `pbkdf2.c:40`.
const KDF_PBKDF2_MAX_KEY_LEN_DIGEST_RATIO: usize = 0xFFFF_FFFF;
/// `KDF_PBKDF2_MIN_ITERATIONS` — `pbkdf2.c:41`.
const KDF_PBKDF2_MIN_ITERATIONS: u64 = 1000;
/// `KDF_PBKDF2_MIN_SALT_LEN` — `pbkdf2.c:42`, `(128 / 8)`.
const KDF_PBKDF2_MIN_SALT_LEN: c_int = 128 / 8;
/// `HKDF_MAXBUF` — `hkdf.c:42`, the static buffer `prov_tls13_hkdf_expand` packs into.
const HKDF_MAXBUF: usize = 2048;
/// `HKDF_MAX_INFOS` — `hkdf.c:44`.
const HKDF_MAX_INFOS: usize = 5;
/// `OSSL_KDF_PARAM_MODE` — `core_names.h:298`.
const OSSL_KDF_PARAM_MODE: *const c_char = c"mode".as_ptr();
/// `OSSL_KDF_PARAM_PREFIX` — `core_names.h:302`.
const OSSL_KDF_PARAM_PREFIX: *const c_char = c"prefix".as_ptr();
/// `OSSL_KDF_PARAM_LABEL` — `core_names.h:295`.
const OSSL_KDF_PARAM_LABEL: *const c_char = c"label".as_ptr();
/// `OSSL_KDF_PARAM_DATA` — `core_names.h:280`.
const OSSL_KDF_PARAM_DATA: *const c_char = c"data".as_ptr();
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
/// `__FILE__` for `pkcs12kdf.c`, measured the same way.
const FILE_PKCS12KDF: *const c_char = c"providers/implementations/kdfs/pkcs12kdf.c".as_ptr();
/// `__FILE__` for `sshkdf.c`, measured the same way.
const FILE_SSHKDF: *const c_char = c"providers/implementations/kdfs/sshkdf.c".as_ptr();
/// `__FILE__` for `pbkdf2.c`, measured the same way.
const FILE_PBKDF2: *const c_char = c"providers/implementations/kdfs/pbkdf2.c".as_ptr();
/// `__FILE__` for `hkdf.c`, measured the same way.
const FILE_HKDF: *const c_char = c"providers/implementations/kdfs/hkdf.c".as_ptr();
/// `__FILE__` for `argon2.c`. `.c.in`-generated, so the spelling is the bare build-relative path
/// (D235's finding for every generated unit in this module).
const FILE_ARGON2: *const c_char = c"providers/implementations/kdfs/argon2.c".as_ptr();
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

// =============================================================================================
// `providers/implementations/kdfs/pkcs12kdf.c` — PKCS12KDF
// =============================================================================================

/// `struct KDF_PKCS12` — `pkcs12kdf.c:42-51`.
#[repr(C)]
pub(crate) struct KdfPkcs12 {
    /// `void *provctx`.
    pub provctx: *mut c_void,
    /// `PROV_DIGEST digest`.
    pub digest: ProvDigest,
    /// `unsigned char *pass` / `size_t pass_len`.
    pub pass: *mut u8,
    pub pass_len: usize,
    /// `unsigned char *salt` / `size_t salt_len`.
    pub salt: *mut u8,
    pub salt_len: usize,
    /// `uint64_t iter`.
    pub iter: u64,
    /// `int id` — the PKCS12 id byte (`pkcs12kdf.c:49`).
    pub id: c_int,
}

/// The `pkcs12_set_ctx_params_decoder` keys this profile's generated switch raises for, each with
/// its (field id, raise site). Every key names its own field, so the field id is the order the
/// generated struct declares them in; the generated `strcmp`-tree at `pkcs12kdf.c:284-372`
/// raises `PROV_R_REPEATED_PARAMETER` at the site of the *second* occurrence of any one.
const PKCS12_SET_DECODER_KEYS: [(&err_sites::ErrSite, *const c_char, u32); 7] = [
    (&err_sites::PROV_PKCS12KDF_288, OSSL_KDF_PARAM_DIGEST, 0),
    (&err_sites::PROV_PKCS12KDF_299, OSSL_ALG_PARAM_ENGINE, 1),
    (&err_sites::PROV_PKCS12KDF_316, OSSL_KDF_PARAM_PKCS12_ID, 2),
    (&err_sites::PROV_PKCS12KDF_327, OSSL_KDF_PARAM_ITER, 3),
    (&err_sites::PROV_PKCS12KDF_343, OSSL_KDF_PARAM_PASSWORD, 4),
    (&err_sites::PROV_PKCS12KDF_354, OSSL_KDF_PARAM_PROPERTIES, 5),
    (&err_sites::PROV_PKCS12KDF_366, OSSL_KDF_PARAM_SALT, 6),
];

/// The `pkcs12_get_ctx_params_decoder` key, `pkcs12kdf.c:448-456`.
const PKCS12_GET_DECODER_KEYS: [(&err_sites::ErrSite, *const c_char, u32); 1] =
    [(&err_sites::PROV_PKCS12KDF_451, OSSL_KDF_PARAM_SIZE, 0)];

/// `static const OSSL_PARAM pkcs12_set_ctx_params_list[]` — `pkcs12kdf.c:249-257`.
static PKCS12_SETTABLE_CTX_PARAMS: [OsslParam; 7] = [
    param_utf8_string(OSSL_KDF_PARAM_PROPERTIES),
    param_utf8_string(OSSL_KDF_PARAM_DIGEST),
    param_octet_string(OSSL_KDF_PARAM_PASSWORD),
    param_octet_string(OSSL_KDF_PARAM_SALT),
    param_uint64(OSSL_KDF_PARAM_ITER),
    param_int(OSSL_KDF_PARAM_PKCS12_ID),
    END,
];

/// `static const OSSL_PARAM pkcs12_get_ctx_params_list[]` — `pkcs12kdf.c:427-430`.
static PKCS12_GETTABLE_CTX_PARAMS: [OsslParam; 2] = [param_size_t(OSSL_KDF_PARAM_SIZE), END];

/// `static int pkcs12kdf_derive(...)` — `pkcs12kdf.c:55-141`. **PKCS12 compatible key/IV
/// generation**: the authority's construction, transcribed with its `goto end` as a labelled
/// block whose single exit does the same four `OPENSSL_free`s and the `EVP_MD_CTX_free`.
///
/// # Safety
/// `md_type` is a live digest; `pass`/`salt` are live for their lengths; `out` is writable for
/// `n` bytes.
#[allow(clippy::too_many_arguments)] // mirrors the authority's signature exactly
unsafe fn pkcs12kdf_derive(
    pass: *const u8,
    passlen: usize,
    salt: *const u8,
    saltlen: usize,
    id: c_int,
    iter: u64,
    md_type: *const crate::evp::digest::EvpMd,
    out: *mut u8,
    n_in: usize,
) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        let ctx = EVP_MD_CTX_new();
        let mut b: *mut u8 = ptr::null_mut();
        let mut d: *mut u8 = ptr::null_mut();
        let mut i_buf: *mut u8 = ptr::null_mut();
        let mut ai: *mut u8 = ptr::null_mut();
        let mut ret: c_int = 0;
        let mut n = n_in;
        let mut out = out;

        if ctx.is_null() {
            raise_site(&err_sites::PROV_PKCS12KDF_67);
        } else {
            let vi = EVP_MD_get_block_size(md_type);
            let ui = EVP_MD_get_size(md_type);
            'end: {
                if ui <= 0 || vi <= 0 {
                    raise_site(&err_sites::PROV_PKCS12KDF_73);
                    break 'end;
                }
                let u = ui as usize;
                let v = vi as usize;
                d = CRYPTO_malloc(v, FILE_PKCS12KDF, LINE).cast();
                ai = CRYPTO_malloc(u, FILE_PKCS12KDF, LINE).cast();
                b = CRYPTO_malloc(v + 1, FILE_PKCS12KDF, LINE).cast();
                let slen = v * saltlen.div_ceil(v);
                let plen = if passlen != 0 {
                    v * passlen.div_ceil(v)
                } else {
                    0
                };
                let ilen = slen + plen;
                i_buf = CRYPTO_malloc(ilen, FILE_PKCS12KDF, LINE).cast();
                if d.is_null() || ai.is_null() || b.is_null() || i_buf.is_null() {
                    break 'end;
                }
                for i in 0..v {
                    *d.add(i) = id as u8;
                }
                let mut p = i_buf;
                for i in 0..slen {
                    *p = *salt.add(i % saltlen);
                    p = p.add(1);
                }
                for i in 0..plen {
                    *p = *pass.add(i % passlen);
                    p = p.add(1);
                }
                loop {
                    if EVP_DigestInit_ex(ctx, md_type, ptr::null_mut()) == 0
                        || EVP_DigestUpdate(ctx, d.cast(), v) == 0
                        || EVP_DigestUpdate(ctx, i_buf.cast(), ilen) == 0
                        || EVP_DigestFinal_ex(ctx, ai, ptr::null_mut()) == 0
                    {
                        break 'end;
                    }
                    let mut iter_cnt: u64 = 1;
                    while iter_cnt < iter {
                        if EVP_DigestInit_ex(ctx, md_type, ptr::null_mut()) == 0
                            || EVP_DigestUpdate(ctx, ai.cast(), u) == 0
                            || EVP_DigestFinal_ex(ctx, ai, ptr::null_mut()) == 0
                        {
                            break 'end;
                        }
                        iter_cnt += 1;
                    }
                    let copy = if n < u { n } else { u };
                    ptr::copy_nonoverlapping(ai, out, copy);
                    if u >= n {
                        ret = 1;
                        break;
                    }
                    n -= u;
                    out = out.add(u);
                    for j in 0..v {
                        *b.add(j) = *ai.add(j % u);
                    }
                    let mut j = 0usize;
                    while j < ilen {
                        let ij = i_buf.add(j);
                        let mut c: u16 = 1;
                        let mut k = v;
                        while k > 0 {
                            k -= 1;
                            c += *ij.add(k) as u16 + *b.add(k) as u16;
                            *ij.add(k) = c as u8;
                            c >>= 8;
                        }
                        j += v;
                    }
                }
            }
        }

        CRYPTO_free(ai.cast(), FILE_PKCS12KDF, LINE);
        CRYPTO_free(b.cast(), FILE_PKCS12KDF, LINE);
        CRYPTO_free(d.cast(), FILE_PKCS12KDF, LINE);
        CRYPTO_free(i_buf.cast(), FILE_PKCS12KDF, LINE);
        EVP_MD_CTX_free(ctx);
        ret
    }
}

/// `static void *kdf_pkcs12_new(void *provctx)` — `pkcs12kdf.c:143-155`.
///
/// # Safety
/// The dispatch contract.
unsafe extern "C" fn pkcs12kdf_new(provctx: *mut c_void) -> *mut c_void {
    // SAFETY: the caller's contract.
    unsafe {
        if is_running() == 0 {
            return ptr::null_mut();
        }
        let ctx = CRYPTO_zalloc(core::mem::size_of::<KdfPkcs12>(), FILE_PKCS12KDF, LINE)
            .cast::<KdfPkcs12>();
        if ctx.is_null() {
            return ptr::null_mut();
        }
        (*ctx).provctx = provctx;
        ctx.cast()
    }
}

/// `static void kdf_pkcs12_cleanup(KDF_PKCS12 *ctx)` — `pkcs12kdf.c:157-163`.
///
/// # Safety
/// `ctx` is a live context.
unsafe fn pkcs12kdf_cleanup(ctx: *mut KdfPkcs12) {
    // SAFETY: `ctx` is live per the contract.
    unsafe {
        ossl_prov_digest_reset(ptr::addr_of_mut!((*ctx).digest));
        CRYPTO_free((*ctx).salt.cast(), FILE_PKCS12KDF, LINE);
        CRYPTO_clear_free((*ctx).pass.cast(), (*ctx).pass_len, FILE_PKCS12KDF, LINE);
        ptr::write_bytes(ctx.cast::<u8>(), 0, core::mem::size_of::<KdfPkcs12>());
    }
}

/// `static void kdf_pkcs12_free(void *vctx)` — `pkcs12kdf.c:165-173`.
///
/// # Safety
/// The dispatch contract.
unsafe extern "C" fn pkcs12kdf_free(vctx: *mut c_void) {
    // SAFETY: `vctx` is NULL or a live context.
    unsafe {
        if !vctx.is_null() {
            pkcs12kdf_cleanup(vctx.cast::<KdfPkcs12>());
            CRYPTO_free(vctx, FILE_PKCS12KDF, LINE);
        }
    }
}

/// `static void kdf_pkcs12_reset(void *vctx)` — `pkcs12kdf.c:175-182`. The `provctx` is saved
/// across the cleanup's `memset` because the whole struct is cleared.
///
/// # Safety
/// The dispatch contract.
unsafe extern "C" fn pkcs12kdf_reset(vctx: *mut c_void) {
    // SAFETY: `vctx` is a live context per the contract.
    unsafe {
        let ctx = vctx.cast::<KdfPkcs12>();
        let provctx = (*ctx).provctx;
        pkcs12kdf_cleanup(ctx);
        (*ctx).provctx = provctx;
    }
}

/// `static void *kdf_pkcs12_dup(void *vctx)` — `pkcs12kdf.c:184-205`.
///
/// # Safety
/// The dispatch contract.
unsafe extern "C" fn pkcs12kdf_dup(vctx: *mut c_void) -> *mut c_void {
    // SAFETY: the caller's contract.
    unsafe {
        let src = vctx.cast::<KdfPkcs12>();
        let dest = pkcs12kdf_new((*src).provctx).cast::<KdfPkcs12>();
        if dest.is_null() {
            return ptr::null_mut();
        }
        if ossl_prov_memdup(
            (*src).salt.cast(),
            (*src).salt_len,
            ptr::addr_of_mut!((*dest).salt),
            ptr::addr_of_mut!((*dest).salt_len),
        ) == 0
            || ossl_prov_memdup(
                (*src).pass.cast(),
                (*src).pass_len,
                ptr::addr_of_mut!((*dest).pass),
                ptr::addr_of_mut!((*dest).pass_len),
            ) == 0
            || ossl_prov_digest_copy(
                ptr::addr_of_mut!((*dest).digest),
                ptr::addr_of!((*src).digest),
            ) == 0
        {
            pkcs12kdf_free(dest.cast());
            return ptr::null_mut();
        }
        (*dest).iter = (*src).iter;
        (*dest).id = (*src).id;
        dest.cast()
    }
}

/// `static int pkcs12kdf_set_membuf(unsigned char **buffer, size_t *buflen,
/// const OSSL_PARAM *p)` — `pkcs12kdf.c:207-222`.
///
/// # Safety
/// `buffer`/`buflen` are live; `p` is a live parameter.
unsafe fn pkcs12kdf_set_membuf(
    buffer: *mut *mut u8,
    buflen: *mut usize,
    p: *const OsslParam,
) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        CRYPTO_clear_free((*buffer).cast(), *buflen, FILE_PKCS12KDF, LINE);
        *buffer = ptr::null_mut();
        *buflen = 0;

        if (*p).data_size == 0 {
            let m = CRYPTO_malloc(1, FILE_PKCS12KDF, LINE).cast::<u8>();
            if m.is_null() {
                return 0;
            }
            *buffer = m;
        } else if !(*p).data.is_null()
            && OSSL_PARAM_get_octet_string(p.cast_mut(), buffer.cast(), 0, buflen) == 0
        {
            return 0;
        }
        1
    }
}

/// `static int kdf_pkcs12_derive(void *vctx, unsigned char *key, size_t keylen, const OSSL_PARAM
/// params[])` — `pkcs12kdf.c:224-246`.
///
/// # Safety
/// The dispatch contract.
unsafe extern "C" fn pkcs12kdf_ctx_derive(
    vctx: *mut c_void,
    key: *mut u8,
    keylen: usize,
    params: *const OsslParam,
) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        if is_running() == 0 || pkcs12kdf_set_ctx_params(vctx, params) == 0 {
            return 0;
        }
        let ctx = vctx.cast::<KdfPkcs12>();
        if (*ctx).pass.is_null() {
            return fail_at(&err_sites::PROV_PKCS12KDF_232);
        }
        if (*ctx).salt.is_null() {
            return fail_at(&err_sites::PROV_PKCS12KDF_237);
        }
        let md = ossl_prov_digest_md(ptr::addr_of!((*ctx).digest));
        pkcs12kdf_derive(
            (*ctx).pass,
            (*ctx).pass_len,
            (*ctx).salt,
            (*ctx).salt_len,
            (*ctx).id,
            (*ctx).iter,
            md,
            key,
            keylen,
        )
    }
}

/// `static int kdf_pkcs12_set_ctx_params(void *vctx, const OSSL_PARAM params[])` —
/// `pkcs12kdf.c:260-297`, with its generated switch replaced by the field-keyed repeat check and
/// one `OSSL_PARAM_locate_const` per key (D305's reading).
///
/// # Safety
/// The dispatch contract.
unsafe extern "C" fn pkcs12kdf_set_ctx_params(
    vctx: *mut c_void,
    params: *const OsslParam,
) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        if vctx.is_null() {
            return 0;
        }
        if let Some(site) = repeated_param_site_by_field(params, &PKCS12_SET_DECODER_KEYS) {
            return fail_at(site);
        }
        let ctx = vctx.cast::<KdfPkcs12>();
        let provctx = prov_libctx_of((*ctx).provctx);

        if ossl_prov_digest_load(
            ptr::addr_of_mut!((*ctx).digest),
            locate_const(params, OSSL_KDF_PARAM_DIGEST),
            locate_const(params, OSSL_KDF_PARAM_PROPERTIES),
            locate_const(params, OSSL_ALG_PARAM_ENGINE),
            provctx,
        ) == 0
        {
            return 0;
        }

        let pw = locate_const(params, OSSL_KDF_PARAM_PASSWORD);
        if !pw.is_null()
            && pkcs12kdf_set_membuf(
                ptr::addr_of_mut!((*ctx).pass),
                ptr::addr_of_mut!((*ctx).pass_len),
                pw,
            ) == 0
        {
            return 0;
        }

        let salt = locate_const(params, OSSL_KDF_PARAM_SALT);
        if !salt.is_null()
            && pkcs12kdf_set_membuf(
                ptr::addr_of_mut!((*ctx).salt),
                ptr::addr_of_mut!((*ctx).salt_len),
                salt,
            ) == 0
        {
            return 0;
        }

        let p12id = locate_const(params, OSSL_KDF_PARAM_PKCS12_ID);
        if !p12id.is_null() && OSSL_PARAM_get_int(p12id, ptr::addr_of_mut!((*ctx).id)) == 0 {
            return 0;
        }

        let iter = locate_const(params, OSSL_KDF_PARAM_ITER);
        if !iter.is_null() && OSSL_PARAM_get_uint64(iter, ptr::addr_of_mut!((*ctx).iter)) == 0 {
            return 0;
        }
        1
    }
}

/// `static int kdf_pkcs12_get_ctx_params(void *vctx, OSSL_PARAM params[])` —
/// `pkcs12kdf.c:311-322`.
///
/// # Safety
/// The dispatch contract.
unsafe extern "C" fn pkcs12kdf_get_ctx_params(vctx: *mut c_void, params: *mut OsslParam) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        if vctx.is_null() {
            return 0;
        }
        if let Some(site) =
            repeated_param_site_by_field(params.cast_const(), &PKCS12_GET_DECODER_KEYS)
        {
            return fail_at(site);
        }
        let p = locate_const(params, OSSL_KDF_PARAM_SIZE);
        if !p.is_null() && OSSL_PARAM_set_size_t(p.cast_mut(), usize::MAX) == 0 {
            return 0;
        }
        1
    }
}

/// `static const OSSL_PARAM *kdf_pkcs12_settable_ctx_params(void *ctx, void *provctx)` —
/// `pkcs12kdf.c:299-303`.
///
/// # Safety
/// The dispatch contract.
unsafe extern "C" fn pkcs12kdf_settable_ctx_params(
    _ctx: *mut c_void,
    _provctx: *mut c_void,
) -> *const OsslParam {
    PKCS12_SETTABLE_CTX_PARAMS.as_ptr()
}

/// `static const OSSL_PARAM *kdf_pkcs12_gettable_ctx_params(void *ctx, void *provctx)` —
/// `pkcs12kdf.c:324-328`.
///
/// # Safety
/// The dispatch contract.
unsafe extern "C" fn pkcs12kdf_gettable_ctx_params(
    _ctx: *mut c_void,
    _provctx: *mut c_void,
) -> *const OsslParam {
    PKCS12_GETTABLE_CTX_PARAMS.as_ptr()
}

/// `const OSSL_DISPATCH ossl_kdf_pkcs12_functions[]` — `pkcs12kdf.c:330-343`.
pub(crate) static PKCS12KDF_FUNCTIONS: [OsslDispatch; 10] = [
    OsslDispatch {
        function_id: OSSL_FUNC_KDF_NEWCTX,
        function: pkcs12kdf_new as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KDF_DUPCTX,
        function: pkcs12kdf_dup as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KDF_FREECTX,
        function: pkcs12kdf_free as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KDF_RESET,
        function: pkcs12kdf_reset as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KDF_DERIVE,
        function: pkcs12kdf_ctx_derive as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KDF_SETTABLE_CTX_PARAMS,
        function: pkcs12kdf_settable_ctx_params as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KDF_SET_CTX_PARAMS,
        function: pkcs12kdf_set_ctx_params as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KDF_GETTABLE_CTX_PARAMS,
        function: pkcs12kdf_gettable_ctx_params as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KDF_GET_CTX_PARAMS,
        function: pkcs12kdf_get_ctx_params as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_DISPATCH_END,
        function: ptr::null_mut(),
    },
];

// =============================================================================================
// `providers/implementations/kdfs/sshkdf.c` — SSHKDF (RFC 4253 §7.2)
// =============================================================================================

/// `struct KDF_SSHKDF` — `sshkdf.c:46-57`, without its FIPS indicator field.
#[repr(C)]
pub(crate) struct KdfSshkdf {
    /// `void *provctx`.
    pub provctx: *mut c_void,
    /// `PROV_DIGEST digest`.
    pub digest: ProvDigest,
    /// `unsigned char *key` / `size_t key_len` — `K`.
    pub key: *mut u8,
    pub key_len: usize,
    /// `unsigned char *xcghash` / `size_t xcghash_len` — `H`.
    pub xcghash: *mut u8,
    pub xcghash_len: usize,
    /// `char type` — `X`, one of `'A'`..`'F'`.
    pub type_: c_char,
    /// `unsigned char *session_id` / `size_t session_id_len`.
    pub session_id: *mut u8,
    pub session_id_len: usize,
}

/// The `sshkdf_set_ctx_params_decoder` keys this profile's generated switch raises for, each with
/// its (field id, raise site). The two FIPS `*-check` keys (`:291`, `:341`) are compiled out. Every
/// key names its own field, so the field id is the site's own identity; the generated `strcmp`-tree
/// at `sshkdf.c:259-403` raises `PROV_R_REPEATED_PARAMETER` at the second occurrence of any one.
const SSHKDF_SET_DECODER_KEYS: [(&err_sites::ErrSite, *const c_char, u32); 7] = [
    (&err_sites::PROV_SSHKDF_301, OSSL_KDF_PARAM_DIGEST, 0),
    (&err_sites::PROV_SSHKDF_317, OSSL_ALG_PARAM_ENGINE, 1),
    (&err_sites::PROV_SSHKDF_351, OSSL_KDF_PARAM_KEY, 2),
    (&err_sites::PROV_SSHKDF_364, OSSL_KDF_PARAM_PROPERTIES, 3),
    (
        &err_sites::PROV_SSHKDF_375,
        OSSL_KDF_PARAM_SSHKDF_SESSION_ID,
        4,
    ),
    (&err_sites::PROV_SSHKDF_386, OSSL_KDF_PARAM_SSHKDF_TYPE, 5),
    (
        &err_sites::PROV_SSHKDF_397,
        OSSL_KDF_PARAM_SSHKDF_XCGHASH,
        6,
    ),
];

/// The `sshkdf_get_ctx_params_decoder` key, `sshkdf.c:533-541` (the FIPS `fips-indicator` at
/// `:524` is compiled out).
const SSHKDF_GET_DECODER_KEYS: [(&err_sites::ErrSite, *const c_char, u32); 1] =
    [(&err_sites::PROV_SSHKDF_536, OSSL_KDF_PARAM_SIZE, 0)];

/// `static const OSSL_PARAM sshkdf_set_ctx_params_list[]` — `sshkdf.c:215-229`, without the two
/// FIPS entries.
static SSHKDF_SETTABLE_CTX_PARAMS: [OsslParam; 7] = [
    param_utf8_string(OSSL_KDF_PARAM_PROPERTIES),
    param_utf8_string(OSSL_KDF_PARAM_DIGEST),
    param_octet_string(OSSL_KDF_PARAM_KEY),
    param_octet_string(OSSL_KDF_PARAM_SSHKDF_XCGHASH),
    param_octet_string(OSSL_KDF_PARAM_SSHKDF_SESSION_ID),
    param_utf8_string(OSSL_KDF_PARAM_SSHKDF_TYPE),
    END,
];

/// `static const OSSL_PARAM sshkdf_get_ctx_params_list[]` — `sshkdf.c:489-495`, without its FIPS
/// entry.
static SSHKDF_GETTABLE_CTX_PARAMS: [OsslParam; 2] = [param_size_t(OSSL_KDF_PARAM_SIZE), END];

/// `static int SSHKDF(...)` — `sshkdf.c:586-660`. RFC 4253 §7.2's key derivation: the first hash
/// covers `K || H || X || session_id`, and every later block re-hashes `K || H || <key so far>`.
/// The authority's `goto out` is a labelled block whose single exit does the same
/// `EVP_MD_CTX_free` and `OPENSSL_cleanse`.
///
/// # Safety
/// `md_type` is a live digest; `key`/`xcghash`/`session_id` are live for their lengths; `okey` is
/// writable for `okey_len` bytes.
#[allow(clippy::too_many_arguments)] // mirrors the authority's signature exactly
unsafe fn sshkdf(
    md_type: *const crate::evp::digest::EvpMd,
    key: *const u8,
    key_len: usize,
    xcghash: *const u8,
    xcghash_len: usize,
    session_id: *const u8,
    session_id_len: usize,
    type_: c_char,
    okey: *mut u8,
    okey_len: usize,
) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        let mut digest = [0u8; EVP_MAX_MD_SIZE];
        let mut dsize: c_uint = 0;
        let mut ret: c_int = 0;

        let md = EVP_MD_CTX_new();
        if md.is_null() {
            return 0;
        }

        'out: {
            if EVP_DigestInit_ex(md, md_type, ptr::null_mut()) == 0 {
                break 'out;
            }
            if EVP_DigestUpdate(md, key.cast(), key_len) == 0 {
                break 'out;
            }
            if EVP_DigestUpdate(md, xcghash.cast(), xcghash_len) == 0 {
                break 'out;
            }
            if EVP_DigestUpdate(md, ptr::addr_of!(type_).cast(), 1) == 0 {
                break 'out;
            }
            if EVP_DigestUpdate(md, session_id.cast(), session_id_len) == 0 {
                break 'out;
            }
            if EVP_DigestFinal_ex(md, digest.as_mut_ptr(), &mut dsize) == 0 {
                break 'out;
            }

            if okey_len < dsize as usize {
                ptr::copy_nonoverlapping(digest.as_ptr(), okey, okey_len);
                ret = 1;
                break 'out;
            }

            ptr::copy_nonoverlapping(digest.as_ptr(), okey, dsize as usize);

            let mut cursize = dsize as usize;
            while cursize < okey_len {
                if EVP_DigestInit_ex(md, md_type, ptr::null_mut()) == 0 {
                    break 'out;
                }
                if EVP_DigestUpdate(md, key.cast(), key_len) == 0 {
                    break 'out;
                }
                if EVP_DigestUpdate(md, xcghash.cast(), xcghash_len) == 0 {
                    break 'out;
                }
                if EVP_DigestUpdate(md, okey.cast(), cursize) == 0 {
                    break 'out;
                }
                if EVP_DigestFinal_ex(md, digest.as_mut_ptr(), &mut dsize) == 0 {
                    break 'out;
                }

                if okey_len < cursize + dsize as usize {
                    ptr::copy_nonoverlapping(
                        digest.as_ptr(),
                        okey.add(cursize),
                        okey_len - cursize,
                    );
                    ret = 1;
                    break 'out;
                }

                ptr::copy_nonoverlapping(digest.as_ptr(), okey.add(cursize), dsize as usize);
                cursize += dsize as usize;
            }

            ret = 1;
        }

        EVP_MD_CTX_free(md);
        cleanse(digest.as_mut_ptr(), EVP_MAX_MD_SIZE);
        ret
    }
}

/// `static void *kdf_sshkdf_new(void *provctx)` — `sshkdf.c:59-71`.
///
/// # Safety
/// The dispatch contract.
unsafe extern "C" fn sshkdf_new(provctx: *mut c_void) -> *mut c_void {
    // SAFETY: the caller's contract.
    unsafe {
        if is_running() == 0 {
            return ptr::null_mut();
        }
        let ctx =
            CRYPTO_zalloc(core::mem::size_of::<KdfSshkdf>(), FILE_SSHKDF, LINE).cast::<KdfSshkdf>();
        if !ctx.is_null() {
            (*ctx).provctx = provctx;
        }
        ctx.cast()
    }
}

/// `static void kdf_sshkdf_reset(void *vctx)` — `sshkdf.c:83-94`. The `provctx` is saved across
/// the `memset` because the whole struct is cleared.
///
/// # Safety
/// `vctx` is a context `sshkdf_new` allocated.
unsafe fn sshkdf_reset(vctx: *mut c_void) {
    // SAFETY: `vctx` is a live context per the contract.
    unsafe {
        let ctx = vctx.cast::<KdfSshkdf>();
        let provctx = (*ctx).provctx;

        ossl_prov_digest_reset(ptr::addr_of_mut!((*ctx).digest));
        CRYPTO_clear_free((*ctx).key.cast(), (*ctx).key_len, FILE_SSHKDF, LINE);
        CRYPTO_clear_free((*ctx).xcghash.cast(), (*ctx).xcghash_len, FILE_SSHKDF, LINE);
        CRYPTO_clear_free(
            (*ctx).session_id.cast(),
            (*ctx).session_id_len,
            FILE_SSHKDF,
            LINE,
        );
        ptr::write_bytes(vctx.cast::<u8>(), 0, core::mem::size_of::<KdfSshkdf>());
        (*ctx).provctx = provctx;
    }
}

/// `static void kdf_sshkdf_free(void *vctx)` — `sshkdf.c:73-81`.
///
/// # Safety
/// The dispatch contract.
unsafe extern "C" fn sshkdf_free(vctx: *mut c_void) {
    // SAFETY: `vctx` is NULL or a live context.
    unsafe {
        if !vctx.is_null() {
            sshkdf_reset(vctx);
            CRYPTO_free(vctx, FILE_SSHKDF, LINE);
        }
    }
}

/// `static void *kdf_sshkdf_dup(void *vctx)` — `sshkdf.c:96-119`.
///
/// # Safety
/// The dispatch contract.
unsafe extern "C" fn sshkdf_dup(vctx: *mut c_void) -> *mut c_void {
    // SAFETY: the caller's contract.
    unsafe {
        let src = vctx.cast::<KdfSshkdf>();
        let dest = sshkdf_new((*src).provctx).cast::<KdfSshkdf>();
        if dest.is_null() {
            return ptr::null_mut();
        }
        if ossl_prov_memdup(
            (*src).key.cast(),
            (*src).key_len,
            ptr::addr_of_mut!((*dest).key),
            ptr::addr_of_mut!((*dest).key_len),
        ) == 0
            || ossl_prov_memdup(
                (*src).xcghash.cast(),
                (*src).xcghash_len,
                ptr::addr_of_mut!((*dest).xcghash),
                ptr::addr_of_mut!((*dest).xcghash_len),
            ) == 0
            || ossl_prov_memdup(
                (*src).session_id.cast(),
                (*src).session_id_len,
                ptr::addr_of_mut!((*dest).session_id),
                ptr::addr_of_mut!((*dest).session_id_len),
            ) == 0
            || ossl_prov_digest_copy(
                ptr::addr_of_mut!((*dest).digest),
                ptr::addr_of!((*src).digest),
            ) == 0
        {
            sshkdf_free(dest.cast());
            return ptr::null_mut();
        }
        (*dest).type_ = (*src).type_;
        dest.cast()
    }
}

/// `static int sshkdf_set_membuf(unsigned char **dst, size_t *dst_len,
/// const OSSL_PARAM *p)` — `sshkdf.c:121-128`.
///
/// # Safety
/// `dst`/`dst_len` are live; `p` is a live parameter.
unsafe fn sshkdf_set_membuf(dst: *mut *mut u8, dst_len: *mut usize, p: *const OsslParam) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        CRYPTO_clear_free((*dst).cast(), *dst_len, FILE_SSHKDF, LINE);
        *dst = ptr::null_mut();
        *dst_len = 0;
        OSSL_PARAM_get_octet_string(p.cast_mut(), dst.cast(), 0, dst_len)
    }
}

/// `static int kdf_sshkdf_derive(void *vctx, unsigned char *key, size_t keylen, const OSSL_PARAM
/// params[])` — `sshkdf.c:175-210`.
///
/// # Safety
/// The dispatch contract.
unsafe extern "C" fn sshkdf_ctx_derive(
    vctx: *mut c_void,
    key: *mut u8,
    keylen: usize,
    params: *const OsslParam,
) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        if is_running() == 0 || sshkdf_set_ctx_params(vctx, params) == 0 {
            return 0;
        }
        let ctx = vctx.cast::<KdfSshkdf>();
        let md = ossl_prov_digest_md(ptr::addr_of!((*ctx).digest));
        if md.is_null() {
            return fail_at(&err_sites::PROV_SSHKDF_186);
        }
        if (*ctx).key.is_null() {
            return fail_at(&err_sites::PROV_SSHKDF_190);
        }
        if (*ctx).xcghash.is_null() {
            return fail_at(&err_sites::PROV_SSHKDF_194);
        }
        if (*ctx).session_id.is_null() {
            return fail_at(&err_sites::PROV_SSHKDF_198);
        }
        if (*ctx).type_ == 0 {
            return fail_at(&err_sites::PROV_SSHKDF_202);
        }
        sshkdf(
            md,
            (*ctx).key,
            (*ctx).key_len,
            (*ctx).xcghash,
            (*ctx).xcghash_len,
            (*ctx).session_id,
            (*ctx).session_id_len,
            (*ctx).type_,
            key,
            keylen,
        )
    }
}

/// `static int kdf_sshkdf_set_ctx_params(void *vctx, const OSSL_PARAM params[])` —
/// `sshkdf.c:410-478`, with its generated switch replaced by the field-keyed repeat check and one
/// `OSSL_PARAM_locate_const` per key (D305's reading). The FIPS arms are absent.
///
/// # Safety
/// The dispatch contract.
unsafe extern "C" fn sshkdf_set_ctx_params(vctx: *mut c_void, params: *const OsslParam) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        if vctx.is_null() {
            return 0;
        }
        if let Some(site) = repeated_param_site_by_field(params, &SSHKDF_SET_DECODER_KEYS) {
            return fail_at(site);
        }
        let ctx = vctx.cast::<KdfSshkdf>();
        let provctx = prov_libctx_of((*ctx).provctx);

        let digest = locate_const(params, OSSL_KDF_PARAM_DIGEST);
        if !digest.is_null() {
            if ossl_prov_digest_load(
                ptr::addr_of_mut!((*ctx).digest),
                digest,
                locate_const(params, OSSL_KDF_PARAM_PROPERTIES),
                locate_const(params, OSSL_ALG_PARAM_ENGINE),
                provctx,
            ) == 0
            {
                return 0;
            }
            let md = ossl_prov_digest_md(ptr::addr_of!((*ctx).digest));
            if EVP_MD_xof(md) != 0 {
                raise_site(&err_sites::PROV_SSHKDF_435);
                return 0;
            }
        }

        let key = locate_const(params, OSSL_KDF_PARAM_KEY);
        if !key.is_null()
            && sshkdf_set_membuf(
                ptr::addr_of_mut!((*ctx).key),
                ptr::addr_of_mut!((*ctx).key_len),
                key,
            ) == 0
        {
            return 0;
        }

        let xcg = locate_const(params, OSSL_KDF_PARAM_SSHKDF_XCGHASH);
        if !xcg.is_null()
            && sshkdf_set_membuf(
                ptr::addr_of_mut!((*ctx).xcghash),
                ptr::addr_of_mut!((*ctx).xcghash_len),
                xcg,
            ) == 0
        {
            return 0;
        }

        let sid = locate_const(params, OSSL_KDF_PARAM_SSHKDF_SESSION_ID);
        if !sid.is_null()
            && sshkdf_set_membuf(
                ptr::addr_of_mut!((*ctx).session_id),
                ptr::addr_of_mut!((*ctx).session_id_len),
                sid,
            ) == 0
        {
            return 0;
        }

        let type_param = locate_const(params, OSSL_KDF_PARAM_SSHKDF_TYPE);
        if !type_param.is_null() {
            let mut kdftype: *const c_char = ptr::null();
            if OSSL_PARAM_get_utf8_string_ptr(type_param, &mut kdftype) == 0 {
                return 0;
            }
            /* Expect one character (byte in this case). */
            if kdftype.is_null() || (*type_param).data_size != 1 {
                return 0;
            }
            if *kdftype < 65 || *kdftype > 70 {
                raise_site(&err_sites::PROV_SSHKDF_472);
                return 0;
            }
            (*ctx).type_ = *kdftype;
        }
        1
    }
}

/// `static int kdf_sshkdf_get_ctx_params(void *vctx, OSSL_PARAM params[])` —
/// `sshkdf.c:549-563`, without its FIPS arm.
///
/// # Safety
/// The dispatch contract.
unsafe extern "C" fn sshkdf_get_ctx_params(vctx: *mut c_void, params: *mut OsslParam) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        if vctx.is_null() {
            return 0;
        }
        if let Some(site) =
            repeated_param_site_by_field(params.cast_const(), &SSHKDF_GET_DECODER_KEYS)
        {
            return fail_at(site);
        }
        let p = locate_const(params, OSSL_KDF_PARAM_SIZE);
        if !p.is_null() && OSSL_PARAM_set_size_t(p.cast_mut(), usize::MAX) == 0 {
            return 0;
        }
        1
    }
}

/// `static const OSSL_PARAM *kdf_sshkdf_settable_ctx_params(void *ctx, void *p_ctx)` —
/// `sshkdf.c:480-484`.
///
/// # Safety
/// The dispatch contract.
unsafe extern "C" fn sshkdf_settable_ctx_params(
    _ctx: *mut c_void,
    _p_ctx: *mut c_void,
) -> *const OsslParam {
    SSHKDF_SETTABLE_CTX_PARAMS.as_ptr()
}

/// `static const OSSL_PARAM *kdf_sshkdf_gettable_ctx_params(void *ctx, void *p_ctx)` —
/// `sshkdf.c:565-569`.
///
/// # Safety
/// The dispatch contract.
unsafe extern "C" fn sshkdf_gettable_ctx_params(
    _ctx: *mut c_void,
    _p_ctx: *mut c_void,
) -> *const OsslParam {
    SSHKDF_GETTABLE_CTX_PARAMS.as_ptr()
}

/// `const OSSL_DISPATCH ossl_kdf_sshkdf_functions[]` — `sshkdf.c:333-346`.
pub(crate) static SSHKDF_FUNCTIONS: [OsslDispatch; 10] = [
    OsslDispatch {
        function_id: OSSL_FUNC_KDF_NEWCTX,
        function: sshkdf_new as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KDF_DUPCTX,
        function: sshkdf_dup as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KDF_FREECTX,
        function: sshkdf_free as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KDF_RESET,
        function: sshkdf_reset as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KDF_DERIVE,
        function: sshkdf_ctx_derive as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KDF_SETTABLE_CTX_PARAMS,
        function: sshkdf_settable_ctx_params as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KDF_SET_CTX_PARAMS,
        function: sshkdf_set_ctx_params as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KDF_GETTABLE_CTX_PARAMS,
        function: sshkdf_gettable_ctx_params as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KDF_GET_CTX_PARAMS,
        function: sshkdf_get_ctx_params as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_DISPATCH_END,
        function: ptr::null_mut(),
    },
];

// =============================================================================================
// `providers/implementations/kdfs/pbkdf2.c` — PBKDF2
// =============================================================================================

/// `struct KDF_PBKDF2` — `pbkdf2.c:54-64`, without its FIPS indicator field.
#[repr(C)]
pub(crate) struct KdfPbkdf2 {
    /// `void *provctx`.
    pub provctx: *mut c_void,
    /// `unsigned char *pass` / `size_t pass_len`.
    pub pass: *mut u8,
    pub pass_len: usize,
    /// `unsigned char *salt` / `size_t salt_len`.
    pub salt: *mut u8,
    pub salt_len: usize,
    /// `uint64_t iter`.
    pub iter: u64,
    /// `PROV_DIGEST digest`.
    pub digest: ProvDigest,
    /// `int lower_bound_checks` — SP800-132's checks, on when `pkcs5` is 0 (`pbkdf2.c:327`).
    pub lower_bound_checks: c_int,
}

/// The `pbkdf2_set_ctx_params_decoder` keys, each with its (field id, raise site). Every key names
/// its own field; the generated `strcmp`-tree at `pbkdf2.c:320-404` raises
/// `PROV_R_REPEATED_PARAMETER` at the second occurrence of any one.
const PBKDF2_SET_DECODER_KEYS: [(&err_sites::ErrSite, *const c_char, u32); 7] = [
    (&err_sites::PROV_PBKDF2_327, OSSL_KDF_PARAM_DIGEST, 0),
    (&err_sites::PROV_PBKDF2_338, OSSL_ALG_PARAM_ENGINE, 1),
    (&err_sites::PROV_PBKDF2_349, OSSL_KDF_PARAM_ITER, 2),
    (&err_sites::PROV_PBKDF2_375, OSSL_KDF_PARAM_PKCS5, 3),
    (&err_sites::PROV_PBKDF2_386, OSSL_KDF_PARAM_PROPERTIES, 4),
    (&err_sites::PROV_PBKDF2_364, OSSL_KDF_PARAM_PASSWORD, 5),
    (&err_sites::PROV_PBKDF2_398, OSSL_KDF_PARAM_SALT, 6),
];

/// The `pbkdf2_get_ctx_params_decoder` key, `pbkdf2.c:522-530`.
const PBKDF2_GET_DECODER_KEYS: [(&err_sites::ErrSite, *const c_char, u32); 1] =
    [(&err_sites::PROV_PBKDF2_525, OSSL_KDF_PARAM_SIZE, 0)];

/// `static const OSSL_PARAM pbkdf2_set_ctx_params_list[]` — `pbkdf2.c:288-296`.
static PBKDF2_SETTABLE_CTX_PARAMS: [OsslParam; 7] = [
    param_utf8_string(OSSL_KDF_PARAM_PROPERTIES),
    param_utf8_string(OSSL_KDF_PARAM_DIGEST),
    param_octet_string(OSSL_KDF_PARAM_PASSWORD),
    param_octet_string(OSSL_KDF_PARAM_SALT),
    param_uint64(OSSL_KDF_PARAM_ITER),
    param_int(OSSL_KDF_PARAM_PKCS5),
    END,
];

/// `static const OSSL_PARAM pbkdf2_get_ctx_params_list[]` — `pbkdf2.c:478-484`, without its FIPS
/// entry.
static PBKDF2_GETTABLE_CTX_PARAMS: [OsslParam; 2] = [param_size_t(OSSL_KDF_PARAM_SIZE), END];

/// `static int pbkdf2_lower_bound_check_passed(int saltlen, uint64_t iter, size_t keylen,
/// int *error, const char **desc)` — `pbkdf2.c:189-213`. The `desc` out-parameter is set only for
/// the FIPS arm's message and is absent here; every non-FIPS caller passes NULL.
///
/// `keylen * 8` is `wrapping_mul` because the authority relies on the wrap: two of its three call
/// sites pass `SIZE_MAX` and only one check is meant to be able to fail at each.
///
/// # Safety
/// `error` is writable.
unsafe fn pbkdf2_lower_bound_check_passed(
    saltlen: c_int,
    iter: u64,
    keylen: usize,
    error: *mut c_int,
) -> c_int {
    // SAFETY: `error` is writable per the contract.
    unsafe {
        if keylen.wrapping_mul(8) < KDF_PBKDF2_MIN_KEY_LEN_BITS {
            *error = err_reasons::PROV_R_KEY_SIZE_TOO_SMALL;
            return 0;
        }
        if saltlen < KDF_PBKDF2_MIN_SALT_LEN {
            *error = err_reasons::PROV_R_INVALID_SALT_LENGTH;
            return 0;
        }
        if iter < KDF_PBKDF2_MIN_ITERATIONS {
            *error = err_reasons::PROV_R_INVALID_ITERATION_COUNT;
            return 0;
        }
        1
    }
}

/// `static int lower_bound_check_passed(KDF_PBKDF2 *ctx, int saltlen, uint64_t iter,
/// size_t keylen, int lower_bound_checks)` — `pbkdf2.c:237-260`, non-FIPS arm: the SP800-132
/// checks when `lower_bound_checks` is on (raised with the *variable* reason the lower-bound
/// function selected), and the iteration-count floor of one when it is off.
///
/// # Safety
/// `_ctx` is unused on this profile; the caller's contract otherwise.
unsafe fn lower_bound_check_passed(
    _ctx: *mut KdfPbkdf2,
    saltlen: c_int,
    iter: u64,
    keylen: usize,
    lower_bound_checks: c_int,
) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        if lower_bound_checks != 0 {
            let mut error: c_int = 0;
            let passed = pbkdf2_lower_bound_check_passed(saltlen, iter, keylen, &mut error);
            if passed == 0 {
                raise_site_dynamic(&err_sites::PROV_PBKDF2_248, error);
                return 0;
            }
        } else if iter < 1 {
            raise_site(&err_sites::PROV_PBKDF2_252);
            return 0;
        }
        1
    }
}

/// `static int pbkdf2_derive(KDF_PBKDF2 *ctx, const char *pass, size_t passlen, const unsigned
/// char *salt, int saltlen, uint64_t iter, const EVP_MD *digest, unsigned char *key, size_t
/// keylen, int lower_bound_checks)` — `pbkdf2.c:586-660`. The authority's `goto err` is a labelled
/// block whose single exit frees both HMAC contexts in the authority's order.
///
/// # Safety
/// The arguments are the authority's: `pass` live for `passlen`, `salt` for `saltlen`, `key`
/// writable for `keylen`, `digest` a live digest.
#[allow(clippy::too_many_arguments)] // mirrors the authority's signature exactly
unsafe fn pbkdf2_derive(
    ctx: *mut KdfPbkdf2,
    pass: *const c_char,
    passlen: usize,
    salt: *const u8,
    saltlen: c_int,
    iter: u64,
    digest: *const crate::evp::digest::EvpMd,
    key: *mut u8,
    keylen: usize,
    lower_bound_checks: c_int,
) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        let mut ret: c_int = 0;
        let mut digtmp = [0u8; EVP_MAX_MD_SIZE];
        let mut itmp = [0u8; 4];
        let mut hctx: *mut HmacCtx = ptr::null_mut();

        let mdlen = EVP_MD_get_size(digest);
        if mdlen <= 0 {
            return 0;
        }

        /*
         * This check should always be done because keylen / mdlen >= (2^32 - 1)
         * results in an overflow of the loop counter 'i'.
         */
        if (keylen / mdlen as usize) >= KDF_PBKDF2_MAX_KEY_LEN_DIGEST_RATIO {
            return fail_at(&err_sites::PROV_PBKDF2_606);
        }

        if lower_bound_check_passed(ctx, saltlen, iter, keylen, lower_bound_checks) == 0 {
            return 0;
        }

        let hctx_tpl = HMAC_CTX_new();
        if hctx_tpl.is_null() {
            return 0;
        }
        let mut p = key;
        let mut tkeylen = keylen as c_int;

        'err: {
            if HMAC_Init_ex(
                hctx_tpl,
                pass.cast(),
                passlen as c_int,
                digest,
                ptr::null_mut(),
            ) == 0
            {
                break 'err;
            }
            hctx = HMAC_CTX_new();
            if hctx.is_null() {
                break 'err;
            }
            let mut i: c_ulong = 1;
            while tkeylen != 0 {
                let cplen = if tkeylen > mdlen { mdlen } else { tkeylen };
                /*
                 * We are unlikely to ever use more than 256 blocks (5120 bits!) but
                 * just in case...
                 */
                itmp[0] = ((i >> 24) & 0xff) as u8;
                itmp[1] = ((i >> 16) & 0xff) as u8;
                itmp[2] = ((i >> 8) & 0xff) as u8;
                itmp[3] = (i & 0xff) as u8;
                if HMAC_CTX_copy(hctx, hctx_tpl) == 0 {
                    break 'err;
                }
                if HMAC_Update(hctx, salt.cast(), saltlen as usize) == 0
                    || HMAC_Update(hctx, itmp.as_ptr().cast(), 4) == 0
                    || HMAC_Final(hctx, digtmp.as_mut_ptr(), ptr::null_mut()) == 0
                {
                    break 'err;
                }
                ptr::copy_nonoverlapping(digtmp.as_ptr(), p, cplen as usize);
                let mut j: u64 = 1;
                while j < iter {
                    if HMAC_CTX_copy(hctx, hctx_tpl) == 0 {
                        break 'err;
                    }
                    if HMAC_Update(hctx, digtmp.as_ptr().cast(), mdlen as usize) == 0
                        || HMAC_Final(hctx, digtmp.as_mut_ptr(), ptr::null_mut()) == 0
                    {
                        break 'err;
                    }
                    for (k, byte) in digtmp.iter().enumerate().take(cplen as usize) {
                        *p.add(k) ^= byte;
                    }
                    j += 1;
                }
                tkeylen -= cplen;
                i += 1;
                p = p.add(cplen as usize);
            }
            ret = 1;
        }

        HMAC_CTX_free(hctx);
        HMAC_CTX_free(hctx_tpl);
        ret
    }
}

/// `static void kdf_pbkdf2_init(KDF_PBKDF2 *ctx)` — `pbkdf2.c:154-170`. A failed SHA-1 load is an
/// error with no way to report it, so the digest is reset and the context keeps going.
///
/// # Safety
/// `ctx` is a live context.
unsafe fn pbkdf2_init(ctx: *mut KdfPbkdf2) {
    // SAFETY: `ctx` is live per the contract.
    unsafe {
        let provctx = prov_libctx_of((*ctx).provctx);
        let mut params = [END, END];
        params[0] = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST, SN_SHA1.cast_mut(), 0);
        if ossl_prov_digest_load_from_params(
            ptr::addr_of_mut!((*ctx).digest),
            params.as_ptr(),
            provctx,
        ) == 0
        {
            ossl_prov_digest_reset(ptr::addr_of_mut!((*ctx).digest));
        }
        (*ctx).iter = PKCS5_DEFAULT_ITER;
        (*ctx).lower_bound_checks = 0;
    }
}

/// `static void *kdf_pbkdf2_new_no_init(void *provctx)` — `pbkdf2.c:73-86`.
///
/// # Safety
/// The dispatch contract.
unsafe extern "C" fn pbkdf2_new_no_init(provctx: *mut c_void) -> *mut c_void {
    // SAFETY: the caller's contract.
    unsafe {
        if is_running() == 0 {
            return ptr::null_mut();
        }
        let ctx =
            CRYPTO_zalloc(core::mem::size_of::<KdfPbkdf2>(), FILE_PBKDF2, LINE).cast::<KdfPbkdf2>();
        if ctx.is_null() {
            return ptr::null_mut();
        }
        (*ctx).provctx = provctx;
        ctx.cast()
    }
}

/// `static void *kdf_pbkdf2_new(void *provctx)` — `pbkdf2.c:88-95`.
///
/// # Safety
/// The dispatch contract.
unsafe extern "C" fn pbkdf2_new(provctx: *mut c_void) -> *mut c_void {
    // SAFETY: the caller's contract.
    unsafe {
        let ctx = pbkdf2_new_no_init(provctx).cast::<KdfPbkdf2>();
        if !ctx.is_null() {
            pbkdf2_init(ctx);
        }
        ctx.cast()
    }
}

/// `static void kdf_pbkdf2_cleanup(KDF_PBKDF2 *ctx)` — `pbkdf2.c:97-107`, without the
/// `OPENSSL_PEDANTIC_ZEROIZATION` arm's `clear_free` of the salt.
///
/// # Safety
/// `ctx` is a live context.
unsafe fn pbkdf2_cleanup(ctx: *mut KdfPbkdf2) {
    // SAFETY: `ctx` is live per the contract.
    unsafe {
        ossl_prov_digest_reset(ptr::addr_of_mut!((*ctx).digest));
        CRYPTO_free((*ctx).salt.cast(), FILE_PBKDF2, LINE);
        CRYPTO_clear_free((*ctx).pass.cast(), (*ctx).pass_len, FILE_PBKDF2, LINE);
        ptr::write_bytes(ctx.cast::<u8>(), 0, core::mem::size_of::<KdfPbkdf2>());
    }
}

/// `static void kdf_pbkdf2_free(void *vctx)` — `pbkdf2.c:109-117`.
///
/// # Safety
/// The dispatch contract.
unsafe extern "C" fn pbkdf2_free(vctx: *mut c_void) {
    // SAFETY: `vctx` is NULL or a live context.
    unsafe {
        if !vctx.is_null() {
            pbkdf2_cleanup(vctx.cast::<KdfPbkdf2>());
            CRYPTO_free(vctx, FILE_PBKDF2, LINE);
        }
    }
}

/// `static void kdf_pbkdf2_reset(void *vctx)` — `pbkdf2.c:119-127`.
///
/// # Safety
/// The dispatch contract.
unsafe extern "C" fn pbkdf2_reset(vctx: *mut c_void) {
    // SAFETY: `vctx` is a live context per the contract.
    unsafe {
        let ctx = vctx.cast::<KdfPbkdf2>();
        let provctx = (*ctx).provctx;
        pbkdf2_cleanup(ctx);
        (*ctx).provctx = provctx;
        pbkdf2_init(ctx);
    }
}

/// `static void *kdf_pbkdf2_dup(void *vctx)` — `pbkdf2.c:129-152`. The duplicate is built
/// **uninitialised**, because every initialised field is copied over it.
///
/// # Safety
/// The dispatch contract.
unsafe extern "C" fn pbkdf2_dup(vctx: *mut c_void) -> *mut c_void {
    // SAFETY: the caller's contract.
    unsafe {
        let src = vctx.cast::<KdfPbkdf2>();
        let dest = pbkdf2_new_no_init((*src).provctx).cast::<KdfPbkdf2>();
        if dest.is_null() {
            return ptr::null_mut();
        }
        if ossl_prov_memdup(
            (*src).salt.cast(),
            (*src).salt_len,
            ptr::addr_of_mut!((*dest).salt),
            ptr::addr_of_mut!((*dest).salt_len),
        ) == 0
            || ossl_prov_memdup(
                (*src).pass.cast(),
                (*src).pass_len,
                ptr::addr_of_mut!((*dest).pass),
                ptr::addr_of_mut!((*dest).pass_len),
            ) == 0
            || ossl_prov_digest_copy(
                ptr::addr_of_mut!((*dest).digest),
                ptr::addr_of!((*src).digest),
            ) == 0
        {
            pbkdf2_free(dest.cast());
            return ptr::null_mut();
        }
        (*dest).iter = (*src).iter;
        (*dest).lower_bound_checks = (*src).lower_bound_checks;
        dest.cast()
    }
}

/// `static int pbkdf2_set_membuf(unsigned char **buffer, size_t *buflen,
/// const OSSL_PARAM *p)` — `pbkdf2.c:172-187`.
///
/// # Safety
/// `buffer`/`buflen` are live; `p` is a live parameter.
unsafe fn pbkdf2_set_membuf(
    buffer: *mut *mut u8,
    buflen: *mut usize,
    p: *const OsslParam,
) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        CRYPTO_clear_free((*buffer).cast(), *buflen, FILE_PBKDF2, LINE);
        *buffer = ptr::null_mut();
        *buflen = 0;

        if (*p).data_size == 0 {
            let m = CRYPTO_malloc(1, FILE_PBKDF2, LINE).cast::<u8>();
            if m.is_null() {
                return 0;
            }
            *buffer = m;
        } else if !(*p).data.is_null()
            && OSSL_PARAM_get_octet_string(p.cast_mut(), buffer.cast(), 0, buflen) == 0
        {
            return 0;
        }
        1
    }
}

/// `static int kdf_pbkdf2_derive(void *vctx, unsigned char *key, size_t keylen, const OSSL_PARAM
/// params[])` — `pbkdf2.c:262-285`.
///
/// # Safety
/// The dispatch contract.
unsafe extern "C" fn pbkdf2_ctx_derive(
    vctx: *mut c_void,
    key: *mut u8,
    keylen: usize,
    params: *const OsslParam,
) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        if is_running() == 0 || pbkdf2_set_ctx_params(vctx, params) == 0 {
            return 0;
        }
        let ctx = vctx.cast::<KdfPbkdf2>();
        if (*ctx).pass.is_null() {
            return fail_at(&err_sites::PROV_PBKDF2_270);
        }
        if (*ctx).salt.is_null() {
            return fail_at(&err_sites::PROV_PBKDF2_275);
        }
        let md = ossl_prov_digest_md(ptr::addr_of!((*ctx).digest));
        pbkdf2_derive(
            ctx,
            (*ctx).pass.cast(),
            (*ctx).pass_len,
            (*ctx).salt,
            (*ctx).salt_len as c_int,
            (*ctx).iter,
            md,
            key,
            keylen,
            (*ctx).lower_bound_checks,
        )
    }
}

/// `static int kdf_pbkdf2_set_ctx_params(void *vctx, const OSSL_PARAM params[])` —
/// `pbkdf2.c:412-478`, with the generated switch replaced by the field-keyed repeat check and one
/// `OSSL_PARAM_locate_const` per key (D305's reading). The FIPS arms are absent.
///
/// # Safety
/// The dispatch contract.
unsafe extern "C" fn pbkdf2_set_ctx_params(vctx: *mut c_void, params: *const OsslParam) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        if vctx.is_null() {
            return 0;
        }
        if let Some(site) = repeated_param_site_by_field(params, &PBKDF2_SET_DECODER_KEYS) {
            return fail_at(site);
        }
        let ctx = vctx.cast::<KdfPbkdf2>();
        let provctx = prov_libctx_of((*ctx).provctx);

        let digest = locate_const(params, OSSL_KDF_PARAM_DIGEST);
        if !digest.is_null() {
            if ossl_prov_digest_load(
                ptr::addr_of_mut!((*ctx).digest),
                digest,
                locate_const(params, OSSL_KDF_PARAM_PROPERTIES),
                locate_const(params, OSSL_ALG_PARAM_ENGINE),
                provctx,
            ) == 0
            {
                return 0;
            }
            let md = ossl_prov_digest_md(ptr::addr_of!((*ctx).digest));
            if EVP_MD_xof(md) != 0 {
                raise_site(&err_sites::PROV_PBKDF2_431);
                return 0;
            }
        }

        let pkcs5 = locate_const(params, OSSL_KDF_PARAM_PKCS5);
        if !pkcs5.is_null() {
            let mut v: c_int = 0;
            if OSSL_PARAM_get_int(pkcs5, &mut v) == 0 {
                return 0;
            }
            (*ctx).lower_bound_checks = (v == 0) as c_int;
        }

        let pw = locate_const(params, OSSL_KDF_PARAM_PASSWORD);
        if !pw.is_null()
            && pbkdf2_set_membuf(
                ptr::addr_of_mut!((*ctx).pass),
                ptr::addr_of_mut!((*ctx).pass_len),
                pw,
            ) == 0
        {
            return 0;
        }

        let salt = locate_const(params, OSSL_KDF_PARAM_SALT);
        if !salt.is_null() {
            if lower_bound_check_passed(
                ctx,
                (*salt).data_size as c_int,
                u64::MAX,
                usize::MAX,
                (*ctx).lower_bound_checks,
            ) == 0
            {
                return 0;
            }
            if pbkdf2_set_membuf(
                ptr::addr_of_mut!((*ctx).salt),
                ptr::addr_of_mut!((*ctx).salt_len),
                salt,
            ) == 0
            {
                return 0;
            }
        }

        let iter = locate_const(params, OSSL_KDF_PARAM_ITER);
        if !iter.is_null() {
            let mut v: u64 = 0;
            if OSSL_PARAM_get_uint64(iter, &mut v) == 0 {
                return 0;
            }
            if lower_bound_check_passed(ctx, c_int::MAX, v, usize::MAX, (*ctx).lower_bound_checks)
                == 0
            {
                return 0;
            }
            (*ctx).iter = v;
        }
        1
    }
}

/// `static int kdf_pbkdf2_get_ctx_params(void *vctx, OSSL_PARAM params[])` —
/// `pbkdf2.c:538-552`, without its FIPS arm.
///
/// # Safety
/// The dispatch contract.
unsafe extern "C" fn pbkdf2_get_ctx_params(vctx: *mut c_void, params: *mut OsslParam) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        if vctx.is_null() {
            return 0;
        }
        if let Some(site) =
            repeated_param_site_by_field(params.cast_const(), &PBKDF2_GET_DECODER_KEYS)
        {
            return fail_at(site);
        }
        let p = locate_const(params, OSSL_KDF_PARAM_SIZE);
        if !p.is_null() && OSSL_PARAM_set_size_t(p.cast_mut(), usize::MAX) == 0 {
            return 0;
        }
        1
    }
}

/// `static const OSSL_PARAM *kdf_pbkdf2_settable_ctx_params(void *ctx, void *p_ctx)` —
/// `pbkdf2.c:456-460`.
///
/// # Safety
/// The dispatch contract.
unsafe extern "C" fn pbkdf2_settable_ctx_params(
    _ctx: *mut c_void,
    _p_ctx: *mut c_void,
) -> *const OsslParam {
    PBKDF2_SETTABLE_CTX_PARAMS.as_ptr()
}

/// `static const OSSL_PARAM *kdf_pbkdf2_gettable_ctx_params(void *ctx, void *p_ctx)` —
/// `pbkdf2.c:482-486`.
///
/// # Safety
/// The dispatch contract.
unsafe extern "C" fn pbkdf2_gettable_ctx_params(
    _ctx: *mut c_void,
    _p_ctx: *mut c_void,
) -> *const OsslParam {
    PBKDF2_GETTABLE_CTX_PARAMS.as_ptr()
}

/// `const OSSL_DISPATCH ossl_kdf_pbkdf2_functions[]` — `pbkdf2.c:392-405`.
pub(crate) static PBKDF2_FUNCTIONS: [OsslDispatch; 10] = [
    OsslDispatch {
        function_id: OSSL_FUNC_KDF_NEWCTX,
        function: pbkdf2_new as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KDF_DUPCTX,
        function: pbkdf2_dup as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KDF_FREECTX,
        function: pbkdf2_free as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KDF_RESET,
        function: pbkdf2_reset as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KDF_DERIVE,
        function: pbkdf2_ctx_derive as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KDF_SETTABLE_CTX_PARAMS,
        function: pbkdf2_settable_ctx_params as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KDF_SET_CTX_PARAMS,
        function: pbkdf2_set_ctx_params as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KDF_GETTABLE_CTX_PARAMS,
        function: pbkdf2_gettable_ctx_params as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KDF_GET_CTX_PARAMS,
        function: pbkdf2_get_ctx_params as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_DISPATCH_END,
        function: ptr::null_mut(),
    },
];

// =============================================================================================
// `providers/implementations/kdfs/hkdf.c` — HKDF, its three fixed-digest spellings, and TLS13-KDF
// =============================================================================================

/// `struct KDF_HKDF` — `hkdf.c:81-99`, without its FIPS indicator field.
#[repr(C)]
pub(crate) struct KdfHkdf {
    /// `void *provctx`.
    pub provctx: *mut c_void,
    /// `int mode` — `EVP_KDF_HKDF_MODE_*`.
    pub mode: c_int,
    /// `PROV_DIGEST digest`.
    pub digest: ProvDigest,
    /// `unsigned char *salt` / `size_t salt_len`.
    pub salt: *mut u8,
    pub salt_len: usize,
    /// `unsigned char *key` / `size_t key_len` — HKDF's `IKM`/`PRK`, TLS13's secret.
    pub key: *mut u8,
    pub key_len: usize,
    /// `unsigned char *prefix` / `size_t prefix_len` — TLS13-KDF only.
    pub prefix: *mut u8,
    pub prefix_len: usize,
    /// `unsigned char *label` / `size_t label_len` — TLS13-KDF only.
    pub label: *mut u8,
    pub label_len: usize,
    /// `unsigned char *data` / `size_t data_len` — TLS13-KDF only.
    pub data: *mut u8,
    pub data_len: usize,
    /// `unsigned char *info` / `size_t info_len`.
    pub info: *mut u8,
    pub info_len: usize,
    /// `int fixed_digest` — 1 for the three `HKDF-SHA*` rows, whose digest cannot be reset.
    pub fixed_digest: c_int,
}

/// `struct hkdf_all_set_ctx_params_st` — `hkdf.c:267-283`, without its two FIPS fields. The three
/// set decoders share one target struct; a decoder fills only the fields its own list names.
#[derive(Default)]
struct HkdfSetCtxParams {
    mode: *const OsslParam,
    propq: *const OsslParam,
    engine: *const OsslParam,
    digest: *const OsslParam,
    key: *const OsslParam,
    salt: *const OsslParam,
    prefix: *const OsslParam,
    label: *const OsslParam,
    data: *const OsslParam,
    info: [*const OsslParam; HKDF_MAX_INFOS],
    num_info: c_int,
}

// `struct hkdf_get_ctx_params_st` — `hkdf.c:558-568`, without its FIPS `ind` field. The get
// decoder's keys are located directly in `hkdf_common_get_ctx_params`, so only the key list below
// is needed; there is no target struct on this profile.

/// The `hkdf_set_ctx_params_decoder` keys, each with its (field id, raise site). `mode` is one
/// field spelled by two descriptors (`utf8_string` and `int`), which is why the key list has one
/// entry for it: the generated decoder raises on the second occurrence of either type. `info` is
/// absent because its repetition is a list, not an error, up to `HKDF_MAX_INFOS`.
const HKDF_SET_DECODER_KEYS: [(&err_sites::ErrSite, *const c_char, u32); 6] = [
    (&err_sites::PROV_HKDF_407, OSSL_KDF_PARAM_DIGEST, 0),
    (&err_sites::PROV_HKDF_418, OSSL_ALG_PARAM_ENGINE, 1),
    (&err_sites::PROV_HKDF_463, OSSL_KDF_PARAM_KEY, 2),
    (&err_sites::PROV_HKDF_476, OSSL_KDF_PARAM_MODE, 3),
    (&err_sites::PROV_HKDF_487, OSSL_KDF_PARAM_PROPERTIES, 4),
    (&err_sites::PROV_HKDF_498, OSSL_KDF_PARAM_SALT, 5),
];

/// The `hkdf_get_ctx_params_decoder` keys, `hkdf.c:571-809`.
const HKDF_GET_DECODER_KEYS: [(&err_sites::ErrSite, *const c_char, u32); 5] = [
    (&err_sites::PROV_HKDF_586, OSSL_KDF_PARAM_DIGEST, 0),
    (&err_sites::PROV_HKDF_610, OSSL_KDF_PARAM_INFO, 1),
    (&err_sites::PROV_HKDF_621, OSSL_KDF_PARAM_MODE, 2),
    (&err_sites::PROV_HKDF_636, OSSL_KDF_PARAM_SALT, 3),
    (&err_sites::PROV_HKDF_647, OSSL_KDF_PARAM_SIZE, 4),
];

/// The `hkdf_fixed_digest_set_ctx_params_decoder` keys, `hkdf.c:810-1420`. Its `digest` key is
/// decoded even though setting it is then refused (`PROV_R_DIGEST_NOT_ALLOWED`, `:916`).
const HKDF_FIXED_DECODER_KEYS: [(&err_sites::ErrSite, *const c_char, u32); 4] = [
    (&err_sites::PROV_HKDF_825, OSSL_KDF_PARAM_DIGEST, 0),
    (&err_sites::PROV_HKDF_870, OSSL_KDF_PARAM_KEY, 1),
    (&err_sites::PROV_HKDF_883, OSSL_KDF_PARAM_MODE, 2),
    (&err_sites::PROV_HKDF_894, OSSL_KDF_PARAM_SALT, 3),
];

/// The `kdf_tls1_3_set_ctx_params_decoder` keys, `hkdf.c:1421-1692`.
const TLS13_SET_DECODER_KEYS: [(&err_sites::ErrSite, *const c_char, u32); 9] = [
    (&err_sites::PROV_HKDF_1440, OSSL_KDF_PARAM_DATA, 0),
    (&err_sites::PROV_HKDF_1482, OSSL_KDF_PARAM_DIGEST, 1),
    (&err_sites::PROV_HKDF_1498, OSSL_ALG_PARAM_ENGINE, 2),
    (&err_sites::PROV_HKDF_1532, OSSL_KDF_PARAM_KEY, 3),
    (&err_sites::PROV_HKDF_1545, OSSL_KDF_PARAM_LABEL, 4),
    (&err_sites::PROV_HKDF_1556, OSSL_KDF_PARAM_MODE, 5),
    (&err_sites::PROV_HKDF_1575, OSSL_KDF_PARAM_PREFIX, 6),
    (&err_sites::PROV_HKDF_1586, OSSL_KDF_PARAM_PROPERTIES, 7),
    (&err_sites::PROV_HKDF_1599, OSSL_KDF_PARAM_SALT, 8),
];

/// `static const OSSL_PARAM hkdf_set_ctx_params_list[]` — `hkdf.c:360-372`, without the FIPS entry.
static HKDF_SETTABLE_CTX_PARAMS: [OsslParam; 8] = [
    param_utf8_string(OSSL_KDF_PARAM_MODE),
    param_int(OSSL_KDF_PARAM_MODE),
    param_utf8_string(OSSL_KDF_PARAM_PROPERTIES),
    param_utf8_string(OSSL_KDF_PARAM_DIGEST),
    param_octet_string(OSSL_KDF_PARAM_KEY),
    param_octet_string(OSSL_KDF_PARAM_SALT),
    param_octet_string(OSSL_KDF_PARAM_INFO),
    END,
];

/// `static const OSSL_PARAM hkdf_get_ctx_params_list[]` — `hkdf.c:543-556`, without its FIPS entry.
static HKDF_GETTABLE_CTX_PARAMS: [OsslParam; 7] = [
    param_size_t(OSSL_KDF_PARAM_SIZE),
    param_utf8_string(OSSL_KDF_PARAM_DIGEST),
    param_utf8_string(OSSL_KDF_PARAM_MODE),
    param_int(OSSL_KDF_PARAM_MODE),
    param_octet_string(OSSL_KDF_PARAM_SALT),
    param_octet_string(OSSL_KDF_PARAM_INFO),
    END,
];

/// `static const OSSL_PARAM hkdf_fixed_digest_set_ctx_params_list[]` — `hkdf.c:782-794`.
static HKDF_FIXED_SETTABLE_CTX_PARAMS: [OsslParam; 6] = [
    param_utf8_string(OSSL_KDF_PARAM_MODE),
    param_int(OSSL_KDF_PARAM_MODE),
    param_octet_string(OSSL_KDF_PARAM_KEY),
    param_octet_string(OSSL_KDF_PARAM_SALT),
    param_octet_string(OSSL_KDF_PARAM_INFO),
    END,
];

/// `static const OSSL_PARAM kdf_tls1_3_set_ctx_params_list[]` — `hkdf.c:1380-1399`, without the two
/// FIPS entries.
static TLS13_SETTABLE_CTX_PARAMS: [OsslParam; 10] = [
    param_utf8_string(OSSL_KDF_PARAM_MODE),
    param_int(OSSL_KDF_PARAM_MODE),
    param_utf8_string(OSSL_KDF_PARAM_PROPERTIES),
    param_utf8_string(OSSL_KDF_PARAM_DIGEST),
    param_octet_string(OSSL_KDF_PARAM_KEY),
    param_octet_string(OSSL_KDF_PARAM_SALT),
    param_octet_string(OSSL_KDF_PARAM_PREFIX),
    param_octet_string(OSSL_KDF_PARAM_LABEL),
    param_octet_string(OSSL_KDF_PARAM_DATA),
    END,
];

/// The generated decoders' non-FIPS behaviour, one per set list: locate each key with
/// `OSSL_PARAM_locate_const` and collect the `info` records against `HKDF_MAX_INFOS`. The five-info
/// count is the one rule `repeated_param_site_by_field` cannot express; a sixth raises
/// `PROV_R_TOO_MANY_RECORDS` at `hkdf.c:429` (the common list) or `:836` (the fixed one).
///
/// # Safety
/// `params` is NULL or a key-terminated array; `r` is writable.
unsafe fn hkdf_collect_info(
    params: *const OsslParam,
    r: &mut HkdfSetCtxParams,
    site: &'static err_sites::ErrSite,
) -> c_int {
    // SAFETY: the walk stops at the NULL key.
    unsafe {
        if params.is_null() {
            return 1;
        }
        let mut p = params;
        while !(*p).key.is_null() {
            if CStr::from_ptr((*p).key).to_bytes() == CStr::from_ptr(OSSL_KDF_PARAM_INFO).to_bytes()
            {
                if r.num_info as usize >= HKDF_MAX_INFOS {
                    raise_site(site);
                    return 0;
                }
                r.info[r.num_info as usize] = p;
                r.num_info += 1;
            }
            p = p.add(1);
        }
    }
    1
}

/// The `hkdf_set_ctx_params_decoder`'s target, key by key.
///
/// # Safety
/// `params` is NULL or a key-terminated array; `r` is writable.
unsafe fn hkdf_set_ctx_params_decode(params: *const OsslParam, r: &mut HkdfSetCtxParams) -> c_int {
    // SAFETY: the walk stops at the NULL key.
    unsafe {
        r.digest = crate::params::OSSL_PARAM_locate_const(params, OSSL_KDF_PARAM_DIGEST);
        r.engine = crate::params::OSSL_PARAM_locate_const(params, OSSL_ALG_PARAM_ENGINE);
        r.key = crate::params::OSSL_PARAM_locate_const(params, OSSL_KDF_PARAM_KEY);
        r.mode = crate::params::OSSL_PARAM_locate_const(params, OSSL_KDF_PARAM_MODE);
        r.propq = crate::params::OSSL_PARAM_locate_const(params, OSSL_KDF_PARAM_PROPERTIES);
        r.salt = crate::params::OSSL_PARAM_locate_const(params, OSSL_KDF_PARAM_SALT);
        hkdf_collect_info(params, r, &err_sites::PROV_HKDF_429)
    }
}

/// The `hkdf_fixed_digest_set_ctx_params_decoder`'s target.
///
/// # Safety
/// `params` is NULL or a key-terminated array; `r` is writable.
unsafe fn hkdf_fixed_set_ctx_params_decode(
    params: *const OsslParam,
    r: &mut HkdfSetCtxParams,
) -> c_int {
    // SAFETY: the walk stops at the NULL key.
    unsafe {
        r.digest = crate::params::OSSL_PARAM_locate_const(params, OSSL_KDF_PARAM_DIGEST);
        r.key = crate::params::OSSL_PARAM_locate_const(params, OSSL_KDF_PARAM_KEY);
        r.mode = crate::params::OSSL_PARAM_locate_const(params, OSSL_KDF_PARAM_MODE);
        r.salt = crate::params::OSSL_PARAM_locate_const(params, OSSL_KDF_PARAM_SALT);
        hkdf_collect_info(params, r, &err_sites::PROV_HKDF_836)
    }
}

/// The `kdf_tls1_3_set_ctx_params_decoder`'s target.
///
/// # Safety
/// `params` is NULL or a key-terminated array; `r` is writable.
unsafe fn tls13_set_ctx_params_decode(params: *const OsslParam, r: &mut HkdfSetCtxParams) -> c_int {
    // SAFETY: the walk stops at the NULL key.
    unsafe {
        r.data = crate::params::OSSL_PARAM_locate_const(params, OSSL_KDF_PARAM_DATA);
        r.digest = crate::params::OSSL_PARAM_locate_const(params, OSSL_KDF_PARAM_DIGEST);
        r.engine = crate::params::OSSL_PARAM_locate_const(params, OSSL_ALG_PARAM_ENGINE);
        r.key = crate::params::OSSL_PARAM_locate_const(params, OSSL_KDF_PARAM_KEY);
        r.label = crate::params::OSSL_PARAM_locate_const(params, OSSL_KDF_PARAM_LABEL);
        r.mode = crate::params::OSSL_PARAM_locate_const(params, OSSL_KDF_PARAM_MODE);
        r.prefix = crate::params::OSSL_PARAM_locate_const(params, OSSL_KDF_PARAM_PREFIX);
        r.propq = crate::params::OSSL_PARAM_locate_const(params, OSSL_KDF_PARAM_PROPERTIES);
        r.salt = crate::params::OSSL_PARAM_locate_const(params, OSSL_KDF_PARAM_SALT);
    }
    1
}

/// `static int HKDF_Extract(...)` — `hkdf.c:1044-1057`. `PRK = HMAC-Hash(salt, IKM)` through the
/// one-shot `EVP_Q_mac`.
///
/// # Safety
/// `evp_md` is a live digest; `salt`/`ikm` are live for their lengths; `prk` is writable for
/// `prk_len`.
#[allow(clippy::too_many_arguments)] // mirrors the authority's signature exactly
unsafe fn hkdf_extract(
    libctx: *mut c_void,
    evp_md: *const crate::evp::digest::EvpMd,
    salt: *const u8,
    salt_len: usize,
    ikm: *const u8,
    ikm_len: usize,
    prk: *mut u8,
    prk_len: usize,
) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        let sz = EVP_MD_get_size(evp_md);
        if sz <= 0 {
            return 0;
        }
        if prk_len != sz as usize {
            raise_site(&err_sites::PROV_HKDF_1055);
            return 0;
        }
        (!EVP_Q_mac(
            libctx,
            c"HMAC".as_ptr(),
            ptr::null(),
            EVP_MD_get0_name(evp_md),
            ptr::null(),
            salt.cast(),
            salt_len,
            ikm,
            ikm_len,
            prk,
            EVP_MD_get_size(evp_md) as usize,
            ptr::null_mut(),
        )
        .is_null()) as c_int
    }
}

/// `static int HKDF_Expand(const EVP_MD *evp_md, const unsigned char *prk, size_t prk_len, const
/// unsigned char *info, size_t info_len, unsigned char *okm, size_t okm_len)` —
/// `hkdf.c:1104-1167`. `N = ceil(L/HashLen)`, `T(i) = HMAC-Hash(PRK, T(i-1) | info | i)`.
///
/// # Safety
/// `evp_md` live; `prk`/`info` live for their lengths; `okm` writable for `okm_len`.
#[allow(clippy::too_many_arguments)] // mirrors the authority's signature exactly
unsafe fn hkdf_expand(
    evp_md: *const crate::evp::digest::EvpMd,
    prk: *const u8,
    prk_len: usize,
    info: *const u8,
    info_len: usize,
    okm: *mut u8,
    okm_len: usize,
) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        let mut ret: c_int = 0;
        let mut prev = [0u8; EVP_MAX_MD_SIZE];
        let mut done_len: usize = 0;

        let sz = EVP_MD_get_size(evp_md);
        if sz <= 0 {
            return 0;
        }
        let dig_len = sz as usize;

        /* calc: N = ceil(L/HashLen) */
        let mut n = okm_len / dig_len;
        if !okm_len.is_multiple_of(dig_len) {
            n += 1;
        }

        if n > 255 || okm.is_null() {
            return 0;
        }

        let hmac = HMAC_CTX_new();
        if hmac.is_null() {
            return 0;
        }

        'err: {
            if HMAC_Init_ex(hmac, prk.cast(), prk_len as c_int, evp_md, ptr::null_mut()) == 0 {
                break 'err;
            }

            let mut i: c_uint = 1;
            while i <= n as c_uint {
                let ctr = [i as u8];
                /* calc: T(i) = HMAC-Hash(PRK, T(i - 1) | info | i) */
                if i > 1 {
                    if HMAC_Init_ex(hmac, ptr::null(), 0, ptr::null(), ptr::null_mut()) == 0 {
                        break 'err;
                    }
                    if HMAC_Update(hmac, prev.as_ptr().cast(), dig_len) == 0 {
                        break 'err;
                    }
                }
                if HMAC_Update(hmac, info.cast(), info_len) == 0 {
                    break 'err;
                }
                if HMAC_Update(hmac, ctr.as_ptr().cast(), 1) == 0 {
                    break 'err;
                }
                if HMAC_Final(hmac, prev.as_mut_ptr(), ptr::null_mut()) == 0 {
                    break 'err;
                }

                let copy_len = if dig_len > okm_len - done_len {
                    okm_len - done_len
                } else {
                    dig_len
                };
                ptr::copy_nonoverlapping(prev.as_ptr(), okm.add(done_len), copy_len);
                done_len += copy_len;
                i += 1;
            }
            ret = 1;
        }

        cleanse(prev.as_mut_ptr(), EVP_MAX_MD_SIZE);
        HMAC_CTX_free(hmac);
        ret
    }
}

/// `static int HKDF(...)` — `hkdf.c:1013-1038`: extract, then expand into the caller's buffer.
///
/// # Safety
/// The arguments are `HKDF_Extract`'s and `HKDF_Expand`'s together.
#[allow(clippy::too_many_arguments)] // mirrors the authority's signature exactly
unsafe fn hkdf_derive_okm(
    libctx: *mut c_void,
    evp_md: *const crate::evp::digest::EvpMd,
    salt: *const u8,
    salt_len: usize,
    ikm: *const u8,
    ikm_len: usize,
    info: *const u8,
    info_len: usize,
    okm: *mut u8,
    okm_len: usize,
) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        let mut prk = [0u8; EVP_MAX_MD_SIZE];

        let sz = EVP_MD_get_size(evp_md);
        if sz <= 0 {
            return 0;
        }
        let prk_len = sz as usize;

        /* Step 1: HKDF-Extract(salt, IKM) -> PRK */
        if hkdf_extract(
            libctx,
            evp_md,
            salt,
            salt_len,
            ikm,
            ikm_len,
            prk.as_mut_ptr(),
            prk_len,
        ) == 0
        {
            return 0;
        }

        /* Step 2: HKDF-Expand(PRK, info, L) -> OKM */
        let ret = hkdf_expand(evp_md, prk.as_ptr(), prk_len, info, info_len, okm, okm_len);
        cleanse(prk.as_mut_ptr(), EVP_MAX_MD_SIZE);
        ret
    }
}

/// `static int prov_tls13_hkdf_expand(...)` — `hkdf.c:1212-1246`. The TLS 1.3 `HkdfLabel`
/// structure, packed with `WPACKET`: `uint16 length, opaque label<7..255>, opaque context<0..255>`.
///
/// # Safety
/// `md` live; `key`/`prefix`/`label`/`data` live for their lengths; `out` writable for `outlen`.
#[allow(clippy::too_many_arguments)] // mirrors the authority's signature exactly
unsafe fn prov_tls13_hkdf_expand(
    md: *const crate::evp::digest::EvpMd,
    key: *const u8,
    keylen: usize,
    prefix: *const u8,
    prefixlen: usize,
    label: *const u8,
    labellen: usize,
    data: *const u8,
    datalen: usize,
    out: *mut u8,
    outlen: usize,
) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        let mut hkdflabel = [0u8; HKDF_MAXBUF];
        let mut hkdflabellen: usize = 0;
        let mut pkt = core::mem::MaybeUninit::<Wpacket>::uninit();
        let pkt = pkt.as_mut_ptr();

        if WPACKET_init_static_len(pkt, hkdflabel.as_mut_ptr(), HKDF_MAXBUF, 0) == 0
            || WPACKET_put_bytes_u16(pkt, outlen as u16) == 0
            || WPACKET_start_sub_packet_len__(pkt, 1) == 0
            || WPACKET_memcpy(pkt, prefix.cast(), prefixlen) == 0
            || WPACKET_memcpy(pkt, label.cast(), labellen) == 0
            || WPACKET_close(pkt) == 0
            || WPACKET_sub_memcpy__(
                pkt,
                data.cast(),
                if data.is_null() { 0 } else { datalen },
                1,
            ) == 0
            || WPACKET_get_total_written(pkt, &mut hkdflabellen) == 0
            || WPACKET_finish(pkt) == 0
        {
            WPACKET_cleanup(pkt);
            return 0;
        }

        hkdf_expand(
            md,
            key,
            keylen,
            hkdflabel.as_ptr(),
            hkdflabellen,
            out,
            outlen,
        )
    }
}

/// `static int prov_tls13_hkdf_generate_secret(...)` — `hkdf.c:1246-1307`. When `prevsecret` is
/// given, its pre-extract secret is this expand of the **hash of no messages**; the extract then
/// runs over it and `insecret`. The authority compares the *pointer* to know whether to cleanse the
/// pre-extract secret, which is a flag here.
///
/// # Safety
/// The arguments are the authority's.
#[allow(clippy::too_many_arguments)] // mirrors the authority's signature exactly
unsafe fn prov_tls13_hkdf_generate_secret(
    libctx: *mut c_void,
    md: *const crate::evp::digest::EvpMd,
    prevsecret: *const u8,
    prevsecretlen: usize,
    insecret: *const u8,
    insecretlen: usize,
    prefix: *const u8,
    prefixlen: usize,
    label: *const u8,
    labellen: usize,
    out: *mut u8,
    outlen: usize,
) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        let mut preextractsec = [0u8; EVP_MAX_MD_SIZE];
        /* Always filled with zeros. */
        let default_zeros = [0u8; EVP_MAX_MD_SIZE];

        let ret = EVP_MD_get_size(md);
        if ret <= 0 {
            return 0;
        }
        let mdlen = ret as usize;

        let mut insecret = insecret;
        let mut insecretlen = insecretlen;
        if insecret.is_null() {
            insecret = default_zeros.as_ptr();
            insecretlen = mdlen;
        }

        let mut prevsecret = prevsecret;
        let mut prevsecretlen = prevsecretlen;
        let mut used_preextract = false;
        if prevsecret.is_null() {
            prevsecret = default_zeros.as_ptr();
            prevsecretlen = mdlen;
        } else {
            let mctx = EVP_MD_CTX_new();
            let mut hash = [0u8; EVP_MAX_MD_SIZE];

            /* The pre-extract derive step uses a hash of no messages. */
            if mctx.is_null()
                || EVP_DigestInit_ex(mctx, md, ptr::null_mut()) <= 0
                || EVP_DigestFinal_ex(mctx, hash.as_mut_ptr(), ptr::null_mut()) <= 0
            {
                EVP_MD_CTX_free(mctx);
                return 0;
            }
            EVP_MD_CTX_free(mctx);

            /* Generate the pre-extract secret. */
            if prov_tls13_hkdf_expand(
                md,
                prevsecret,
                prevsecretlen,
                prefix,
                prefixlen,
                label,
                labellen,
                hash.as_ptr(),
                mdlen,
                preextractsec.as_mut_ptr(),
                mdlen,
            ) == 0
            {
                return 0;
            }
            prevsecret = preextractsec.as_ptr();
            prevsecretlen = mdlen;
            used_preextract = true;
        }

        let ret = hkdf_extract(
            libctx,
            md,
            prevsecret,
            prevsecretlen,
            insecret,
            insecretlen,
            out,
            outlen,
        );

        if used_preextract {
            cleanse(preextractsec.as_mut_ptr(), mdlen);
        }
        ret
    }
}

/// `static size_t kdf_hkdf_size(KDF_HKDF *ctx)` — `hkdf.c:192-209`.
///
/// # Safety
/// `ctx` live.
unsafe fn hkdf_size(ctx: *mut KdfHkdf) -> usize {
    // SAFETY: `ctx` is live per the contract.
    unsafe {
        if (*ctx).mode != EVP_KDF_HKDF_MODE_EXTRACT_ONLY {
            return usize::MAX;
        }
        let md = ossl_prov_digest_md(ptr::addr_of!((*ctx).digest));
        if md.is_null() {
            raise_site(&err_sites::PROV_HKDF_199);
            return 0;
        }
        let sz = EVP_MD_get_size(md);
        if sz <= 0 {
            return 0;
        }
        sz as usize
    }
}

/// `static void *kdf_hkdf_new(void *provctx)` — `hkdf.c:101-113`.
///
/// # Safety
/// The dispatch contract.
unsafe extern "C" fn hkdf_new(provctx: *mut c_void) -> *mut c_void {
    // SAFETY: the caller's contract.
    unsafe {
        if is_running() == 0 {
            return ptr::null_mut();
        }
        let ctx = CRYPTO_zalloc(core::mem::size_of::<KdfHkdf>(), FILE_HKDF, LINE).cast::<KdfHkdf>();
        if !ctx.is_null() {
            (*ctx).provctx = provctx;
        }
        ctx.cast()
    }
}

/// `static void kdf_hkdf_reset_ex(void *vctx, int on_free)` — `hkdf.c:130-158`. A fixed-digest row
/// saves and restores only its `PROV_DIGEST`; every other field is cleared. `PROV_DIGEST` is not
/// `Copy`, so the saved copy is made field by field.
///
/// # Safety
/// `vctx` is a live context.
unsafe fn hkdf_reset_ex(vctx: *mut c_void, on_free: c_int) {
    // SAFETY: `vctx` is live per the contract.
    unsafe {
        let ctx = vctx.cast::<KdfHkdf>();
        let provctx = (*ctx).provctx;
        let preserve_digest = if on_free != 0 { 0 } else { (*ctx).fixed_digest };
        let saved = ProvDigest {
            md: (*ctx).digest.md,
            alloc_md: (*ctx).digest.alloc_md,
            engine: (*ctx).digest.engine,
        };

        if preserve_digest != 0 {
            /* For fixed digests just save and restore the PROV_DIGEST object. */
        } else {
            ossl_prov_digest_reset(ptr::addr_of_mut!((*ctx).digest));
        }

        CRYPTO_free((*ctx).salt.cast(), FILE_HKDF, LINE);
        CRYPTO_free((*ctx).prefix.cast(), FILE_HKDF, LINE);
        CRYPTO_free((*ctx).label.cast(), FILE_HKDF, LINE);
        CRYPTO_clear_free((*ctx).data.cast(), (*ctx).data_len, FILE_HKDF, LINE);
        CRYPTO_clear_free((*ctx).key.cast(), (*ctx).key_len, FILE_HKDF, LINE);
        CRYPTO_clear_free((*ctx).info.cast(), (*ctx).info_len, FILE_HKDF, LINE);
        ptr::write_bytes(vctx.cast::<u8>(), 0, core::mem::size_of::<KdfHkdf>());
        (*ctx).provctx = provctx;
        if preserve_digest != 0 {
            (*ctx).fixed_digest = preserve_digest;
            (*ctx).digest.md = saved.md;
            (*ctx).digest.alloc_md = saved.alloc_md;
            (*ctx).digest.engine = saved.engine;
        }
    }
}

/// `static void kdf_hkdf_reset(void *vctx)` — `hkdf.c:125-128`.
///
/// # Safety
/// The dispatch contract.
unsafe extern "C" fn hkdf_reset(vctx: *mut c_void) {
    // SAFETY: the caller's contract.
    unsafe { hkdf_reset_ex(vctx, 0) }
}

/// `static void kdf_hkdf_free(void *vctx)` — `hkdf.c:115-123`.
///
/// # Safety
/// The dispatch contract.
unsafe extern "C" fn hkdf_free(vctx: *mut c_void) {
    // SAFETY: `vctx` is NULL or a live context.
    unsafe {
        if !vctx.is_null() {
            hkdf_reset_ex(vctx, 1);
            CRYPTO_free(vctx, FILE_HKDF, LINE);
        }
    }
}

/// `static void *kdf_hkdf_dup(void *vctx)` — `hkdf.c:160-190`.
///
/// # Safety
/// The dispatch contract.
unsafe extern "C" fn hkdf_dup(vctx: *mut c_void) -> *mut c_void {
    // SAFETY: the caller's contract.
    unsafe {
        let src = vctx.cast::<KdfHkdf>();
        let dest = hkdf_new((*src).provctx).cast::<KdfHkdf>();
        if dest.is_null() {
            return ptr::null_mut();
        }
        if ossl_prov_memdup(
            (*src).salt.cast(),
            (*src).salt_len,
            ptr::addr_of_mut!((*dest).salt),
            ptr::addr_of_mut!((*dest).salt_len),
        ) == 0
            || ossl_prov_memdup(
                (*src).key.cast(),
                (*src).key_len,
                ptr::addr_of_mut!((*dest).key),
                ptr::addr_of_mut!((*dest).key_len),
            ) == 0
            || ossl_prov_memdup(
                (*src).prefix.cast(),
                (*src).prefix_len,
                ptr::addr_of_mut!((*dest).prefix),
                ptr::addr_of_mut!((*dest).prefix_len),
            ) == 0
            || ossl_prov_memdup(
                (*src).label.cast(),
                (*src).label_len,
                ptr::addr_of_mut!((*dest).label),
                ptr::addr_of_mut!((*dest).label_len),
            ) == 0
            || ossl_prov_memdup(
                (*src).data.cast(),
                (*src).data_len,
                ptr::addr_of_mut!((*dest).data),
                ptr::addr_of_mut!((*dest).data_len),
            ) == 0
            || ossl_prov_memdup(
                (*src).info.cast(),
                (*src).info_len,
                ptr::addr_of_mut!((*dest).info),
                ptr::addr_of_mut!((*dest).info_len),
            ) == 0
            || ossl_prov_digest_copy(
                ptr::addr_of_mut!((*dest).digest),
                ptr::addr_of!((*src).digest),
            ) == 0
        {
            hkdf_free(dest.cast());
            return ptr::null_mut();
        }
        (*dest).mode = (*src).mode;
        (*dest).fixed_digest = (*src).fixed_digest;
        dest.cast()
    }
}

/// `static int hkdf_common_set_ctx_params(KDF_HKDF *ctx, struct hkdf_all_set_ctx_params_st *p)` —
/// `hkdf.c:287-355`. The digest/XOF arm, the two-typed `mode` arm, and the key/salt/info arms.
///
/// # Safety
/// `ctx` live; `p` this frame's; `params` the caller's array is not read here.
unsafe fn hkdf_common_set_ctx_params(ctx: *mut KdfHkdf, p: *const HkdfSetCtxParams) -> c_int {
    // SAFETY: `ctx` is live per the contract.
    unsafe {
        let libctx = prov_libctx_of((*ctx).provctx);

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
                raise_site(&err_sites::PROV_HKDF_299);
                return 0;
            }
        }

        if !(*p).mode.is_null() {
            let mut n: c_int = 0;
            if (*(*p).mode).data_type == OSSL_PARAM_UTF8_STRING {
                let value = (*(*p).mode).data.cast::<c_char>();
                if OPENSSL_strcasecmp(value, c"EXTRACT_AND_EXPAND".as_ptr()) == 0 {
                    (*ctx).mode = EVP_KDF_HKDF_MODE_EXTRACT_AND_EXPAND;
                } else if OPENSSL_strcasecmp(value, c"EXTRACT_ONLY".as_ptr()) == 0 {
                    (*ctx).mode = EVP_KDF_HKDF_MODE_EXTRACT_ONLY;
                } else if OPENSSL_strcasecmp(value, c"EXPAND_ONLY".as_ptr()) == 0 {
                    (*ctx).mode = EVP_KDF_HKDF_MODE_EXPAND_ONLY;
                } else {
                    raise_site(&err_sites::PROV_HKDF_313);
                    return 0;
                }
            } else if OSSL_PARAM_get_int((*p).mode, &mut n) != 0 {
                if n != EVP_KDF_HKDF_MODE_EXTRACT_AND_EXPAND
                    && n != EVP_KDF_HKDF_MODE_EXTRACT_ONLY
                    && n != EVP_KDF_HKDF_MODE_EXPAND_ONLY
                {
                    raise_site(&err_sites::PROV_HKDF_320);
                    return 0;
                }
                (*ctx).mode = n;
            } else {
                raise_site(&err_sites::PROV_HKDF_325);
                return 0;
            }
        }

        if !(*p).key.is_null()
            && ossl_param_get1_octet_string_from_param(
                (*p).key,
                ptr::addr_of_mut!((*ctx).key),
                ptr::addr_of_mut!((*ctx).key_len),
            ) == 0
        {
            return 0;
        }

        if !(*p).salt.is_null()
            && ossl_param_get1_octet_string_from_param(
                (*p).salt,
                ptr::addr_of_mut!((*ctx).salt),
                ptr::addr_of_mut!((*ctx).salt_len),
            ) == 0
        {
            return 0;
        }

        /* Only relevant for HKDF not to the TLS 1.3 KDF. */
        let infos: [*const OsslParam; HKDF_MAX_INFOS] = (*p).info;
        if ossl_param_get1_concat_octet_string(
            (*p).num_info as usize,
            infos.as_ptr(),
            ptr::addr_of_mut!((*ctx).info),
            ptr::addr_of_mut!((*ctx).info_len),
        ) == 0
        {
            return 0;
        }

        1
    }
}

/// `static int kdf_hkdf_derive(void *vctx, unsigned char *key, size_t keylen, const OSSL_PARAM
/// params[])` — `hkdf.c:229-267`.
///
/// # Safety
/// The dispatch contract.
unsafe extern "C" fn hkdf_ctx_derive(
    vctx: *mut c_void,
    key: *mut u8,
    keylen: usize,
    params: *const OsslParam,
) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        if is_running() == 0 || hkdf_ctx_set_ctx_params(vctx, params) == 0 {
            return 0;
        }
        let ctx = vctx.cast::<KdfHkdf>();
        let libctx = prov_libctx_of((*ctx).provctx);

        let md = ossl_prov_digest_md(ptr::addr_of!((*ctx).digest));
        if md.is_null() {
            return fail_at(&err_sites::PROV_HKDF_239);
        }
        if (*ctx).key.is_null() {
            return fail_at(&err_sites::PROV_HKDF_243);
        }
        if keylen == 0 {
            return fail_at(&err_sites::PROV_HKDF_247);
        }

        if (*ctx).mode == EVP_KDF_HKDF_MODE_EXTRACT_ONLY {
            hkdf_extract(
                libctx,
                md,
                (*ctx).salt,
                (*ctx).salt_len,
                (*ctx).key,
                (*ctx).key_len,
                key,
                keylen,
            )
        } else if (*ctx).mode == EVP_KDF_HKDF_MODE_EXPAND_ONLY {
            hkdf_expand(
                md,
                (*ctx).key,
                (*ctx).key_len,
                (*ctx).info,
                (*ctx).info_len,
                key,
                keylen,
            )
        } else {
            hkdf_derive_okm(
                libctx,
                md,
                (*ctx).salt,
                (*ctx).salt_len,
                (*ctx).key,
                (*ctx).key_len,
                (*ctx).info,
                (*ctx).info_len,
                key,
                keylen,
            )
        }
    }
}

/// `static int kdf_hkdf_set_ctx_params(void *vctx, const OSSL_PARAM params[])` —
/// `hkdf.c:506-524`. The FIPS `ind_k` arm is absent.
///
/// # Safety
/// The dispatch contract.
unsafe extern "C" fn hkdf_ctx_set_ctx_params(vctx: *mut c_void, params: *const OsslParam) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        if vctx.is_null() {
            return 0;
        }
        if let Some(site) = repeated_param_site_by_field(params, &HKDF_SET_DECODER_KEYS) {
            return fail_at(site);
        }
        let mut p = HkdfSetCtxParams::default();
        if hkdf_set_ctx_params_decode(params, &mut p) == 0 {
            return 0;
        }
        hkdf_common_set_ctx_params(vctx.cast::<KdfHkdf>(), &p)
    }
}

/// `static int hkdf_common_get_ctx_params(void *vctx, OSSL_PARAM params[])` — `hkdf.c:667-736`,
/// without its FIPS arm.
///
/// # Safety
/// The dispatch contract.
unsafe extern "C" fn hkdf_common_get_ctx_params(
    vctx: *mut c_void,
    params: *mut OsslParam,
) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        if vctx.is_null() {
            return 0;
        }
        if let Some(site) =
            repeated_param_site_by_field(params.cast_const(), &HKDF_GET_DECODER_KEYS)
        {
            return fail_at(site);
        }
        let ctx = vctx.cast::<KdfHkdf>();

        let p_size = locate_const(params, OSSL_KDF_PARAM_SIZE);
        if !p_size.is_null() {
            let sz = hkdf_size(ctx);
            if sz == 0 {
                return 0;
            }
            if OSSL_PARAM_set_size_t(p_size.cast_mut(), sz) == 0 {
                return 0;
            }
        }

        let p_digest = locate_const(params, OSSL_KDF_PARAM_DIGEST);
        if !p_digest.is_null() {
            let md = ossl_prov_digest_md(ptr::addr_of!((*ctx).digest));
            if md.is_null() {
                return 0;
            }
            if OSSL_PARAM_set_utf8_string(p_digest.cast_mut(), EVP_MD_get0_name(md)) == 0 {
                return 0;
            }
        }

        /* OSSL_KDF_PARAM_MODE has multiple parameter types, so look for all instances. */
        let p_mode = locate_const(params, OSSL_KDF_PARAM_MODE);
        if !p_mode.is_null() {
            if (*p_mode).data_type == OSSL_PARAM_UTF8_STRING {
                let name = match (*ctx).mode {
                    EVP_KDF_HKDF_MODE_EXTRACT_AND_EXPAND => c"EXTRACT_AND_EXPAND".as_ptr(),
                    EVP_KDF_HKDF_MODE_EXTRACT_ONLY => c"EXTRACT_ONLY".as_ptr(),
                    EVP_KDF_HKDF_MODE_EXPAND_ONLY => c"EXPAND_ONLY".as_ptr(),
                    _ => return 0,
                };
                if OSSL_PARAM_set_utf8_string(p_mode.cast_mut(), name) == 0 {
                    return 0;
                }
            } else if OSSL_PARAM_set_int(p_mode.cast_mut(), (*ctx).mode) == 0 {
                return 0;
            }
        }

        let p_salt = locate_const(params, OSSL_KDF_PARAM_SALT);
        if !p_salt.is_null() {
            if (*ctx).salt.is_null() || (*ctx).salt_len == 0 {
                (*p_salt.cast_mut()).return_size = 0;
            } else if OSSL_PARAM_set_octet_string(
                p_salt.cast_mut(),
                (*ctx).salt.cast(),
                (*ctx).salt_len,
            ) == 0
            {
                return 0;
            }
        }

        let p_info = locate_const(params, OSSL_KDF_PARAM_INFO);
        if !p_info.is_null() {
            if (*ctx).info.is_null() || (*ctx).info_len == 0 {
                (*p_info.cast_mut()).return_size = 0;
            } else if OSSL_PARAM_set_octet_string(
                p_info.cast_mut(),
                (*ctx).info.cast(),
                (*ctx).info_len,
            ) == 0
            {
                return 0;
            }
        }

        1
    }
}

/// `static const OSSL_PARAM *kdf_hkdf_settable_ctx_params(void *ctx, void *provctx)` —
/// `hkdf.c:497-503`.
///
/// # Safety
/// The dispatch contract.
unsafe extern "C" fn hkdf_settable_ctx_params(
    _ctx: *mut c_void,
    _provctx: *mut c_void,
) -> *const OsslParam {
    HKDF_SETTABLE_CTX_PARAMS.as_ptr()
}

/// `static const OSSL_PARAM *hkdf_gettable_ctx_params(void *ctx, void *provctx)` —
/// `hkdf.c:540-543`.
///
/// # Safety
/// The dispatch contract.
unsafe extern "C" fn hkdf_gettable_ctx_params(
    _ctx: *mut c_void,
    _provctx: *mut c_void,
) -> *const OsslParam {
    HKDF_GETTABLE_CTX_PARAMS.as_ptr()
}

/// `static void *kdf_hkdf_fixed_digest_new(void *provctx, const char *digest)` —
/// `hkdf.c:655-679`. A successful load fixes the digest; failures release the context.
///
/// # Safety
/// The dispatch contract; `digest` is NUL-terminated.
unsafe fn hkdf_fixed_digest_new(provctx: *mut c_void, digest: *const c_char) -> *mut c_void {
    // SAFETY: the caller's contract.
    unsafe {
        let ctx = hkdf_new(provctx).cast::<KdfHkdf>();
        if ctx.is_null() {
            return ptr::null_mut();
        }
        let mut params = [END, END];
        params[0] = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST, digest.cast_mut(), 0);
        let libctx = prov_libctx_of((*ctx).provctx);
        if ossl_prov_digest_load_from_params(
            ptr::addr_of_mut!((*ctx).digest),
            params.as_ptr(),
            libctx,
        ) == 0
        {
            hkdf_free(ctx.cast());
            return ptr::null_mut();
        }
        /* Now the digest can no longer be changed. */
        (*ctx).fixed_digest = 1;
        ctx.cast()
    }
}

/// `static void *kdf_hkdf_sha256_new(void *provctx)` — the `KDF_HKDF_FIXED_DIGEST_NEW` expansion,
/// `hkdf.c:646-652`.
///
/// # Safety
/// The dispatch contract.
unsafe extern "C" fn hkdf_sha256_new(provctx: *mut c_void) -> *mut c_void {
    // SAFETY: the caller's contract.
    unsafe { hkdf_fixed_digest_new(provctx, c"SHA256".as_ptr()) }
}

/// `static void *kdf_hkdf_sha384_new(void *provctx)`.
///
/// # Safety
/// The dispatch contract.
unsafe extern "C" fn hkdf_sha384_new(provctx: *mut c_void) -> *mut c_void {
    // SAFETY: the caller's contract.
    unsafe { hkdf_fixed_digest_new(provctx, c"SHA384".as_ptr()) }
}

/// `static void *kdf_hkdf_sha512_new(void *provctx)`.
///
/// # Safety
/// The dispatch contract.
unsafe extern "C" fn hkdf_sha512_new(provctx: *mut c_void) -> *mut c_void {
    // SAFETY: the caller's contract.
    unsafe { hkdf_fixed_digest_new(provctx, c"SHA512".as_ptr()) }
}

/// `static int kdf_hkdf_fixed_digest_set_ctx_params(void *vctx, const OSSL_PARAM params[])` —
/// `hkdf.c:712-740`. Setting the digest is refused; everything else goes through the common arm.
///
/// # Safety
/// The dispatch contract.
unsafe extern "C" fn hkdf_fixed_digest_set_ctx_params(
    vctx: *mut c_void,
    params: *const OsslParam,
) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        if vctx.is_null() {
            return 0;
        }
        if let Some(site) = repeated_param_site_by_field(params, &HKDF_FIXED_DECODER_KEYS) {
            return fail_at(site);
        }
        let mut p = HkdfSetCtxParams::default();
        if hkdf_fixed_set_ctx_params_decode(params, &mut p) == 0 {
            return 0;
        }
        if !p.digest.is_null() {
            return fail_at(&err_sites::PROV_HKDF_916);
        }
        hkdf_common_set_ctx_params(vctx.cast::<KdfHkdf>(), &p)
    }
}

/// `static const OSSL_PARAM *kdf_hkdf_fixed_digest_settable_ctx_params(void *ctx, void *provctx)` —
/// `hkdf.c:741-745`.
///
/// # Safety
/// The dispatch contract.
unsafe extern "C" fn hkdf_fixed_digest_settable_ctx_params(
    _ctx: *mut c_void,
    _provctx: *mut c_void,
) -> *const OsslParam {
    HKDF_FIXED_SETTABLE_CTX_PARAMS.as_ptr()
}

/// `static int kdf_tls1_3_derive(void *vctx, unsigned char *key, size_t keylen, const OSSL_PARAM
/// params[])` — `hkdf.c:1310-1344`. `EXTRACT_AND_EXPAND` is refused rather than defaulted.
///
/// # Safety
/// The dispatch contract.
unsafe extern "C" fn tls13_derive(
    vctx: *mut c_void,
    key: *mut u8,
    keylen: usize,
    params: *const OsslParam,
) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        if is_running() == 0 || tls13_set_ctx_params(vctx, params) == 0 {
            return 0;
        }
        let ctx = vctx.cast::<KdfHkdf>();
        let md = ossl_prov_digest_md(ptr::addr_of!((*ctx).digest));
        if md.is_null() {
            return fail_at(&err_sites::PROV_HKDF_1349);
        }

        if (*ctx).mode == EVP_KDF_HKDF_MODE_EXTRACT_ONLY {
            prov_tls13_hkdf_generate_secret(
                prov_libctx_of((*ctx).provctx),
                md,
                (*ctx).salt,
                (*ctx).salt_len,
                (*ctx).key,
                (*ctx).key_len,
                (*ctx).prefix,
                (*ctx).prefix_len,
                (*ctx).label,
                (*ctx).label_len,
                key,
                keylen,
            )
        } else if (*ctx).mode == EVP_KDF_HKDF_MODE_EXPAND_ONLY {
            prov_tls13_hkdf_expand(
                md,
                (*ctx).key,
                (*ctx).key_len,
                (*ctx).prefix,
                (*ctx).prefix_len,
                (*ctx).label,
                (*ctx).label_len,
                (*ctx).data,
                (*ctx).data_len,
                key,
                keylen,
            )
        } else {
            0
        }
    }
}

/// `static int kdf_tls1_3_set_ctx_params(void *vctx, const OSSL_PARAM params[])` —
/// `hkdf.c:1352-1420`, without its two FIPS arms.
///
/// # Safety
/// The dispatch contract.
unsafe extern "C" fn tls13_set_ctx_params(vctx: *mut c_void, params: *const OsslParam) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        if vctx.is_null() {
            return 0;
        }
        if let Some(site) = repeated_param_site_by_field(params, &TLS13_SET_DECODER_KEYS) {
            return fail_at(site);
        }
        let mut p = HkdfSetCtxParams::default();
        if tls13_set_ctx_params_decode(params, &mut p) == 0 {
            return 0;
        }
        if hkdf_common_set_ctx_params(vctx.cast::<KdfHkdf>(), &p) == 0 {
            return 0;
        }
        let ctx = vctx.cast::<KdfHkdf>();
        if (*ctx).mode == EVP_KDF_HKDF_MODE_EXTRACT_AND_EXPAND {
            return fail_at(&err_sites::PROV_HKDF_1629);
        }

        if !p.prefix.is_null()
            && ossl_param_get1_octet_string_from_param(
                p.prefix,
                ptr::addr_of_mut!((*ctx).prefix),
                ptr::addr_of_mut!((*ctx).prefix_len),
            ) == 0
        {
            return 0;
        }
        if !p.label.is_null()
            && ossl_param_get1_octet_string_from_param(
                p.label,
                ptr::addr_of_mut!((*ctx).label),
                ptr::addr_of_mut!((*ctx).label_len),
            ) == 0
        {
            return 0;
        }
        if !p.data.is_null()
            && ossl_param_get1_octet_string_from_param(
                p.data,
                ptr::addr_of_mut!((*ctx).data),
                ptr::addr_of_mut!((*ctx).data_len),
            ) == 0
        {
            return 0;
        }
        1
    }
}

/// `static const OSSL_PARAM *kdf_tls1_3_settable_ctx_params(void *ctx, void *provctx)` —
/// `hkdf.c:1694-1698`.
///
/// # Safety
/// The dispatch contract.
unsafe extern "C" fn tls13_settable_ctx_params(
    _ctx: *mut c_void,
    _provctx: *mut c_void,
) -> *const OsslParam {
    TLS13_SETTABLE_CTX_PARAMS.as_ptr()
}

/// `const OSSL_DISPATCH ossl_kdf_hkdf_functions[]` — `hkdf.c:645-652`.
pub(crate) static HKDF_FUNCTIONS: [OsslDispatch; 10] = [
    OsslDispatch {
        function_id: OSSL_FUNC_KDF_NEWCTX,
        function: hkdf_new as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KDF_DUPCTX,
        function: hkdf_dup as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KDF_FREECTX,
        function: hkdf_free as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KDF_RESET,
        function: hkdf_reset as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KDF_DERIVE,
        function: hkdf_ctx_derive as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KDF_SETTABLE_CTX_PARAMS,
        function: hkdf_settable_ctx_params as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KDF_SET_CTX_PARAMS,
        function: hkdf_ctx_set_ctx_params as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KDF_GETTABLE_CTX_PARAMS,
        function: hkdf_gettable_ctx_params as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KDF_GET_CTX_PARAMS,
        function: hkdf_common_get_ctx_params as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_DISPATCH_END,
        function: ptr::null_mut(),
    },
];

/// `const OSSL_DISPATCH ossl_kdf_hkdf_sha256_functions[]` — the
/// `MAKE_KDF_HKDF_FIXED_DIGEST_FUNCTIONS` expansion, `hkdf.c:588-604`.
pub(crate) static HKDF_SHA256_FUNCTIONS: [OsslDispatch; 10] = [
    OsslDispatch {
        function_id: OSSL_FUNC_KDF_NEWCTX,
        function: hkdf_sha256_new as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KDF_DUPCTX,
        function: hkdf_dup as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KDF_FREECTX,
        function: hkdf_free as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KDF_RESET,
        function: hkdf_reset as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KDF_DERIVE,
        function: hkdf_ctx_derive as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KDF_SETTABLE_CTX_PARAMS,
        function: hkdf_fixed_digest_settable_ctx_params as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KDF_SET_CTX_PARAMS,
        function: hkdf_fixed_digest_set_ctx_params as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KDF_GETTABLE_CTX_PARAMS,
        function: hkdf_gettable_ctx_params as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KDF_GET_CTX_PARAMS,
        function: hkdf_common_get_ctx_params as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_DISPATCH_END,
        function: ptr::null_mut(),
    },
];

/// `const OSSL_DISPATCH ossl_kdf_hkdf_sha384_functions[]`.
pub(crate) static HKDF_SHA384_FUNCTIONS: [OsslDispatch; 10] = [
    OsslDispatch {
        function_id: OSSL_FUNC_KDF_NEWCTX,
        function: hkdf_sha384_new as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KDF_DUPCTX,
        function: hkdf_dup as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KDF_FREECTX,
        function: hkdf_free as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KDF_RESET,
        function: hkdf_reset as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KDF_DERIVE,
        function: hkdf_ctx_derive as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KDF_SETTABLE_CTX_PARAMS,
        function: hkdf_fixed_digest_settable_ctx_params as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KDF_SET_CTX_PARAMS,
        function: hkdf_fixed_digest_set_ctx_params as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KDF_GETTABLE_CTX_PARAMS,
        function: hkdf_gettable_ctx_params as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KDF_GET_CTX_PARAMS,
        function: hkdf_common_get_ctx_params as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_DISPATCH_END,
        function: ptr::null_mut(),
    },
];

/// `const OSSL_DISPATCH ossl_kdf_hkdf_sha512_functions[]`.
pub(crate) static HKDF_SHA512_FUNCTIONS: [OsslDispatch; 10] = [
    OsslDispatch {
        function_id: OSSL_FUNC_KDF_NEWCTX,
        function: hkdf_sha512_new as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KDF_DUPCTX,
        function: hkdf_dup as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KDF_FREECTX,
        function: hkdf_free as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KDF_RESET,
        function: hkdf_reset as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KDF_DERIVE,
        function: hkdf_ctx_derive as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KDF_SETTABLE_CTX_PARAMS,
        function: hkdf_fixed_digest_settable_ctx_params as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KDF_SET_CTX_PARAMS,
        function: hkdf_fixed_digest_set_ctx_params as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KDF_GETTABLE_CTX_PARAMS,
        function: hkdf_gettable_ctx_params as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KDF_GET_CTX_PARAMS,
        function: hkdf_common_get_ctx_params as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_DISPATCH_END,
        function: ptr::null_mut(),
    },
];

/// `const OSSL_DISPATCH ossl_kdf_tls1_3_kdf_functions[]` — `hkdf.c:1700-1713`.
pub(crate) static TLS13_KDF_FUNCTIONS: [OsslDispatch; 10] = [
    OsslDispatch {
        function_id: OSSL_FUNC_KDF_NEWCTX,
        function: hkdf_new as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KDF_DUPCTX,
        function: hkdf_dup as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KDF_FREECTX,
        function: hkdf_free as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KDF_RESET,
        function: hkdf_reset as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KDF_DERIVE,
        function: tls13_derive as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KDF_SETTABLE_CTX_PARAMS,
        function: tls13_settable_ctx_params as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KDF_SET_CTX_PARAMS,
        function: tls13_set_ctx_params as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KDF_GETTABLE_CTX_PARAMS,
        function: hkdf_gettable_ctx_params as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KDF_GET_CTX_PARAMS,
        function: hkdf_common_get_ctx_params as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_DISPATCH_END,
        function: ptr::null_mut(),
    },
];

// =============================================================================================
// `providers/implementations/kdfs/tls1_prf.c` — TLS1-PRF (RFC 2246 §5, RFC 5246 §5)
// =============================================================================================

/// `OSSL_DIGEST_NAME_MD5_SHA1` — `include/openssl/core_names.h:36`. The one digest name that
/// switches `kdf_tls1_prf_set_ctx_params` onto the two-MAC TLS v1.0/v1.1 arm.
const OSSL_DIGEST_NAME_MD5_SHA1: *const c_char = c"MD5-SHA1".as_ptr();

/// `OSSL_DIGEST_NAME_MD5` — `include/openssl/core_names.h:35`.
const OSSL_DIGEST_NAME_MD5: *const c_char = c"MD5".as_ptr();

/// `OSSL_DIGEST_NAME_SHA1` — `include/openssl/core_names.h:37`.
const OSSL_DIGEST_NAME_SHA1: *const c_char = c"SHA1".as_ptr();

/// `OSSL_KDF_PARAM_SEED` — `include/openssl/core_names.h:310`.
const OSSL_KDF_PARAM_SEED: *const c_char = c"seed".as_ptr();

/// `FILE_TLS1_PRF` — the unit's own `__FILE__`.
const FILE_TLS1_PRF: *const c_char = c"providers/implementations/kdfs/tls1_prf.c".as_ptr();

/// `TLSPRF_MAX_SEEDS` — `tls1_prf.c:100`.
const TLSPRF_MAX_SEEDS: usize = 6;

/// `safe_add_size_t(a, b, &err)` — `internal/safe_math.h`'s `OSSL_SAFE_MATH_UNSIGNED(size_t,
/// size_t)` expansion for the add case: `a + b`, with `*err` set and 0 returned on overflow. The
/// `seed` fields' concatenation is the one caller, and it must not wrap a length.
fn safe_add_size_t(a: usize, b: usize, err: &mut c_int) -> usize {
    match a.checked_add(b) {
        Some(v) => v,
        None => {
            *err = 1;
            0
        }
    }
}

/// `struct TLS1_PRF` — `tls1_prf.c:103-119`, without its FIPS indicator field.
#[repr(C)]
pub(crate) struct Tls1Prf {
    /// `void *provctx`.
    pub provctx: *mut c_void,
    /// `EVP_MAC_CTX *P_hash` — the main digest's MAC context.
    pub p_hash: *mut EvpMacCtx,
    /// `EVP_MAC_CTX *P_sha1` — the SHA-1 MAC context for the MD5/SHA-1 combined PRF.
    pub p_sha1: *mut EvpMacCtx,
    /// `unsigned char *sec` / `size_t seclen`.
    pub sec: *mut u8,
    pub seclen: usize,
    /// `unsigned char *seed` / `size_t seedlen` — the concatenated seed data.
    pub seed: *mut u8,
    pub seedlen: usize,
}

/// `struct tls1prf_set_ctx_params_st` — `tls1_prf.c:311-329`, without its three FIPS fields.
#[derive(Default)]
struct Tls1PrfSetCtxParams {
    digest: *const OsslParam,
    engine: *const OsslParam,
    propq: *const OsslParam,
    secret: *const OsslParam,
    seed: [*const OsslParam; TLSPRF_MAX_SEEDS],
    num_seed: c_int,
}

/// The `tls1prf_set_ctx_params_decoder` keys this profile's generated switch raises for, each with
/// its (field id, raise site). The three FIPS `*-check` keys (`:372`, `:403`, `:428`) are compiled
/// out, and `seed` is absent because its repetition is a **list**, not an error, up to
/// `TLSPRF_MAX_SEEDS` (collected below against the `:470` raise). The generated `strcmp`-tree at
/// `tls1_prf.c:337-477` raises `PROV_R_REPEATED_PARAMETER` at the second occurrence of any one of
/// these four.
const TLS1_PRF_SET_DECODER_KEYS: [(&err_sites::ErrSite, *const c_char, u32); 4] = [
    (&err_sites::PROV_TLS1_PRF_382, OSSL_KDF_PARAM_DIGEST, 0),
    (&err_sites::PROV_TLS1_PRF_415, OSSL_ALG_PARAM_ENGINE, 1),
    (&err_sites::PROV_TLS1_PRF_440, OSSL_KDF_PARAM_PROPERTIES, 2),
    (&err_sites::PROV_TLS1_PRF_459, OSSL_KDF_PARAM_SECRET, 3),
];

/// The `tls1prf_get_ctx_params_decoder` key, `tls1_prf.c:657-673` (the FIPS `fips-indicator` at
/// `:655` is compiled out).
const TLS1_PRF_GET_DECODER_KEYS: [(&err_sites::ErrSite, *const c_char, u32); 1] =
    [(&err_sites::PROV_TLS1_PRF_667, OSSL_KDF_PARAM_SIZE, 0)];

/// `static const OSSL_PARAM tls1prf_set_ctx_params_list[]` — `tls1_prf.c:293-308`, without its
/// three FIPS entries.
static TLS1_PRF_SETTABLE_CTX_PARAMS: [OsslParam; 5] = [
    param_utf8_string(OSSL_KDF_PARAM_PROPERTIES),
    param_utf8_string(OSSL_KDF_PARAM_DIGEST),
    param_octet_string(OSSL_KDF_PARAM_SECRET),
    param_octet_string(OSSL_KDF_PARAM_SEED),
    END,
];

/// `static const OSSL_PARAM tls1prf_get_ctx_params_list[]` — `tls1_prf.c:674-680`, without its
/// FIPS entry.
static TLS1_PRF_GETTABLE_CTX_PARAMS: [OsslParam; 2] = [param_size_t(OSSL_KDF_PARAM_SIZE), END];

/// The generated set decoder's seed rule, the one thing `repeated_param_site_by_field` cannot
/// express: `seed` is a **list**, and a seventh record raises `PROV_R_TOO_MANY_RECORDS` at
/// `tls1_prf.c:470`.
///
/// # Safety
/// `params` is NULL or a key-terminated array; `r` is writable.
unsafe fn tls1_prf_collect_seed(params: *const OsslParam, r: &mut Tls1PrfSetCtxParams) -> c_int {
    // SAFETY: the walk stops at the NULL key.
    unsafe {
        if params.is_null() {
            return 1;
        }
        let mut p = params;
        while !(*p).key.is_null() {
            if CStr::from_ptr((*p).key).to_bytes() == CStr::from_ptr(OSSL_KDF_PARAM_SEED).to_bytes()
            {
                if r.num_seed as usize >= TLSPRF_MAX_SEEDS {
                    raise_site(&err_sites::PROV_TLS1_PRF_470);
                    return 0;
                }
                r.seed[r.num_seed as usize] = p;
                r.num_seed += 1;
            }
            p = p.add(1);
        }
    }
    1
}

/// `static int tls1_prf_P_hash(EVP_MAC_CTX *ctx_init, const unsigned char *sec, size_t sec_len,
/// const unsigned char *seed, size_t seed_len, unsigned char *out, size_t olen)` —
/// `tls1_prf.c:503-567`. `A(0) = seed`, `A(i) = HMAC(sec, A(i-1))`, `out = HMAC(sec, A(i) || seed)
/// || ...` until `olen` bytes are produced. The authority's `goto err` is a labelled block whose
/// single exit frees both MAC contexts and cleanses the bounce buffer.
///
/// # Safety
/// `ctx_init` is a live MAC context; `sec`/`seed` are live for their lengths; `out` is writable
/// for `olen` bytes.
#[allow(clippy::too_many_arguments)] // mirrors the authority's signature exactly
unsafe fn tls1_prf_p_hash(
    ctx_init: *mut EvpMacCtx,
    sec: *const u8,
    sec_len: usize,
    seed: *const u8,
    seed_len: usize,
    out: *mut u8,
    olen: usize,
) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        let mut ctx: *mut EvpMacCtx = ptr::null_mut();
        let mut ctx_ai: *mut EvpMacCtx = ptr::null_mut();
        let mut ai = [0u8; EVP_MAX_MD_SIZE];
        let mut ai_len: usize = 0;
        let mut ret: c_int = 0;

        'err: {
            if EVP_MAC_init(ctx_init, sec, sec_len, ptr::null()) == 0 {
                break 'err;
            }
            let chunk = EVP_MAC_CTX_get_mac_size(ctx_init);
            if chunk == 0 {
                break 'err;
            }
            /* A(0) = seed */
            ctx_ai = EVP_MAC_CTX_dup(ctx_init);
            if ctx_ai.is_null() {
                break 'err;
            }
            if !seed.is_null() && EVP_MAC_update(ctx_ai, seed, seed_len) == 0 {
                break 'err;
            }

            let mut out_p = out;
            let mut olen_rem = olen;
            loop {
                /* calc: A(i) = HMAC_<hash>(secret, A(i-1)) */
                if EVP_MAC_final(ctx_ai, ai.as_mut_ptr(), &mut ai_len, EVP_MAX_MD_SIZE) == 0 {
                    break 'err;
                }
                EVP_MAC_CTX_free(ctx_ai);
                ctx_ai = ptr::null_mut();

                /* calc next chunk: HMAC_<hash>(secret, A(i) + seed) */
                ctx = EVP_MAC_CTX_dup(ctx_init);
                if ctx.is_null() {
                    break 'err;
                }
                if EVP_MAC_update(ctx, ai.as_ptr(), ai_len) == 0 {
                    break 'err;
                }
                /* save state for calculating next A(i) value */
                if olen_rem > chunk {
                    ctx_ai = EVP_MAC_CTX_dup(ctx);
                    if ctx_ai.is_null() {
                        break 'err;
                    }
                }
                if !seed.is_null() && EVP_MAC_update(ctx, seed, seed_len) == 0 {
                    break 'err;
                }
                if olen_rem <= chunk {
                    /* last chunk - use Ai as temp bounce buffer */
                    if EVP_MAC_final(ctx, ai.as_mut_ptr(), &mut ai_len, EVP_MAX_MD_SIZE) == 0 {
                        break 'err;
                    }
                    ptr::copy_nonoverlapping(ai.as_ptr(), out_p, olen_rem);
                    break;
                }
                if EVP_MAC_final(ctx, out_p, ptr::null_mut(), olen_rem) == 0 {
                    break 'err;
                }
                EVP_MAC_CTX_free(ctx);
                ctx = ptr::null_mut();
                out_p = out_p.add(chunk);
                olen_rem -= chunk;
            }
            ret = 1;
        }

        EVP_MAC_CTX_free(ctx);
        EVP_MAC_CTX_free(ctx_ai);
        cleanse(ai.as_mut_ptr(), EVP_MAX_MD_SIZE);
        ret
    }
}

/// `static int tls1_prf_alg(EVP_MAC_CTX *mdctx, EVP_MAC_CTX *sha1ctx, const unsigned char *sec,
/// size_t slen, const unsigned char *seed, size_t seed_len, unsigned char *out, size_t olen)` —
/// `tls1_prf.c:589-625`. With a `sha1ctx` the TLS v1.0/v1.1 arm splits the secret in halves and
/// XORs the MD5 and SHA-1 expansions; otherwise it is the single-hash TLS v1.2 arm.
///
/// # Safety
/// The two MAC contexts are live; `sec`/`seed` are live for their lengths; `out` is writable for
/// `olen` bytes.
#[allow(clippy::too_many_arguments)] // mirrors the authority's signature exactly
unsafe fn tls1_prf_alg(
    mdctx: *mut EvpMacCtx,
    sha1ctx: *mut EvpMacCtx,
    sec: *const u8,
    slen: usize,
    seed: *const u8,
    seed_len: usize,
    out: *mut u8,
    olen: usize,
) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        if !sha1ctx.is_null() {
            /* TLS v1.0 and TLS v1.1 */
            /* calc: L_S1 = L_S2 = ceil(L_S / 2) */
            let l_s1 = slen.div_ceil(2);
            let l_s2 = l_s1;

            if tls1_prf_p_hash(mdctx, sec, l_s1, seed, seed_len, out, olen) == 0 {
                return 0;
            }

            let tmp = CRYPTO_malloc(olen, FILE_TLS1_PRF, LINE).cast::<u8>();
            if tmp.is_null() {
                return 0;
            }

            if tls1_prf_p_hash(
                sha1ctx,
                sec.add(slen - l_s2),
                l_s2,
                seed,
                seed_len,
                tmp,
                olen,
            ) == 0
            {
                CRYPTO_clear_free(tmp.cast(), olen, FILE_TLS1_PRF, LINE);
                return 0;
            }
            for i in 0..olen {
                *out.add(i) ^= *tmp.add(i);
            }
            CRYPTO_clear_free(tmp.cast(), olen, FILE_TLS1_PRF, LINE);
            return 1;
        }

        /* TLS v1.2 */
        if tls1_prf_p_hash(mdctx, sec, slen, seed, seed_len, out, olen) == 0 {
            return 0;
        }

        1
    }
}

/// `static void *kdf_tls1_prf_new(void *provctx)` — `tls1_prf.c:121-133`.
///
/// # Safety
/// The dispatch contract.
unsafe extern "C" fn tls1_prf_new(provctx: *mut c_void) -> *mut c_void {
    // SAFETY: the caller's contract.
    unsafe {
        if is_running() == 0 {
            return ptr::null_mut();
        }
        let ctx =
            CRYPTO_zalloc(core::mem::size_of::<Tls1Prf>(), FILE_TLS1_PRF, LINE).cast::<Tls1Prf>();
        if !ctx.is_null() {
            (*ctx).provctx = provctx;
        }
        ctx.cast()
    }
}

/// `static void kdf_tls1_prf_reset(void *vctx)` — `tls1_prf.c:145-156`. The `provctx` is saved
/// across the `memset` because the whole struct is cleared.
///
/// # Safety
/// `vctx` is a context `tls1_prf_new` allocated.
unsafe fn tls1_prf_reset(vctx: *mut c_void) {
    // SAFETY: `vctx` is a live context per the contract.
    unsafe {
        let ctx = vctx.cast::<Tls1Prf>();
        let provctx = (*ctx).provctx;

        EVP_MAC_CTX_free((*ctx).p_hash);
        EVP_MAC_CTX_free((*ctx).p_sha1);
        CRYPTO_clear_free((*ctx).sec.cast(), (*ctx).seclen, FILE_TLS1_PRF, LINE);
        CRYPTO_clear_free((*ctx).seed.cast(), (*ctx).seedlen, FILE_TLS1_PRF, LINE);
        ptr::write_bytes(vctx.cast::<u8>(), 0, core::mem::size_of::<Tls1Prf>());
        (*ctx).provctx = provctx;
    }
}

/// `static void kdf_tls1_prf_free(void *vctx)` — `tls1_prf.c:135-143`.
///
/// # Safety
/// The dispatch contract.
unsafe extern "C" fn tls1_prf_free(vctx: *mut c_void) {
    // SAFETY: `vctx` is NULL or a live context.
    unsafe {
        if !vctx.is_null() {
            tls1_prf_reset(vctx);
            CRYPTO_free(vctx, FILE_TLS1_PRF, LINE);
        }
    }
}

/// `static void *kdf_tls1_prf_dup(void *vctx)` — `tls1_prf.c:158-183`. Each MAC context is
/// duplicated only when the source held one, because a NULL source field must stay NULL.
///
/// # Safety
/// The dispatch contract.
unsafe extern "C" fn tls1_prf_dup(vctx: *mut c_void) -> *mut c_void {
    // SAFETY: the caller's contract.
    unsafe {
        let src = vctx.cast::<Tls1Prf>();
        let dest = tls1_prf_new((*src).provctx).cast::<Tls1Prf>();
        if dest.is_null() {
            return ptr::null_mut();
        }
        if !(*src).p_hash.is_null() {
            (*dest).p_hash = EVP_MAC_CTX_dup((*src).p_hash);
            if (*dest).p_hash.is_null() {
                tls1_prf_free(dest.cast());
                return ptr::null_mut();
            }
        }
        if !(*src).p_sha1.is_null() {
            (*dest).p_sha1 = EVP_MAC_CTX_dup((*src).p_sha1);
            if (*dest).p_sha1.is_null() {
                tls1_prf_free(dest.cast());
                return ptr::null_mut();
            }
        }
        if ossl_prov_memdup(
            (*src).sec.cast(),
            (*src).seclen,
            ptr::addr_of_mut!((*dest).sec),
            ptr::addr_of_mut!((*dest).seclen),
        ) == 0
            || ossl_prov_memdup(
                (*src).seed.cast(),
                (*src).seedlen,
                ptr::addr_of_mut!((*dest).seed),
                ptr::addr_of_mut!((*dest).seedlen),
            ) == 0
        {
            tls1_prf_free(dest.cast());
            return ptr::null_mut();
        }
        dest.cast()
    }
}

/// `static int kdf_tls1_prf_derive(void *vctx, unsigned char *key, size_t keylen, const OSSL_PARAM
/// params[])` — `tls1_prf.c:256-290`.
///
/// # Safety
/// The dispatch contract.
unsafe extern "C" fn tls1_prf_ctx_derive(
    vctx: *mut c_void,
    key: *mut u8,
    keylen: usize,
    params: *const OsslParam,
) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        if is_running() == 0 || tls1_prf_set_ctx_params(vctx, params) == 0 {
            return 0;
        }
        let ctx = vctx.cast::<Tls1Prf>();
        if (*ctx).p_hash.is_null() {
            return fail_at(&err_sites::PROV_TLS1_PRF_263);
        }
        if (*ctx).sec.is_null() {
            return fail_at(&err_sites::PROV_TLS1_PRF_267);
        }
        if (*ctx).seedlen == 0 {
            return fail_at(&err_sites::PROV_TLS1_PRF_271);
        }
        if keylen == 0 {
            return fail_at(&err_sites::PROV_TLS1_PRF_275);
        }
        tls1_prf_alg(
            (*ctx).p_hash,
            (*ctx).p_sha1,
            (*ctx).sec,
            (*ctx).seclen,
            (*ctx).seed,
            (*ctx).seedlen,
            key,
            keylen,
        )
    }
}

/// `static int kdf_tls1_prf_set_ctx_params(void *vctx, const OSSL_PARAM params[])` —
/// `tls1_prf.c:485-616`, with the generated switch replaced by the field-keyed repeat check, one
/// `OSSL_PARAM_locate_const` per key and the seed list rule (D305's reading). The FIPS arms are
/// absent.
///
/// # Safety
/// The dispatch contract.
unsafe extern "C" fn tls1_prf_set_ctx_params(vctx: *mut c_void, params: *const OsslParam) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        if vctx.is_null() {
            return 0;
        }
        if let Some(site) = repeated_param_site_by_field(params, &TLS1_PRF_SET_DECODER_KEYS) {
            return fail_at(site);
        }
        let ctx = vctx.cast::<Tls1Prf>();
        let libctx = prov_libctx_of((*ctx).provctx);
        let mut p = Tls1PrfSetCtxParams {
            digest: locate_const(params, OSSL_KDF_PARAM_DIGEST),
            engine: locate_const(params, OSSL_ALG_PARAM_ENGINE),
            propq: locate_const(params, OSSL_KDF_PARAM_PROPERTIES),
            secret: locate_const(params, OSSL_KDF_PARAM_SECRET),
            ..Default::default()
        };
        if tls1_prf_collect_seed(params, &mut p) == 0 {
            return 0;
        }

        if !p.digest.is_null() {
            let mut digest: ProvDigest = core::mem::zeroed();
            let mut dgst: *const c_char = ptr::null();

            if OSSL_PARAM_get_utf8_string_ptr(p.digest, &mut dgst) == 0 {
                return 0;
            }

            if OPENSSL_strcasecmp(dgst, OSSL_DIGEST_NAME_MD5_SHA1) == 0 {
                if ossl_prov_macctx_load(
                    ptr::addr_of_mut!((*ctx).p_hash),
                    ptr::null(),
                    ptr::null(),
                    ptr::null(),
                    p.propq,
                    p.engine,
                    OSSL_MAC_NAME_HMAC,
                    ptr::null(),
                    OSSL_DIGEST_NAME_MD5,
                    libctx,
                ) == 0
                {
                    return 0;
                }
                if ossl_prov_macctx_load(
                    ptr::addr_of_mut!((*ctx).p_sha1),
                    ptr::null(),
                    ptr::null(),
                    ptr::null(),
                    p.propq,
                    p.engine,
                    OSSL_MAC_NAME_HMAC,
                    ptr::null(),
                    OSSL_DIGEST_NAME_SHA1,
                    libctx,
                ) == 0
                {
                    return 0;
                }
            } else {
                EVP_MAC_CTX_free((*ctx).p_sha1);
                (*ctx).p_sha1 = ptr::null_mut();
                if ossl_prov_macctx_load(
                    ptr::addr_of_mut!((*ctx).p_hash),
                    ptr::null(),
                    ptr::null(),
                    p.digest,
                    p.propq,
                    p.engine,
                    OSSL_MAC_NAME_HMAC,
                    ptr::null(),
                    ptr::null(),
                    libctx,
                ) == 0
                {
                    return 0;
                }
            }

            if ossl_prov_digest_load(
                ptr::addr_of_mut!(digest),
                p.digest,
                p.propq,
                p.engine,
                libctx,
            ) == 0
            {
                return 0;
            }

            let md = ossl_prov_digest_md(ptr::addr_of!(digest));
            if EVP_MD_xof(md) != 0 {
                raise_site(&err_sites::PROV_TLS1_PRF_537);
                ossl_prov_digest_reset(ptr::addr_of_mut!(digest));
                return 0;
            }

            ossl_prov_digest_reset(ptr::addr_of_mut!(digest));
        }

        if !p.secret.is_null() {
            CRYPTO_clear_free((*ctx).sec.cast(), (*ctx).seclen, FILE_TLS1_PRF, LINE);
            (*ctx).sec = ptr::null_mut();
            if OSSL_PARAM_get_octet_string(
                p.secret,
                ptr::addr_of_mut!((*ctx).sec).cast(),
                0,
                ptr::addr_of_mut!((*ctx).seclen),
            ) == 0
            {
                return 0;
            }
        }

        /*
         * The seed fields concatenate across set calls, so process them all
         * but only reallocate once.
         */
        if p.num_seed > 0 {
            let mut vals: [*const c_void; TLSPRF_MAX_SEEDS] = [ptr::null(); TLSPRF_MAX_SEEDS];
            let mut sizes: [usize; TLSPRF_MAX_SEEDS] = [0; TLSPRF_MAX_SEEDS];
            let mut seedlen = (*ctx).seedlen;
            let mut n: usize = 0;

            for i in 0..p.num_seed as usize {
                sizes[i] = 0;
                vals[i] = ptr::null();
                if (*p.seed[i]).data_size != 0 && !(*p.seed[i]).data.is_null() {
                    let mut err: c_int = 0;

                    if OSSL_PARAM_get_octet_string_ptr(
                        p.seed[i],
                        ptr::addr_of_mut!(vals[n]),
                        ptr::addr_of_mut!(sizes[n]),
                    ) == 0
                    {
                        return 0;
                    }

                    seedlen = safe_add_size_t(seedlen, sizes[n], &mut err);
                    if err != 0 {
                        return 0;
                    }
                    n += 1;
                }
            }

            if seedlen != (*ctx).seedlen {
                let seed = CRYPTO_clear_realloc(
                    (*ctx).seed.cast(),
                    (*ctx).seedlen,
                    seedlen,
                    FILE_TLS1_PRF,
                    LINE,
                )
                .cast::<u8>();

                if seed.is_null() {
                    return 0;
                }
                (*ctx).seed = seed;

                /* No errors are possible, so copy them across */
                for i in 0..n {
                    ptr::copy_nonoverlapping(
                        vals[i].cast::<u8>(),
                        (*ctx).seed.add((*ctx).seedlen),
                        sizes[i],
                    );
                    (*ctx).seedlen += sizes[i];
                }
            }
        }

        1
    }
}

/// `static int kdf_tls1_prf_get_ctx_params(void *vctx, OSSL_PARAM params[])` —
/// `tls1_prf.c:683-698`, without its FIPS arm.
///
/// # Safety
/// The dispatch contract.
unsafe extern "C" fn tls1_prf_get_ctx_params(vctx: *mut c_void, params: *mut OsslParam) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        if vctx.is_null() {
            return 0;
        }
        if let Some(site) =
            repeated_param_site_by_field(params.cast_const(), &TLS1_PRF_GET_DECODER_KEYS)
        {
            return fail_at(site);
        }
        let p = locate_const(params, OSSL_KDF_PARAM_SIZE);
        if !p.is_null() && OSSL_PARAM_set_size_t(p.cast_mut(), usize::MAX) == 0 {
            return 0;
        }
        1
    }
}

/// `static const OSSL_PARAM *kdf_tls1_prf_settable_ctx_params(void *ctx, void *provctx)` —
/// `tls1_prf.c:618-623`.
///
/// # Safety
/// The dispatch contract.
unsafe extern "C" fn tls1_prf_settable_ctx_params(
    _ctx: *mut c_void,
    _p_ctx: *mut c_void,
) -> *const OsslParam {
    TLS1_PRF_SETTABLE_CTX_PARAMS.as_ptr()
}

/// `static const OSSL_PARAM *kdf_tls1_prf_gettable_ctx_params(void *ctx, void *provctx)` —
/// `tls1_prf.c:700-705`.
///
/// # Safety
/// The dispatch contract.
unsafe extern "C" fn tls1_prf_gettable_ctx_params(
    _ctx: *mut c_void,
    _p_ctx: *mut c_void,
) -> *const OsslParam {
    TLS1_PRF_GETTABLE_CTX_PARAMS.as_ptr()
}

/// `const OSSL_DISPATCH ossl_kdf_tls1_prf_functions[]` — `tls1_prf.c:466-481`.
pub(crate) static TLS1_PRF_FUNCTIONS: [OsslDispatch; 10] = [
    OsslDispatch {
        function_id: OSSL_FUNC_KDF_NEWCTX,
        function: tls1_prf_new as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KDF_DUPCTX,
        function: tls1_prf_dup as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KDF_FREECTX,
        function: tls1_prf_free as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KDF_RESET,
        function: tls1_prf_reset as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KDF_DERIVE,
        function: tls1_prf_ctx_derive as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KDF_SETTABLE_CTX_PARAMS,
        function: tls1_prf_settable_ctx_params as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KDF_SET_CTX_PARAMS,
        function: tls1_prf_set_ctx_params as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KDF_GETTABLE_CTX_PARAMS,
        function: tls1_prf_gettable_ctx_params as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KDF_GET_CTX_PARAMS,
        function: tls1_prf_get_ctx_params as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_DISPATCH_END,
        function: ptr::null_mut(),
    },
];

// =============================================================================================
// `providers/implementations/kdfs/kbkdf.c` — KBKDF (NIST SP 800-108 counter and feedback modes)
// =============================================================================================

/// `OSSL_KDF_PARAM_CIPHER` — `include/openssl/core_names.h:278` (`OSSL_ALG_PARAM_CIPHER`,
/// `"cipher"`), the CMAC arm's cipher name.
const OSSL_KDF_PARAM_CIPHER: *const c_char = c"cipher".as_ptr();

/// `OSSL_KDF_PARAM_KBKDF_USE_L` — `include/openssl/core_names.h:292`.
const OSSL_KDF_PARAM_KBKDF_USE_L: *const c_char = c"use-l".as_ptr();

/// `OSSL_KDF_PARAM_KBKDF_USE_SEPARATOR` — `include/openssl/core_names.h:293`.
const OSSL_KDF_PARAM_KBKDF_USE_SEPARATOR: *const c_char = c"use-separator".as_ptr();

/// `OSSL_KDF_PARAM_KBKDF_R` — `include/openssl/core_names.h:291`.
const OSSL_KDF_PARAM_KBKDF_R: *const c_char = c"r".as_ptr();

/// `OSSL_MAC_NAME_CMAC` — `include/openssl/core_names.h:60`.
const OSSL_MAC_NAME_CMAC: *const c_char = c"CMAC".as_ptr();

/// `FILE_KBKDF` — the unit's own `__FILE__`.
const FILE_KBKDF: *const c_char = c"providers/implementations/kdfs/kbkdf.c".as_ptr();

/// `KBKDF_MAX_INFOS` — `kbkdf.c:57`.
const KBKDF_MAX_INFOS: usize = 5;

/// `COUNTER` — `kbkdf.c:60`, SP800-108 section 5.1.
const KBKDF_COUNTER: c_int = 0;

/// `FEEDBACK` — `kbkdf.c:61`, SP800-108 section 5.2.
const KBKDF_FEEDBACK: c_int = 1;

/// `struct KBKDF` — `kbkdf.c:65-84`, without its FIPS indicator field.
#[repr(C)]
pub(crate) struct Kbkdf {
    /// `void *provctx`.
    pub provctx: *mut c_void,
    /// `kbkdf_mode mode`.
    pub mode: c_int,
    /// `EVP_MAC_CTX *ctx_init`.
    pub ctx_init: *mut EvpMacCtx,
    /// `int r` — the counter length in bits, one of 8, 16, 24, 32.
    pub r: c_int,
    /// `unsigned char *ki` / `size_t ki_len` — the key `K_I`.
    pub ki: *mut u8,
    pub ki_len: usize,
    /// `unsigned char *label` / `size_t label_len` — SP800-108's `Label`, from `salt`.
    pub label: *mut u8,
    pub label_len: usize,
    /// `unsigned char *context` / `size_t context_len` — the concatenated `info` records.
    pub context: *mut u8,
    pub context_len: usize,
    /// `unsigned char *iv` / `size_t iv_len` — the feedback-mode `K(0)`, from `seed`.
    pub iv: *mut u8,
    pub iv_len: usize,
    /// `int use_l` — whether `L` is appended to the fixed input data.
    pub use_l: c_int,
    /// `int is_kmac` — whether the loaded MAC is KMAC128/KMAC256 rather than HMAC/CMAC.
    pub is_kmac: c_int,
    /// `int use_separator` — whether the `0x00` separation indicator is appended.
    pub use_separator: c_int,
}

/// `struct kbkdf_set_ctx_params_st` — `kbkdf.c:395-412`, without its FIPS field.
#[derive(Default)]
struct KbkdfSetCtxParams {
    cipher: *const OsslParam,
    digest: *const OsslParam,
    engine: *const OsslParam,
    info: [*const OsslParam; KBKDF_MAX_INFOS],
    num_info: c_int,
    key: *const OsslParam,
    mac: *const OsslParam,
    mode: *const OsslParam,
    propq: *const OsslParam,
    r: *const OsslParam,
    salt: *const OsslParam,
    seed: *const OsslParam,
    sep: *const OsslParam,
    use_l: *const OsslParam,
}

/// The `kbkdf_set_ctx_params_decoder` keys this profile's generated switch raises for, each with
/// its (field id, raise site). The FIPS `key-check` key (`:489`) is compiled out, and `info` is
/// absent because its repetition is a **list**, not an error, up to `KBKDF_MAX_INFOS` (collected
/// below against the `:465` raise). The generated `strcmp`-tree at `kbkdf.c:419-630` raises
/// `PROV_R_REPEATED_PARAMETER` at the second occurrence of any one of these twelve.
const KBKDF_SET_DECODER_KEYS: [(&err_sites::ErrSite, *const c_char, u32); 12] = [
    (&err_sites::PROV_KBKDF_432, OSSL_KDF_PARAM_CIPHER, 0),
    (&err_sites::PROV_KBKDF_443, OSSL_KDF_PARAM_DIGEST, 1),
    (&err_sites::PROV_KBKDF_454, OSSL_ALG_PARAM_ENGINE, 2),
    (&err_sites::PROV_KBKDF_499, OSSL_KDF_PARAM_KEY, 3),
    (&err_sites::PROV_KBKDF_516, OSSL_KDF_PARAM_MAC, 4),
    (&err_sites::PROV_KBKDF_527, OSSL_KDF_PARAM_MODE, 5),
    (&err_sites::PROV_KBKDF_539, OSSL_KDF_PARAM_PROPERTIES, 6),
    (&err_sites::PROV_KBKDF_552, OSSL_KDF_PARAM_KBKDF_R, 7),
    (&err_sites::PROV_KBKDF_567, OSSL_KDF_PARAM_SALT, 8),
    (&err_sites::PROV_KBKDF_578, OSSL_KDF_PARAM_SEED, 9),
    (&err_sites::PROV_KBKDF_608, OSSL_KDF_PARAM_KBKDF_USE_L, 10),
    (
        &err_sites::PROV_KBKDF_619,
        OSSL_KDF_PARAM_KBKDF_USE_SEPARATOR,
        11,
    ),
];

/// The `kbkdf_get_ctx_params_decoder` key, `kbkdf.c:776-796` (the FIPS `fips-indicator` at `:778`
/// is compiled out).
const KBKDF_GET_DECODER_KEYS: [(&err_sites::ErrSite, *const c_char, u32); 1] =
    [(&err_sites::PROV_KBKDF_790, OSSL_KDF_PARAM_SIZE, 0)];

/// `static const OSSL_PARAM kbkdf_set_ctx_params_list[]` — `kbkdf.c:374-391`, without its FIPS
/// entry.
static KBKDF_SETTABLE_CTX_PARAMS: [OsslParam; 13] = [
    param_octet_string(OSSL_KDF_PARAM_INFO),
    param_octet_string(OSSL_KDF_PARAM_SALT),
    param_octet_string(OSSL_KDF_PARAM_KEY),
    param_octet_string(OSSL_KDF_PARAM_SEED),
    param_utf8_string(OSSL_KDF_PARAM_DIGEST),
    param_utf8_string(OSSL_KDF_PARAM_CIPHER),
    param_utf8_string(OSSL_KDF_PARAM_MAC),
    param_utf8_string(OSSL_KDF_PARAM_MODE),
    param_utf8_string(OSSL_KDF_PARAM_PROPERTIES),
    param_int(OSSL_KDF_PARAM_KBKDF_USE_L),
    param_int(OSSL_KDF_PARAM_KBKDF_USE_SEPARATOR),
    param_int(OSSL_KDF_PARAM_KBKDF_R),
    END,
];

/// `static const OSSL_PARAM kbkdf_get_ctx_params_list[]` — `kbkdf.c:743-749`, without its FIPS
/// entry.
static KBKDF_GETTABLE_CTX_PARAMS: [OsslParam; 2] = [param_size_t(OSSL_KDF_PARAM_SIZE), END];

/// `static uint32_t be32(uint32_t host)` — `kbkdf.c:98-111`. The authority's `IS_LITTLE_ENDIAN`
/// arm byteswaps; `to_be` is the value whose in-memory bytes are big-endian on any host, which is
/// what the byte-addressed `EVP_MAC_update` calls below read.
fn be32(host: u32) -> u32 {
    host.to_be()
}

/// `static void init(KBKDF *ctx)` — `kbkdf.c:113-119`.
///
/// # Safety
/// `ctx` is a live context.
unsafe fn kbkdf_init(ctx: *mut Kbkdf) {
    // SAFETY: `ctx` is live per the contract.
    unsafe {
        (*ctx).r = 32;
        (*ctx).use_l = 1;
        (*ctx).use_separator = 1;
        (*ctx).is_kmac = 0;
    }
}

/// `static int derive(EVP_MAC_CTX *ctx_init, kbkdf_mode mode, unsigned char *iv, size_t iv_len,
/// unsigned char *label, size_t label_len, unsigned char *context, size_t context_len,
/// unsigned char *k_i, size_t h, uint32_t l, int has_separator, unsigned char *ko, size_t ko_len,
/// int r)` — `kbkdf.c:214-273`. SP800-108 sections 5.1/5.2 in one body: the counter (or the
/// previous block, in feedback mode) is fed first, then the fixed input data `Label || 0x00 ||
/// Context || L`. The authority's `goto done` is a labelled block.
///
/// # Safety
/// `ctx_init` is a live MAC context; `iv`/`label`/`context` are live for their lengths; `k_i` is
/// writable for `h` bytes and `ko` for `ko_len`.
#[allow(clippy::too_many_arguments)] // mirrors the authority's signature exactly
unsafe fn kbkdf_derive_inner(
    ctx_init: *mut EvpMacCtx,
    mode: c_int,
    iv: *const u8,
    iv_len: usize,
    label: *const u8,
    label_len: usize,
    context: *const u8,
    context_len: usize,
    k_i: *mut u8,
    h: usize,
    l: u32,
    has_separator: c_int,
    ko: *mut u8,
    ko_len: usize,
    r: c_int,
) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        let mut ret: c_int = 0;
        let mut ctx: *mut EvpMacCtx = ptr::null_mut();
        let mut written: usize = 0;
        let mut k_i_len: usize = iv_len;
        let zero: u8 = 0;
        /* One or more of the fixed input data fields may be omitted: `l == 0` omits `L` and
         * `has_separator == 0` omits the `0x00` separation indicator. */
        let has_l = (l != 0) as c_int;

        /* Setup K(0) for feedback mode. */
        if iv_len > 0 {
            ptr::copy_nonoverlapping(iv, k_i, iv_len);
        }

        'done: {
            let mut counter: u32 = 1;
            while written < ko_len {
                let i = be32(counter);

                ctx = EVP_MAC_CTX_dup(ctx_init);
                if ctx.is_null() {
                    break 'done;
                }

                /* Perform feedback, if appropriate. */
                if mode == KBKDF_FEEDBACK && EVP_MAC_update(ctx, k_i, k_i_len) == 0 {
                    break 'done;
                }

                let off = (4 - (r / 8)) as usize;
                if EVP_MAC_update(
                    ctx,
                    ptr::addr_of!(i).cast::<u8>().add(off),
                    (r / 8) as usize,
                ) == 0
                    || EVP_MAC_update(ctx, label, label_len) == 0
                    || (has_separator != 0 && EVP_MAC_update(ctx, ptr::addr_of!(zero), 1) == 0)
                    || EVP_MAC_update(ctx, context, context_len) == 0
                    || (has_l != 0 && EVP_MAC_update(ctx, ptr::addr_of!(l).cast::<u8>(), 4) == 0)
                    || EVP_MAC_final(ctx, k_i, ptr::null_mut(), h) == 0
                {
                    break 'done;
                }

                let to_write = ko_len - written;
                ptr::copy_nonoverlapping(k_i, ko.add(written), core::cmp::min(to_write, h));
                written += h;

                k_i_len = h;
                EVP_MAC_CTX_free(ctx);
                ctx = ptr::null_mut();
                counter += 1;
            }

            ret = 1;
        }
        EVP_MAC_CTX_free(ctx);
        ret
    }
}

/// `static int kmac_init(EVP_MAC_CTX *ctx, const unsigned char *custom, size_t customlen)` —
/// `kbkdf.c:276-286`.
///
/// # Safety
/// `ctx` is a live MAC context; `custom` is NULL or live for `customlen`.
unsafe fn kbkdf_kmac_init(ctx: *mut EvpMacCtx, custom: *const u8, customlen: usize) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        if custom.is_null() || customlen == 0 {
            return 1;
        }
        let mut params = [END, END];
        params[0] = OSSL_PARAM_construct_octet_string(
            OSSL_MAC_PARAM_CUSTOM,
            custom.cast_mut().cast(),
            customlen,
        );
        params[1] = OSSL_PARAM_construct_end();
        (EVP_MAC_CTX_set_params(ctx, params.as_ptr()) > 0) as c_int
    }
}

/// `static int kmac_derive(EVP_MAC_CTX *ctx, unsigned char *out, size_t outlen, const unsigned
/// char *context, size_t contextlen)` — `kbkdf.c:288-298`.
///
/// # Safety
/// `ctx` is a live MAC context; `context` is NULL or live for `contextlen`; `out` is writable for
/// `outlen`.
unsafe fn kbkdf_kmac_derive(
    ctx: *mut EvpMacCtx,
    out: *mut u8,
    outlen: usize,
    context: *const u8,
    contextlen: usize,
) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        let mut params = [END, END];
        params[0] =
            OSSL_PARAM_construct_size_t(OSSL_MAC_PARAM_SIZE, ptr::addr_of!(outlen).cast_mut());
        params[1] = OSSL_PARAM_construct_end();
        (EVP_MAC_CTX_set_params(ctx, params.as_ptr()) > 0
            && EVP_MAC_update(ctx, context, contextlen) != 0
            && EVP_MAC_final(ctx, out, ptr::null_mut(), outlen) != 0) as c_int
    }
}

/// `static void *kbkdf_new(void *provctx)` — `kbkdf.c:121-136`.
///
/// # Safety
/// The dispatch contract.
unsafe extern "C" fn kbkdf_new(provctx: *mut c_void) -> *mut c_void {
    // SAFETY: the caller's contract.
    unsafe {
        if is_running() == 0 {
            return ptr::null_mut();
        }
        let ctx = CRYPTO_zalloc(core::mem::size_of::<Kbkdf>(), FILE_KBKDF, LINE).cast::<Kbkdf>();
        if ctx.is_null() {
            return ptr::null_mut();
        }
        (*ctx).provctx = provctx;
        kbkdf_init(ctx);
        ctx.cast()
    }
}

/// `static void kbkdf_reset(void *vctx)` — `kbkdf.c:148-161`. The `provctx` is saved across the
/// `memset`, and `init` runs again because the whole configuration is the struct.
///
/// # Safety
/// `vctx` is a context `kbkdf_new` allocated.
unsafe fn kbkdf_reset(vctx: *mut c_void) {
    // SAFETY: `vctx` is a live context per the contract.
    unsafe {
        let ctx = vctx.cast::<Kbkdf>();
        let provctx = (*ctx).provctx;

        EVP_MAC_CTX_free((*ctx).ctx_init);
        CRYPTO_clear_free((*ctx).context.cast(), (*ctx).context_len, FILE_KBKDF, LINE);
        CRYPTO_clear_free((*ctx).label.cast(), (*ctx).label_len, FILE_KBKDF, LINE);
        CRYPTO_clear_free((*ctx).ki.cast(), (*ctx).ki_len, FILE_KBKDF, LINE);
        CRYPTO_clear_free((*ctx).iv.cast(), (*ctx).iv_len, FILE_KBKDF, LINE);
        ptr::write_bytes(vctx.cast::<u8>(), 0, core::mem::size_of::<Kbkdf>());
        (*ctx).provctx = provctx;
        kbkdf_init(ctx);
    }
}

/// `static void kbkdf_free(void *vctx)` — `kbkdf.c:138-146`.
///
/// # Safety
/// The dispatch contract.
unsafe extern "C" fn kbkdf_free(vctx: *mut c_void) {
    // SAFETY: `vctx` is NULL or a live context.
    unsafe {
        if !vctx.is_null() {
            kbkdf_reset(vctx);
            CRYPTO_free(vctx, FILE_KBKDF, LINE);
        }
    }
}

/// `static void *kbkdf_dup(void *vctx)` — `kbkdf.c:163-193`. `EVP_MAC_CTX_dup` is called
/// unconditionally, exactly as the authority does: a NULL `ctx_init` faults on both sides, which
/// is the authority's own contract (`EVP_MAC_CTX_dup` dereferences its argument).
///
/// # Safety
/// The dispatch contract.
unsafe extern "C" fn kbkdf_dup(vctx: *mut c_void) -> *mut c_void {
    // SAFETY: the caller's contract.
    unsafe {
        let src = vctx.cast::<Kbkdf>();
        let dest = kbkdf_new((*src).provctx).cast::<Kbkdf>();
        if dest.is_null() {
            return ptr::null_mut();
        }
        (*dest).ctx_init = EVP_MAC_CTX_dup((*src).ctx_init);
        if (*dest).ctx_init.is_null()
            || ossl_prov_memdup(
                (*src).ki.cast(),
                (*src).ki_len,
                ptr::addr_of_mut!((*dest).ki),
                ptr::addr_of_mut!((*dest).ki_len),
            ) == 0
            || ossl_prov_memdup(
                (*src).label.cast(),
                (*src).label_len,
                ptr::addr_of_mut!((*dest).label),
                ptr::addr_of_mut!((*dest).label_len),
            ) == 0
            || ossl_prov_memdup(
                (*src).context.cast(),
                (*src).context_len,
                ptr::addr_of_mut!((*dest).context),
                ptr::addr_of_mut!((*dest).context_len),
            ) == 0
            || ossl_prov_memdup(
                (*src).iv.cast(),
                (*src).iv_len,
                ptr::addr_of_mut!((*dest).iv),
                ptr::addr_of_mut!((*dest).iv_len),
            ) == 0
        {
            kbkdf_free(dest.cast());
            return ptr::null_mut();
        }
        (*dest).mode = (*src).mode;
        (*dest).r = (*src).r;
        (*dest).use_l = (*src).use_l;
        (*dest).use_separator = (*src).use_separator;
        (*dest).is_kmac = (*src).is_kmac;
        dest.cast()
    }
}

/// The generated set decoder's `info` rule: a list, and a sixth record raises
/// `PROV_R_TOO_MANY_RECORDS` at `kbkdf.c:465`.
///
/// # Safety
/// `params` is NULL or a key-terminated array; `r` is writable.
unsafe fn kbkdf_collect_info(params: *const OsslParam, r: &mut KbkdfSetCtxParams) -> c_int {
    // SAFETY: the walk stops at the NULL key.
    unsafe {
        if params.is_null() {
            return 1;
        }
        let mut p = params;
        while !(*p).key.is_null() {
            if CStr::from_ptr((*p).key).to_bytes() == CStr::from_ptr(OSSL_KDF_PARAM_INFO).to_bytes()
            {
                if r.num_info as usize >= KBKDF_MAX_INFOS {
                    raise_site(&err_sites::PROV_KBKDF_465);
                    return 0;
                }
                r.info[r.num_info as usize] = p;
                r.num_info += 1;
            }
            p = p.add(1);
        }
    }
    1
}

/// `static int kbkdf_derive(void *vctx, unsigned char *key, size_t keylen, const OSSL_PARAM
/// params[])` — `kbkdf.c:300-371`.
///
/// # Safety
/// The dispatch contract.
unsafe extern "C" fn kbkdf_ctx_derive(
    vctx: *mut c_void,
    key: *mut u8,
    keylen: usize,
    params: *const OsslParam,
) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        let ctx = vctx.cast::<Kbkdf>();
        let mut ret: c_int = 0;
        let mut k_i: *mut u8 = ptr::null_mut();
        let mut l: u32 = 0;
        let mut h: usize = 0;

        if is_running() == 0 || kbkdf_set_ctx_params(vctx, params) == 0 {
            return 0;
        }

        /* label, context, and iv are permitted to be empty.  Check everything else. */
        if (*ctx).ctx_init.is_null() {
            if (*ctx).ki_len == 0 || (*ctx).ki.is_null() {
                return fail_at(&err_sites::PROV_KBKDF_315);
            }
            /* Could either be missing MAC or missing message digest or missing cipher -
             * arbitrarily, I pick this one. */
            return fail_at(&err_sites::PROV_KBKDF_320);
        }

        /* Fail if the output length is zero */
        if keylen == 0 {
            return fail_at(&err_sites::PROV_KBKDF_326);
        }

        'done: {
            if (*ctx).is_kmac != 0 {
                ret = kbkdf_kmac_derive(
                    (*ctx).ctx_init,
                    key,
                    keylen,
                    (*ctx).context,
                    (*ctx).context_len,
                );
                break 'done;
            }

            h = EVP_MAC_CTX_get_mac_size((*ctx).ctx_init);
            if h == 0 {
                break 'done;
            }

            if (*ctx).iv_len != 0 && (*ctx).iv_len != h {
                raise_site(&err_sites::PROV_KBKDF_341);
                break 'done;
            }

            if (*ctx).mode == KBKDF_COUNTER {
                /* Fail if keylen is too large for r */
                let counter_max: u64 = 1u64 << ((*ctx).r as u64);
                if (keylen / h) as u64 >= counter_max {
                    raise_site(&err_sites::PROV_KBKDF_349);
                    break 'done;
                }
            }

            if (*ctx).use_l != 0 {
                l = be32(keylen.wrapping_mul(8) as u32);
            }

            k_i = CRYPTO_zalloc(h, FILE_KBKDF, LINE).cast::<u8>();
            if k_i.is_null() {
                break 'done;
            }

            ret = kbkdf_derive_inner(
                (*ctx).ctx_init,
                (*ctx).mode,
                (*ctx).iv,
                (*ctx).iv_len,
                (*ctx).label,
                (*ctx).label_len,
                (*ctx).context,
                (*ctx).context_len,
                k_i,
                h,
                l,
                (*ctx).use_separator,
                key,
                keylen,
                (*ctx).r,
            );
        }
        if ret != 1 {
            cleanse(key, keylen);
        }
        CRYPTO_clear_free(k_i.cast(), h, FILE_KBKDF, LINE);
        ret
    }
}

/// `static int kbkdf_set_ctx_params(void *vctx, const OSSL_PARAM params[])` —
/// `kbkdf.c:392-488`, with the generated switch replaced by the field-keyed repeat check, one
/// `OSSL_PARAM_locate_const` per key and the `info` list rule (D305's reading). The FIPS arm is
/// absent.
///
/// # Safety
/// The dispatch contract.
unsafe extern "C" fn kbkdf_set_ctx_params(vctx: *mut c_void, params: *const OsslParam) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        if vctx.is_null() {
            return 0;
        }
        if let Some(site) = repeated_param_site_by_field(params, &KBKDF_SET_DECODER_KEYS) {
            return fail_at(site);
        }
        let ctx = vctx.cast::<Kbkdf>();
        let mut p = KbkdfSetCtxParams {
            cipher: locate_const(params, OSSL_KDF_PARAM_CIPHER),
            digest: locate_const(params, OSSL_KDF_PARAM_DIGEST),
            engine: locate_const(params, OSSL_ALG_PARAM_ENGINE),
            key: locate_const(params, OSSL_KDF_PARAM_KEY),
            mac: locate_const(params, OSSL_KDF_PARAM_MAC),
            mode: locate_const(params, OSSL_KDF_PARAM_MODE),
            propq: locate_const(params, OSSL_KDF_PARAM_PROPERTIES),
            r: locate_const(params, OSSL_KDF_PARAM_KBKDF_R),
            salt: locate_const(params, OSSL_KDF_PARAM_SALT),
            seed: locate_const(params, OSSL_KDF_PARAM_SEED),
            sep: locate_const(params, OSSL_KDF_PARAM_KBKDF_USE_SEPARATOR),
            use_l: locate_const(params, OSSL_KDF_PARAM_KBKDF_USE_L),
            ..Default::default()
        };
        if kbkdf_collect_info(params, &mut p) == 0 {
            return 0;
        }

        let libctx = prov_libctx_of((*ctx).provctx);

        if ossl_prov_macctx_load(
            ptr::addr_of_mut!((*ctx).ctx_init),
            p.mac,
            p.cipher,
            p.digest,
            p.propq,
            p.engine,
            ptr::null(),
            ptr::null(),
            ptr::null(),
            libctx,
        ) == 0
        {
            return 0;
        }

        if !(*ctx).ctx_init.is_null() {
            (*ctx).is_kmac = 0;
            let mac = EVP_MAC_CTX_get0_mac((*ctx).ctx_init);
            if EVP_MAC_is_a(mac, OSSL_MAC_NAME_KMAC128) != 0
                || EVP_MAC_is_a(mac, OSSL_MAC_NAME_KMAC256) != 0
            {
                (*ctx).is_kmac = 1;
            } else if EVP_MAC_is_a(mac, OSSL_MAC_NAME_HMAC) == 0
                && EVP_MAC_is_a(mac, OSSL_MAC_NAME_CMAC) == 0
            {
                raise_site(&err_sites::PROV_KBKDF_667);
                return 0;
            }
        }

        if !p.mode.is_null() {
            let mut s: *const c_char = ptr::null();
            if OSSL_PARAM_get_utf8_string_ptr(p.mode, &mut s) == 0 {
                return 0;
            }
            if OPENSSL_strncasecmp(c"counter".as_ptr(), s, (*p.mode).data_size) == 0 {
                (*ctx).mode = KBKDF_COUNTER;
            } else if OPENSSL_strncasecmp(c"feedback".as_ptr(), s, (*p.mode).data_size) == 0 {
                (*ctx).mode = KBKDF_FEEDBACK;
            } else {
                raise_site(&err_sites::PROV_KBKDF_680);
                return 0;
            }
        }

        if ossl_param_get1_octet_string_from_param(
            p.key,
            ptr::addr_of_mut!((*ctx).ki),
            ptr::addr_of_mut!((*ctx).ki_len),
        ) == 0
        {
            return 0;
        }

        if ossl_param_get1_octet_string_from_param(
            p.salt,
            ptr::addr_of_mut!((*ctx).label),
            ptr::addr_of_mut!((*ctx).label_len),
        ) == 0
        {
            return 0;
        }

        if ossl_param_get1_concat_octet_string(
            p.num_info as usize,
            p.info.as_ptr(),
            ptr::addr_of_mut!((*ctx).context),
            ptr::addr_of_mut!((*ctx).context_len),
        ) == 0
        {
            return 0;
        }

        if ossl_param_get1_octet_string_from_param(
            p.seed,
            ptr::addr_of_mut!((*ctx).iv),
            ptr::addr_of_mut!((*ctx).iv_len),
        ) == 0
        {
            return 0;
        }

        if !p.use_l.is_null() && OSSL_PARAM_get_int(p.use_l, ptr::addr_of_mut!((*ctx).use_l)) == 0 {
            return 0;
        }

        if !p.r.is_null() {
            let mut new_r: c_int = 0;

            if OSSL_PARAM_get_int(p.r, &mut new_r) == 0 {
                return 0;
            }
            if new_r != 8 && new_r != 16 && new_r != 24 && new_r != 32 {
                return 0;
            }
            (*ctx).r = new_r;
        }

        if !p.sep.is_null()
            && OSSL_PARAM_get_int(p.sep, ptr::addr_of_mut!((*ctx).use_separator)) == 0
        {
            return 0;
        }

        /* Set up digest context, if we can. */
        if !(*ctx).ctx_init.is_null()
            && (*ctx).ki_len != 0
            && (((*ctx).is_kmac != 0
                && kbkdf_kmac_init((*ctx).ctx_init, (*ctx).label, (*ctx).label_len) == 0)
                || EVP_MAC_init((*ctx).ctx_init, (*ctx).ki, (*ctx).ki_len, ptr::null()) == 0)
        {
            return 0;
        }
        1
    }
}

/// `static int kbkdf_get_ctx_params(void *vctx, OSSL_PARAM params[])` — `kbkdf.c:503-518`,
/// without its FIPS arm.
///
/// # Safety
/// The dispatch contract.
unsafe extern "C" fn kbkdf_get_ctx_params(vctx: *mut c_void, params: *mut OsslParam) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        if vctx.is_null() {
            return 0;
        }
        if let Some(site) =
            repeated_param_site_by_field(params.cast_const(), &KBKDF_GET_DECODER_KEYS)
        {
            return fail_at(site);
        }
        /* KBKDF can produce results as large as you like. */
        let p = locate_const(params, OSSL_KDF_PARAM_SIZE);
        if !p.is_null() && OSSL_PARAM_set_size_t(p.cast_mut(), usize::MAX) == 0 {
            return 0;
        }
        1
    }
}

/// `static const OSSL_PARAM *kbkdf_settable_ctx_params(void *ctx, void *provctx)` —
/// `kbkdf.c:490-494`.
///
/// # Safety
/// The dispatch contract.
unsafe extern "C" fn kbkdf_settable_ctx_params(
    _ctx: *mut c_void,
    _p_ctx: *mut c_void,
) -> *const OsslParam {
    KBKDF_SETTABLE_CTX_PARAMS.as_ptr()
}

/// `static const OSSL_PARAM *kbkdf_gettable_ctx_params(void *ctx, void *provctx)` —
/// `kbkdf.c:520-524`.
///
/// # Safety
/// The dispatch contract.
unsafe extern "C" fn kbkdf_gettable_ctx_params(
    _ctx: *mut c_void,
    _p_ctx: *mut c_void,
) -> *const OsslParam {
    KBKDF_GETTABLE_CTX_PARAMS.as_ptr()
}

/// `const OSSL_DISPATCH ossl_kdf_kbkdf_functions[]` — `kbkdf.c:526-539`.
pub(crate) static KBKDF_FUNCTIONS: [OsslDispatch; 10] = [
    OsslDispatch {
        function_id: OSSL_FUNC_KDF_NEWCTX,
        function: kbkdf_new as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KDF_DUPCTX,
        function: kbkdf_dup as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KDF_FREECTX,
        function: kbkdf_free as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KDF_RESET,
        function: kbkdf_reset as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KDF_DERIVE,
        function: kbkdf_ctx_derive as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KDF_SETTABLE_CTX_PARAMS,
        function: kbkdf_settable_ctx_params as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KDF_SET_CTX_PARAMS,
        function: kbkdf_set_ctx_params as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KDF_GETTABLE_CTX_PARAMS,
        function: kbkdf_gettable_ctx_params as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KDF_GET_CTX_PARAMS,
        function: kbkdf_get_ctx_params as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_DISPATCH_END,
        function: ptr::null_mut(),
    },
];

// =============================================================================================
// `providers/implementations/kdfs/scrypt.c` — SCRYPT (RFC 7914)
// =============================================================================================

/// `FILE_SCRYPT` — the unit's own `__FILE__`.
const FILE_SCRYPT: *const c_char = c"providers/implementations/kdfs/scrypt.c".as_ptr();

/// `LOG2_UINT64_MAX` — `scrypt.c:587`, the largest shift `N`'s bound uses.
const LOG2_UINT64_MAX: u64 = core::mem::size_of::<u64>() as u64 * 8 - 1;

/// `SCRYPT_PR_MAX` — `scrypt.c:596`, `p * r <= (2^30 - 1)`.
const SCRYPT_PR_MAX: u64 = (1 << 30) - 1;

/// `struct KDF_SCRYPT` — `scrypt.c:49-60`.
#[repr(C)]
pub(crate) struct KdfScrypt {
    /// `OSSL_LIB_CTX *libctx`.
    pub libctx: *mut c_void,
    /// `char *propq`.
    pub propq: *mut c_char,
    /// `unsigned char *pass` / `size_t pass_len`.
    pub pass: *mut u8,
    pub pass_len: usize,
    /// `unsigned char *salt` / `size_t salt_len`.
    pub salt: *mut u8,
    pub salt_len: usize,
    /// `uint64_t N`.
    pub n: u64,
    /// `uint64_t r, p`.
    pub r: u64,
    pub p: u64,
    /// `uint64_t maxmem_bytes`.
    pub maxmem_bytes: u64,
    /// `EVP_MD *sha256`.
    pub sha256: *mut crate::evp::digest::EvpMd,
}

/// `struct scrypt_set_ctx_params_st` — `scrypt.c:238-246`.
#[derive(Default)]
struct ScryptSetCtxParams {
    maxmem: *const OsslParam,
    n: *const OsslParam,
    p: *const OsslParam,
    propq: *const OsslParam,
    pw: *const OsslParam,
    r: *const OsslParam,
    salt: *const OsslParam,
}

/// The `scrypt_set_ctx_params_decoder` keys, each with its (field id, raise site). Every key names
/// its own field and none is a list, so the generated `strcmp`-tree at `scrypt.c:249-344` raises
/// `PROV_R_REPEATED_PARAMETER` at the second occurrence of any one.
const SCRYPT_SET_DECODER_KEYS: [(&err_sites::ErrSite, *const c_char, u32); 7] = [
    (&err_sites::PROV_SCRYPT_264, OSSL_KDF_PARAM_SCRYPT_MAXMEM, 0),
    (&err_sites::PROV_SCRYPT_277, OSSL_KDF_PARAM_SCRYPT_N, 1),
    (&err_sites::PROV_SCRYPT_292, OSSL_KDF_PARAM_PASSWORD, 2),
    (&err_sites::PROV_SCRYPT_303, OSSL_KDF_PARAM_PROPERTIES, 3),
    (&err_sites::PROV_SCRYPT_312, OSSL_KDF_PARAM_SCRYPT_P, 4),
    (&err_sites::PROV_SCRYPT_325, OSSL_KDF_PARAM_SCRYPT_R, 5),
    (&err_sites::PROV_SCRYPT_336, OSSL_KDF_PARAM_SALT, 6),
];

/// The `scrypt_get_ctx_params_decoder` key, `scrypt.c:420-439`.
const SCRYPT_GET_DECODER_KEYS: [(&err_sites::ErrSite, *const c_char, u32); 1] =
    [(&err_sites::PROV_SCRYPT_432, OSSL_KDF_PARAM_SIZE, 0)];

/// `static const OSSL_PARAM scrypt_set_ctx_params_list[]` — `scrypt.c:224-241`.
static SCRYPT_SETTABLE_CTX_PARAMS: [OsslParam; 8] = [
    param_octet_string(OSSL_KDF_PARAM_PASSWORD),
    param_octet_string(OSSL_KDF_PARAM_SALT),
    param_uint64(OSSL_KDF_PARAM_SCRYPT_N),
    param_uint32(OSSL_KDF_PARAM_SCRYPT_R),
    param_uint32(OSSL_KDF_PARAM_SCRYPT_P),
    param_uint64(OSSL_KDF_PARAM_SCRYPT_MAXMEM),
    param_utf8_string(OSSL_KDF_PARAM_PROPERTIES),
    END,
];

/// `static const OSSL_PARAM scrypt_get_ctx_params_list[]` — `scrypt.c:407-411`.
static SCRYPT_GETTABLE_CTX_PARAMS: [OsslParam; 2] = [param_size_t(OSSL_KDF_PARAM_SIZE), END];

/// `#define R(a, b) (((a) << (b)) | ((a) >> (32 - (b))))` — `scrypt.c:331`, a 32-bit rotate.
#[inline]
fn scrypt_r(a: u32, b: u32) -> u32 {
    a.rotate_left(b)
}

/// `static void salsa208_word_specification(uint32_t inout[16])` — `scrypt.c:332-375`.
///
/// # Safety
/// `inout` is writable for 16 `u32`s.
unsafe fn salsa208_word_specification(inout: *mut u32) {
    // SAFETY: the caller's contract.
    unsafe {
        let mut x = [0u32; 16];
        ptr::copy_nonoverlapping(inout, x.as_mut_ptr(), 16);
        let mut i = 8;
        while i > 0 {
            x[4] ^= scrypt_r(x[0].wrapping_add(x[12]), 7);
            x[8] ^= scrypt_r(x[4].wrapping_add(x[0]), 9);
            x[12] ^= scrypt_r(x[8].wrapping_add(x[4]), 13);
            x[0] ^= scrypt_r(x[12].wrapping_add(x[8]), 18);
            x[9] ^= scrypt_r(x[5].wrapping_add(x[1]), 7);
            x[13] ^= scrypt_r(x[9].wrapping_add(x[5]), 9);
            x[1] ^= scrypt_r(x[13].wrapping_add(x[9]), 13);
            x[5] ^= scrypt_r(x[1].wrapping_add(x[13]), 18);
            x[14] ^= scrypt_r(x[10].wrapping_add(x[6]), 7);
            x[2] ^= scrypt_r(x[14].wrapping_add(x[10]), 9);
            x[6] ^= scrypt_r(x[2].wrapping_add(x[14]), 13);
            x[10] ^= scrypt_r(x[6].wrapping_add(x[2]), 18);
            x[3] ^= scrypt_r(x[15].wrapping_add(x[11]), 7);
            x[7] ^= scrypt_r(x[3].wrapping_add(x[15]), 9);
            x[11] ^= scrypt_r(x[7].wrapping_add(x[3]), 13);
            x[15] ^= scrypt_r(x[11].wrapping_add(x[7]), 18);
            x[1] ^= scrypt_r(x[0].wrapping_add(x[3]), 7);
            x[2] ^= scrypt_r(x[1].wrapping_add(x[0]), 9);
            x[3] ^= scrypt_r(x[2].wrapping_add(x[1]), 13);
            x[0] ^= scrypt_r(x[3].wrapping_add(x[2]), 18);
            x[6] ^= scrypt_r(x[5].wrapping_add(x[4]), 7);
            x[7] ^= scrypt_r(x[6].wrapping_add(x[5]), 9);
            x[4] ^= scrypt_r(x[7].wrapping_add(x[6]), 13);
            x[5] ^= scrypt_r(x[4].wrapping_add(x[7]), 18);
            x[11] ^= scrypt_r(x[10].wrapping_add(x[9]), 7);
            x[8] ^= scrypt_r(x[11].wrapping_add(x[10]), 9);
            x[9] ^= scrypt_r(x[8].wrapping_add(x[11]), 13);
            x[10] ^= scrypt_r(x[9].wrapping_add(x[8]), 18);
            x[12] ^= scrypt_r(x[15].wrapping_add(x[14]), 7);
            x[13] ^= scrypt_r(x[12].wrapping_add(x[15]), 9);
            x[14] ^= scrypt_r(x[13].wrapping_add(x[12]), 13);
            x[15] ^= scrypt_r(x[14].wrapping_add(x[13]), 18);
            i -= 2;
        }
        for (i, xi) in x.iter().enumerate() {
            *inout.add(i) = (*inout.add(i)).wrapping_add(*xi);
        }
        cleanse(x.as_mut_ptr().cast(), 64);
    }
}

/// `static void scryptBlockMix(uint32_t *B_, uint32_t *B, uint64_t r)` — `scrypt.c:377-391`.
///
/// # Safety
/// `B` is readable for `32 * r` `u32`s; `B_` is writable for the same; `r >= 1`.
unsafe fn scrypt_block_mix(b_: *mut u32, b: *const u32, r: u64) {
    // SAFETY: the caller's contract.
    unsafe {
        let mut x = [0u32; 16];
        ptr::copy_nonoverlapping(b.add(((r * 2 - 1) * 16) as usize), x.as_mut_ptr(), 16);
        let mut pb = b;
        for i in 0..(r * 2) {
            for xj in x.iter_mut() {
                *xj ^= *pb;
                pb = pb.add(1);
            }
            salsa208_word_specification(x.as_mut_ptr());
            ptr::copy_nonoverlapping(
                x.as_ptr(),
                b_.add(((i / 2 + (i & 1) * r) * 16) as usize),
                16,
            );
        }
        cleanse(x.as_mut_ptr().cast(), 64);
    }
}

/// `static void scryptROMix(unsigned char *B, uint64_t r, uint64_t N, uint32_t *X, uint32_t *T,
/// uint32_t *V)` — `scrypt.c:393-429`.
///
/// # Safety
/// `B` is readable and writable for `128 * r` bytes; `X`/`T` are writable for `32 * r` `u32`s and
/// `V` for `32 * r * N`.
unsafe fn scrypt_ro_mix(b: *mut u8, r: u64, n: u64, x: *mut u32, t: *mut u32, v: *mut u32) {
    // SAFETY: the caller's contract.
    unsafe {
        /* Convert from little endian input */
        let mut pb = b;
        let mut pv = v;
        let mut i: u64 = 0;
        while i < 32 * r {
            *pv = *pb as u32;
            pb = pb.add(1);
            *pv |= (*pb as u32) << 8;
            pb = pb.add(1);
            *pv |= (*pb as u32) << 16;
            pb = pb.add(1);
            *pv |= (*pb as u32) << 24;
            pb = pb.add(1);
            pv = pv.add(1);
            i += 1;
        }

        i = 1;
        while i < n {
            scrypt_block_mix(pv, pv.sub((32 * r) as usize), r);
            pv = pv.add((32 * r) as usize);
            i += 1;
        }

        scrypt_block_mix(x, v.add(((n - 1) * 32 * r) as usize), r);

        for _ in 0..n {
            let j = (*x.add((16 * (2 * r - 1)) as usize) as u64 % n) as u32;
            let mut pvv = v.add((32 * r * j as u64) as usize);
            for k in 0..(32 * r) {
                *t.add(k as usize) = *x.add(k as usize) ^ *pvv;
                pvv = pvv.add(1);
            }
            scrypt_block_mix(x, t, r);
        }
        /* Convert output to little endian */
        let mut pb = b;
        for i in 0..(32 * r) {
            let xtmp = *x.add(i as usize);
            *pb = (xtmp & 0xff) as u8;
            pb = pb.add(1);
            *pb = ((xtmp >> 8) & 0xff) as u8;
            pb = pb.add(1);
            *pb = ((xtmp >> 16) & 0xff) as u8;
            pb = pb.add(1);
            *pb = ((xtmp >> 24) & 0xff) as u8;
            pb = pb.add(1);
        }
    }
}

/// `static int scrypt_alg(const char *pass, size_t passlen, const unsigned char *salt,
/// size_t saltlen, uint64_t N, uint64_t r, uint64_t p, uint64_t maxmem, unsigned char *key,
/// size_t keylen, EVP_MD *sha256, OSSL_LIB_CTX *libctx, const char *propq)` —
/// `scrypt.c:598-703`. RFC 7914's `scryptROMix` chain over a `PBKDF2`-expanded `B`; the `goto err`
/// is a labelled block whose single exit raises `EVP_R_PBKDF2_ERROR` and clears `B`.
///
/// # Safety
/// `pass` is readable for `passlen`; `salt` for `saltlen`; `key` is writable for `keylen` when
/// non-NULL; `sha256` is live; `libctx`/`propq` are the context's.
#[allow(clippy::too_many_arguments)] // mirrors the authority's signature exactly
unsafe fn scrypt_alg(
    pass: *const c_char,
    passlen: usize,
    salt: *const u8,
    saltlen: usize,
    n: u64,
    r: u64,
    p: u64,
    mut maxmem: u64,
    key: *mut u8,
    keylen: usize,
    sha256: *mut crate::evp::digest::EvpMd,
    libctx: *mut c_void,
    propq: *const c_char,
) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        let mut rv: c_int = 0;

        /* Sanity check parameters */
        /* initial check, r,p must be non zero, N >= 2 and a power of 2 */
        if r == 0 || p == 0 || n < 2 || (n & (n - 1)) != 0 {
            return 0;
        }
        /* Check p * r < SCRYPT_PR_MAX avoiding overflow */
        if p > SCRYPT_PR_MAX / r {
            return fail_at(&err_sites::PROV_SCRYPT_615);
        }

        /*
         * Need to check N: if 2^(128 * r / 8) overflows limit this is
         * automatically satisfied since N <= UINT64_MAX.
         */
        if 16 * r <= LOG2_UINT64_MAX && n >= (1u64 << (16 * r)) {
            return fail_at(&err_sites::PROV_SCRYPT_626);
        }

        /* Memory checks: check total allocated buffer size fits in uint64_t */

        /*
         * B size in section 5 step 1.S
         * Note: we know p * 128 * r < UINT64_MAX because we already checked
         * p * r < SCRYPT_PR_MAX
         */
        let blen = p * 128 * r;
        /*
         * Yet we pass it as integer to PKCS5_PBKDF2_HMAC... [This would
         * have to be revised when/if PKCS5_PBKDF2_HMAC accepts size_t.]
         */
        if blen > c_int::MAX as u64 {
            return fail_at(&err_sites::PROV_SCRYPT_644);
        }

        /*
         * Check 32 * r * (N + 2) * sizeof(uint32_t) fits in uint64_t
         * This is combined size V, X and T (section 4)
         */
        let i = u64::MAX / (32 * core::mem::size_of::<u32>() as u64);
        if n + 2 > i / r {
            return fail_at(&err_sites::PROV_SCRYPT_654);
        }
        let vlen = 32 * r * (n + 2) * core::mem::size_of::<u32>() as u64;

        /* check total allocated size fits in uint64_t */
        if blen > u64::MAX - vlen {
            return fail_at(&err_sites::PROV_SCRYPT_661);
        }

        /* Check that the maximum memory doesn't exceed a size_t limits */
        if maxmem > usize::MAX as u64 {
            maxmem = usize::MAX as u64;
        }

        if blen + vlen > maxmem {
            return fail_at(&err_sites::PROV_SCRYPT_670);
        }

        /* If no key return to indicate parameters are OK */
        if key.is_null() {
            return 1;
        }

        let b: *mut u8 = CRYPTO_malloc((blen + vlen) as usize, FILE_SCRYPT, LINE).cast::<u8>();
        if b.is_null() {
            return 0;
        }
        let x: *mut u32 = b.add(blen as usize).cast::<u32>();
        let t: *mut u32 = x.add((32 * r) as usize);
        let v: *mut u32 = t.add((32 * r) as usize);

        'err: {
            if ossl_pkcs5_pbkdf2_hmac_ex(
                pass,
                passlen as c_int,
                salt,
                saltlen as c_int,
                1,
                sha256,
                blen as c_int,
                b,
                libctx,
                propq,
            ) == 0
            {
                break 'err;
            }

            for i in 0..p {
                scrypt_ro_mix(b.add((128 * r * i) as usize), r, n, x, t, v);
            }

            if ossl_pkcs5_pbkdf2_hmac_ex(
                pass,
                passlen as c_int,
                b,
                blen as c_int,
                1,
                sha256,
                keylen as c_int,
                key,
                libctx,
                propq,
            ) == 0
            {
                break 'err;
            }
            rv = 1;
        }

        if rv == 0 {
            raise_site(&err_sites::PROV_SCRYPT_699);
        }

        CRYPTO_clear_free(b.cast(), (blen + vlen) as usize, FILE_SCRYPT, LINE);
        rv
    }
}

/// `static int is_power_of_two(uint64_t value)` — `scrypt.c:218-221`.
fn is_power_of_two(value: u64) -> bool {
    (value != 0) && (value & (value - 1)) == 0
}

/// `static void kdf_scrypt_init(KDF_SCRYPT *ctx)` — `scrypt.c:139-149`.
///
/// # Safety
/// `ctx` is a live context.
unsafe fn kdf_scrypt_init(ctx: *mut KdfScrypt) {
    // SAFETY: `ctx` is live per the contract.
    unsafe {
        (*ctx).n = 1 << 20;
        (*ctx).r = 8;
        (*ctx).p = 1;
        (*ctx).maxmem_bytes = 1025 * 1024 * 1024;
    }
}

/// `static void *kdf_scrypt_new_inner(OSSL_LIB_CTX *libctx)` — `scrypt.c:64-77`.
///
/// # Safety
/// `libctx` is NULL or a live library context.
unsafe fn kdf_scrypt_new_inner(libctx: *mut c_void) -> *mut c_void {
    // SAFETY: the caller's contract.
    unsafe {
        if is_running() == 0 {
            return ptr::null_mut();
        }
        let ctx =
            CRYPTO_zalloc(core::mem::size_of::<KdfScrypt>(), FILE_SCRYPT, LINE).cast::<KdfScrypt>();
        if ctx.is_null() {
            return ptr::null_mut();
        }
        (*ctx).libctx = libctx;
        kdf_scrypt_init(ctx);
        ctx.cast()
    }
}

/// `static void *kdf_scrypt_new(void *provctx)` — `scrypt.c:79-82`.
///
/// # Safety
/// The dispatch contract.
unsafe extern "C" fn kdf_scrypt_new(provctx: *mut c_void) -> *mut c_void {
    // SAFETY: the caller's contract.
    unsafe { kdf_scrypt_new_inner(prov_libctx_of(provctx)) }
}

/// `static void kdf_scrypt_reset(void *vctx)` — `scrypt.c:96-105`. The salt is released with
/// `OPENSSL_free` and the pass with `OPENSSL_clear_free`, and `pass_len` is deliberately left
/// alone, all as the authority has it.
///
/// # Safety
/// `vctx` is a context `kdf_scrypt_new` allocated.
unsafe fn kdf_scrypt_reset(vctx: *mut c_void) {
    // SAFETY: `vctx` is a live context per the contract.
    unsafe {
        let ctx = vctx.cast::<KdfScrypt>();

        CRYPTO_free((*ctx).salt.cast(), FILE_SCRYPT, LINE);
        (*ctx).salt = ptr::null_mut();
        CRYPTO_clear_free((*ctx).pass.cast(), (*ctx).pass_len, FILE_SCRYPT, LINE);
        (*ctx).pass = ptr::null_mut();
        kdf_scrypt_init(ctx);
    }
}

/// `static void kdf_scrypt_free(void *vctx)` — `scrypt.c:84-94`.
///
/// # Safety
/// The dispatch contract.
unsafe extern "C" fn kdf_scrypt_free(vctx: *mut c_void) {
    // SAFETY: `vctx` is NULL or a live context.
    unsafe {
        if !vctx.is_null() {
            let ctx = vctx.cast::<KdfScrypt>();
            CRYPTO_free((*ctx).propq.cast(), FILE_SCRYPT, LINE);
            EVP_MD_free((*ctx).sha256);
            kdf_scrypt_reset(vctx);
            CRYPTO_free(vctx, FILE_SCRYPT, LINE);
        }
    }
}

/// `static void *kdf_scrypt_dup(void *vctx)` — `scrypt.c:107-137`.
///
/// # Safety
/// The dispatch contract.
unsafe extern "C" fn kdf_scrypt_dup(vctx: *mut c_void) -> *mut c_void {
    // SAFETY: the caller's contract.
    unsafe {
        let src = vctx.cast::<KdfScrypt>();
        let dest = kdf_scrypt_new_inner((*src).libctx).cast::<KdfScrypt>();
        if dest.is_null() {
            return ptr::null_mut();
        }
        if !(*src).sha256.is_null() && EVP_MD_up_ref((*src).sha256) == 0 {
            kdf_scrypt_free(dest.cast());
            return ptr::null_mut();
        }
        if !(*src).propq.is_null() {
            (*dest).propq = CRYPTO_strdup((*src).propq, FILE_SCRYPT, LINE);
            if (*dest).propq.is_null() {
                kdf_scrypt_free(dest.cast());
                return ptr::null_mut();
            }
        }
        if ossl_prov_memdup(
            (*src).salt.cast(),
            (*src).salt_len,
            ptr::addr_of_mut!((*dest).salt),
            ptr::addr_of_mut!((*dest).salt_len),
        ) == 0
            || ossl_prov_memdup(
                (*src).pass.cast(),
                (*src).pass_len,
                ptr::addr_of_mut!((*dest).pass),
                ptr::addr_of_mut!((*dest).pass_len),
            ) == 0
        {
            kdf_scrypt_free(dest.cast());
            return ptr::null_mut();
        }
        (*dest).n = (*src).n;
        (*dest).r = (*src).r;
        (*dest).p = (*src).p;
        (*dest).maxmem_bytes = (*src).maxmem_bytes;
        (*dest).sha256 = (*src).sha256;
        dest.cast()
    }
}

/// `static int scrypt_set_membuf(unsigned char **buffer, size_t *buflen, const OSSL_PARAM *p)` —
/// `scrypt.c:151-166`.
///
/// # Safety
/// `buffer`/`buflen` are live; `p` is a live parameter.
unsafe fn scrypt_set_membuf(
    buffer: *mut *mut u8,
    buflen: *mut usize,
    p: *const OsslParam,
) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        CRYPTO_clear_free((*buffer).cast(), *buflen, FILE_SCRYPT, LINE);
        *buffer = ptr::null_mut();
        *buflen = 0;

        if (*p).data_size == 0 {
            let m = CRYPTO_malloc(1, FILE_SCRYPT, LINE).cast::<u8>();
            if m.is_null() {
                return 0;
            }
            *buffer = m;
        } else if !(*p).data.is_null()
            && OSSL_PARAM_get_octet_string(p.cast_mut(), buffer.cast(), 0, buflen) == 0
        {
            return 0;
        }
        1
    }
}

/// `static int set_digest(KDF_SCRYPT *ctx)` — `scrypt.c:168-177`.
///
/// # Safety
/// `ctx` is a live context.
unsafe fn scrypt_set_digest(ctx: *mut KdfScrypt) -> c_int {
    // SAFETY: `ctx` is live per the contract.
    unsafe {
        EVP_MD_free((*ctx).sha256);
        (*ctx).sha256 = EVP_MD_fetch((*ctx).libctx, c"sha256".as_ptr(), (*ctx).propq);
        if (*ctx).sha256.is_null() {
            return fail_at(&err_sites::PROV_SCRYPT_171);
        }
        1
    }
}

/// `static int set_property_query(KDF_SCRYPT *ctx, const char *propq)` — `scrypt.c:179-189`.
///
/// # Safety
/// `ctx` is live; `propq` is NULL or NUL-terminated.
unsafe fn scrypt_set_property_query(ctx: *mut KdfScrypt, propq: *const c_char) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        CRYPTO_free((*ctx).propq.cast(), FILE_SCRYPT, LINE);
        (*ctx).propq = ptr::null_mut();
        if !propq.is_null() {
            (*ctx).propq = CRYPTO_strdup(propq, FILE_SCRYPT, LINE);
            if (*ctx).propq.is_null() {
                return 0;
            }
        }
        1
    }
}

/// `static int kdf_scrypt_derive(void *vctx, unsigned char *key, size_t keylen, const OSSL_PARAM
/// params[])` — `scrypt.c:191-216`.
///
/// # Safety
/// The dispatch contract.
unsafe extern "C" fn kdf_scrypt_ctx_derive(
    vctx: *mut c_void,
    key: *mut u8,
    keylen: usize,
    params: *const OsslParam,
) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        let ctx = vctx.cast::<KdfScrypt>();

        if is_running() == 0 || kdf_scrypt_set_ctx_params(vctx, params) == 0 {
            return 0;
        }

        if (*ctx).pass.is_null() {
            return fail_at(&err_sites::PROV_SCRYPT_198);
        }

        if (*ctx).salt.is_null() {
            return fail_at(&err_sites::PROV_SCRYPT_203);
        }

        if (*ctx).sha256.is_null() && scrypt_set_digest(ctx) == 0 {
            return 0;
        }

        scrypt_alg(
            (*ctx).pass.cast(),
            (*ctx).pass_len,
            (*ctx).salt,
            (*ctx).salt_len,
            (*ctx).n,
            (*ctx).r,
            (*ctx).p,
            (*ctx).maxmem_bytes,
            key,
            keylen,
            (*ctx).sha256,
            (*ctx).libctx,
            (*ctx).propq,
        )
    }
}

/// `static int kdf_scrypt_set_ctx_params(void *vctx, const OSSL_PARAM params[])` —
/// `scrypt.c:349-397`, with the generated switch replaced by the field-keyed repeat check and one
/// `OSSL_PARAM_locate_const` per key (D305's reading). `n` must exceed one and be a power of two;
/// `r`, `p` and `maxmem_bytes` must be at least one; a `propq` re-fetches `sha256`.
///
/// # Safety
/// The dispatch contract.
unsafe extern "C" fn kdf_scrypt_set_ctx_params(
    vctx: *mut c_void,
    params: *const OsslParam,
) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        if vctx.is_null() {
            return 0;
        }
        if let Some(site) = repeated_param_site_by_field(params, &SCRYPT_SET_DECODER_KEYS) {
            return fail_at(site);
        }
        let ctx = vctx.cast::<KdfScrypt>();
        let p = ScryptSetCtxParams {
            maxmem: locate_const(params, OSSL_KDF_PARAM_SCRYPT_MAXMEM),
            n: locate_const(params, OSSL_KDF_PARAM_SCRYPT_N),
            p: locate_const(params, OSSL_KDF_PARAM_SCRYPT_P),
            propq: locate_const(params, OSSL_KDF_PARAM_PROPERTIES),
            pw: locate_const(params, OSSL_KDF_PARAM_PASSWORD),
            r: locate_const(params, OSSL_KDF_PARAM_SCRYPT_R),
            salt: locate_const(params, OSSL_KDF_PARAM_SALT),
        };
        let mut u64_value: u64 = 0;

        if !p.pw.is_null()
            && scrypt_set_membuf(
                ptr::addr_of_mut!((*ctx).pass),
                ptr::addr_of_mut!((*ctx).pass_len),
                p.pw,
            ) == 0
        {
            return 0;
        }

        if !p.salt.is_null()
            && scrypt_set_membuf(
                ptr::addr_of_mut!((*ctx).salt),
                ptr::addr_of_mut!((*ctx).salt_len),
                p.salt,
            ) == 0
        {
            return 0;
        }

        if !p.n.is_null() {
            if OSSL_PARAM_get_uint64(p.n, &mut u64_value) == 0
                || u64_value <= 1
                || !is_power_of_two(u64_value)
            {
                return 0;
            }
            (*ctx).n = u64_value;
        }

        if !p.r.is_null() {
            if OSSL_PARAM_get_uint64(p.r, &mut u64_value) == 0 || u64_value < 1 {
                return 0;
            }
            (*ctx).r = u64_value;
        }

        if !p.p.is_null() {
            if OSSL_PARAM_get_uint64(p.p, &mut u64_value) == 0 || u64_value < 1 {
                return 0;
            }
            (*ctx).p = u64_value;
        }

        if !p.maxmem.is_null() {
            if OSSL_PARAM_get_uint64(p.maxmem, &mut u64_value) == 0 || u64_value < 1 {
                return 0;
            }
            (*ctx).maxmem_bytes = u64_value;
        }

        if !p.propq.is_null()
            && ((*p.propq).data_type != OSSL_PARAM_UTF8_STRING
                || scrypt_set_property_query(ctx, (*p.propq).data.cast()) == 0
                || scrypt_set_digest(ctx) == 0)
        {
            return 0;
        }
        1
    }
}

/// `static int kdf_scrypt_get_ctx_params(void *vctx, OSSL_PARAM params[])` — `scrypt.c:444-459`.
///
/// # Safety
/// The dispatch contract.
unsafe extern "C" fn kdf_scrypt_get_ctx_params(vctx: *mut c_void, params: *mut OsslParam) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        if vctx.is_null() {
            return 0;
        }
        if let Some(site) =
            repeated_param_site_by_field(params.cast_const(), &SCRYPT_GET_DECODER_KEYS)
        {
            return fail_at(site);
        }
        let p = locate_const(params, OSSL_KDF_PARAM_SIZE);
        if !p.is_null() && OSSL_PARAM_set_size_t(p.cast_mut(), usize::MAX) == 0 {
            return 0;
        }
        1
    }
}

/// `static const OSSL_PARAM *kdf_scrypt_settable_ctx_params(void *ctx, void *p_ctx)` —
/// `scrypt.c:399-403`.
///
/// # Safety
/// The dispatch contract.
unsafe extern "C" fn kdf_scrypt_settable_ctx_params(
    _ctx: *mut c_void,
    _p_ctx: *mut c_void,
) -> *const OsslParam {
    SCRYPT_SETTABLE_CTX_PARAMS.as_ptr()
}

/// `static const OSSL_PARAM *kdf_scrypt_gettable_ctx_params(void *ctx, void *p_ctx)` —
/// `scrypt.c:461-465`.
///
/// # Safety
/// The dispatch contract.
unsafe extern "C" fn kdf_scrypt_gettable_ctx_params(
    _ctx: *mut c_void,
    _p_ctx: *mut c_void,
) -> *const OsslParam {
    SCRYPT_GETTABLE_CTX_PARAMS.as_ptr()
}

/// `const OSSL_DISPATCH ossl_kdf_scrypt_functions[]` — `scrypt.c:316-329`.
pub(crate) static SCRYPT_FUNCTIONS: [OsslDispatch; 10] = [
    OsslDispatch {
        function_id: OSSL_FUNC_KDF_NEWCTX,
        function: kdf_scrypt_new as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KDF_DUPCTX,
        function: kdf_scrypt_dup as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KDF_FREECTX,
        function: kdf_scrypt_free as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KDF_RESET,
        function: kdf_scrypt_reset as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KDF_DERIVE,
        function: kdf_scrypt_ctx_derive as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KDF_SETTABLE_CTX_PARAMS,
        function: kdf_scrypt_settable_ctx_params as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KDF_SET_CTX_PARAMS,
        function: kdf_scrypt_set_ctx_params as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KDF_GETTABLE_CTX_PARAMS,
        function: kdf_scrypt_gettable_ctx_params as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KDF_GET_CTX_PARAMS,
        function: kdf_scrypt_get_ctx_params as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_DISPATCH_END,
        function: ptr::null_mut(),
    },
];

// =============================================================================================
// `providers/implementations/kdfs/krb5kdf.c` — KRB5KDF (RFC 3961 §5.1)
// =============================================================================================

/// `OSSL_KDF_PARAM_CONSTANT` — `include/openssl/core_names.h:279` (`"constant"`).
const OSSL_KDF_PARAM_CONSTANT: *const c_char = c"constant".as_ptr();

/// `FILE_KRB5KDF` — the unit's own `__FILE__`.
const FILE_KRB5KDF: *const c_char = c"providers/implementations/kdfs/krb5kdf.c".as_ptr();

/// `EVP_MAX_BLOCK_LENGTH` — `include/openssl/evp.h:37`.
const EVP_MAX_BLOCK_LENGTH: usize = 32;

/// `EVP_MAX_KEY_LENGTH` — `include/openssl/evp.h:35`.
const EVP_MAX_KEY_LENGTH: usize = 64;

/// `struct KRB5KDF_CTX` — `krb5kdf.c:56-63`.
#[repr(C)]
pub(crate) struct Krb5kdfCtx {
    /// `void *provctx`.
    pub provctx: *mut c_void,
    /// `PROV_CIPHER cipher`.
    pub cipher: ProvCipher,
    /// `unsigned char *key` / `size_t key_len`.
    pub key: *mut u8,
    pub key_len: usize,
    /// `unsigned char *constant` / `size_t constant_len`.
    pub constant: *mut u8,
    pub constant_len: usize,
}

/// `struct krb5kdf_set_ctx_params_st` — `krb5kdf.c:188-196`.
#[derive(Default)]
struct Krb5kdfSetCtxParams {
    propq: *const OsslParam,
    engine: *const OsslParam,
    cipher: *const OsslParam,
    key: *const OsslParam,
    cnst: *const OsslParam,
}

/// The `krb5kdf_set_ctx_params_decoder` keys, each with its (field id, raise site). None is a
/// list, so the generated `strcmp`-tree at `krb5kdf.c:191-256` raises `PROV_R_REPEATED_PARAMETER`
/// at the second occurrence of any one.
const KRB5KDF_SET_DECODER_KEYS: [(&err_sites::ErrSite, *const c_char, u32); 5] = [
    (&err_sites::PROV_KRB5KDF_199, OSSL_KDF_PARAM_CIPHER, 0),
    (&err_sites::PROV_KRB5KDF_210, OSSL_KDF_PARAM_CONSTANT, 1),
    (&err_sites::PROV_KRB5KDF_222, OSSL_ALG_PARAM_ENGINE, 2),
    (&err_sites::PROV_KRB5KDF_233, OSSL_KDF_PARAM_KEY, 3),
    (&err_sites::PROV_KRB5KDF_244, OSSL_KDF_PARAM_PROPERTIES, 4),
];

/// The `krb5kdf_get_ctx_params_decoder` key, `krb5kdf.c:308-320`.
const KRB5KDF_GET_DECODER_KEYS: [(&err_sites::ErrSite, *const c_char, u32); 1] =
    [(&err_sites::PROV_KRB5KDF_314, OSSL_KDF_PARAM_SIZE, 0)];

/// `static const OSSL_PARAM krb5kdf_set_ctx_params_list[]` — `krb5kdf.c:160-165`.
static KRB5KDF_SETTABLE_CTX_PARAMS: [OsslParam; 5] = [
    param_utf8_string(OSSL_KDF_PARAM_PROPERTIES),
    param_utf8_string(OSSL_KDF_PARAM_CIPHER),
    param_octet_string(OSSL_KDF_PARAM_KEY),
    param_octet_string(OSSL_KDF_PARAM_CONSTANT),
    END,
];

/// `static const OSSL_PARAM krb5kdf_get_ctx_params_list[]` — `krb5kdf.c:305-307`.
static KRB5KDF_GETTABLE_CTX_PARAMS: [OsslParam; 2] = [param_size_t(OSSL_KDF_PARAM_SIZE), END];

/// `static int fixup_des3_key(unsigned char *key)` — `krb5kdf.c:257-277`. Only the odd-parity
/// fixup is conditional on `!OPENSSL_NO_DES`, which this profile does not define.
///
/// # Safety
/// `key` is readable and writable for 24 bytes.
unsafe fn krb5kdf_fixup_des3_key(key: *mut u8) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        for i in (0..3).rev() {
            let cblock = key.add(i * 8);
            ptr::copy(cblock.add(i * 7), cblock, 7);
            *cblock.add(7) = 0;
            for j in 0..7 {
                *cblock.add(7) |= (*cblock.add(j) & 1) << (j + 1);
            }
            DES_set_odd_parity(cblock.cast::<[u8; 8]>());
        }

        /* fail if keys are such that triple des degrades to single des */
        if CRYPTO_memcmp(key.cast(), key.add(8).cast(), 8) == 0
            || CRYPTO_memcmp(key.add(8).cast(), key.add(16).cast(), 8) == 0
        {
            return 0;
        }

        1
    }
}

/// `static void n_fold(unsigned char *block, unsigned int blocksize, const unsigned char
/// *constant, unsigned int constant_len)` — `krb5kdf.c:300-359`. RFC 3961's n-fold, computed
/// space-optimally: for each `l` from `L-1` down to 0, one rotated constant byte is added into
/// `block[l % blocksize]` with the carry propagated **backwards**. All the unsigned arithmetic is
/// `wrapping_*` because the authority relies on `unsigned int` wrap for every subtraction and
/// multiplication here (`lcm` can exceed 32 bits before the `% blocksize`).
///
/// # Safety
/// `block` is writable for `blocksize`; `constant` is readable for `constant_len`.
unsafe fn krb5kdf_n_fold(block: *mut u8, blocksize: u32, constant: *const u8, constant_len: u32) {
    // SAFETY: the caller's contract.
    unsafe {
        if constant_len == blocksize {
            ptr::copy_nonoverlapping(constant, block, constant_len as usize);
            return;
        }

        /* Least Common Multiple of lengths: LCM(a,b)*/
        let mut gcd = blocksize;
        let mut remainder = constant_len;
        /* Calculate Great Common Divisor first GCD(a,b) */
        while remainder != 0 {
            let tmp = gcd % remainder;
            gcd = remainder;
            remainder = tmp;
        }
        /* resulting a is the GCD, LCM(a,b) = |a*b|/GCD(a,b) */
        let lcm = blocksize.wrapping_mul(constant_len) / gcd;

        /* now spread out the bits */
        ptr::write_bytes(block, 0, blocksize as usize);

        /* last to first to be able to bring carry forward */
        let mut carry: u32 = 0;
        let mut l: i64 = lcm as i64 - 1;
        while l >= 0 {
            let lu = l as u32;

            /* destination byte in block is l % N */
            let b = lu % blocksize;
            /* Our virtual s buffer is R = L/K long (K = constant_len) */
            /* So we rotate backwards from R-1 to 0 (none) rotations */
            let rotbits = 13u32.wrapping_mul(lu / constant_len);
            /* find the byte on s where rotbits falls onto */
            let rbyte = lu.wrapping_sub(rotbits / 8);
            /* calculate how much shift on that byte */
            let rshift = rotbits & 0x07;
            /* rbyte % constant_len gives us the unrotated byte in the constant buffer, get also
             * the previous byte then appropriately shift them to get the rotated byte we need */
            let mut tmp = ((*constant.add(rbyte.wrapping_sub(1) as usize % constant_len as usize)
                as u32)
                << (8 - rshift)
                | (*constant.add((rbyte % constant_len) as usize) as u32) >> rshift)
                & 0xff;
            /* add with carry to any value placed by previous passes */
            tmp += carry + *block.add(b as usize) as u32;
            *block.add(b as usize) = (tmp & 0xff) as u8;
            /* save any carry that may be left */
            carry = tmp >> 8;
            l -= 1;
        }

        /* if any carry is left at the end, add it through the number */
        let mut b: i64 = blocksize as i64 - 1;
        while b >= 0 && carry != 0 {
            carry += *block.add(b as usize) as u32;
            *block.add(b as usize) = (carry & 0xff) as u8;
            carry >>= 8;
            b -= 1;
        }
    }
}

/// `static int cipher_init(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *cipher, ENGINE *engine, const
/// unsigned char *key, size_t key_len)` — `krb5kdf.c:361-391`. The `goto out` is a labelled block;
/// the padding is switched off because the caller's length either is a block multiple or the
/// cipher copes with partial blocks.
///
/// # Safety
/// `ctx` is a live cipher context; `cipher`/`engine`/`key` are per the authority's contract.
unsafe fn krb5kdf_cipher_init(
    ctx: *mut EvpCipherCtx,
    cipher: *const EvpCipher,
    engine: *mut c_void,
    key: *const u8,
    key_len: usize,
) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        let mut ret = EVP_EncryptInit_ex(ctx, cipher, engine, ptr::null(), ptr::null());
        'out: {
            if ret == 0 {
                break 'out;
            }
            /* set the key len for the odd variable key len cipher */
            let klen = EVP_CIPHER_CTX_get_key_length(ctx);
            if key_len != klen as usize {
                ret = EVP_CIPHER_CTX_set_key_length(ctx, key_len as c_int);
                if ret <= 0 {
                    ret = 0;
                    break 'out;
                }
            }
            ret = EVP_EncryptInit_ex(ctx, ptr::null(), ptr::null_mut(), key, ptr::null());
            if ret == 0 {
                break 'out;
            }
            /* we never want padding, either the length requested is a multiple of the cipher
             * block size or we are passed a cipher that can cope with partial blocks via
             * techniques like cipher text stealing */
            ret = EVP_CIPHER_CTX_set_padding(ctx, 0);
            if ret == 0 {
                break 'out;
            }
        }
        ret
    }
}

/// `static int KRB5KDF(const EVP_CIPHER *cipher, ENGINE *engine, const unsigned char *key,
/// size_t key_len, const unsigned char *constant, size_t constant_len, unsigned char *okey,
/// size_t okey_len)` — `krb5kdf.c:393-509`. The `goto out` is a labelled block whose single exit
/// frees the cipher context and cleanses the two-block scratch buffer.
///
/// # Safety
/// `cipher` is live; `key` is readable for `key_len`; `constant` for `constant_len`; `okey` is
/// writable for `okey_len`.
#[allow(clippy::too_many_arguments)] // mirrors the authority's signature exactly
unsafe fn krb5kdf_alg(
    cipher: *const EvpCipher,
    engine: *mut c_void,
    key: *const u8,
    key_len: usize,
    constant: *const u8,
    constant_len: usize,
    okey: *mut u8,
    okey_len: usize,
) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        let mut block = [0u8; EVP_MAX_BLOCK_LENGTH * 2];
        let mut des3_no_fixup = 0;

        if key_len != okey_len {
            /* special case for 3des, where the caller may be requesting the random raw key,
             * instead of the fixed up key */
            if EVP_CIPHER_get_nid(cipher) == NID_des_ede3_cbc && key_len == 24 && okey_len == 21 {
                des3_no_fixup = 1;
            } else {
                return fail_at(&err_sites::PROV_KRB5KDF_538);
            }
        }

        let ctx: *mut EvpCipherCtx = EVP_CIPHER_CTX_new();
        if ctx.is_null() {
            return 0;
        }

        let mut ret = krb5kdf_cipher_init(ctx, cipher, engine, key, key_len);
        'out: {
            if ret == 0 {
                break 'out;
            }

            /* Initialize input block */
            let blocksize = EVP_CIPHER_CTX_get_block_size(ctx) as usize;

            if blocksize == 0 {
                raise_site(&err_sites::PROV_KRB5KDF_557);
                ret = 0;
                break 'out;
            }

            if constant_len > blocksize {
                raise_site(&err_sites::PROV_KRB5KDF_563);
                ret = 0;
                break 'out;
            }

            krb5kdf_n_fold(
                block.as_mut_ptr(),
                blocksize as u32,
                constant,
                constant_len as u32,
            );
            let mut plainblock = block.as_mut_ptr();
            let mut cipherblock = block.as_mut_ptr().add(EVP_MAX_BLOCK_LENGTH);

            let mut osize: usize = 0;
            while osize < okey_len {
                let mut olen: c_int = 0;

                ret =
                    EVP_EncryptUpdate(ctx, cipherblock, &mut olen, plainblock, blocksize as c_int);
                if ret == 0 {
                    break 'out;
                }
                let mut cipherlen = olen as usize;
                ret = EVP_EncryptFinal_ex(ctx, cipherblock, &mut olen);
                if ret == 0 {
                    break 'out;
                }
                if olen != 0 {
                    raise_site(&err_sites::PROV_KRB5KDF_584);
                    ret = 0;
                    break 'out;
                }

                /* write cipherblock out */
                if cipherlen > okey_len - osize {
                    cipherlen = okey_len - osize;
                }
                ptr::copy_nonoverlapping(cipherblock, okey.add(osize), cipherlen);

                if okey_len > osize + cipherlen {
                    /* we need to reinitialize cipher context per spec */
                    ret = EVP_CIPHER_CTX_reset(ctx);
                    if ret == 0 {
                        break 'out;
                    }
                    ret = krb5kdf_cipher_init(ctx, cipher, engine, key, key_len);
                    if ret == 0 {
                        break 'out;
                    }

                    /* also swap block offsets so last ciphertext becomes new plaintext */
                    plainblock = cipherblock;
                    if cipherblock == block.as_mut_ptr() {
                        cipherblock = cipherblock.add(EVP_MAX_BLOCK_LENGTH);
                    } else {
                        cipherblock = block.as_mut_ptr();
                    }
                }
                osize += cipherlen;
            }

            if EVP_CIPHER_get_nid(cipher) == NID_des_ede3_cbc && des3_no_fixup == 0 {
                ret = krb5kdf_fixup_des3_key(okey);
                if ret == 0 {
                    raise_site(&err_sites::PROV_KRB5KDF_618);
                    break 'out;
                }
            }

            ret = 1;
        }
        EVP_CIPHER_CTX_free(ctx);
        cleanse(block.as_mut_ptr().cast(), EVP_MAX_BLOCK_LENGTH * 2);
        ret
    }
}

/// `static void *krb5kdf_new(void *provctx)` — `krb5kdf.c:65-76`.
///
/// # Safety
/// The dispatch contract.
unsafe extern "C" fn krb5kdf_new(provctx: *mut c_void) -> *mut c_void {
    // SAFETY: the caller's contract.
    unsafe {
        if is_running() == 0 {
            return ptr::null_mut();
        }
        let ctx = CRYPTO_zalloc(core::mem::size_of::<Krb5kdfCtx>(), FILE_KRB5KDF, LINE)
            .cast::<Krb5kdfCtx>();
        if ctx.is_null() {
            return ptr::null_mut();
        }
        (*ctx).provctx = provctx;
        ctx.cast()
    }
}

/// `static void krb5kdf_reset(void *vctx)` — `krb5kdf.c:88-98`. The `provctx` is saved across the
/// `memset` because the whole struct is cleared.
///
/// # Safety
/// `vctx` is a context `krb5kdf_new` allocated.
unsafe fn krb5kdf_reset(vctx: *mut c_void) {
    // SAFETY: `vctx` is a live context per the contract.
    unsafe {
        let ctx = vctx.cast::<Krb5kdfCtx>();
        let provctx = (*ctx).provctx;

        ossl_prov_cipher_reset(ptr::addr_of_mut!((*ctx).cipher));
        CRYPTO_clear_free((*ctx).key.cast(), (*ctx).key_len, FILE_KRB5KDF, LINE);
        CRYPTO_clear_free(
            (*ctx).constant.cast(),
            (*ctx).constant_len,
            FILE_KRB5KDF,
            LINE,
        );
        ptr::write_bytes(vctx.cast::<u8>(), 0, core::mem::size_of::<Krb5kdfCtx>());
        (*ctx).provctx = provctx;
    }
}

/// `static void krb5kdf_free(void *vctx)` — `krb5kdf.c:78-86`.
///
/// # Safety
/// The dispatch contract.
unsafe extern "C" fn krb5kdf_free(vctx: *mut c_void) {
    // SAFETY: `vctx` is NULL or a live context.
    unsafe {
        if !vctx.is_null() {
            krb5kdf_reset(vctx);
            CRYPTO_free(vctx, FILE_KRB5KDF, LINE);
        }
    }
}

/// `static int krb5kdf_set_membuf(unsigned char **dst, size_t *dst_len, const OSSL_PARAM *p)` —
/// `krb5kdf.c:100-107`.
///
/// # Safety
/// `dst`/`dst_len` are live; `p` is a live parameter.
unsafe fn krb5kdf_set_membuf(dst: *mut *mut u8, dst_len: *mut usize, p: *const OsslParam) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        CRYPTO_clear_free((*dst).cast(), *dst_len, FILE_KRB5KDF, LINE);
        *dst = ptr::null_mut();
        *dst_len = 0;
        OSSL_PARAM_get_octet_string(p.cast_mut(), dst.cast(), 0, dst_len)
    }
}

/// `static void *krb5kdf_dup(void *vctx)` — `krb5kdf.c:109-128`.
///
/// # Safety
/// The dispatch contract.
unsafe extern "C" fn krb5kdf_dup(vctx: *mut c_void) -> *mut c_void {
    // SAFETY: the caller's contract.
    unsafe {
        let src = vctx.cast::<Krb5kdfCtx>();
        let dest = krb5kdf_new((*src).provctx).cast::<Krb5kdfCtx>();
        if dest.is_null() {
            return ptr::null_mut();
        }
        if ossl_prov_memdup(
            (*src).key.cast(),
            (*src).key_len,
            ptr::addr_of_mut!((*dest).key),
            ptr::addr_of_mut!((*dest).key_len),
        ) == 0
            || ossl_prov_memdup(
                (*src).constant.cast(),
                (*src).constant_len,
                ptr::addr_of_mut!((*dest).constant),
                ptr::addr_of_mut!((*dest).constant_len),
            ) == 0
            || ossl_prov_cipher_copy(
                ptr::addr_of_mut!((*dest).cipher),
                ptr::addr_of!((*src).cipher),
            ) == 0
        {
            krb5kdf_free(dest.cast());
            return ptr::null_mut();
        }
        dest.cast()
    }
}

/// `static int krb5kdf_derive(void *vctx, unsigned char *key, size_t keylen, const OSSL_PARAM
/// params[])` — `krb5kdf.c:130-157`.
///
/// # Safety
/// The dispatch contract.
unsafe extern "C" fn krb5kdf_ctx_derive(
    vctx: *mut c_void,
    key: *mut u8,
    keylen: usize,
    params: *const OsslParam,
) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        let ctx = vctx.cast::<Krb5kdfCtx>();

        if is_running() == 0 || krb5kdf_set_ctx_params(vctx, params) == 0 {
            return 0;
        }

        let cipher = ossl_prov_cipher_cipher(ptr::addr_of!((*ctx).cipher));
        if cipher.is_null() {
            return fail_at(&err_sites::PROV_KRB5KDF_140);
        }
        if (*ctx).key.is_null() {
            return fail_at(&err_sites::PROV_KRB5KDF_144);
        }
        if (*ctx).constant.is_null() {
            return fail_at(&err_sites::PROV_KRB5KDF_148);
        }
        let engine = ossl_prov_cipher_engine(ptr::addr_of!((*ctx).cipher));
        krb5kdf_alg(
            cipher,
            engine,
            (*ctx).key,
            (*ctx).key_len,
            (*ctx).constant,
            (*ctx).constant_len,
            key,
            keylen,
        )
    }
}

/// `static int krb5kdf_set_ctx_params(void *vctx, const OSSL_PARAM params[])` —
/// `krb5kdf.c:169-191`, with the generated switch replaced by the field-keyed repeat check and one
/// `OSSL_PARAM_locate_const` per key (D305's reading).
///
/// # Safety
/// The dispatch contract.
unsafe extern "C" fn krb5kdf_set_ctx_params(vctx: *mut c_void, params: *const OsslParam) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        if vctx.is_null() {
            return 0;
        }
        if let Some(site) = repeated_param_site_by_field(params, &KRB5KDF_SET_DECODER_KEYS) {
            return fail_at(site);
        }
        let ctx = vctx.cast::<Krb5kdfCtx>();
        let p = Krb5kdfSetCtxParams {
            propq: locate_const(params, OSSL_KDF_PARAM_PROPERTIES),
            engine: locate_const(params, OSSL_ALG_PARAM_ENGINE),
            cipher: locate_const(params, OSSL_KDF_PARAM_CIPHER),
            key: locate_const(params, OSSL_KDF_PARAM_KEY),
            cnst: locate_const(params, OSSL_KDF_PARAM_CONSTANT),
        };
        let provctx = prov_libctx_of((*ctx).provctx);

        if ossl_prov_cipher_load(
            ptr::addr_of_mut!((*ctx).cipher),
            p.cipher,
            p.propq,
            p.engine,
            provctx,
        ) == 0
        {
            return 0;
        }

        if !p.key.is_null()
            && krb5kdf_set_membuf(
                ptr::addr_of_mut!((*ctx).key),
                ptr::addr_of_mut!((*ctx).key_len),
                p.key,
            ) == 0
        {
            return 0;
        }

        if !p.cnst.is_null()
            && krb5kdf_set_membuf(
                ptr::addr_of_mut!((*ctx).constant),
                ptr::addr_of_mut!((*ctx).constant_len),
                p.cnst,
            ) == 0
        {
            return 0;
        }

        1
    }
}

/// `static int krb5kdf_get_ctx_params(void *vctx, OSSL_PARAM params[])` — `krb5kdf.c:205-226`.
/// The `size` answer is the cipher's key length, or `EVP_MAX_KEY_LENGTH` while no cipher is set.
///
/// # Safety
/// The dispatch contract.
unsafe extern "C" fn krb5kdf_get_ctx_params(vctx: *mut c_void, params: *mut OsslParam) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        if vctx.is_null() {
            return 0;
        }
        if let Some(site) =
            repeated_param_site_by_field(params.cast_const(), &KRB5KDF_GET_DECODER_KEYS)
        {
            return fail_at(site);
        }
        let ctx = vctx.cast::<Krb5kdfCtx>();
        let p = locate_const(params, OSSL_KDF_PARAM_SIZE);
        if !p.is_null() {
            let cipher = ossl_prov_cipher_cipher(ptr::addr_of!((*ctx).cipher));

            let len = if !cipher.is_null() {
                EVP_CIPHER_get_key_length(cipher) as usize
            } else {
                EVP_MAX_KEY_LENGTH
            };

            if OSSL_PARAM_set_size_t(p.cast_mut(), len) == 0 {
                return 0;
            }
        }
        1
    }
}

/// `static const OSSL_PARAM *krb5kdf_settable_ctx_params(void *ctx, void *provctx)` —
/// `krb5kdf.c:193-197`.
///
/// # Safety
/// The dispatch contract.
unsafe extern "C" fn krb5kdf_settable_ctx_params(
    _ctx: *mut c_void,
    _p_ctx: *mut c_void,
) -> *const OsslParam {
    KRB5KDF_SETTABLE_CTX_PARAMS.as_ptr()
}

/// `static const OSSL_PARAM *krb5kdf_gettable_ctx_params(void *ctx, void *provctx)` —
/// `krb5kdf.c:228-232`.
///
/// # Safety
/// The dispatch contract.
unsafe extern "C" fn krb5kdf_gettable_ctx_params(
    _ctx: *mut c_void,
    _p_ctx: *mut c_void,
) -> *const OsslParam {
    KRB5KDF_GETTABLE_CTX_PARAMS.as_ptr()
}

/// `const OSSL_DISPATCH ossl_kdf_krb5kdf_functions[]` — `krb5kdf.c:234-249`.
pub(crate) static KRB5KDF_FUNCTIONS: [OsslDispatch; 10] = [
    OsslDispatch {
        function_id: OSSL_FUNC_KDF_NEWCTX,
        function: krb5kdf_new as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KDF_DUPCTX,
        function: krb5kdf_dup as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KDF_FREECTX,
        function: krb5kdf_free as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KDF_RESET,
        function: krb5kdf_reset as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KDF_DERIVE,
        function: krb5kdf_ctx_derive as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KDF_SETTABLE_CTX_PARAMS,
        function: krb5kdf_settable_ctx_params as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KDF_SET_CTX_PARAMS,
        function: krb5kdf_set_ctx_params as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KDF_GETTABLE_CTX_PARAMS,
        function: krb5kdf_gettable_ctx_params as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KDF_GET_CTX_PARAMS,
        function: krb5kdf_get_ctx_params as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_DISPATCH_END,
        function: ptr::null_mut(),
    },
];

// =============================================================================================
// `providers/implementations/kdfs/hmacdrbg_kdf.c` — HMAC-DRBG-KDF
// =============================================================================================

/// `OSSL_KDF_PARAM_HMACDRBG_ENTROPY` — `include/openssl/core_names.h:287`.
const OSSL_KDF_PARAM_HMACDRBG_ENTROPY: *const c_char = c"entropy".as_ptr();

/// `OSSL_KDF_PARAM_HMACDRBG_NONCE` — `include/openssl/core_names.h:288`.
const OSSL_KDF_PARAM_HMACDRBG_NONCE: *const c_char = c"nonce".as_ptr();

/// `FILE_HMACDRBG_KDF` — the unit's own `__FILE__`.
const FILE_HMACDRBG_KDF: *const c_char = c"providers/implementations/kdfs/hmacdrbg_kdf.c".as_ptr();

/// `struct KDF_HMAC_DRBG` — `hmacdrbg_kdf.c:38-44`.
#[repr(C)]
pub(crate) struct KdfHmacDrbg {
    /// `PROV_DRBG_HMAC base` — the HMAC-DRBG core, which is `src/provider/rand.rs`'s.
    pub base: ProvDrbgHmac,
    /// `void *provctx`.
    pub provctx: *mut c_void,
    /// `unsigned char *entropy, *nonce`.
    pub entropy: *mut u8,
    pub nonce: *mut u8,
    /// `size_t entropylen, noncelen`.
    pub entropylen: usize,
    pub noncelen: usize,
    /// `int init` — whether `ossl_drbg_hmac_init` has run for this entropy/nonce pair.
    pub init: c_int,
}

/// `struct hmac_drbg_kdf_get_ctx_params_st` — `hmacdrbg_kdf.c:154-158`.
#[derive(Default)]
struct HmacDrbgKdfGetCtxParams {
    mac: *const OsslParam,
    digest: *const OsslParam,
}

/// `struct hmac_drbg_kdf_set_ctx_params_st` — `hmacdrbg_kdf.c:247-254`.
#[derive(Default)]
struct HmacDrbgKdfSetCtxParams {
    propq: *const OsslParam,
    engine: *const OsslParam,
    digest: *const OsslParam,
    ent: *const OsslParam,
    nonce: *const OsslParam,
}

/// The `hmac_drbg_kdf_get_ctx_params_decoder` keys, `hmacdrbg_kdf.c:165-193` — the two names the
/// row can report back, each raising `PROV_R_REPEATED_PARAMETER` on its second occurrence.
const HMACDRBG_KDF_GET_DECODER_KEYS: [(&err_sites::ErrSite, *const c_char, u32); 2] = [
    (&err_sites::PROV_HMACDRBG_KDF_177, OSSL_KDF_PARAM_DIGEST, 0),
    (&err_sites::PROV_HMACDRBG_KDF_188, OSSL_KDF_PARAM_MAC, 1),
];

/// The `hmac_drbg_kdf_set_ctx_params_decoder` keys, each with its (field id, raise site). None is
/// a list, so the generated `strcmp`-tree at `hmacdrbg_kdf.c:258-341` raises
/// `PROV_R_REPEATED_PARAMETER` at the second occurrence of any one.
const HMACDRBG_KDF_SET_DECODER_KEYS: [(&err_sites::ErrSite, *const c_char, u32); 5] = [
    (&err_sites::PROV_HMACDRBG_KDF_273, OSSL_KDF_PARAM_DIGEST, 0),
    (&err_sites::PROV_HMACDRBG_KDF_292, OSSL_ALG_PARAM_ENGINE, 1),
    (
        &err_sites::PROV_HMACDRBG_KDF_303,
        OSSL_KDF_PARAM_HMACDRBG_ENTROPY,
        2,
    ),
    (
        &err_sites::PROV_HMACDRBG_KDF_316,
        OSSL_KDF_PARAM_HMACDRBG_NONCE,
        3,
    ),
    (
        &err_sites::PROV_HMACDRBG_KDF_327,
        OSSL_KDF_PARAM_PROPERTIES,
        4,
    ),
];

/// `static const OSSL_PARAM hmac_drbg_kdf_get_ctx_params_list[]` — `hmacdrbg_kdf.c:147-151`.
static HMACDRBG_KDF_GETTABLE_CTX_PARAMS: [OsslParam; 3] = [
    param_utf8_string(OSSL_KDF_PARAM_MAC),
    param_utf8_string(OSSL_KDF_PARAM_DIGEST),
    END,
];

/// `static const OSSL_PARAM hmac_drbg_kdf_set_ctx_params_list[]` — `hmacdrbg_kdf.c:238-244`. The
/// MAC is fixed to HMAC, so it is not settable.
static HMACDRBG_KDF_SETTABLE_CTX_PARAMS: [OsslParam; 5] = [
    param_utf8_string(OSSL_KDF_PARAM_PROPERTIES),
    param_utf8_string(OSSL_KDF_PARAM_DIGEST),
    param_octet_string(OSSL_KDF_PARAM_HMACDRBG_ENTROPY),
    param_octet_string(OSSL_KDF_PARAM_HMACDRBG_NONCE),
    END,
];

/// `static void *hmac_drbg_kdf_new(void *provctx)` — `hmacdrbg_kdf.c:46-60`. The one unit in this
/// module whose allocation failure is itself an error record (`ERR_R_MALLOC_FAILURE`).
///
/// # Safety
/// The dispatch contract.
unsafe extern "C" fn hmac_drbg_kdf_new(provctx: *mut c_void) -> *mut c_void {
    // SAFETY: the caller's contract.
    unsafe {
        if is_running() == 0 {
            return ptr::null_mut();
        }
        let ctx = CRYPTO_zalloc(core::mem::size_of::<KdfHmacDrbg>(), FILE_HMACDRBG_KDF, LINE)
            .cast::<KdfHmacDrbg>();
        if ctx.is_null() {
            raise_site(&err_sites::PROV_HMACDRBG_KDF_53);
            return ptr::null_mut();
        }
        (*ctx).provctx = provctx;
        ctx.cast()
    }
}

/// `static void hmac_drbg_kdf_reset(void *vctx)` — `hmacdrbg_kdf.c:62-74`. The `provctx` is saved
/// across the `OPENSSL_cleanse` of the whole struct.
///
/// # Safety
/// `vctx` is a context `hmac_drbg_kdf_new` allocated.
unsafe fn hmac_drbg_kdf_reset(vctx: *mut c_void) {
    // SAFETY: `vctx` is a live context per the contract.
    unsafe {
        let ctx = vctx.cast::<KdfHmacDrbg>();
        let provctx = (*ctx).provctx;

        EVP_MAC_CTX_free((*ctx).base.ctx);
        ossl_prov_digest_reset(ptr::addr_of_mut!((*ctx).base.digest));
        CRYPTO_clear_free(
            (*ctx).entropy.cast(),
            (*ctx).entropylen,
            FILE_HMACDRBG_KDF,
            LINE,
        );
        CRYPTO_clear_free(
            (*ctx).nonce.cast(),
            (*ctx).noncelen,
            FILE_HMACDRBG_KDF,
            LINE,
        );
        cleanse(vctx.cast::<u8>(), core::mem::size_of::<KdfHmacDrbg>());
        (*ctx).provctx = provctx;
    }
}

/// `static void hmac_drbg_kdf_free(void *vctx)` — `hmacdrbg_kdf.c:76-84`.
///
/// # Safety
/// The dispatch contract.
unsafe extern "C" fn hmac_drbg_kdf_free(vctx: *mut c_void) {
    // SAFETY: `vctx` is NULL or a live context.
    unsafe {
        if !vctx.is_null() {
            hmac_drbg_kdf_reset(vctx);
            CRYPTO_free(vctx, FILE_HMACDRBG_KDF, LINE);
        }
    }
}

/// `static int ossl_drbg_hmac_dup(PROV_DRBG_HMAC *dst, const PROV_DRBG_HMAC *src)` —
/// `hmacdrbg_kdf.c:86-99`. A NULL `src->ctx` leaves `dst->ctx` as the fresh context's, which is
/// NULL from the `zalloc` in `hmac_drbg_kdf_new`.
///
/// # Safety
/// `dst` is writable and `src` readable; both point at live `PROV_DRBG_HMAC`s.
unsafe fn hmac_drbg_kdf_base_dup(dst: *mut ProvDrbgHmac, src: *const ProvDrbgHmac) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        if !(*src).ctx.is_null() {
            (*dst).ctx = EVP_MAC_CTX_dup((*src).ctx);
            if (*dst).ctx.is_null() {
                return 0;
            }
        }
        if ossl_prov_digest_copy(
            ptr::addr_of_mut!((*dst).digest),
            ptr::addr_of!((*src).digest),
        ) == 0
        {
            return 0;
        }
        ptr::copy_nonoverlapping((*src).k.as_ptr(), (*dst).k.as_mut_ptr(), EVP_MAX_MD_SIZE);
        ptr::copy_nonoverlapping((*src).v.as_ptr(), (*dst).v.as_mut_ptr(), EVP_MAX_MD_SIZE);
        (*dst).blocklen = (*src).blocklen;
        1
    }
}

/// `static void *hmac_drbg_kdf_dup(void *vctx)` — `hmacdrbg_kdf.c:101-121`.
///
/// # Safety
/// The dispatch contract.
unsafe extern "C" fn hmac_drbg_kdf_dup(vctx: *mut c_void) -> *mut c_void {
    // SAFETY: the caller's contract.
    unsafe {
        let src = vctx.cast::<KdfHmacDrbg>();
        let dst = hmac_drbg_kdf_new((*src).provctx).cast::<KdfHmacDrbg>();
        if dst.is_null() {
            return ptr::null_mut();
        }
        if hmac_drbg_kdf_base_dup(ptr::addr_of_mut!((*dst).base), ptr::addr_of!((*src).base)) == 0
            || ossl_prov_memdup(
                (*src).entropy.cast(),
                (*src).entropylen,
                ptr::addr_of_mut!((*dst).entropy),
                ptr::addr_of_mut!((*dst).entropylen),
            ) == 0
            || ossl_prov_memdup(
                (*src).nonce.cast(),
                (*src).noncelen,
                ptr::addr_of_mut!((*dst).nonce),
                ptr::addr_of_mut!((*dst).noncelen),
            ) == 0
        {
            hmac_drbg_kdf_free(dst.cast());
            return ptr::null_mut();
        }
        (*dst).init = (*src).init;
        dst.cast()
    }
}

/// `static int hmac_drbg_kdf_derive(void *vctx, unsigned char *out, size_t outlen, const
/// OSSL_PARAM params[])` — `hmacdrbg_kdf.c:123-144`.
///
/// # Safety
/// The dispatch contract.
unsafe extern "C" fn hmac_drbg_kdf_ctx_derive(
    vctx: *mut c_void,
    out: *mut u8,
    outlen: usize,
    params: *const OsslParam,
) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        let ctx = vctx.cast::<KdfHmacDrbg>();
        let drbg = ptr::addr_of_mut!((*ctx).base);

        if is_running() == 0 || hmac_drbg_kdf_set_ctx_params(vctx, params) == 0 {
            return 0;
        }
        if (*ctx).init == 0 {
            if (*ctx).entropy.is_null()
                || (*ctx).entropylen == 0
                || (*ctx).nonce.is_null()
                || (*ctx).noncelen == 0
                || ossl_drbg_hmac_init(
                    drbg,
                    (*ctx).entropy,
                    (*ctx).entropylen,
                    (*ctx).nonce,
                    (*ctx).noncelen,
                    ptr::null(),
                    0,
                ) == 0
            {
                return 0;
            }
            (*ctx).init = 1;
        }

        ossl_drbg_hmac_generate(drbg, out, outlen, ptr::null(), 0)
    }
}

/// `static int hmac_drbg_kdf_get_ctx_params(void *vctx, OSSL_PARAM params[])` —
/// `hmacdrbg_kdf.c:198-224`. The two answers are the loaded MAC's own name and the loaded digest's
/// own name, and a `mac` request against an unloaded MAC is a bare refusal.
///
/// # Safety
/// The dispatch contract.
unsafe extern "C" fn hmac_drbg_kdf_get_ctx_params(
    vctx: *mut c_void,
    params: *mut OsslParam,
) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        if vctx.is_null() {
            return 0;
        }
        if let Some(site) =
            repeated_param_site_by_field(params.cast_const(), &HMACDRBG_KDF_GET_DECODER_KEYS)
        {
            return fail_at(site);
        }
        let hmac = vctx.cast::<KdfHmacDrbg>();
        let drbg = ptr::addr_of!((*hmac).base);
        let p = HmacDrbgKdfGetCtxParams {
            mac: locate_const(params, OSSL_KDF_PARAM_MAC),
            digest: locate_const(params, OSSL_KDF_PARAM_DIGEST),
        };

        if !p.mac.is_null() {
            if (*drbg).ctx.is_null() {
                return 0;
            }
            let name = EVP_MAC_get0_name(EVP_MAC_CTX_get0_mac((*drbg).ctx));
            if OSSL_PARAM_set_utf8_string(p.mac.cast_mut(), name) == 0 {
                return 0;
            }
        }

        if !p.digest.is_null() {
            let md = ossl_prov_digest_md(ptr::addr_of!((*drbg).digest));
            if md.is_null()
                || OSSL_PARAM_set_utf8_string(p.digest.cast_mut(), EVP_MD_get0_name(md)) == 0
            {
                return 0;
            }
        }
        1
    }
}

/// `static int hmac_drbg_kdf_set_ctx_params(void *vctx, const OSSL_PARAM params[])` —
/// `hmacdrbg_kdf.c:247-296`, with the generated switch replaced by the field-keyed repeat check and
/// one `OSSL_PARAM_locate_const` per key (D305's reading).
///
/// # Safety
/// The dispatch contract.
unsafe extern "C" fn hmac_drbg_kdf_set_ctx_params(
    vctx: *mut c_void,
    params: *const OsslParam,
) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        if vctx.is_null() {
            return 0;
        }
        if let Some(site) = repeated_param_site_by_field(params, &HMACDRBG_KDF_SET_DECODER_KEYS) {
            return fail_at(site);
        }
        let hmac = vctx.cast::<KdfHmacDrbg>();
        let drbg = ptr::addr_of_mut!((*hmac).base);
        let p = HmacDrbgKdfSetCtxParams {
            propq: locate_const(params, OSSL_KDF_PARAM_PROPERTIES),
            engine: locate_const(params, OSSL_ALG_PARAM_ENGINE),
            digest: locate_const(params, OSSL_KDF_PARAM_DIGEST),
            ent: locate_const(params, OSSL_KDF_PARAM_HMACDRBG_ENTROPY),
            nonce: locate_const(params, OSSL_KDF_PARAM_HMACDRBG_NONCE),
        };
        let libctx = prov_libctx_of((*hmac).provctx);
        let mut ptr_: *mut c_void = ptr::null_mut();
        let mut size: usize = 0;

        if !p.ent.is_null() {
            if OSSL_PARAM_get_octet_string(p.ent, &mut ptr_, 0, &mut size) == 0 {
                return 0;
            }
            CRYPTO_free((*hmac).entropy.cast(), FILE_HMACDRBG_KDF, LINE);
            (*hmac).entropy = ptr_.cast();
            (*hmac).entropylen = size;
            (*hmac).init = 0;
            ptr_ = ptr::null_mut();
        }

        if !p.nonce.is_null() {
            if OSSL_PARAM_get_octet_string(p.nonce, &mut ptr_, 0, &mut size) == 0 {
                return 0;
            }
            CRYPTO_free((*hmac).nonce.cast(), FILE_HMACDRBG_KDF, LINE);
            (*hmac).nonce = ptr_.cast();
            (*hmac).noncelen = size;
            (*hmac).init = 0;
        }

        if !p.digest.is_null() {
            if ossl_prov_digest_load(
                ptr::addr_of_mut!((*drbg).digest),
                p.digest,
                p.propq,
                p.engine,
                libctx,
            ) == 0
            {
                return 0;
            }

            /* Confirm digest is allowed. Allow all digests that are not XOF */
            let md = ossl_prov_digest_md(ptr::addr_of!((*drbg).digest));
            if !md.is_null() {
                if EVP_MD_xof(md) != 0 {
                    return fail_at(&err_sites::PROV_HMACDRBG_KDF_386);
                }
                let md_size = EVP_MD_get_size(md);
                if md_size <= 0 {
                    return 0;
                }
                (*drbg).blocklen = md_size as usize;
            }
            if ossl_prov_macctx_load(
                ptr::addr_of_mut!((*drbg).ctx),
                ptr::null(),
                ptr::null(),
                p.digest,
                p.propq,
                p.engine,
                OSSL_MAC_NAME_HMAC,
                ptr::null(),
                ptr::null(),
                libctx,
            ) == 0
            {
                return 0;
            }
        }
        1
    }
}

/// `static const OSSL_PARAM *hmac_drbg_kdf_settable_ctx_params(void *vctx, void *p_ctx)` —
/// `hmacdrbg_kdf.c:258-262`.
///
/// # Safety
/// The dispatch contract.
unsafe extern "C" fn hmac_drbg_kdf_settable_ctx_params(
    _ctx: *mut c_void,
    _p_ctx: *mut c_void,
) -> *const OsslParam {
    HMACDRBG_KDF_SETTABLE_CTX_PARAMS.as_ptr()
}

/// `static const OSSL_PARAM *hmac_drbg_kdf_gettable_ctx_params(void *vctx, void *p_ctx)` —
/// `hmacdrbg_kdf.c:181-185`.
///
/// # Safety
/// The dispatch contract.
unsafe extern "C" fn hmac_drbg_kdf_gettable_ctx_params(
    _ctx: *mut c_void,
    _p_ctx: *mut c_void,
) -> *const OsslParam {
    HMACDRBG_KDF_GETTABLE_CTX_PARAMS.as_ptr()
}

/// `const OSSL_DISPATCH ossl_kdf_hmac_drbg_functions[]` — `hmacdrbg_kdf.c:264-279`. The FREECTX
/// slot precedes DUPCTX here, which is the authority's own order in this unit.
pub(crate) static HMACDRBG_KDF_FUNCTIONS: [OsslDispatch; 10] = [
    OsslDispatch {
        function_id: OSSL_FUNC_KDF_NEWCTX,
        function: hmac_drbg_kdf_new as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KDF_FREECTX,
        function: hmac_drbg_kdf_free as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KDF_DUPCTX,
        function: hmac_drbg_kdf_dup as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KDF_RESET,
        function: hmac_drbg_kdf_reset as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KDF_DERIVE,
        function: hmac_drbg_kdf_ctx_derive as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KDF_SETTABLE_CTX_PARAMS,
        function: hmac_drbg_kdf_settable_ctx_params as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KDF_SET_CTX_PARAMS,
        function: hmac_drbg_kdf_set_ctx_params as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KDF_GETTABLE_CTX_PARAMS,
        function: hmac_drbg_kdf_gettable_ctx_params as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KDF_GET_CTX_PARAMS,
        function: hmac_drbg_kdf_get_ctx_params as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_DISPATCH_END,
        function: ptr::null_mut(),
    },
];

// =============================================================================================
// `providers/implementations/kdfs/argon2.c` — ARGON2D, ARGON2I and ARGON2ID (RFC 9106)
// =============================================================================================
//
// The unit's third and last `OSSL_OP_KDF` group, and the only one in this module whose derivation
// is **memory-hard**: `fill_memory_blocks` builds a `m_cost`-block matrix with the BlaMka
// permutation and folds it into one `blake2b_long` output. It is also the only unit here whose
// threaded path is compiled on this profile: `configuration.h` defines `OPENSSL_THREADS` and
// neither `OPENSSL_NO_DEFAULT_THREAD_POOL` nor `OPENSSL_NO_THREAD_POOL`, so `ARGON2_NO_THREADS` is
// **not** defined and `fill_mem_blocks_mt` is live beside `fill_mem_blocks_st`.
//
// ## The two things a transcription can lose here
//
// **The arithmetic wraps.** `a + b + 2 * mul_lower(a, b)` overflows `uint64_t` constantly, and this
// crate builds with `overflow-checks = true` even in release, so every one of those additions is a
// `wrapping_add` -- a panic here would be a divergence from an answer the authority does give, not
// a defect report. `index_alpha` is the same story in `u32`: `index - 1` at `index == 0` is the
// authority's own `(uint32_t)-1` and is written as `wrapping_sub(1)`.
//
// **`kdf_argon2_get_ctx_params` answers `-2`.** Not 1: the unit's last statement is `return -2;`
// (`argon2.c:1734`), which is neither the dispatch interface's success value nor a documented
// refusal. It is reproduced as written, and the probe observes whatever `EVP_KDF_CTX_get_params`
// makes of it on both sides rather than this file asserting what that is.
//
// ## What is deliberately not carried
//
// Five of the unit's bound macros have **no reference in its code**: `ARGON2_MAX_OUT_LENGTH`,
// `ARGON2_MAX_MEMORY`, `ARGON2_MAX_TIME`, `ARGON2_MIN_PWD_LENGTH` and `ARGON2_MIN_AD_LENGTH` are
// named in the authority's comments as checks it skips ("`ARGON2_MAX_MEMORY == max m_cost value, so
// skip check`"), and a Rust `const` with no reader is a `dead_code` finding rather than a
// transcription. The bounds that *are* referenced are below with their coordinates. The three
// values that read as unused but are not are the ones a setter compares against: a bound whose
// comparison can never fire is still a comparison the authority makes.

/// `BLAKE2B_OUTBYTES` — `prov/blake2.h:26`, the width `blake2b_long`'s two buffers take.
const BLAKE2B_OUTBYTES: usize = 64;

/// `ARGON2_MIN_LANES` — `argon2.c:51`.
const ARGON2_MIN_LANES: u32 = 1;
/// `ARGON2_MAX_LANES` — `argon2.c:52`.
const ARGON2_MAX_LANES: u32 = 0xFF_FFFF;
/// `ARGON2_MIN_THREADS` — `argon2.c:53`.
const ARGON2_MIN_THREADS: u32 = 1;
/// `ARGON2_MAX_THREADS` — `argon2.c:54`.
const ARGON2_MAX_THREADS: u32 = 0xFF_FFFF;
/// `ARGON2_SYNC_POINTS` — `argon2.c:55`.
const ARGON2_SYNC_POINTS: u32 = 4;
/// `ARGON2_MIN_OUT_LENGTH` — `argon2.c:56`.
const ARGON2_MIN_OUT_LENGTH: u32 = 4;
/// `ARGON2_MIN_MEMORY` — `argon2.c:58`, `(2 * ARGON2_SYNC_POINTS)`.
const ARGON2_MIN_MEMORY: u32 = 2 * ARGON2_SYNC_POINTS;
/// `ARGON2_MIN_TIME` — `argon2.c:61`.
const ARGON2_MIN_TIME: u32 = 1;
/// `ARGON2_MAX_PWD_LENGTH` — `argon2.c:64`. The bound `set_pwd` checks.
const ARGON2_MAX_PWD_LENGTH: u32 = 0xFFFF_FFFF;
/// `ARGON2_MAX_SALT_LENGTH` — `argon2.c:68`.
const ARGON2_MAX_SALT_LENGTH: u32 = 0xFFFF_FFFF;
/// `ARGON2_MIN_SALT_LENGTH` — `argon2.c:67`.
const ARGON2_MIN_SALT_LENGTH: u32 = 8;
/// `ARGON2_MAX_SECRET` — `argon2.c:70`.
const ARGON2_MAX_SECRET: u32 = 0xFFFF_FFFF;
/// `ARGON2_MAX_AD_LENGTH` — `argon2.c:66`.
const ARGON2_MAX_AD_LENGTH: u32 = 0xFFFF_FFFF;
/// `ARGON2_BLOCK_SIZE` — `argon2.c:71`.
const ARGON2_BLOCK_SIZE: usize = 1024;
/// `ARGON2_QWORDS_IN_BLOCK` — `argon2.c:72`, `(ARGON2_BLOCK_SIZE / 8)`.
const ARGON2_QWORDS_IN_BLOCK: usize = ARGON2_BLOCK_SIZE / 8;
/// `ARGON2_ADDRESSES_IN_BLOCK` — `argon2.c:76`.
const ARGON2_ADDRESSES_IN_BLOCK: u32 = 128;
/// `ARGON2_PREHASH_DIGEST_LENGTH` — `argon2.c:77`.
const ARGON2_PREHASH_DIGEST_LENGTH: usize = 64;
/// `ARGON2_PREHASH_SEED_LENGTH` — `argon2.c:78-79`, `DIGEST_LENGTH + 2 * sizeof(uint32_t)`.
const ARGON2_PREHASH_SEED_LENGTH: usize = ARGON2_PREHASH_DIGEST_LENGTH + 2 * 4;
/// `ARGON2_DEFAULT_OUTLEN` — `argon2.c:81`.
const ARGON2_DEFAULT_OUTLEN: u32 = 64;
/// `ARGON2_DEFAULT_T_COST` — `argon2.c:82`.
const ARGON2_DEFAULT_T_COST: u32 = 3;
/// `ARGON2_DEFAULT_M_COST` — `argon2.c:83`, which is `ARGON2_MIN_MEMORY`.
const ARGON2_DEFAULT_M_COST: u32 = ARGON2_MIN_MEMORY;
/// `ARGON2_DEFAULT_LANES` — `argon2.c:84`.
const ARGON2_DEFAULT_LANES: u32 = 1;
/// `ARGON2_DEFAULT_THREADS` — `argon2.c:85`.
const ARGON2_DEFAULT_THREADS: u32 = 1;
/// `ARGON2_VERSION_10` — `argon2.c:142`.
const ARGON2_VERSION_10: u32 = 0x10;
/// `ARGON2_VERSION_13` — `argon2.c:143`.
const ARGON2_VERSION_13: u32 = 0x13;
/// `ARGON2_VERSION_NUMBER` — `argon2.c:144`, which is `ARGON2_VERSION_13`.
const ARGON2_VERSION_NUMBER: u32 = ARGON2_VERSION_13;
/// `ARGON2_D` — `argon2.c:148`.
const ARGON2_D: u32 = 0;
/// `ARGON2_I` — `argon2.c:149`. The data-independent variant.
const ARGON2_I: u32 = 1;
/// `ARGON2_ID` — `argon2.c:150`. Data-independent for the first half of pass 0 only.
const ARGON2_ID: u32 = 2;
/// `OSSL_MAC_NAME_BLAKE2BMAC` — `core_names.h`, the MAC `kdf_argon2_derive` fetches.
const OSSL_MAC_NAME_BLAKE2BMAC: *const c_char = c"blake2bmac".as_ptr();
/// `OSSL_MD_NAME_BLAKE2B512` — `core_names.h`, the digest it fetches.
const OSSL_MD_NAME_BLAKE2B512: *const c_char = c"blake2b512".as_ptr();
/// `OSSL_DIGEST_PARAM_SIZE` — `core_names.h:229` (`"size"`). `blake2b_md` and `blake2b_long` set
/// it on the fetched digest to choose the output width; it is `src/evp/digest.rs`'s own private
/// constant too, and the two are the same byte string.
const OSSL_DIGEST_PARAM_SIZE: *const c_char = c"size".as_ptr();

/// `typedef struct { uint64_t v[ARGON2_QWORDS_IN_BLOCK]; } BLOCK` — `argon2.c:137-139`.
#[repr(C)]
pub(crate) struct Block {
    /// `uint64_t v[ARGON2_QWORDS_IN_BLOCK]`.
    pub v: [u64; ARGON2_QWORDS_IN_BLOCK],
}

/// An all-zero `Block`, which is what every stack-local one starts as in the authority (either by
/// `memset` or because the authority zeroes it before use).
impl Block {
    /// A zeroed block.
    fn zero() -> Block {
        Block {
            v: [0u64; ARGON2_QWORDS_IN_BLOCK],
        }
    }
}

/// `typedef struct { uint32_t pass; uint32_t lane; uint8_t slice; uint32_t index; } ARGON2_POS` —
/// `argon2.c:153-158`.
#[repr(C)]
struct Argon2Pos {
    /// `uint32_t pass`.
    pass: u32,
    /// `uint32_t lane`.
    lane: u32,
    /// `uint8_t slice`.
    slice: u8,
    /// `uint32_t index` — written by `fill_mem_blocks_mt` and never read.
    index: u32,
}

/// `typedef struct { ARGON2_POS pos; KDF_ARGON2 *ctx; } ARGON2_THREAD_DATA` — `argon2.c:189-192`.
#[repr(C)]
struct Argon2ThreadData {
    /// `ARGON2_POS pos`.
    pos: Argon2Pos,
    /// `KDF_ARGON2 *ctx`.
    ctx: *mut KdfArgon2,
}

/// `struct KDF_ARGON2` — `argon2.c:160-187`. Every field is the authority's; the FIPS indicator of
/// the other units in this module does not appear here because this unit has no FIPS arm.
#[repr(C)]
pub(crate) struct KdfArgon2 {
    /// `void *provctx`.
    pub provctx: *mut c_void,
    /// `uint32_t outlen`.
    pub outlen: u32,
    /// `uint8_t *pwd` / `uint32_t pwdlen`.
    pub pwd: *mut u8,
    pub pwdlen: u32,
    /// `uint8_t *salt` / `uint32_t saltlen`.
    pub salt: *mut u8,
    pub saltlen: u32,
    /// `uint8_t *secret` / `uint32_t secretlen`.
    pub secret: *mut u8,
    pub secretlen: u32,
    /// `uint8_t *ad` / `uint32_t adlen`.
    pub ad: *mut u8,
    pub adlen: u32,
    /// `uint32_t t_cost`.
    pub t_cost: u32,
    /// `uint32_t m_cost`.
    pub m_cost: u32,
    /// `uint32_t lanes`.
    pub lanes: u32,
    /// `uint32_t threads`.
    pub threads: u32,
    /// `uint32_t version`.
    pub version: u32,
    /// `uint32_t early_clean`.
    pub early_clean: u32,
    /// `ARGON2_TYPE type`.
    pub type_: u32,
    /// `BLOCK *memory`.
    pub memory: *mut Block,
    /// `uint32_t passes`.
    pub passes: u32,
    /// `uint32_t memory_blocks`.
    pub memory_blocks: u32,
    /// `uint32_t segment_length`.
    pub segment_length: u32,
    /// `uint32_t lane_length`.
    pub lane_length: u32,
    /// `OSSL_LIB_CTX *libctx`.
    pub libctx: *mut c_void,
    /// `EVP_MD *md` — the fetched `blake2b512`.
    pub md: *mut crate::evp::digest::EvpMd,
    /// `EVP_MAC *mac` — the fetched `blake2bmac`.
    pub mac: *mut crate::evp::mac::EvpMac,
    /// `char *propq`.
    pub propq: *mut c_char,
}

/// `struct argon2_set_ctx_params_st` — generated `argon2.c:1415-1430`. The fields are the
/// generated struct's, in its order; the decoder's key-and-site list below uses each field's index
/// here as its id, which is the reading `scrypt.c`'s decoder already uses.
#[derive(Default)]
struct Argon2SetCtxParams {
    ad: *const OsslParam,
    eclean: *const OsslParam,
    iter: *const OsslParam,
    lanes: *const OsslParam,
    mem: *const OsslParam,
    propq: *const OsslParam,
    pw: *const OsslParam,
    salt: *const OsslParam,
    secret: *const OsslParam,
    size: *const OsslParam,
    thrds: *const OsslParam,
    vers: *const OsslParam,
}

/// The `argon2_set_ctx_params_decoder` keys, each with its (field id, raise site). The generated
/// `strcmp`-trie at `argon2.c:1441-1585` gives every key its own field and none is a list, so the
/// second occurrence of any one raises `PROV_R_REPEATED_PARAMETER` at its own coordinate. The
/// field ids are `Argon2SetCtxParams`'s declaration order, which is the generated struct's.
const ARGON2_SET_DECODER_KEYS: [(&err_sites::ErrSite, *const c_char, u32); 12] = [
    (&err_sites::PROV_ARGON2_1448, OSSL_KDF_PARAM_ARGON2_AD, 0),
    (&err_sites::PROV_ARGON2_1459, OSSL_KDF_PARAM_EARLY_CLEAN, 1),
    (&err_sites::PROV_ARGON2_1470, OSSL_KDF_PARAM_ITER, 2),
    (&err_sites::PROV_ARGON2_1481, OSSL_KDF_PARAM_ARGON2_LANES, 3),
    (
        &err_sites::PROV_ARGON2_1492,
        OSSL_KDF_PARAM_ARGON2_MEMCOST,
        4,
    ),
    (&err_sites::PROV_ARGON2_1518, OSSL_KDF_PARAM_PROPERTIES, 5),
    (&err_sites::PROV_ARGON2_1507, OSSL_KDF_PARAM_PASSWORD, 6),
    (&err_sites::PROV_ARGON2_1534, OSSL_KDF_PARAM_SALT, 7),
    (&err_sites::PROV_ARGON2_1545, OSSL_KDF_PARAM_SECRET, 8),
    (&err_sites::PROV_ARGON2_1556, OSSL_KDF_PARAM_SIZE, 9),
    (&err_sites::PROV_ARGON2_1568, OSSL_KDF_PARAM_THREADS, 10),
    (
        &err_sites::PROV_ARGON2_1579,
        OSSL_KDF_PARAM_ARGON2_VERSION,
        11,
    ),
];

/// The `argon2_get_ctx_params_decoder` key, `argon2.c:1700-1718`.
const ARGON2_GET_DECODER_KEYS: [(&err_sites::ErrSite, *const c_char, u32); 1] =
    [(&err_sites::PROV_ARGON2_1711, OSSL_KDF_PARAM_SIZE, 0)];

/// `static const OSSL_PARAM argon2_set_ctx_params_list[]` — generated `argon2.c:1398-1412`.
#[rustfmt::skip]
static ARGON2_SETTABLE_CTX_PARAMS: [OsslParam; 13] = [
    param_octet_string(OSSL_KDF_PARAM_PASSWORD),
    param_octet_string(OSSL_KDF_PARAM_SALT),
    param_octet_string(OSSL_KDF_PARAM_SECRET),
    param_octet_string(OSSL_KDF_PARAM_ARGON2_AD),
    param_uint32(OSSL_KDF_PARAM_SIZE),
    param_uint32(OSSL_KDF_PARAM_ITER),
    param_uint32(OSSL_KDF_PARAM_THREADS),
    param_uint32(OSSL_KDF_PARAM_ARGON2_LANES),
    param_uint32(OSSL_KDF_PARAM_ARGON2_MEMCOST),
    param_uint32(OSSL_KDF_PARAM_EARLY_CLEAN),
    param_uint32(OSSL_KDF_PARAM_ARGON2_VERSION),
    param_utf8_string(OSSL_KDF_PARAM_PROPERTIES),
    END,
];

/// `static const OSSL_PARAM argon2_get_ctx_params_list[]` — generated `argon2.c:1687-1690`.
static ARGON2_GETTABLE_CTX_PARAMS: [OsslParam; 2] = [param_size_t(OSSL_KDF_PARAM_SIZE), END];

/// `G(a, b, c, d)` — `argon2.c:89-101`, the BlaMka quarter-round over four elements of a block.
///
/// `a = a + b + 2 * mul_lower(a, b)` appears three times and each addition can overflow `u64`, so
/// every one of them wraps. The four rotations land in `{16, 24, 32, 63}`, which is where
/// [`argon2_rotr64`] is exact.
#[inline]
fn argon2_g(v: &mut [u64; ARGON2_QWORDS_IN_BLOCK], a: usize, b: usize, c: usize, d: usize) {
    let mut va = v[a];
    let mut vb = v[b];
    let mut vc = v[c];
    let mut vd = v[d];

    va = va
        .wrapping_add(vb)
        .wrapping_add(argon2_mul_lower(va, vb).wrapping_mul(2));
    vd = argon2_rotr64(vd ^ va, 32);
    vc = vc
        .wrapping_add(vd)
        .wrapping_add(argon2_mul_lower(vc, vd).wrapping_mul(2));
    vb = argon2_rotr64(vb ^ vc, 24);
    va = va
        .wrapping_add(vb)
        .wrapping_add(argon2_mul_lower(va, vb).wrapping_mul(2));
    vd = argon2_rotr64(vd ^ va, 16);
    vc = vc
        .wrapping_add(vd)
        .wrapping_add(argon2_mul_lower(vc, vd).wrapping_mul(2));
    vb = argon2_rotr64(vb ^ vc, 63);

    v[a] = va;
    v[b] = vb;
    v[c] = vc;
    v[d] = vd;
}

/// `PERMUTATION_P(v0, ..., v15)` — `argon2.c:102-114`, the eight `G` calls over sixteen indexed
/// elements. The two macros below are the two addressing orders that feed it.
#[inline]
fn argon2_p(v: &mut [u64; ARGON2_QWORDS_IN_BLOCK], i: [usize; 16]) {
    argon2_g(v, i[0], i[4], i[8], i[12]);
    argon2_g(v, i[1], i[5], i[9], i[13]);
    argon2_g(v, i[2], i[6], i[10], i[14]);
    argon2_g(v, i[3], i[7], i[11], i[15]);
    argon2_g(v, i[0], i[5], i[10], i[15]);
    argon2_g(v, i[1], i[6], i[11], i[12]);
    argon2_g(v, i[2], i[7], i[8], i[13]);
    argon2_g(v, i[3], i[4], i[9], i[14]);
}

/// `PERMUTATION_P_COLUMN(x, i)` — `argon2.c:116-124`: sixteen **consecutive** words from `16 * i`.
#[inline]
fn argon2_p_column(v: &mut [u64; ARGON2_QWORDS_IN_BLOCK], i: usize) {
    let base = 16 * i;
    argon2_p(
        v,
        [
            base,
            base + 1,
            base + 2,
            base + 3,
            base + 4,
            base + 5,
            base + 6,
            base + 7,
            base + 8,
            base + 9,
            base + 10,
            base + 11,
            base + 12,
            base + 13,
            base + 14,
            base + 15,
        ],
    );
}

/// `PERMUTATION_P_ROW(x, i)` — `argon2.c:126-135`: the strided sixteen from `2 * i`, the transpose
/// of the column order.
#[inline]
fn argon2_p_row(v: &mut [u64; ARGON2_QWORDS_IN_BLOCK], i: usize) {
    let base = 2 * i;
    argon2_p(
        v,
        [
            base,
            base + 1,
            base + 16,
            base + 17,
            base + 32,
            base + 33,
            base + 48,
            base + 49,
            base + 64,
            base + 65,
            base + 80,
            base + 81,
            base + 96,
            base + 97,
            base + 112,
            base + 113,
        ],
    );
}

/// `static ossl_inline uint64_t load64(const uint8_t *src)` — `argon2.c:274-284`, little-endian by
/// construction.
///
/// # Safety
/// `src` is readable for eight bytes.
unsafe fn argon2_load64(src: *const u8) -> u64 {
    let mut w: u64 = 0;
    // SAFETY: `src` is readable for eight bytes per the contract, so `i` is in bounds.
    unsafe {
        for i in 0..8usize {
            w |= (*src.add(i) as u64) << (8 * i);
        }
    }
    w
}

/// `static ossl_inline void store32(uint8_t *dst, uint32_t w)` — `argon2.c:286-292`.
///
/// # Safety
/// `dst` is writable for four bytes.
unsafe fn argon2_store32(dst: *mut u8, w: u32) {
    // SAFETY: `dst` is writable for four bytes per the contract.
    unsafe {
        for i in 0..4usize {
            *dst.add(i) = (w >> (8 * i)) as u8;
        }
    }
}

/// `static ossl_inline void store64(uint8_t *dst, uint64_t w)` — `argon2.c:294-304`.
///
/// # Safety
/// `dst` is writable for eight bytes.
unsafe fn argon2_store64(dst: *mut u8, w: u64) {
    // SAFETY: `dst` is writable for eight bytes per the contract.
    unsafe {
        for i in 0..8usize {
            *dst.add(i) = (w >> (8 * i)) as u8;
        }
    }
}

/// `static ossl_inline uint64_t rotr64(const uint64_t w, const unsigned int c)` —
/// `argon2.c:306-309`.
///
/// The authority's `(w >> c) | (w << (64 - c))` for `0 < c < 64`, which is [`u64::rotate_right`];
/// `c == 0` is undefined in the authority's spelling and `rotate_right` is defined there, and no
/// caller in the unit passes it.
#[inline]
fn argon2_rotr64(w: u64, c: u32) -> u64 {
    w.rotate_right(c)
}

/// `static ossl_inline uint64_t mul_lower(uint64_t x, uint64_t y)` — `argon2.c:311-315`, the low
/// halves multiplied. `m = 0xFFFFFFFF` and the product of two masked `u64`s cannot overflow.
#[inline]
fn argon2_mul_lower(x: u64, y: u64) -> u64 {
    const M: u64 = 0xFFFF_FFFF;
    (x & M) * (y & M)
}

/// `static void init_block_value(BLOCK *b, uint8_t in)` — `argon2.c:317-320`.
///
/// # Safety
/// `b` is writable for a whole block.
unsafe fn init_block_value(b: *mut Block, in_: u8) {
    // SAFETY: `b` is writable for `ARGON2_BLOCK_SIZE` bytes per the contract.
    unsafe { ptr::write_bytes((*b).v.as_mut_ptr().cast::<u8>(), in_, ARGON2_BLOCK_SIZE) };
}

/// `static void copy_block(BLOCK *dst, const BLOCK *src)` — `argon2.c:322-325`.
///
/// # Safety
/// `dst` is writable and `src` readable, each for one block, and they do not overlap.
unsafe fn copy_block(dst: *mut Block, src: *const Block) {
    // SAFETY: both are one block per the contract, and the authority's `memcpy` states the
    // non-overlap.
    unsafe {
        ptr::copy_nonoverlapping(
            (*src).v.as_ptr(),
            (*dst).v.as_mut_ptr(),
            ARGON2_QWORDS_IN_BLOCK,
        )
    };
}

/// `static void xor_block(BLOCK *dst, const BLOCK *src)` — `argon2.c:327-333`.
///
/// # Safety
/// `dst` and `src` are live blocks; `dst` is writable.
unsafe fn xor_block(dst: *mut Block, src: *const Block) {
    // SAFETY: both are live blocks per the contract, and `zip` stops at `v`'s length in both.
    unsafe {
        for (d, s) in (*dst).v.iter_mut().zip((*src).v.iter()) {
            *d ^= *s;
        }
    }
}

/// `static void load_block(BLOCK *dst, const void *input)` — `argon2.c:335-341`.
///
/// # Safety
/// `dst` is writable for a block and `input` is readable for `ARGON2_BLOCK_SIZE` bytes.
unsafe fn load_block(dst: *mut Block, input: *const c_void) {
    // SAFETY: `input` is readable for a block per the contract, so `i * 8` stays inside it.
    unsafe {
        for (i, slot) in (*dst).v.iter_mut().enumerate() {
            *slot = argon2_load64(input.cast::<u8>().add(i * 8));
        }
    }
}

/// `static void store_block(void *output, const BLOCK *src)` — `argon2.c:343-349`.
///
/// # Safety
/// `output` is writable for a block; `src` is a live block.
unsafe fn store_block(output: *mut c_void, src: *const Block) {
    // SAFETY: `output` is writable for a block per the contract.
    unsafe {
        for (i, w) in (*src).v.iter().enumerate() {
            argon2_store64(output.cast::<u8>().add(i * 8), *w);
        }
    }
}

/// `static void fill_first_blocks(uint8_t *blockhash, const KDF_ARGON2 *ctx)` — `argon2.c:351-374`.
///
/// # Safety
/// `blockhash` is writable for `ARGON2_PREHASH_SEED_LENGTH` bytes; `ctx` is live with `memory`
/// allocated for `memory_blocks` blocks and `md`/`mac` fetched.
unsafe fn fill_first_blocks(blockhash: *mut u8, ctx: *const KdfArgon2) {
    let mut blockhash_bytes = [0u8; ARGON2_BLOCK_SIZE];

    // SAFETY: every pointer below is the caller's, per the contract.
    unsafe {
        for l in 0..(*ctx).lanes {
            argon2_store32(blockhash.add(ARGON2_PREHASH_DIGEST_LENGTH), 0);
            argon2_store32(blockhash.add(ARGON2_PREHASH_DIGEST_LENGTH + 4), l);
            blake2b_long(
                (*ctx).md,
                (*ctx).mac,
                blockhash_bytes.as_mut_ptr(),
                ARGON2_BLOCK_SIZE,
                blockhash.cast(),
                ARGON2_PREHASH_SEED_LENGTH,
            );
            load_block(
                (*ctx).memory.add((l * (*ctx).lane_length) as usize),
                blockhash_bytes.as_ptr().cast(),
            );
            argon2_store32(blockhash.add(ARGON2_PREHASH_DIGEST_LENGTH), 1);
            blake2b_long(
                (*ctx).md,
                (*ctx).mac,
                blockhash_bytes.as_mut_ptr(),
                ARGON2_BLOCK_SIZE,
                blockhash.cast(),
                ARGON2_PREHASH_SEED_LENGTH,
            );
            load_block(
                (*ctx).memory.add((l * (*ctx).lane_length + 1) as usize),
                blockhash_bytes.as_ptr().cast(),
            );
        }
        cleanse(blockhash_bytes.as_mut_ptr(), ARGON2_BLOCK_SIZE);
    }
}

/// `static void fill_block(const BLOCK *prev, const BLOCK *ref, BLOCK *next, int with_xor)` —
/// `argon2.c:376-397`.
///
/// # Safety
/// The three pointers are live blocks, with `next` writable.
unsafe fn fill_block(prev: *const Block, ref_: *const Block, next: *mut Block, with_xor: c_int) {
    let mut block_r = Block::zero();
    let mut tmp = Block::zero();

    // SAFETY: the three pointers are live blocks per the contract; the two locals are this
    // frame's.
    unsafe {
        copy_block(&mut block_r, ref_);
        xor_block(&mut block_r, prev);
        copy_block(&mut tmp, &block_r);

        if with_xor != 0 {
            xor_block(&mut tmp, next.cast_const());
        }

        for i in 0..8usize {
            argon2_p_column(&mut block_r.v, i);
        }
        for i in 0..8usize {
            argon2_p_row(&mut block_r.v, i);
        }

        copy_block(next, &tmp);
        xor_block(next, &block_r);
    }
}

/// `static void next_addresses(BLOCK *address_block, BLOCK *input_block, const BLOCK *zero_block)` —
/// `argon2.c:399-405`.
///
/// # Safety
/// The three pointers are live blocks, with `address_block` and `input_block` writable.
unsafe fn next_addresses(
    address_block: *mut Block,
    input_block: *mut Block,
    zero_block: *const Block,
) {
    // SAFETY: the three pointers are live blocks per the contract.
    unsafe {
        (*input_block).v[6] = (*input_block).v[6].wrapping_add(1);
        fill_block(zero_block, input_block, address_block, 0);
        fill_block(zero_block, address_block, address_block, 0);
    }
}

/// `static int data_indep_addressing(const KDF_ARGON2 *ctx, uint32_t pass, uint8_t slice)` —
/// `argon2.c:407-419`. `ARGON2_I` is always data-independent; `ARGON2_ID` is for the first half of
/// pass 0's slices only; `ARGON2_D` never is.
///
/// # Safety
/// `ctx` is a live context.
unsafe fn data_indep_addressing(ctx: *const KdfArgon2, pass: u32, slice: u8) -> c_int {
    // SAFETY: `ctx` is live per the contract.
    match unsafe { (*ctx).type_ } {
        ARGON2_I => 1,
        ARGON2_ID => c_int::from(pass == 0 && u32::from(slice) < ARGON2_SYNC_POINTS / 2),
        _ => 0,
    }
}

/// `static uint32_t index_alpha(const KDF_ARGON2 *ctx, uint32_t pass, uint8_t slice, uint32_t
/// index, uint32_t pseudo_rand, int same_lane)` — `argon2.c:432-466`.
///
/// The reference-area computation, and the one place where the index arithmetic is deliberately
/// modular: `(index == 0) ? (-1) : 0` is `0xFFFFFFFF` for a `uint32_t`, and `ref_area_sz - 1 - ...`
/// at `argon2.c:462` can borrow below zero. Both wrap.
///
/// # Safety
/// `ctx` is a live context with `segment_length` and `lane_length` set.
unsafe fn index_alpha(
    ctx: *const KdfArgon2,
    pass: u32,
    slice: u8,
    index: u32,
    pseudo_rand: u32,
    same_lane: c_int,
) -> u32 {
    // SAFETY: `ctx` is live per the contract.
    unsafe {
        let (ref_area_sz, start_pos): (u32, u32) = if pass == 0 {
            let sz = if slice == 0 {
                index.wrapping_sub(1)
            } else if same_lane != 0 {
                u32::from(slice)
                    .wrapping_mul((*ctx).segment_length)
                    .wrapping_add(index)
                    .wrapping_sub(1)
            } else {
                u32::from(slice)
                    .wrapping_mul((*ctx).segment_length)
                    .wrapping_add(if index == 0 { u32::MAX } else { 0 })
            };
            (sz, 0)
        } else {
            let sz = if same_lane != 0 {
                (*ctx)
                    .lane_length
                    .wrapping_sub((*ctx).segment_length)
                    .wrapping_add(index)
                    .wrapping_sub(1)
            } else {
                (*ctx)
                    .lane_length
                    .wrapping_sub((*ctx).segment_length)
                    .wrapping_add(if index == 0 { u32::MAX } else { 0 })
            };
            let start = if slice != (ARGON2_SYNC_POINTS - 1) as u8 {
                (u32::from(slice) + 1).wrapping_mul((*ctx).segment_length)
            } else {
                0
            };
            (sz, start)
        };

        let mut rel_pos: u64 = u64::from(pseudo_rand);
        rel_pos = rel_pos.wrapping_mul(rel_pos) >> 32;
        rel_pos = u64::from(ref_area_sz)
            .wrapping_sub(1)
            .wrapping_sub((u64::from(ref_area_sz).wrapping_mul(rel_pos)) >> 32);
        let abs_pos = (u64::from(start_pos).wrapping_add(rel_pos)) % u64::from((*ctx).lane_length);

        abs_pos as u32
    }
}

/// `static void fill_segment(const KDF_ARGON2 *ctx, uint32_t pass, uint32_t lane, uint8_t slice)`
/// — `argon2.c:468-548`.
///
/// The block-at-a-time walk over one (pass, lane, slice). The two cursors `curr_offset` and
/// `prev_offset` are advanced by the loop's own `++curr_offset, ++prev_offset` and reset once per
/// lane boundary, so they are a `while` loop's manual step rather than a range's.
///
/// # Safety
/// `ctx` is live with `memory` allocated for `memory_blocks` blocks, `lane_length`,
/// `segment_length` and `passes` set, and for the data-independent variants `md`/`mac` fetched.
unsafe fn fill_segment(ctx: *const KdfArgon2, pass: u32, lane: u32, slice: u8) {
    let mut address_block = Block::zero();
    let mut input_block = Block::zero();
    let mut zero_block = Block::zero();

    // `memset(&input_block, 0, sizeof(BLOCK))` — `argon2.c:479`, before the NULL test.
    // SAFETY: `input_block` is this frame's own live block.
    unsafe {
        ptr::write_bytes(
            input_block.v.as_mut_ptr().cast::<u8>(),
            0,
            ARGON2_BLOCK_SIZE,
        )
    };

    if ctx.is_null() {
        return;
    }

    // SAFETY: `ctx` is non-NULL and live per the contract.
    unsafe {
        if data_indep_addressing(ctx, pass, slice) != 0 {
            init_block_value(&mut zero_block, 0);
            init_block_value(&mut input_block, 0);

            input_block.v[0] = u64::from(pass);
            input_block.v[1] = u64::from(lane);
            input_block.v[2] = u64::from(slice);
            input_block.v[3] = u64::from((*ctx).memory_blocks);
            input_block.v[4] = u64::from((*ctx).passes);
            input_block.v[5] = u64::from((*ctx).type_);
        }

        let mut start_idx: u32 = 0;

        /* We've generated the first two blocks. Generate the 1st block of addrs. */
        if pass == 0 && slice == 0 {
            start_idx = 2;
            if data_indep_addressing(ctx, pass, slice) != 0 {
                next_addresses(&mut address_block, &mut input_block, &zero_block);
            }
        }

        let mut curr_offset: u32 = lane
            .wrapping_mul((*ctx).lane_length)
            .wrapping_add(u32::from(slice).wrapping_mul((*ctx).segment_length))
            .wrapping_add(start_idx);

        let mut prev_offset: u32 = if curr_offset.is_multiple_of((*ctx).lane_length) {
            curr_offset.wrapping_add((*ctx).lane_length).wrapping_sub(1)
        } else {
            curr_offset.wrapping_sub(1)
        };

        let mut j = start_idx;
        while j < (*ctx).segment_length {
            if curr_offset % (*ctx).lane_length == 1 {
                prev_offset = curr_offset.wrapping_sub(1);
            }

            /* Taking pseudo-random value from the previous block. */
            let rnd: u64 = if data_indep_addressing(ctx, pass, slice) != 0 {
                if j.is_multiple_of(ARGON2_ADDRESSES_IN_BLOCK) {
                    next_addresses(&mut address_block, &mut input_block, &zero_block);
                }
                address_block.v[(j % ARGON2_ADDRESSES_IN_BLOCK) as usize]
            } else {
                (*(*ctx).memory.add(prev_offset as usize)).v[0]
            };

            /* Computing the lane of the reference block */
            let mut ref_lane = (rnd >> 32) % u64::from((*ctx).lanes);
            /* Can not reference other lanes yet */
            if pass == 0 && slice == 0 {
                ref_lane = u64::from(lane);
            }

            /* Computing the number of possible reference block within the lane. */
            let ref_index = index_alpha(
                ctx,
                pass,
                slice,
                j,
                (rnd & 0xFFFF_FFFF) as u32,
                c_int::from(ref_lane == u64::from(lane)),
            );

            /* Creating a new block */
            let ref_block = (*ctx).memory.add(
                (u64::from((*ctx).lane_length).wrapping_mul(ref_lane) + u64::from(ref_index))
                    as usize,
            );
            let curr_block = (*ctx).memory.add(curr_offset as usize);

            if ARGON2_VERSION_10 == (*ctx).version {
                /* Version 1.2.1 and earlier: overwrite, not XOR */
                fill_block(
                    (*ctx).memory.add(prev_offset as usize),
                    ref_block,
                    curr_block,
                    0,
                );
                j = j.wrapping_add(1);
                curr_offset = curr_offset.wrapping_add(1);
                prev_offset = prev_offset.wrapping_add(1);
                continue;
            }

            fill_block(
                (*ctx).memory.add(prev_offset as usize),
                ref_block,
                curr_block,
                if pass == 0 { 0 } else { 1 },
            );

            j = j.wrapping_add(1);
            curr_offset = curr_offset.wrapping_add(1);
            prev_offset = prev_offset.wrapping_add(1);
        }
    }
}

/// `static uint32_t fill_segment_thr(void *thread_data)` — `argon2.c:552-561`. The worker the pool
/// runs; the return value is unused by the joiner, as in the authority.
///
/// # Safety
/// `thread_data` is a live `Argon2ThreadData` whose `ctx` outlives the thread.
unsafe extern "C" fn fill_segment_thr(thread_data: *mut c_void) -> CryptoThreadRetval {
    let my_data = thread_data.cast::<Argon2ThreadData>();

    // SAFETY: `my_data` is live per the contract.
    unsafe {
        fill_segment(
            (*my_data).ctx,
            (*my_data).pos.pass,
            (*my_data).pos.lane,
            (*my_data).pos.slice,
        );
    }
    0
}

/// `static int fill_mem_blocks_mt(KDF_ARGON2 *ctx)` — `argon2.c:563-628`.
///
/// The threaded fill, and the reason this unit needed D397's pool. `threads` workers are kept in
/// flight and the handles are joined in the authority's order: **the slot that is about to be
/// reused is joined first** (`l >= ctx->threads`), and the tail is drained at the end of every sync
/// point (`l = lanes - threads .. lanes`). A spawn that fails joins whatever is still live before
/// answering 0 -- and it joins from index 0, including handles the recycle step has already joined,
/// which is why the authority's own `goto fail` is reachable from that loop and why this
/// transcription's `break` lands on the same answer.
///
/// # Safety
/// `ctx` is live with `libctx` set, `fill_segment`'s preconditions met, and `lanes`/`threads`
/// such that `threads <= lanes`.
unsafe fn fill_mem_blocks_mt(ctx: *mut KdfArgon2) -> c_int {
    // SAFETY: `ctx` is live per the contract; both allocations are this call's own.
    unsafe {
        let lanes = (*ctx).lanes;
        let threads = (*ctx).threads;

        let t = CRYPTO_calloc(
            lanes as usize,
            core::mem::size_of::<*mut c_void>(),
            FILE_ARGON2,
            LINE,
        )
        .cast::<*mut c_void>();
        let t_data = CRYPTO_calloc(
            lanes as usize,
            core::mem::size_of::<Argon2ThreadData>(),
            FILE_ARGON2,
            LINE,
        )
        .cast::<Argon2ThreadData>();

        if t.is_null() || t_data.is_null() {
            if !t_data.is_null() {
                CRYPTO_free(t_data.cast(), FILE_ARGON2, LINE);
            }
            if !t.is_null() {
                CRYPTO_free(t.cast(), FILE_ARGON2, LINE);
            }
            return 0;
        }

        let mut ok = true;
        'fill: for r in 0..(*ctx).passes {
            for s in 0..ARGON2_SYNC_POINTS {
                let mut l: u32 = 0;
                while l < lanes {
                    if l >= threads {
                        if ossl_crypto_thread_join(*t.add((l - threads) as usize), ptr::null_mut())
                            == 0
                        {
                            ok = false;
                            break 'fill;
                        }
                        if ossl_crypto_thread_clean(*t.add((l - threads) as usize)) == 0 {
                            ok = false;
                            break 'fill;
                        }
                        *t.add((l - threads) as usize) = ptr::null_mut();
                    }

                    let p = Argon2Pos {
                        pass: r,
                        lane: l,
                        slice: s as u8,
                        index: 0,
                    };

                    (*t_data.add(l as usize)).ctx = ctx;
                    // `memcpy(&(t_data[l].pos), &p, sizeof(ARGON2_POS))`.
                    ptr::copy_nonoverlapping(
                        ptr::addr_of!(p),
                        ptr::addr_of_mut!((*t_data.add(l as usize)).pos),
                        1,
                    );
                    *t.add(l as usize) = ossl_crypto_thread_start(
                        (*ctx).libctx,
                        Some(fill_segment_thr as CryptoThreadRoutine),
                        t_data.add(l as usize).cast::<c_void>(),
                    );
                    if (*t.add(l as usize)).is_null() {
                        for ll in 0..l {
                            if ossl_crypto_thread_join(*t.add(ll as usize), ptr::null_mut()) == 0 {
                                ok = false;
                                break 'fill;
                            }
                            if ossl_crypto_thread_clean(*t.add(ll as usize)) == 0 {
                                ok = false;
                                break 'fill;
                            }
                            *t.add(ll as usize) = ptr::null_mut();
                        }
                        ok = false;
                        break 'fill;
                    }
                    l += 1;
                }
                let mut l = lanes - threads;
                while l < lanes {
                    if ossl_crypto_thread_join(*t.add(l as usize), ptr::null_mut()) == 0 {
                        ok = false;
                        break 'fill;
                    }
                    if ossl_crypto_thread_clean(*t.add(l as usize)) == 0 {
                        ok = false;
                        break 'fill;
                    }
                    *t.add(l as usize) = ptr::null_mut();
                    l += 1;
                }
            }
        }

        CRYPTO_free(t_data.cast(), FILE_ARGON2, LINE);
        CRYPTO_free(t.cast(), FILE_ARGON2, LINE);

        c_int::from(ok)
    }
}

/// `static int fill_mem_blocks_st(KDF_ARGON2 *ctx)` — `argon2.c:632-641`.
///
/// # Safety
/// `ctx` is live with `fill_segment`'s preconditions met.
unsafe fn fill_mem_blocks_st(ctx: *mut KdfArgon2) -> c_int {
    // SAFETY: `ctx` is live per the contract.
    unsafe {
        for r in 0..(*ctx).passes {
            for s in 0..ARGON2_SYNC_POINTS {
                for l in 0..(*ctx).lanes {
                    fill_segment(ctx, r, l, s as u8);
                }
            }
        }
    }
    1
}

/// `static ossl_inline int fill_memory_blocks(KDF_ARGON2 *ctx)` — `argon2.c:643-650`.
///
/// # Safety
/// `ctx` is live with `fill_segment`'s preconditions met.
unsafe fn fill_memory_blocks(ctx: *mut KdfArgon2) -> c_int {
    // SAFETY: `ctx` is live per the contract.
    unsafe {
        if (*ctx).threads == 1 {
            fill_mem_blocks_st(ctx)
        } else {
            fill_mem_blocks_mt(ctx)
        }
    }
}

/// `static void initial_hash(uint8_t *blockhash, KDF_ARGON2 *ctx)` — `argon2.c:652-725`.
///
/// `H0`: the seven `uint32_t` arguments, then the password, salt, secret and associated data, each
/// preceded by its little-endian length. The password and secret are cleansed **in place** when
/// `early_clean` is set, which is why the authority's `ctx` is not `const` here.
///
/// # Safety
/// `ctx` is live with `md` fetched; `blockhash` is NULL or writable for
/// `ARGON2_PREHASH_DIGEST_LENGTH` bytes.
unsafe fn initial_hash(blockhash: *mut u8, ctx: *mut KdfArgon2) {
    let mut value = [0u8; 4];
    let mut args = [0u32; 7];

    // SAFETY: `ctx` is live per the contract, so its members are readable and the two cleanse
    // sites write only through its own pointers.
    unsafe {
        if ctx.is_null() || blockhash.is_null() {
            return;
        }

        args[0] = (*ctx).lanes;
        args[1] = (*ctx).outlen;
        args[2] = (*ctx).m_cost;
        args[3] = (*ctx).t_cost;
        args[4] = (*ctx).version;
        args[5] = (*ctx).type_;
        args[6] = (*ctx).pwdlen;

        let mdctx = EVP_MD_CTX_new();
        if mdctx.is_null() || EVP_DigestInit_ex(mdctx, (*ctx).md, ptr::null_mut()) != 1 {
            EVP_MD_CTX_free(mdctx);
            return;
        }

        'body: {
            for arg in args {
                argon2_store32(value.as_mut_ptr(), arg);
                if EVP_DigestUpdate(mdctx, value.as_ptr().cast(), value.len()) != 1 {
                    break 'body;
                }
            }

            if !(*ctx).pwd.is_null() {
                if EVP_DigestUpdate(mdctx, (*ctx).pwd.cast(), (*ctx).pwdlen as usize) != 1 {
                    break 'body;
                }
                if (*ctx).early_clean != 0 {
                    cleanse((*ctx).pwd, (*ctx).pwdlen as usize);
                    (*ctx).pwdlen = 0;
                }
            }

            argon2_store32(value.as_mut_ptr(), (*ctx).saltlen);

            if EVP_DigestUpdate(mdctx, value.as_ptr().cast(), value.len()) != 1 {
                break 'body;
            }

            if !(*ctx).salt.is_null()
                && EVP_DigestUpdate(mdctx, (*ctx).salt.cast(), (*ctx).saltlen as usize) != 1
            {
                break 'body;
            }

            argon2_store32(value.as_mut_ptr(), (*ctx).secretlen);
            if EVP_DigestUpdate(mdctx, value.as_ptr().cast(), value.len()) != 1 {
                break 'body;
            }

            if !(*ctx).secret.is_null() {
                if EVP_DigestUpdate(mdctx, (*ctx).secret.cast(), (*ctx).secretlen as usize) != 1 {
                    break 'body;
                }
                if (*ctx).early_clean != 0 {
                    cleanse((*ctx).secret, (*ctx).secretlen as usize);
                    (*ctx).secretlen = 0;
                }
            }

            argon2_store32(value.as_mut_ptr(), (*ctx).adlen);
            if EVP_DigestUpdate(mdctx, value.as_ptr().cast(), value.len()) != 1 {
                break 'body;
            }

            if !(*ctx).ad.is_null()
                && EVP_DigestUpdate(mdctx, (*ctx).ad.cast(), (*ctx).adlen as usize) != 1
            {
                break 'body;
            }

            let mut tmp: c_uint = ARGON2_PREHASH_DIGEST_LENGTH as c_uint;
            EVP_DigestFinal_ex(mdctx, blockhash, &mut tmp);
        }

        EVP_MD_CTX_free(mdctx);
    }
}

/// `static int initialize(KDF_ARGON2 *ctx)` — `argon2.c:727-755`.
///
/// The matrix allocation, and the only place the two variants differ in *security*: `ARGON2_D`
/// allocates with the plain allocator and the other two with the secure one, which is what
/// `finalize`'s two clears mirror.
///
/// # Safety
/// `ctx` is live with `memory_blocks`, `lanes`, `t_cost` and `type` set and `md`/`mac` fetched.
unsafe fn argon2_initialize(ctx: *mut KdfArgon2) -> c_int {
    let mut blockhash = [0u8; ARGON2_PREHASH_SEED_LENGTH];

    // SAFETY: `ctx` is live per the contract; `blockhash` is this frame's own.
    unsafe {
        if ctx.is_null() {
            return 0;
        }

        let memory_blocks = (*ctx).memory_blocks as usize;
        if memory_blocks.wrapping_mul(ARGON2_BLOCK_SIZE) / ARGON2_BLOCK_SIZE != memory_blocks {
            return 0;
        }

        if (*ctx).type_ != ARGON2_D {
            (*ctx).memory =
                CRYPTO_secure_calloc(memory_blocks, ARGON2_BLOCK_SIZE, FILE_ARGON2, LINE)
                    .cast::<Block>();
        } else {
            (*ctx).memory =
                CRYPTO_calloc(memory_blocks, ARGON2_BLOCK_SIZE, FILE_ARGON2, LINE).cast::<Block>();
        }

        if (*ctx).memory.is_null() {
            raise_site_data(
                &err_sites::PROV_ARGON2_741,
                c"cannot allocate required memory".as_ptr(),
            );
            return 0;
        }

        initial_hash(blockhash.as_mut_ptr(), ctx);
        cleanse(
            blockhash.as_mut_ptr().add(ARGON2_PREHASH_DIGEST_LENGTH),
            ARGON2_PREHASH_SEED_LENGTH - ARGON2_PREHASH_DIGEST_LENGTH,
        );
        fill_first_blocks(blockhash.as_mut_ptr(), ctx);
        cleanse(blockhash.as_mut_ptr(), ARGON2_PREHASH_SEED_LENGTH);

        1
    }
}

/// `static void finalize(const KDF_ARGON2 *ctx, void *out)` — `argon2.c:757-788`.
///
/// XORs the last block of every lane, then folds the result through `blake2b_long` into the
/// caller's output -- and **releases the matrix**, which is why it is the last thing that touches
/// `ctx->memory`.
///
/// # Safety
/// `ctx` is live with `memory` allocated; `out` is writable for `ctx->outlen` bytes.
unsafe fn argon2_finalize(ctx: *const KdfArgon2, out: *mut c_void) {
    let mut blockhash = Block::zero();
    let mut blockhash_bytes = [0u8; ARGON2_BLOCK_SIZE];

    // SAFETY: `ctx` is live per the contract and every pointer below is derived from it or is
    // this frame's own.
    unsafe {
        if ctx.is_null() {
            return;
        }

        copy_block(
            &mut blockhash,
            (*ctx).memory.add(((*ctx).lane_length - 1) as usize),
        );

        /* XOR the last blocks */
        for l in 1..(*ctx).lanes {
            let last_block_in_lane = l
                .wrapping_mul((*ctx).lane_length)
                .wrapping_add((*ctx).lane_length - 1);
            xor_block(
                &mut blockhash,
                (*ctx).memory.add(last_block_in_lane as usize),
            );
        }

        /* Hash the result */
        store_block(blockhash_bytes.as_mut_ptr().cast(), &blockhash);
        blake2b_long(
            (*ctx).md,
            (*ctx).mac,
            out.cast::<u8>(),
            (*ctx).outlen as usize,
            blockhash_bytes.as_ptr().cast(),
            ARGON2_BLOCK_SIZE,
        );
        cleanse(blockhash.v.as_mut_ptr().cast::<u8>(), ARGON2_BLOCK_SIZE);
        cleanse(blockhash_bytes.as_mut_ptr(), ARGON2_BLOCK_SIZE);

        if (*ctx).type_ != ARGON2_D {
            CRYPTO_secure_clear_free(
                (*ctx).memory.cast(),
                (*ctx).memory_blocks as usize * ARGON2_BLOCK_SIZE,
                FILE_ARGON2,
                LINE,
            );
        } else {
            CRYPTO_clear_free(
                (*ctx).memory.cast(),
                (*ctx).memory_blocks as usize * ARGON2_BLOCK_SIZE,
                FILE_ARGON2,
                LINE,
            );
        }
    }
}

/// `static int blake2b_mac(EVP_MAC *mac, void *out, size_t outlen, const void *in, size_t inlen,
/// const void *key, size_t keylen)` — `argon2.c:790-814`.
///
/// The keyed arm of [`blake2b`], and the reason `EVP_MAC` is fetched at all: the key is set as an
/// `OSSL_MAC_PARAM_KEY` and the width as an `OSSL_MAC_PARAM_SIZE`.
///
/// # Safety
/// `mac` is a live fetched MAC; `out` is writable for `outlen` bytes and `in`/`key` readable for
/// their lengths.
#[allow(clippy::too_many_arguments)] // mirrors the authority's signature exactly
unsafe fn blake2b_mac(
    mac: *mut crate::evp::mac::EvpMac,
    out: *mut c_void,
    mut outlen: usize,
    in_: *const c_void,
    inlen: usize,
    key: *const c_void,
    keylen: usize,
) -> c_int {
    let mut ret: c_int = 0;
    let mut out_written: usize = 0;

    // SAFETY: the arguments are forwarded under this function's contract.
    unsafe {
        let ctx = EVP_MAC_CTX_new(mac);
        if ctx.is_null() {
            return ret;
        }

        let par = [
            OSSL_PARAM_construct_octet_string(OSSL_MAC_PARAM_KEY, key.cast_mut(), keylen),
            OSSL_PARAM_construct_size_t(OSSL_MAC_PARAM_SIZE, &mut outlen),
            OSSL_PARAM_construct_end(),
        ];

        if EVP_MAC_CTX_set_params(ctx, par.as_ptr()) == 1
            && EVP_MAC_init(ctx, ptr::null(), 0, ptr::null()) == 1
            && EVP_MAC_update(ctx, in_.cast::<c_uchar>(), inlen) == 1
            && EVP_MAC_final(ctx, out.cast::<c_uchar>(), &mut out_written, outlen) == 1
        {
            ret = 1;
        }

        EVP_MAC_CTX_free(ctx);
        ret
    }
}

/// `static int blake2b_md(EVP_MD *md, void *out, size_t outlen, const void *in, size_t inlen)` —
/// `argon2.c:816-835`.
///
/// The unkeyed arm: `EVP_DigestInit_ex2` with the width as a parameter, and a **NULL** final length
/// because the caller already named the width.
///
/// # Safety
/// `md` is a live fetched digest; `out` is writable for `outlen` bytes and `in` readable for
/// `inlen`.
unsafe fn blake2b_md(
    md: *mut crate::evp::digest::EvpMd,
    out: *mut c_void,
    mut outlen: usize,
    in_: *const c_void,
    inlen: usize,
) -> c_int {
    // SAFETY: the arguments are forwarded under this function's contract.
    unsafe {
        let ctx = EVP_MD_CTX_new();
        if ctx.is_null() {
            return 0;
        }

        let par = [
            OSSL_PARAM_construct_size_t(OSSL_DIGEST_PARAM_SIZE, &mut outlen),
            OSSL_PARAM_construct_end(),
        ];

        let ret = EVP_DigestInit_ex2(ctx, md, par.as_ptr()) == 1
            && EVP_DigestUpdate(ctx, in_, inlen) == 1
            && EVP_DigestFinal_ex(ctx, out.cast::<c_uchar>(), ptr::null_mut()) == 1;

        EVP_MD_CTX_free(ctx);
        c_int::from(ret)
    }
}

/// `static int blake2b(EVP_MD *md, EVP_MAC *mac, void *out, size_t outlen, const void *in, size_t
/// inlen, const void *key, size_t keylen)` — `argon2.c:837-847`.
///
/// The key selects the arm: no key (or a zero-length one) is the digest, anything else the keyed
/// MAC.
///
/// # Safety
/// `md` and `mac` are live; `out` is writable for `outlen` bytes and `in`/`key` readable for their
/// lengths.
#[allow(clippy::too_many_arguments)] // mirrors the authority's signature exactly
unsafe fn blake2b(
    md: *mut crate::evp::digest::EvpMd,
    mac: *mut crate::evp::mac::EvpMac,
    out: *mut c_void,
    outlen: usize,
    in_: *const c_void,
    inlen: usize,
    key: *const c_void,
    keylen: usize,
) -> c_int {
    // SAFETY: the arguments are forwarded under the callees' contracts.
    unsafe {
        if out.is_null() || outlen == 0 {
            return 0;
        }

        if key.is_null() || keylen == 0 {
            return blake2b_md(md, out, outlen, in_, inlen);
        }

        blake2b_mac(mac, out, outlen, in_, inlen, key, keylen)
    }
}

/// `static int blake2b_long(EVP_MD *md, EVP_MAC *mac, unsigned char *out, size_t outlen, const void
/// *in, size_t inlen)` — `argon2.c:849-912`.
///
/// `H'`: the variable-length hash. The width is *prepended* to the input, the first block is taken
/// at `min(outlen, 64)`, and every further 32-byte half is chained through the 64-byte unfinalised
/// buffer -- which is why the two local buffers are exactly `BLAKE2B_OUTBYTES` and why the last
/// `blake2b` call asks for the remaining, possibly shorter, width.
///
/// # Safety
/// `md` and `mac` are live; `out` is NULL or writable for `outlen` bytes; `in` is readable for
/// `inlen`.
unsafe fn blake2b_long(
    md: *mut crate::evp::digest::EvpMd,
    mac: *mut crate::evp::mac::EvpMac,
    out: *mut u8,
    outlen: usize,
    in_: *const c_void,
    inlen: usize,
) -> c_int {
    let mut ret: c_int;
    let mut outlen_curr: u32;
    let mut outbuf = [0u8; BLAKE2B_OUTBYTES];
    let mut inbuf = [0u8; BLAKE2B_OUTBYTES];
    let mut outlen_bytes = [0u8; 4];
    let mut outlen_md: usize;

    // SAFETY: the arguments are forwarded under the callees' contracts, and the four buffers are
    // this frame's own.
    unsafe {
        if out.is_null() || outlen == 0 {
            return 0;
        }

        /* Ensure little-endian byte order */
        argon2_store32(outlen_bytes.as_mut_ptr(), outlen as u32);

        let ctx = EVP_MD_CTX_new();
        if ctx.is_null() {
            return 0;
        }

        outlen_md = if outlen <= BLAKE2B_OUTBYTES {
            outlen
        } else {
            BLAKE2B_OUTBYTES
        };
        let par = [
            OSSL_PARAM_construct_size_t(OSSL_DIGEST_PARAM_SIZE, &mut outlen_md),
            OSSL_PARAM_construct_end(),
        ];

        ret = c_int::from(
            EVP_DigestInit_ex2(ctx, md, par.as_ptr()) == 1
                && EVP_DigestUpdate(ctx, outlen_bytes.as_ptr().cast(), outlen_bytes.len()) == 1
                && EVP_DigestUpdate(ctx, in_, inlen) == 1
                && EVP_DigestFinal_ex(
                    ctx,
                    if outlen > BLAKE2B_OUTBYTES {
                        outbuf.as_mut_ptr()
                    } else {
                        out
                    },
                    ptr::null_mut(),
                ) == 1,
        );

        'body: {
            if ret == 0 {
                break 'body;
            }

            if outlen > BLAKE2B_OUTBYTES {
                ptr::copy_nonoverlapping(outbuf.as_ptr(), out, BLAKE2B_OUTBYTES / 2);
                let mut outp = out.add(BLAKE2B_OUTBYTES / 2);
                outlen_curr = outlen as u32 - (BLAKE2B_OUTBYTES / 2) as u32;

                while outlen_curr > BLAKE2B_OUTBYTES as u32 {
                    ptr::copy_nonoverlapping(outbuf.as_ptr(), inbuf.as_mut_ptr(), BLAKE2B_OUTBYTES);
                    if blake2b(
                        md,
                        mac,
                        outbuf.as_mut_ptr().cast(),
                        BLAKE2B_OUTBYTES,
                        inbuf.as_ptr().cast(),
                        BLAKE2B_OUTBYTES,
                        ptr::null(),
                        0,
                    ) != 1
                    {
                        ret = 0;
                        break 'body;
                    }
                    ptr::copy_nonoverlapping(outbuf.as_ptr(), outp, BLAKE2B_OUTBYTES / 2);
                    outp = outp.add(BLAKE2B_OUTBYTES / 2);
                    outlen_curr -= (BLAKE2B_OUTBYTES / 2) as u32;
                }

                ptr::copy_nonoverlapping(outbuf.as_ptr(), inbuf.as_mut_ptr(), BLAKE2B_OUTBYTES);
                if blake2b(
                    md,
                    mac,
                    outbuf.as_mut_ptr().cast(),
                    outlen_curr as usize,
                    inbuf.as_ptr().cast(),
                    BLAKE2B_OUTBYTES,
                    ptr::null(),
                    0,
                ) != 1
                {
                    ret = 0;
                    break 'body;
                }
                ptr::copy_nonoverlapping(outbuf.as_ptr(), outp, outlen_curr as usize);
            }
            ret = 1;
        }

        EVP_MD_CTX_free(ctx);
        ret
    }
}

/// `static void kdf_argon2_init(KDF_ARGON2 *c, ARGON2_TYPE type)` — `argon2.c:914-929`. The
/// `libctx` is saved across the wipe, which is what makes `OPENSSL_zalloc`'s work survivable when
/// the initialiser is called on an already-constructed context by `reset`.
///
/// # Safety
/// `c` is a live context.
unsafe fn kdf_argon2_init(c: *mut KdfArgon2, type_: u32) {
    // SAFETY: `c` is live per the contract.
    unsafe {
        let libctx = (*c).libctx;
        ptr::write_bytes(c.cast::<u8>(), 0, core::mem::size_of::<KdfArgon2>());

        (*c).libctx = libctx;
        (*c).outlen = ARGON2_DEFAULT_OUTLEN;
        (*c).t_cost = ARGON2_DEFAULT_T_COST;
        (*c).m_cost = ARGON2_DEFAULT_M_COST;
        (*c).lanes = ARGON2_DEFAULT_LANES;
        (*c).threads = ARGON2_DEFAULT_THREADS;
        (*c).version = ARGON2_VERSION_NUMBER;
        (*c).type_ = type_;
    }
}

/// `static void *kdf_argon2d_new(void *provctx)` — `argon2.c:931-948`.
///
/// # Safety
/// The dispatch contract.
unsafe extern "C" fn kdf_argon2d_new(provctx: *mut c_void) -> *mut c_void {
    // SAFETY: the caller's contract.
    unsafe {
        if is_running() == 0 {
            return ptr::null_mut();
        }

        let ctx =
            CRYPTO_zalloc(core::mem::size_of::<KdfArgon2>(), FILE_ARGON2, LINE).cast::<KdfArgon2>();
        if ctx.is_null() {
            raise_site(&err_sites::PROV_ARGON2_938);
            return ptr::null_mut();
        }

        (*ctx).libctx = prov_libctx_of(provctx);
        kdf_argon2_init(ctx, ARGON2_D);
        ctx.cast()
    }
}

/// `static void *kdf_argon2i_new(void *provctx)` — `argon2.c:950-967`.
///
/// # Safety
/// The dispatch contract.
unsafe extern "C" fn kdf_argon2i_new(provctx: *mut c_void) -> *mut c_void {
    // SAFETY: the caller's contract.
    unsafe {
        if is_running() == 0 {
            return ptr::null_mut();
        }

        let ctx =
            CRYPTO_zalloc(core::mem::size_of::<KdfArgon2>(), FILE_ARGON2, LINE).cast::<KdfArgon2>();
        if ctx.is_null() {
            raise_site(&err_sites::PROV_ARGON2_957);
            return ptr::null_mut();
        }

        (*ctx).libctx = prov_libctx_of(provctx);
        kdf_argon2_init(ctx, ARGON2_I);
        ctx.cast()
    }
}

/// `static void *kdf_argon2id_new(void *provctx)` — `argon2.c:969-986`.
///
/// # Safety
/// The dispatch contract.
unsafe extern "C" fn kdf_argon2id_new(provctx: *mut c_void) -> *mut c_void {
    // SAFETY: the caller's contract.
    unsafe {
        if is_running() == 0 {
            return ptr::null_mut();
        }

        let ctx =
            CRYPTO_zalloc(core::mem::size_of::<KdfArgon2>(), FILE_ARGON2, LINE).cast::<KdfArgon2>();
        if ctx.is_null() {
            raise_site(&err_sites::PROV_ARGON2_976);
            return ptr::null_mut();
        }

        (*ctx).libctx = prov_libctx_of(provctx);
        kdf_argon2_init(ctx, ARGON2_ID);
        ctx.cast()
    }
}

/// `static void kdf_argon2_free(void *vctx)` — `argon2.c:988-1015`.
///
/// # Safety
/// The dispatch contract.
unsafe extern "C" fn kdf_argon2_free(vctx: *mut c_void) {
    let ctx = vctx.cast::<KdfArgon2>();

    // SAFETY: `ctx` is NULL or live per the contract.
    unsafe {
        if ctx.is_null() {
            return;
        }

        if !(*ctx).pwd.is_null() {
            CRYPTO_clear_free((*ctx).pwd.cast(), (*ctx).pwdlen as usize, FILE_ARGON2, LINE);
        }
        if !(*ctx).salt.is_null() {
            CRYPTO_clear_free(
                (*ctx).salt.cast(),
                (*ctx).saltlen as usize,
                FILE_ARGON2,
                LINE,
            );
        }
        if !(*ctx).secret.is_null() {
            CRYPTO_clear_free(
                (*ctx).secret.cast(),
                (*ctx).secretlen as usize,
                FILE_ARGON2,
                LINE,
            );
        }
        if !(*ctx).ad.is_null() {
            CRYPTO_clear_free((*ctx).ad.cast(), (*ctx).adlen as usize, FILE_ARGON2, LINE);
        }

        EVP_MD_free((*ctx).md);
        EVP_MAC_free((*ctx).mac);
        CRYPTO_free((*ctx).propq.cast(), FILE_ARGON2, LINE);

        ptr::write_bytes(vctx.cast::<u8>(), 0, core::mem::size_of::<KdfArgon2>());
        CRYPTO_free(vctx, FILE_ARGON2, LINE);
    }
}

/// `static int kdf_argon2_derive(void *vctx, unsigned char *out, size_t outlen, const OSSL_PARAM
/// params[])` — `argon2.c:1017-1122`.
///
/// The unit's whole public contract in one function: set the parameters, fetch the two BLAKE2
/// methods, then bound-check, size the matrix and run it. Three details are the authority's rather
/// than the RFC's: the **`size_param` refusal** (a caller who set `size` shorter than the buffer it
/// now hands in is refused, where a caller who set nothing is re-sized silently), the threads bound
/// against `ossl_get_avail_threads` of the *provider's* context, and the `m_cost >= 8 * lanes`
/// floor above the RFC's own minimum.
///
/// # Safety
/// The dispatch contract.
unsafe extern "C" fn kdf_argon2_derive(
    vctx: *mut c_void,
    out: *mut u8,
    outlen: usize,
    params: *const OsslParam,
) -> c_int {
    let ctx = vctx.cast::<KdfArgon2>();
    let mut size_param: *const OsslParam = ptr::null();

    // SAFETY: the caller's contract, and `size_param` is this frame's own slot.
    unsafe {
        if is_running() == 0 || argon2_set_ctx_params(ctx, params, &mut size_param) == 0 {
            return 0;
        }

        if (*ctx).mac.is_null() {
            (*ctx).mac = EVP_MAC_fetch((*ctx).libctx, OSSL_MAC_NAME_BLAKE2BMAC, (*ctx).propq);
        }
        if (*ctx).mac.is_null() {
            raise_site_data(
                &err_sites::PROV_ARGON2_1031,
                c"cannot fetch blake2bmac".as_ptr(),
            );
            return 0;
        }

        if (*ctx).md.is_null() {
            (*ctx).md = EVP_MD_fetch((*ctx).libctx, OSSL_MD_NAME_BLAKE2B512, (*ctx).propq);
        }
        if (*ctx).md.is_null() {
            raise_site_data(
                &err_sites::PROV_ARGON2_1039,
                c"cannot fetch blake2b512".as_ptr(),
            );
            return 0;
        }

        if (*ctx).salt.is_null() || (*ctx).saltlen == 0 {
            return fail_at(&err_sites::PROV_ARGON2_1045);
        }

        if outlen != (*ctx).outlen as usize {
            /* User set a size that was too short so raise an error */
            if !size_param.is_null() {
                return fail_at(&err_sites::PROV_ARGON2_1052);
            }
            if kdf_argon2_ctx_set_out_length(ctx, outlen as u32) == 0 {
                return 0;
            }
        }

        match (*ctx).type_ {
            ARGON2_D | ARGON2_I | ARGON2_ID => {}
            _ => {
                raise_site_data(
                    &err_sites::PROV_ARGON2_1065,
                    c"invalid Argon2 type".as_ptr(),
                );
                return 0;
            }
        }

        if (*ctx).threads > 1 {
            let avail = ossl_get_avail_threads((*ctx).libctx);
            if (*ctx).threads as u64 > avail {
                let mut msg = [0 as c_char; 64];
                // SAFETY: `msg` is a 64-byte buffer and the format is the authority's. The two
                // `%u` conversions are `unsigned int`: the authority passes the `uint64_t` return
                // of `ossl_get_avail_threads` to one, so the low 32 bits are what reaches the
                // buffer on this ABI and that is what is passed here.
                BIO_snprintf(
                    msg.as_mut_ptr(),
                    msg.len(),
                    c"requested %u threads, available: %u".as_ptr(),
                    (*ctx).threads,
                    ossl_get_avail_threads((*ctx).libctx) as c_uint,
                );
                raise_site_data(&err_sites::PROV_ARGON2_1077, msg.as_ptr());
                return 0;
            }
            if (*ctx).threads > (*ctx).lanes {
                let mut msg = [0 as c_char; 64];
                // SAFETY: `msg` is a 64-byte buffer and the format is the authority's.
                BIO_snprintf(
                    msg.as_mut_ptr(),
                    msg.len(),
                    c"requested more threads (%u) than lanes (%u)".as_ptr(),
                    (*ctx).threads,
                    (*ctx).lanes,
                );
                raise_site_data(&err_sites::PROV_ARGON2_1084, msg.as_ptr());
                return 0;
            }
        }

        if (*ctx).m_cost < 8 * (*ctx).lanes {
            raise_site_data(
                &err_sites::PROV_ARGON2_1092,
                c"m_cost must be greater or equal than 8 times the number of lanes".as_ptr(),
            );
            return 0;
        }

        let mut memory_blocks = (*ctx).m_cost;
        if memory_blocks < 2 * ARGON2_SYNC_POINTS * (*ctx).lanes {
            memory_blocks = 2 * ARGON2_SYNC_POINTS * (*ctx).lanes;
        }

        /* Ensure that all segments have equal length */
        let segment_length = memory_blocks / ((*ctx).lanes * ARGON2_SYNC_POINTS);
        memory_blocks = segment_length * ((*ctx).lanes * ARGON2_SYNC_POINTS);

        (*ctx).memory = ptr::null_mut();
        (*ctx).memory_blocks = memory_blocks;
        (*ctx).segment_length = segment_length;
        (*ctx).passes = (*ctx).t_cost;
        (*ctx).lane_length = segment_length * ARGON2_SYNC_POINTS;

        if argon2_initialize(ctx) != 1 {
            return 0;
        }

        if fill_memory_blocks(ctx) != 1 {
            return 0;
        }

        argon2_finalize(ctx, out.cast::<c_void>());

        1
    }
}

/// `static void kdf_argon2_reset(void *vctx)` — `argon2.c:1124-1154`.
///
/// # Safety
/// The dispatch contract.
unsafe extern "C" fn kdf_argon2_reset(vctx: *mut c_void) {
    let ctx = vctx.cast::<KdfArgon2>();

    // SAFETY: `ctx` is live per the contract.
    unsafe {
        let type_ = (*ctx).type_;
        let libctx = (*ctx).libctx;

        EVP_MD_free((*ctx).md);
        EVP_MAC_free((*ctx).mac);
        CRYPTO_free((*ctx).propq.cast(), FILE_ARGON2, LINE);

        if !(*ctx).pwd.is_null() {
            CRYPTO_clear_free((*ctx).pwd.cast(), (*ctx).pwdlen as usize, FILE_ARGON2, LINE);
        }
        if !(*ctx).salt.is_null() {
            CRYPTO_clear_free(
                (*ctx).salt.cast(),
                (*ctx).saltlen as usize,
                FILE_ARGON2,
                LINE,
            );
        }
        if !(*ctx).secret.is_null() {
            CRYPTO_clear_free(
                (*ctx).secret.cast(),
                (*ctx).secretlen as usize,
                FILE_ARGON2,
                LINE,
            );
        }
        if !(*ctx).ad.is_null() {
            CRYPTO_clear_free((*ctx).ad.cast(), (*ctx).adlen as usize, FILE_ARGON2, LINE);
        }

        ptr::write_bytes(vctx.cast::<u8>(), 0, core::mem::size_of::<KdfArgon2>());
        (*ctx).libctx = libctx;
        kdf_argon2_init(ctx, type_);
    }
}

/// `static int kdf_argon2_ctx_set_threads(KDF_ARGON2 *ctx, uint32_t threads)` —
/// `argon2.c:1156-1172`.
///
/// # Safety
/// `ctx` is live.
unsafe fn kdf_argon2_ctx_set_threads(ctx: *mut KdfArgon2, threads: u32) -> c_int {
    // SAFETY: `ctx` is live per the contract.
    unsafe {
        if threads < ARGON2_MIN_THREADS {
            let mut msg = [0 as c_char; 32];
            // SAFETY: `msg` is a 32-byte buffer and the format is the authority's.
            BIO_snprintf(
                msg.as_mut_ptr(),
                msg.len(),
                c"min threads: %u".as_ptr(),
                ARGON2_MIN_THREADS,
            );
            raise_site_data(&err_sites::PROV_ARGON2_1157, msg.as_ptr());
            return 0;
        }

        if threads > ARGON2_MAX_THREADS {
            let mut msg = [0 as c_char; 32];
            // SAFETY: `msg` is a 32-byte buffer and the format is the authority's.
            BIO_snprintf(
                msg.as_mut_ptr(),
                msg.len(),
                c"max threads: %u".as_ptr(),
                ARGON2_MAX_THREADS,
            );
            raise_site_data(&err_sites::PROV_ARGON2_1163, msg.as_ptr());
            return 0;
        }

        (*ctx).threads = threads;
        1
    }
}

/// `static int kdf_argon2_ctx_set_lanes(KDF_ARGON2 *ctx, uint32_t lanes)` — `argon2.c:1174-1190`.
///
/// # Safety
/// `ctx` is live.
unsafe fn kdf_argon2_ctx_set_lanes(ctx: *mut KdfArgon2, lanes: u32) -> c_int {
    // SAFETY: `ctx` is live per the contract.
    unsafe {
        if lanes > ARGON2_MAX_LANES {
            let mut msg = [0 as c_char; 32];
            // SAFETY: `msg` is a 32-byte buffer and the format is the authority's.
            BIO_snprintf(
                msg.as_mut_ptr(),
                msg.len(),
                c"max lanes: %u".as_ptr(),
                ARGON2_MAX_LANES,
            );
            raise_site_data(&err_sites::PROV_ARGON2_1175, msg.as_ptr());
            return 0;
        }

        if lanes < ARGON2_MIN_LANES {
            let mut msg = [0 as c_char; 32];
            // SAFETY: `msg` is a 32-byte buffer and the format is the authority's.
            BIO_snprintf(
                msg.as_mut_ptr(),
                msg.len(),
                c"min lanes: %u".as_ptr(),
                ARGON2_MIN_LANES,
            );
            raise_site_data(&err_sites::PROV_ARGON2_1181, msg.as_ptr());
            return 0;
        }

        (*ctx).lanes = lanes;
        1
    }
}

/// `static int kdf_argon2_ctx_set_t_cost(KDF_ARGON2 *ctx, uint32_t t_cost)` — `argon2.c:1192-1204`.
/// No upper bound is checked; the authority's comment names the reason.
///
/// # Safety
/// `ctx` is live.
unsafe fn kdf_argon2_ctx_set_t_cost(ctx: *mut KdfArgon2, t_cost: u32) -> c_int {
    // SAFETY: `ctx` is live per the contract.
    unsafe {
        if t_cost < ARGON2_MIN_TIME {
            let mut msg = [0 as c_char; 32];
            // SAFETY: `msg` is a 32-byte buffer and the format is the authority's.
            BIO_snprintf(
                msg.as_mut_ptr(),
                msg.len(),
                c"min: %u".as_ptr(),
                ARGON2_MIN_TIME,
            );
            raise_site_data(&err_sites::PROV_ARGON2_1195, msg.as_ptr());
            return 0;
        }

        (*ctx).t_cost = t_cost;
        1
    }
}

/// `static int kdf_argon2_ctx_set_m_cost(KDF_ARGON2 *ctx, uint32_t m_cost)` — `argon2.c:1206-1218`.
///
/// # Safety
/// `ctx` is live.
unsafe fn kdf_argon2_ctx_set_m_cost(ctx: *mut KdfArgon2, m_cost: u32) -> c_int {
    // SAFETY: `ctx` is live per the contract.
    unsafe {
        if m_cost < ARGON2_MIN_MEMORY {
            let mut msg = [0 as c_char; 32];
            // SAFETY: `msg` is a 32-byte buffer and the format is the authority's.
            BIO_snprintf(
                msg.as_mut_ptr(),
                msg.len(),
                c"min: %u".as_ptr(),
                ARGON2_MIN_MEMORY,
            );
            raise_site_data(&err_sites::PROV_ARGON2_1209, msg.as_ptr());
            return 0;
        }

        (*ctx).m_cost = m_cost;
        1
    }
}

/// `static int kdf_argon2_ctx_set_out_length(KDF_ARGON2 *ctx, uint32_t outlen)` —
/// `argon2.c:1220-1236`. Only the floor is checked; the authority's comment names the reason the
/// ceiling is not.
///
/// # Safety
/// `ctx` is live.
unsafe fn kdf_argon2_ctx_set_out_length(ctx: *mut KdfArgon2, outlen: u32) -> c_int {
    // SAFETY: `ctx` is live per the contract.
    unsafe {
        if outlen < ARGON2_MIN_OUT_LENGTH {
            let mut msg = [0 as c_char; 32];
            // SAFETY: `msg` is a 32-byte buffer and the format is the authority's.
            BIO_snprintf(
                msg.as_mut_ptr(),
                msg.len(),
                c"min: %u".as_ptr(),
                ARGON2_MIN_OUT_LENGTH,
            );
            raise_site_data(&err_sites::PROV_ARGON2_1227, msg.as_ptr());
            return 0;
        }

        (*ctx).outlen = outlen;
        1
    }
}

/// `static int kdf_argon2_ctx_set_secret(KDF_ARGON2 *ctx, const OSSL_PARAM *p)` —
/// `argon2.c:1238-1263`. The over-length refusal answers 0 **without** raising, which is the
/// authority's shape and not an omission.
///
/// # Safety
/// `ctx` is live; `p` is a live parameter with a non-NULL `data`.
unsafe fn kdf_argon2_ctx_set_secret(ctx: *mut KdfArgon2, p: *const OsslParam) -> c_int {
    let mut buflen: usize = 0;

    // SAFETY: `ctx` and `p` are per the contract.
    unsafe {
        if (*p).data.is_null() {
            return 0;
        }

        if !(*ctx).secret.is_null() {
            CRYPTO_clear_free(
                (*ctx).secret.cast(),
                (*ctx).secretlen as usize,
                FILE_ARGON2,
                LINE,
            );
            (*ctx).secret = ptr::null_mut();
            (*ctx).secretlen = 0;
        }

        if OSSL_PARAM_get_octet_string(
            p,
            ptr::addr_of_mut!((*ctx).secret).cast::<*mut c_void>(),
            0,
            &mut buflen,
        ) == 0
        {
            return 0;
        }

        if buflen > ARGON2_MAX_SECRET as usize {
            CRYPTO_free((*ctx).secret.cast(), FILE_ARGON2, LINE);
            (*ctx).secret = ptr::null_mut();
            (*ctx).secretlen = 0;
            return 0;
        }

        (*ctx).secretlen = buflen as u32;
        1
    }
}

/// `static int kdf_argon2_ctx_set_pwd(KDF_ARGON2 *ctx, const OSSL_PARAM *p)` — `argon2.c:1265-1295`.
///
/// # Safety
/// `ctx` is live; `p` is a live parameter with a non-NULL `data`.
unsafe fn kdf_argon2_ctx_set_pwd(ctx: *mut KdfArgon2, p: *const OsslParam) -> c_int {
    let mut buflen: usize = 0;

    // SAFETY: `ctx` and `p` are per the contract.
    unsafe {
        if (*p).data.is_null() {
            return 0;
        }

        if !(*ctx).pwd.is_null() {
            CRYPTO_clear_free((*ctx).pwd.cast(), (*ctx).pwdlen as usize, FILE_ARGON2, LINE);
            (*ctx).pwd = ptr::null_mut();
            (*ctx).pwdlen = 0;
        }

        if OSSL_PARAM_get_octet_string(
            p,
            ptr::addr_of_mut!((*ctx).pwd).cast::<*mut c_void>(),
            0,
            &mut buflen,
        ) == 0
        {
            return 0;
        }

        if buflen > ARGON2_MAX_PWD_LENGTH as usize {
            let mut msg = [0 as c_char; 32];
            // SAFETY: `msg` is a 32-byte buffer and the format is the authority's.
            BIO_snprintf(
                msg.as_mut_ptr(),
                msg.len(),
                c"max: %u".as_ptr(),
                ARGON2_MAX_PWD_LENGTH,
            );
            raise_site_data(&err_sites::PROV_ARGON2_1280, msg.as_ptr());
            CRYPTO_free((*ctx).pwd.cast(), FILE_ARGON2, LINE);
            (*ctx).pwd = ptr::null_mut();
            (*ctx).pwdlen = 0;
            return 0;
        }

        (*ctx).pwdlen = buflen as u32;
        1
    }
}

/// `static int kdf_argon2_ctx_set_salt(KDF_ARGON2 *ctx, const OSSL_PARAM *p)` —
/// `argon2.c:1297-1333`.
///
/// The one input with a **floor**: a salt shorter than `ARGON2_MIN_SALT_LENGTH` is refused, and a
/// missing salt is refused later by `kdf_argon2_derive` rather than here.
///
/// # Safety
/// `ctx` is live; `p` is a live parameter with a non-NULL `data`.
unsafe fn kdf_argon2_ctx_set_salt(ctx: *mut KdfArgon2, p: *const OsslParam) -> c_int {
    let mut buflen: usize = 0;

    // SAFETY: `ctx` and `p` are per the contract.
    unsafe {
        if (*p).data.is_null() {
            return 0;
        }

        if !(*ctx).salt.is_null() {
            CRYPTO_clear_free(
                (*ctx).salt.cast(),
                (*ctx).saltlen as usize,
                FILE_ARGON2,
                LINE,
            );
            (*ctx).salt = ptr::null_mut();
            (*ctx).saltlen = 0;
        }

        if OSSL_PARAM_get_octet_string(
            p,
            ptr::addr_of_mut!((*ctx).salt).cast::<*mut c_void>(),
            0,
            &mut buflen,
        ) == 0
        {
            return 0;
        }

        if buflen < ARGON2_MIN_SALT_LENGTH as usize {
            let mut msg = [0 as c_char; 32];
            // SAFETY: `msg` is a 32-byte buffer and the format is the authority's.
            BIO_snprintf(
                msg.as_mut_ptr(),
                msg.len(),
                c"min: %u".as_ptr(),
                ARGON2_MIN_SALT_LENGTH,
            );
            raise_site_data(&err_sites::PROV_ARGON2_1312, msg.as_ptr());
            CRYPTO_free((*ctx).salt.cast(), FILE_ARGON2, LINE);
            (*ctx).salt = ptr::null_mut();
            (*ctx).saltlen = 0;
            return 0;
        }

        if buflen > ARGON2_MAX_SALT_LENGTH as usize {
            let mut msg = [0 as c_char; 32];
            // SAFETY: `msg` is a 32-byte buffer and the format is the authority's.
            BIO_snprintf(
                msg.as_mut_ptr(),
                msg.len(),
                c"max: %u".as_ptr(),
                ARGON2_MAX_SALT_LENGTH,
            );
            raise_site_data(&err_sites::PROV_ARGON2_1318, msg.as_ptr());
            CRYPTO_free((*ctx).salt.cast(), FILE_ARGON2, LINE);
            (*ctx).salt = ptr::null_mut();
            (*ctx).saltlen = 0;
            return 0;
        }

        (*ctx).saltlen = buflen as u32;
        1
    }
}

/// `static int kdf_argon2_ctx_set_ad(KDF_ARGON2 *ctx, const OSSL_PARAM *p)` — `argon2.c:1335-1360`.
/// Like `set_secret`, the over-length refusal is silent.
///
/// # Safety
/// `ctx` is live; `p` is a live parameter with a non-NULL `data`.
unsafe fn kdf_argon2_ctx_set_ad(ctx: *mut KdfArgon2, p: *const OsslParam) -> c_int {
    let mut buflen: usize = 0;

    // SAFETY: `ctx` and `p` are per the contract.
    unsafe {
        if (*p).data.is_null() {
            return 0;
        }

        if !(*ctx).ad.is_null() {
            CRYPTO_clear_free((*ctx).ad.cast(), (*ctx).adlen as usize, FILE_ARGON2, LINE);
            (*ctx).ad = ptr::null_mut();
            (*ctx).adlen = 0;
        }

        if OSSL_PARAM_get_octet_string(
            p,
            ptr::addr_of_mut!((*ctx).ad).cast::<*mut c_void>(),
            0,
            &mut buflen,
        ) == 0
        {
            return 0;
        }

        if buflen > ARGON2_MAX_AD_LENGTH as usize {
            CRYPTO_free((*ctx).ad.cast(), FILE_ARGON2, LINE);
            (*ctx).ad = ptr::null_mut();
            (*ctx).adlen = 0;
            return 0;
        }

        (*ctx).adlen = buflen as u32;
        1
    }
}

/// `static void kdf_argon2_ctx_set_flag_early_clean(KDF_ARGON2 *ctx, uint32_t f)` —
/// `argon2.c:1362-1365`. The value is normalised to 0 or 1.
///
/// # Safety
/// `ctx` is live.
unsafe fn kdf_argon2_ctx_set_flag_early_clean(ctx: *mut KdfArgon2, f: u32) {
    // SAFETY: `ctx` is live per the contract.
    unsafe { (*ctx).early_clean = u32::from(f != 0) };
}

/// `static int kdf_argon2_ctx_set_version(KDF_ARGON2 *ctx, uint32_t version)` —
/// `argon2.c:1367-1379`. Only `0x10` and `0x13` are accepted, which is why a probe can drive the
/// version-1.0 overwrite arm of `fill_segment`.
///
/// # Safety
/// `ctx` is live.
unsafe fn kdf_argon2_ctx_set_version(ctx: *mut KdfArgon2, version: u32) -> c_int {
    // SAFETY: `ctx` is live per the contract.
    unsafe {
        match version {
            ARGON2_VERSION_10 | ARGON2_VERSION_13 => {
                (*ctx).version = version;
                1
            }
            _ => {
                raise_site_data(
                    &err_sites::PROV_ARGON2_1373,
                    c"invalid Argon2 version".as_ptr(),
                );
                0
            }
        }
    }
}

/// `static int set_property_query(KDF_ARGON2 *ctx, const char *propq)` — `argon2.c:1381-1395`.
/// The two fetched methods are dropped with the old query, so the next derive re-fetches them.
///
/// # Safety
/// `ctx` is live; `propq` is NULL or NUL-terminated.
unsafe fn set_property_query(ctx: *mut KdfArgon2, propq: *const c_char) -> c_int {
    // SAFETY: `ctx` is live and `propq` is per the contract.
    unsafe {
        CRYPTO_free((*ctx).propq.cast(), FILE_ARGON2, LINE);
        (*ctx).propq = ptr::null_mut();
        if !propq.is_null() {
            (*ctx).propq = CRYPTO_strdup(propq, FILE_ARGON2, LINE);
            if (*ctx).propq.is_null() {
                return 0;
            }
        }
        EVP_MD_free((*ctx).md);
        (*ctx).md = ptr::null_mut();
        EVP_MAC_free((*ctx).mac);
        (*ctx).mac = ptr::null_mut();
        1
    }
}

/// `static int argon2_set_ctx_params(KDF_ARGON2 *ctx, const OSSL_PARAM params[], OSSL_PARAM
/// **size_param_ptr)` — generated `argon2.c:1592-1668`.
///
/// The generated switch is the field-keyed repeat check plus one `OSSL_PARAM_locate_const` per key,
/// which is this module's established reading of a decoder (D305). `size_param_ptr` is an
/// **out**-parameter because `kdf_argon2_derive` needs to know whether the caller set `size`; it is
/// written unconditionally on the path that reaches it, and the derive's own guard is what makes a
/// write-through-on-failure impossible.
///
/// # Safety
/// `ctx` is NULL or live; `params` is NULL or key-terminated; `size_param_ptr` is writable.
unsafe fn argon2_set_ctx_params(
    ctx: *mut KdfArgon2,
    params: *const OsslParam,
    size_param_ptr: *mut *const OsslParam,
) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        if ctx.is_null() {
            return 0;
        }
        if let Some(site) = repeated_param_site_by_field(params, &ARGON2_SET_DECODER_KEYS) {
            return fail_at(site);
        }

        let p = Argon2SetCtxParams {
            ad: locate_const(params, OSSL_KDF_PARAM_ARGON2_AD),
            eclean: locate_const(params, OSSL_KDF_PARAM_EARLY_CLEAN),
            iter: locate_const(params, OSSL_KDF_PARAM_ITER),
            lanes: locate_const(params, OSSL_KDF_PARAM_ARGON2_LANES),
            mem: locate_const(params, OSSL_KDF_PARAM_ARGON2_MEMCOST),
            propq: locate_const(params, OSSL_KDF_PARAM_PROPERTIES),
            pw: locate_const(params, OSSL_KDF_PARAM_PASSWORD),
            salt: locate_const(params, OSSL_KDF_PARAM_SALT),
            secret: locate_const(params, OSSL_KDF_PARAM_SECRET),
            size: locate_const(params, OSSL_KDF_PARAM_SIZE),
            thrds: locate_const(params, OSSL_KDF_PARAM_THREADS),
            vers: locate_const(params, OSSL_KDF_PARAM_ARGON2_VERSION),
        };
        let mut u32_value: u32 = 0;

        if !p.pw.is_null() && kdf_argon2_ctx_set_pwd(ctx, p.pw) == 0 {
            return 0;
        }

        if !p.salt.is_null() && kdf_argon2_ctx_set_salt(ctx, p.salt) == 0 {
            return 0;
        }

        if !p.secret.is_null() && kdf_argon2_ctx_set_secret(ctx, p.secret) == 0 {
            return 0;
        }

        if !p.ad.is_null() && kdf_argon2_ctx_set_ad(ctx, p.ad) == 0 {
            return 0;
        }

        *size_param_ptr = p.size;
        if !p.size.is_null() {
            if OSSL_PARAM_get_uint32(p.size, &mut u32_value) == 0 {
                return 0;
            }
            if kdf_argon2_ctx_set_out_length(ctx, u32_value) == 0 {
                return 0;
            }
        }

        if !p.iter.is_null() {
            if OSSL_PARAM_get_uint32(p.iter, &mut u32_value) == 0 {
                return 0;
            }
            if kdf_argon2_ctx_set_t_cost(ctx, u32_value) == 0 {
                return 0;
            }
        }

        if !p.thrds.is_null() {
            if OSSL_PARAM_get_uint32(p.thrds, &mut u32_value) == 0 {
                return 0;
            }
            if kdf_argon2_ctx_set_threads(ctx, u32_value) == 0 {
                return 0;
            }
        }

        if !p.lanes.is_null() {
            if OSSL_PARAM_get_uint32(p.lanes, &mut u32_value) == 0 {
                return 0;
            }
            if kdf_argon2_ctx_set_lanes(ctx, u32_value) == 0 {
                return 0;
            }
        }

        if !p.mem.is_null() {
            if OSSL_PARAM_get_uint32(p.mem, &mut u32_value) == 0 {
                return 0;
            }
            if kdf_argon2_ctx_set_m_cost(ctx, u32_value) == 0 {
                return 0;
            }
        }

        if !p.eclean.is_null() {
            if OSSL_PARAM_get_uint32(p.eclean, &mut u32_value) == 0 {
                return 0;
            }
            kdf_argon2_ctx_set_flag_early_clean(ctx, u32_value);
        }

        if !p.vers.is_null() {
            if OSSL_PARAM_get_uint32(p.vers, &mut u32_value) == 0 {
                return 0;
            }
            if kdf_argon2_ctx_set_version(ctx, u32_value) == 0 {
                return 0;
            }
        }

        if !p.propq.is_null()
            && ((*p.propq).data_type != OSSL_PARAM_UTF8_STRING
                || set_property_query(ctx, (*p.propq).data.cast()) == 0)
        {
            return 0;
        }

        1
    }
}

/// `static int kdf_argon2_set_ctx_params(void *vctx, const OSSL_PARAM params[])` —
/// `argon2.c:1670-1676`. The `size_param` it builds is discarded; only `derive` reads it.
///
/// # Safety
/// The dispatch contract.
unsafe extern "C" fn kdf_argon2_set_ctx_params(
    vctx: *mut c_void,
    params: *const OsslParam,
) -> c_int {
    let ctx = vctx.cast::<KdfArgon2>();
    let mut size_param: *const OsslParam = ptr::null();

    // SAFETY: the caller's contract, and `size_param` is this frame's own slot.
    unsafe { argon2_set_ctx_params(ctx, params, &mut size_param) }
}

/// `static const OSSL_PARAM *kdf_argon2_settable_ctx_params(void *ctx, void *p_ctx)` —
/// generated `argon2.c:1678-1682`.
///
/// # Safety
/// The dispatch contract.
unsafe extern "C" fn kdf_argon2_settable_ctx_params(
    _ctx: *mut c_void,
    _p_ctx: *mut c_void,
) -> *const OsslParam {
    ARGON2_SETTABLE_CTX_PARAMS.as_ptr()
}

/// `static int kdf_argon2_get_ctx_params(void *vctx, OSSL_PARAM params[])` — generated
/// `argon2.c:1723-1735`.
///
/// Answers `SIZE_MAX` for `size` and then **`-2`** -- the authority's own return value, which is
/// neither this interface's success value nor a documented refusal. It is reproduced as written;
/// what a caller makes of it is the probe's observation to make on both sides.
///
/// # Safety
/// The dispatch contract.
unsafe extern "C" fn kdf_argon2_get_ctx_params(vctx: *mut c_void, params: *mut OsslParam) -> c_int {
    let ctx = vctx.cast::<KdfArgon2>();

    // SAFETY: the caller's contract.
    unsafe {
        if ctx.is_null() {
            return 0;
        }
        if let Some(site) =
            repeated_param_site_by_field(params.cast_const(), &ARGON2_GET_DECODER_KEYS)
        {
            return fail_at(site);
        }
        let p = locate_const(params, OSSL_KDF_PARAM_SIZE);
        if !p.is_null() && OSSL_PARAM_set_size_t(p.cast_mut(), usize::MAX) == 0 {
            return 0;
        }
        -2
    }
}

/// `static const OSSL_PARAM *kdf_argon2_gettable_ctx_params(void *ctx, void *p_ctx)` —
/// generated `argon2.c:1737-1741`.
///
/// # Safety
/// The dispatch contract.
unsafe extern "C" fn kdf_argon2_gettable_ctx_params(
    _ctx: *mut c_void,
    _p_ctx: *mut c_void,
) -> *const OsslParam {
    ARGON2_GETTABLE_CTX_PARAMS.as_ptr()
}

/// `const OSSL_DISPATCH ossl_kdf_argon2i_functions[]` — `argon2.c:1743-1755`. Eight callbacks and
/// the terminator: there is no `DUPCTX` slot, because the unit does not implement one.
pub(crate) static ARGON2I_FUNCTIONS: [OsslDispatch; 9] = [
    OsslDispatch {
        function_id: OSSL_FUNC_KDF_NEWCTX,
        function: kdf_argon2i_new as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KDF_FREECTX,
        function: kdf_argon2_free as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KDF_RESET,
        function: kdf_argon2_reset as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KDF_DERIVE,
        function: kdf_argon2_derive as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KDF_SETTABLE_CTX_PARAMS,
        function: kdf_argon2_settable_ctx_params as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KDF_SET_CTX_PARAMS,
        function: kdf_argon2_set_ctx_params as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KDF_GETTABLE_CTX_PARAMS,
        function: kdf_argon2_gettable_ctx_params as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KDF_GET_CTX_PARAMS,
        function: kdf_argon2_get_ctx_params as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_DISPATCH_END,
        function: ptr::null_mut(),
    },
];

/// `const OSSL_DISPATCH ossl_kdf_argon2d_functions[]` — `argon2.c:1757-1769`.
pub(crate) static ARGON2D_FUNCTIONS: [OsslDispatch; 9] = [
    OsslDispatch {
        function_id: OSSL_FUNC_KDF_NEWCTX,
        function: kdf_argon2d_new as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KDF_FREECTX,
        function: kdf_argon2_free as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KDF_RESET,
        function: kdf_argon2_reset as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KDF_DERIVE,
        function: kdf_argon2_derive as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KDF_SETTABLE_CTX_PARAMS,
        function: kdf_argon2_settable_ctx_params as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KDF_SET_CTX_PARAMS,
        function: kdf_argon2_set_ctx_params as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KDF_GETTABLE_CTX_PARAMS,
        function: kdf_argon2_gettable_ctx_params as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KDF_GET_CTX_PARAMS,
        function: kdf_argon2_get_ctx_params as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_DISPATCH_END,
        function: ptr::null_mut(),
    },
];

/// `const OSSL_DISPATCH ossl_kdf_argon2id_functions[]` — `argon2.c:1771-1783`.
pub(crate) static ARGON2ID_FUNCTIONS: [OsslDispatch; 9] = [
    OsslDispatch {
        function_id: OSSL_FUNC_KDF_NEWCTX,
        function: kdf_argon2id_new as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KDF_FREECTX,
        function: kdf_argon2_free as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KDF_RESET,
        function: kdf_argon2_reset as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KDF_DERIVE,
        function: kdf_argon2_derive as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KDF_SETTABLE_CTX_PARAMS,
        function: kdf_argon2_settable_ctx_params as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KDF_SET_CTX_PARAMS,
        function: kdf_argon2_set_ctx_params as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KDF_GETTABLE_CTX_PARAMS,
        function: kdf_argon2_gettable_ctx_params as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KDF_GET_CTX_PARAMS,
        function: kdf_argon2_get_ctx_params as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_DISPATCH_END,
        function: ptr::null_mut(),
    },
];

/// `static const OSSL_ALGORITHM deflt_kdfs[]` — `providers/defltprov.c:355-375`, restricted to
/// the rows this module implements, **in the authority's order**: `HKDF` rows 0-4, `SSKDF` row 5,
/// `PBKDF2` row 6, `PKCS12KDF` row 7, `SSHKDF` row 8, `X963KDF` row 9, `TLS1-PRF` row 10,
/// `KBKDF` row 11, `X942KDF-ASN1` row 12, `SCRYPT` row 13, `KRB5KDF` row 14, `HMAC-DRBG-KDF`
/// row 15, `ARGON2I` row 16, `ARGON2D` row 17 and `ARGON2ID` row 18, so the table is a
/// **subsequence** of all nineteen and every row of the authority's is now published (D244, D400).
///
/// **The property definition is `"provider=default"` on every row**, which is `defltprov.c`'s
/// `ALG` macro (D247).
///
/// The three `ARGON2` rows carry **no alias**: `PROV_NAMES_ARGON2I`/`_D`/`_ID` are the primary
/// names alone, unlike `SCRYPT`'s `id-scrypt` pair or `PBKDF2`'s OID. Their `#ifndef
/// OPENSSL_NO_ARGON2` guard is satisfied on this profile, so all three are live.
pub(crate) static DEFLT_KDFS: [OsslAlgorithm; 20] = [
    OsslAlgorithm {
        // `PROV_NAMES_HKDF` — the primary name alone.
        algorithm_names: c"HKDF".as_ptr(),
        property_definition: c"provider=default".as_ptr(),
        implementation: HKDF_FUNCTIONS.as_ptr().cast(),
        algorithm_description: ptr::null(),
    },
    OsslAlgorithm {
        // `PROV_NAMES_HKDF_SHA256` — the two aliases are part of the row.
        algorithm_names: c"HKDF-SHA256:id-alg-hkdf-with-sha256:1.2.840.113549.1.9.16.3.28".as_ptr(),
        property_definition: c"provider=default".as_ptr(),
        implementation: HKDF_SHA256_FUNCTIONS.as_ptr().cast(),
        algorithm_description: ptr::null(),
    },
    OsslAlgorithm {
        // `PROV_NAMES_HKDF_SHA384` — the two aliases are part of the row.
        algorithm_names: c"HKDF-SHA384:id-alg-hkdf-with-sha384:1.2.840.113549.1.9.16.3.29".as_ptr(),
        property_definition: c"provider=default".as_ptr(),
        implementation: HKDF_SHA384_FUNCTIONS.as_ptr().cast(),
        algorithm_description: ptr::null(),
    },
    OsslAlgorithm {
        // `PROV_NAMES_HKDF_SHA512` — the two aliases are part of the row.
        algorithm_names: c"HKDF-SHA512:id-alg-hkdf-with-sha512:1.2.840.113549.1.9.16.3.30".as_ptr(),
        property_definition: c"provider=default".as_ptr(),
        implementation: HKDF_SHA512_FUNCTIONS.as_ptr().cast(),
        algorithm_description: ptr::null(),
    },
    OsslAlgorithm {
        // `PROV_NAMES_TLS1_3_KDF` — the primary name alone.
        algorithm_names: c"TLS13-KDF".as_ptr(),
        property_definition: c"provider=default".as_ptr(),
        implementation: TLS13_KDF_FUNCTIONS.as_ptr().cast(),
        algorithm_description: ptr::null(),
    },
    OsslAlgorithm {
        // `PROV_NAMES_SSKDF` — `prov/names.h`, the primary name alone.
        algorithm_names: c"SSKDF".as_ptr(),
        property_definition: c"provider=default".as_ptr(),
        implementation: SSKDF_FUNCTIONS.as_ptr().cast(),
        algorithm_description: ptr::null(),
    },
    OsslAlgorithm {
        // `PROV_NAMES_PBKDF2` — the alias `1.2.840.113549.1.5.12` is part of the row.
        algorithm_names: c"PBKDF2:1.2.840.113549.1.5.12".as_ptr(),
        property_definition: c"provider=default".as_ptr(),
        implementation: PBKDF2_FUNCTIONS.as_ptr().cast(),
        algorithm_description: ptr::null(),
    },
    OsslAlgorithm {
        // `PROV_NAMES_PKCS12KDF` — the primary name alone.
        algorithm_names: c"PKCS12KDF".as_ptr(),
        property_definition: c"provider=default".as_ptr(),
        implementation: PKCS12KDF_FUNCTIONS.as_ptr().cast(),
        algorithm_description: ptr::null(),
    },
    OsslAlgorithm {
        // `PROV_NAMES_SSHKDF` — the primary name alone.
        algorithm_names: c"SSHKDF".as_ptr(),
        property_definition: c"provider=default".as_ptr(),
        implementation: SSHKDF_FUNCTIONS.as_ptr().cast(),
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
        // `PROV_NAMES_TLS1_PRF` — the primary name alone.
        algorithm_names: c"TLS1-PRF".as_ptr(),
        property_definition: c"provider=default".as_ptr(),
        implementation: TLS1_PRF_FUNCTIONS.as_ptr().cast(),
        algorithm_description: ptr::null(),
    },
    OsslAlgorithm {
        // `PROV_NAMES_KBKDF` — the primary name alone.
        algorithm_names: c"KBKDF".as_ptr(),
        property_definition: c"provider=default".as_ptr(),
        implementation: KBKDF_FUNCTIONS.as_ptr().cast(),
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
        // `PROV_NAMES_SCRYPT` — the two aliases are part of the row.
        algorithm_names: c"SCRYPT:id-scrypt:1.3.6.1.4.1.11591.4.11".as_ptr(),
        property_definition: c"provider=default".as_ptr(),
        implementation: SCRYPT_FUNCTIONS.as_ptr().cast(),
        algorithm_description: ptr::null(),
    },
    OsslAlgorithm {
        // `PROV_NAMES_KRB5KDF` — the primary name alone.
        algorithm_names: c"KRB5KDF".as_ptr(),
        property_definition: c"provider=default".as_ptr(),
        implementation: KRB5KDF_FUNCTIONS.as_ptr().cast(),
        algorithm_description: ptr::null(),
    },
    OsslAlgorithm {
        // `PROV_NAMES_HMAC_DRBG` — the primary name alone.
        algorithm_names: c"HMAC-DRBG-KDF".as_ptr(),
        property_definition: c"provider=default".as_ptr(),
        implementation: HMACDRBG_KDF_FUNCTIONS.as_ptr().cast(),
        algorithm_description: ptr::null(),
    },
    OsslAlgorithm {
        // `PROV_NAMES_ARGON2I` — the primary name alone.
        algorithm_names: c"ARGON2I".as_ptr(),
        property_definition: c"provider=default".as_ptr(),
        implementation: ARGON2I_FUNCTIONS.as_ptr().cast(),
        algorithm_description: ptr::null(),
    },
    OsslAlgorithm {
        // `PROV_NAMES_ARGON2D` — the primary name alone.
        algorithm_names: c"ARGON2D".as_ptr(),
        property_definition: c"provider=default".as_ptr(),
        implementation: ARGON2D_FUNCTIONS.as_ptr().cast(),
        algorithm_description: ptr::null(),
    },
    OsslAlgorithm {
        // `PROV_NAMES_ARGON2ID` — the primary name alone.
        algorithm_names: c"ARGON2ID".as_ptr(),
        property_definition: c"provider=default".as_ptr(),
        implementation: ARGON2ID_FUNCTIONS.as_ptr().cast(),
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
        assert_eq!(DEFLT_KDFS.len(), 20);
        // SAFETY: the terminator's fields are NULL by construction and each landed row's name is a
        // `'static` C string.
        unsafe {
            assert!(DEFLT_KDFS[19].algorithm_names.is_null());
            for (row, want) in [
                (&DEFLT_KDFS[0], b"HKDF".as_slice()),
                (
                    &DEFLT_KDFS[1],
                    b"HKDF-SHA256:id-alg-hkdf-with-sha256:1.2.840.113549.1.9.16.3.28",
                ),
                (
                    &DEFLT_KDFS[2],
                    b"HKDF-SHA384:id-alg-hkdf-with-sha384:1.2.840.113549.1.9.16.3.29",
                ),
                (
                    &DEFLT_KDFS[3],
                    b"HKDF-SHA512:id-alg-hkdf-with-sha512:1.2.840.113549.1.9.16.3.30",
                ),
                (&DEFLT_KDFS[4], b"TLS13-KDF"),
                (&DEFLT_KDFS[5], b"SSKDF"),
                (&DEFLT_KDFS[6], b"PBKDF2:1.2.840.113549.1.5.12"),
                (&DEFLT_KDFS[7], b"PKCS12KDF"),
                (&DEFLT_KDFS[8], b"SSHKDF"),
                (&DEFLT_KDFS[9], b"X963KDF:X942KDF-CONCAT"),
                (&DEFLT_KDFS[10], b"TLS1-PRF"),
                (&DEFLT_KDFS[11], b"KBKDF"),
                (&DEFLT_KDFS[12], b"X942KDF-ASN1:X942KDF"),
                (&DEFLT_KDFS[13], b"SCRYPT:id-scrypt:1.3.6.1.4.1.11591.4.11"),
                (&DEFLT_KDFS[14], b"KRB5KDF"),
                (&DEFLT_KDFS[15], b"HMAC-DRBG-KDF"),
                (&DEFLT_KDFS[16], b"ARGON2I"),
                (&DEFLT_KDFS[17], b"ARGON2D"),
                (&DEFLT_KDFS[18], b"ARGON2ID"),
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
    fn the_dispatch_tables_carry_nine_entries_and_terminate() {
        for table in [
            &SSKDF_FUNCTIONS,
            &X963KDF_FUNCTIONS,
            &X942KDF_FUNCTIONS,
            &PKCS12KDF_FUNCTIONS,
            &SSHKDF_FUNCTIONS,
            &PBKDF2_FUNCTIONS,
            &HKDF_FUNCTIONS,
            &HKDF_SHA256_FUNCTIONS,
            &HKDF_SHA384_FUNCTIONS,
            &HKDF_SHA512_FUNCTIONS,
            &TLS13_KDF_FUNCTIONS,
            &TLS1_PRF_FUNCTIONS,
            &KBKDF_FUNCTIONS,
            &SCRYPT_FUNCTIONS,
            &KRB5KDF_FUNCTIONS,
            &HMACDRBG_KDF_FUNCTIONS,
        ] {
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

        // The three Argon2 tables are the one shape in this module that is **eight** callbacks and
        // a terminator: the unit implements no `DUPCTX`, so the terminator is at index 8 rather
        // than 9 (`argon2.c:1743-1783`).
        for table in [&ARGON2I_FUNCTIONS, &ARGON2D_FUNCTIONS, &ARGON2ID_FUNCTIONS] {
            assert_eq!(table.len(), 9);
            assert_eq!(
                table[8].function_id,
                crate::context::dispatch::OSSL_DISPATCH_END
            );
            assert!(table[8].function.is_null());
            for entry in &table[..8] {
                assert!(!entry.function.is_null());
            }
        }
        assert_eq!(ARGON2I_FUNCTIONS[3].function_id, OSSL_FUNC_KDF_DERIVE);
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

    /// The authority's own Argon2 corpus, embedded rather than retyped.
    ///
    /// `test/recipes/30-test_evp_data/evpkdf_argon2.txt` is the file the authority's own
    /// `test/evp_test.c` drives the three rows with -- RFC 9106's published vectors plus the
    /// unit's bound cases -- and it is parsed here at test time so that neither an input nor an
    /// expected output is a second transcription (D392's rule). The file's two directives are
    /// reproduced as the harness reads them: `Threads = N` is `OSSL_set_max_threads(libctx, N)`
    /// (`evp_test.c:5458-5464`), which is what makes the two threaded cases derivable at all, and
    /// `Ctrl.<anything> = <key>:<value>` is one parameter whose **key is the value's** -- so the
    /// file's own `Ctrl.lanes = threads:0` really does set `threads`, as it does in the harness.
    /// A `hex` prefix means the octets the hex spells; anything else is the value's own ASCII.
    const ARGON2_VECTORS: &str = include_str!(
        "../../forensics/authorities/src/openssl-3.6.4/test/recipes/30-test_evp_data/evpkdf_argon2.txt"
    );

    /// A NUL-terminated copy of an ASCII token, for the C-ABI key arguments.
    fn argon2_cstr(s: &str) -> Vec<u8> {
        let mut v = s.as_bytes().to_vec();
        v.push(0);
        v
    }

    /// The bytes a hex spelling names, as the file's `hexsalt:` and friends use it.
    fn argon2_hex(s: &str) -> Vec<u8> {
        let b = s.as_bytes();
        let mut out = Vec::with_capacity(b.len() / 2);
        let mut i = 0;
        while i + 1 < b.len() {
            let hi = (b[i] as char).to_digit(16);
            let lo = (b[i + 1] as char).to_digit(16);
            let (Some(hi), Some(lo)) = (hi, lo) else {
                break;
            };
            out.push((hi * 16 + lo) as u8);
            i += 2;
        }
        out
    }

    /// A `uint32_t` parameter value, decimal or `0x`-prefixed as the file spells it.
    fn argon2_u32(s: &str) -> Option<u32> {
        match s.strip_prefix("0x") {
            Some(hex) => u32::from_str_radix(hex, 16).ok(),
            None => s.parse::<u32>().ok(),
        }
    }

    /// One case, as the file writes it.
    struct Argon2Case {
        alg: Vec<u8>,
        threads: Option<u64>,
        /// `(key, octets)` for the four byte-string parameters.
        octets: Vec<(Vec<u8>, Vec<u8>)>,
        /// `(key, value)` for the seven `uint32_t` ones.
        u32s: Vec<(Vec<u8>, u32)>,
        /// The expected output, empty when the case is a bound case.
        output: Vec<u8>,
        /// `Result = ...` was present, so the derive must be refused.
        refused: bool,
    }

    /// The file's cases. A case begins at `KDF =` and every later line of its block belongs to it;
    /// `Title`, comments and blank lines outside a block are skipped.
    fn parse_argon2_vectors(text: &str) -> Vec<Argon2Case> {
        let mut cases: Vec<Argon2Case> = Vec::new();

        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let Some((key, value)) = line.split_once('=') else {
                continue;
            };
            let (key, value) = (key.trim(), value.trim());

            if key == "KDF" {
                cases.push(Argon2Case {
                    alg: argon2_cstr(value),
                    threads: None,
                    octets: Vec::new(),
                    u32s: Vec::new(),
                    output: Vec::new(),
                    refused: false,
                });
                continue;
            }

            let Some(case) = cases.last_mut() else {
                continue;
            };

            if key == "Threads" {
                case.threads = value.parse::<u64>().ok();
            } else if key == "Output" {
                case.output = argon2_hex(value);
            } else if key == "Result" {
                case.refused = true;
            } else if key.starts_with("Ctrl.") {
                let Some((pkey, pvalue)) = value.split_once(':') else {
                    continue;
                };
                let (pkey, pvalue) = (pkey.trim(), pvalue.trim());
                match pkey {
                    "hexpass" | "hexsalt" | "hexsecret" | "hexad" => {
                        case.octets
                            .push((argon2_cstr(&pkey[3..]), argon2_hex(pvalue)));
                    }
                    "pass" | "salt" | "secret" | "ad" => {
                        case.octets
                            .push((argon2_cstr(pkey), pvalue.as_bytes().to_vec()));
                    }
                    _ => {
                        if let Some(v) = argon2_u32(pvalue) {
                            case.u32s.push((argon2_cstr(pkey), v));
                        }
                    }
                }
            }
        }
        cases
    }

    /// Every case in the authority's file, through the three published rows.
    ///
    /// The court `RT-DIGEST` is what observes *where* a refusal happens and what the threaded fill
    /// lands on; this test is what pins the **derived bytes** to values the author did not choose,
    /// which a differential court cannot do on its own: two implementations that agree on the same
    /// bytes have agreed, but only a published vector says the bytes are Argon2's. The counts at
    /// the end are the file's, so a case that stops being parsed is a failure rather than a
    /// quietly smaller corpus.
    #[test]
    fn the_argon2_rows_agree_with_the_authoritys_own_vectors() {
        use crate::context::thread_data::OSSL_set_max_threads;
        use crate::context::{OSSL_LIB_CTX_free, OSSL_LIB_CTX_new};
        use crate::evp::kdf::{
            EVP_KDF_CTX_free, EVP_KDF_CTX_new, EVP_KDF_derive, EVP_KDF_fetch, EVP_KDF_free,
        };
        use crate::params::OSSL_PARAM_construct_uint32;

        let mut cases = parse_argon2_vectors(ARGON2_VECTORS);
        assert_eq!(cases.len(), 23, "the file's `KDF =` cases");

        let mut derived = 0;
        let mut refused = 0;

        for case in &mut cases {
            let libctx = OSSL_LIB_CTX_new();
            assert!(!libctx.is_null(), "a fresh library context");

            let mut params: Vec<OsslParam> =
                Vec::with_capacity(case.octets.len() + case.u32s.len() + 1);

            // SAFETY: every key is a NUL-terminated copy the case owns and every value buffer
            // outlives `params`, which is built once and read once below; nothing mutates either
            // after a pointer to it is taken.
            unsafe {
                for (key, value) in case.octets.iter() {
                    params.push(OSSL_PARAM_construct_octet_string(
                        key.as_ptr().cast(),
                        value.as_ptr().cast_mut().cast(),
                        value.len(),
                    ));
                }
                for (key, value) in case.u32s.iter_mut() {
                    params.push(OSSL_PARAM_construct_uint32(key.as_ptr().cast(), value));
                }
                params.push(OSSL_PARAM_construct_end());

                if let Some(n) = case.threads {
                    assert_eq!(OSSL_set_max_threads(libctx, n), 1, "Threads = {n}");
                }

                let kdf = EVP_KDF_fetch(libctx, case.alg.as_ptr().cast(), core::ptr::null());
                assert!(!kdf.is_null(), "the row fetches from a fresh context");
                let kctx = EVP_KDF_CTX_new(kdf);
                assert!(!kctx.is_null(), "a derivation context");

                let len = if case.refused { 32 } else { case.output.len() };
                let mut out = vec![0u8; len];
                let ret = EVP_KDF_derive(kctx, out.as_mut_ptr(), len, params.as_ptr());

                if case.refused {
                    assert_eq!(ret, 0, "a bound case is refused");
                    refused += 1;
                } else {
                    assert_eq!(ret, 1, "a vector derives");
                    assert_eq!(out, case.output, "the derived bytes");
                    derived += 1;
                }

                EVP_KDF_CTX_free(kctx);
                EVP_KDF_free(kdf);
            }

            // SAFETY: `libctx` is this iteration's own fresh context and nothing below it is
            // live once the block above has released the KDF and its context.
            unsafe { OSSL_LIB_CTX_free(libctx) };
        }

        assert_eq!(derived, 12, "the file's derivable cases");
        assert_eq!(refused, 11, "the file's bound cases");
    }
}
