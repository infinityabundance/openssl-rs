//! Phase 8.3 — the default provider's MAC rows: `providers/implementations/macs/cmac_prov.c`
//! (the `CMAC` row), `siphash_prov.c` (`SIPHASH`), `hmac_prov.c` (`HMAC`) and `gmac_prov.c`
//! (`GMAC`, transcribed here and registered in D419).
//!
//! **Why these rows land with the ciphers rather than with a MAC stratum.** CMAC is the first
//! `OSSL_OP_MAC` row anything in this crate needs: `crypto/modes/siv128.c` implements RFC 5297's
//! S2V with `EVP_MAC_fetch(…, "CMAC", …)`, and D239 measured that the crate published no
//! `OSSL_OP_MAC` row at all, so `EVP_MAC_fetch(NULL, "CMAC", NULL)` answered 0 where the
//! authority answers 1. The rows are Phase 8's own obligation — `deflt_macs[]`'s nine rows are
//! `open`/`owning_phase: 8` in `forensics/atlas/provider-algorithms.json` — so the SIV rows wait
//! on CMAC rather than on another stratum. **GMAC's engine was transcribed in the same unit while
//! its registration was held**, and the holding was a measurement rather than a caution:
//! `gmac_set_ctx_params` resolves a `cipher` name and then refuses every mode but
//! `EVP_CIPH_GCM_MODE`, and this profile's only GCM ciphers are `AES-{128,192,256}-GCM`, which were
//! themselves Phase 9's on `RAND_bytes_ex` (D234). Publishing the row then would have made
//! `EVP_MAC_fetch(NULL, "GMAC", NULL)` answer 1 on both sides and then made every `EVP_MAC_init`
//! fail where the authority succeeds -- worse than not publishing it, because the difference would
//! be invisible to a fetch-only observation (D243). **The GCM ciphers landed in D417, so the row is
//! registered in D419** and `RT-CIPHER`'s `rt_deflt_gmac` arm drives it end to end.
//!
//! **`HMAC` is the row with a real engine behind it.** It is the third of HMAC's three units and
//! the reason this stratum took `ssl3_cbc_digest_record` (D251), `PROV_DIGEST` (D249) and
//! `constant_time.h`'s helpers (D250) ahead of itself: the row is a shell over
//! `crypto/hmac/hmac.c`, and what it adds is the `tls-data-size` arm — a state machine where the
//! first `update` is a stored 13-byte record header and the second is the record body whose MAC is
//! computed in constant time. Nothing else in the crate reaches that function, which is why an
//! ordinary HMAC comparison would not have observed it at all.
//!
//! **A row is a shell over landed machinery.** `CMAC_CTX_new`/`_free`/`_copy`/
//! `_get0_cipher_ctx`, `CMAC_Init`/`Update`/`Final` and `ossl_cmac_init` are `src/mac/cmac.rs`'s,
//! transcribed in Phase 7 with the deprecated public API and courted by `RT-CMAC`; GMAC is a
//! shell over `EVP_CIPHER`'s GCM path, so its tag comes from `EVP_EncryptFinal_ex` plus
//! `EVP_CIPHER_CTX_get_params(OSSL_CIPHER_PARAM_AEAD_TAG)` and not from GHASH directly. What
//! these units add is the two things a provider row owns: the `OSSL_FUNC_MAC_*` dispatch table,
//! and the *parameterisation* — `cmac_set_ctx_params` and `gmac_set_ctx_params` turn a `cipher`
//! **name** into an `EVP_CIPHER` through `ossl_prov_cipher_load` in
//! `PROV_LIBCTX_OF(macctx->provctx)`, which is why `src/provider/util.rs` and
//! `src/provider/ctx.rs` land beside them.
//!
//! **The two rows are not the same shape, and the difference is transcription rather than taste.**
//! `CMAC` publishes `GETTABLE_CTX_PARAMS`/`GET_CTX_PARAMS` (`block-size`, `size`); `GMAC`
//! publishes the **provider-level** `GETTABLE_PARAMS`/`GET_PARAMS` (`size` only) and has no
//! ctx-params getter at all. `GMAC` also takes an `iv`, applies it through
//! `EVP_CTRL_AEAD_SET_IVLEN` and a second `EVP_EncryptInit_ex`, and applies a `key` **after** the
//! cipher and the IV, where CMAC returns as soon as it has seen one.
//!
//! **`BLAKE2BMAC` and `BLAKE2SMAC` are one row written twice.** The authority's implementation is
//! `blake2_mac_impl.c`, and `blake2b_mac.c`/`blake2s_mac.c` are thirty-four-line `#define`
//! preambles that `#include` it — so the two rows differ only in the substitutions the C makes, and
//! `blake2_mac_row!` is the transcription of those `#define`s rather than a convenience. Three
//! things about the row are easy to get wrong: the context reports a **non-zero size before
//! anything is set**, because the parameter block's first byte *is* the digest length; a key
//! shorter than `KEYBYTES` is zero-padded into a full-width buffer and then fed as one whole
//! *block*, so the padding is part of what is hashed; and `custom`/`salt` are read out of the
//! descriptor directly, bounded by their own widths, because `OSSL_PARAM` has no setter for a
//! fixed-width field.
//!
//! **The FIPS arms are absent, and they are absent from the authority's own build too.** Every
//! `OSSL_FIPS_IND_*` macro is a no-op or a literal `1` when `FIPS_MODULE` is undefined
//! (`providers/fips/include/fips/fipsindicator.h`'s `#else` block), and the generated decoders
//! `# if defined(FIPS_MODULE)`-guard the two `fips` keys, so this profile's `cmac_prov.c` has:
//! two get-decoder keys (`block-size`, `size`), four set-decoder keys (`cipher`, `engine`, `key`,
//! `properties`), no `tdes_check_param`, and no `EVP_CIPHER_is_a` allow-list. `gmac_prov.c` has
//! one get-decoder key (`size`) and five set-decoder keys (`cipher`, `engine`, `iv`, `key`,
//! `properties`); `hmac_prov.c` has three get-decoder keys (`block-size`, `fips-indicator`,
//! `size`) and six set-decoder keys (`digest`, `engine`, `fips-key-check`, `key`, `properties`,
//! `tls-data-size`). Every raise site that remains reachable in either unit is transcribed, and
//! the courts drain the queues the refusals leave.
//!
//! **The published parameter lists are observable, and this module's lists are checked against the
//! authority's own descriptors.** `EVP_MAC_CTX_gettable_params`, `_settable_params` and
//! `EVP_MAC_gettable_params` hand a caller the array, and a caller reads `data_size` as well as
//! `data_type` and the key. The constructors in `src/provider/cipher.rs` mirror the authority's
//! macros one-for-one for that reason, and `RT-CIPHER` prints every entry of every published list
//! (D253).
//!
//! SPDX-License-Identifier: Apache-2.0

// `ossl_cmac_functions` is the authority's own name for the `CMAC` row's dispatch table --
// non-`static` in `cmac_prov.c.in` and declared in the uninstalled `prov/implementations.h`, so
// the plan can promise it and `plan_reconciliation.py` has to be able to see it built (D420).
#![allow(non_upper_case_globals)]

use core::ffi::{c_char, c_int, c_uchar, c_uint, c_void};
use core::ptr;

use crate::context::dispatch::{OsslDispatch, OSSL_DISPATCH_END};
use crate::evp::cipher::EVP_CIPHER_get_mode;
use crate::evp::cipher_ctx::{
    EVP_CIPHER_CTX_copy, EVP_CIPHER_CTX_ctrl, EVP_CIPHER_CTX_free, EVP_CIPHER_CTX_get0_cipher,
    EVP_CIPHER_CTX_get_block_size, EVP_CIPHER_CTX_get_key_length, EVP_CIPHER_CTX_get_params,
    EVP_CIPHER_CTX_new, EVP_EncryptFinal_ex, EVP_EncryptInit_ex, EVP_EncryptUpdate, EvpCipherCtx,
};
/// `EVP_MD_CTX_new`, `EVP_MD_CTX_free`, `EVP_MD_CTX_copy`, `EVP_DigestInit_ex`, `EVP_DigestUpdate`
/// and `EVP_DigestFinalXOF` arrive with this unit: KMAC is the first MAC row that is a **shell over
/// the EVP digest layer** rather than over a primitive, so it is the first to drive a digest context
/// from a provider row.
use crate::evp::digest::{
    EVP_DigestFinalXOF, EVP_DigestInit_ex, EVP_DigestUpdate, EVP_MD_CTX_copy, EVP_MD_CTX_free,
    EVP_MD_CTX_new, EVP_MD_get_block_size, EVP_MD_get_size, EvpMdCtx,
};
use crate::evp::mac::{
    OSSL_FUNC_MAC_DUPCTX, OSSL_FUNC_MAC_FINAL, OSSL_FUNC_MAC_FREECTX,
    OSSL_FUNC_MAC_GETTABLE_CTX_PARAMS, OSSL_FUNC_MAC_GETTABLE_PARAMS, OSSL_FUNC_MAC_GET_CTX_PARAMS,
    OSSL_FUNC_MAC_GET_PARAMS, OSSL_FUNC_MAC_INIT, OSSL_FUNC_MAC_NEWCTX,
    OSSL_FUNC_MAC_SETTABLE_CTX_PARAMS, OSSL_FUNC_MAC_SET_CTX_PARAMS, OSSL_FUNC_MAC_UPDATE,
};
use crate::mac::cmac::{
    ossl_cmac_init, CMAC_CTX_copy, CMAC_CTX_free, CMAC_CTX_get0_cipher_ctx, CMAC_CTX_new,
    CMAC_Final, CMAC_Init, CMAC_Update, CmacCtx,
};
use crate::mac::hmac::{
    HMAC_CTX_copy, HMAC_CTX_free, HMAC_CTX_new, HMAC_Final, HMAC_Init_ex, HMAC_Update, HMAC_size,
    HmacCtx,
};
use crate::mac::poly1305::{
    Poly1305, Poly1305_Final, Poly1305_Init, Poly1305_Update, POLY1305_DIGEST_SIZE,
    POLY1305_KEY_SIZE,
};
use crate::mac::siphash::{
    SipHash_Final, SipHash_Init, SipHash_Update, SipHash_hash_size, SipHash_set_hash_size, Siphash,
    SIPHASH_C_ROUNDS, SIPHASH_D_ROUNDS, SIPHASH_KEY_SIZE,
};
use crate::mac::ssl3_cbc::ssl3_cbc_digest_record;
use crate::params::{OsslParam, END, OSSL_PARAM_OCTET_STRING};
use crate::provider::activate::OsslAlgorithm;
use crate::provider::cipher::{
    param_int, param_octet_string, param_octet_string_with, param_size_t, param_uint,
    param_utf8_string, param_utf8_string_with, repeated_param_site,
};
use crate::provider::ctx::prov_libctx_of;
use crate::provider::util::prov_digest::{
    ossl_prov_digest_copy, ossl_prov_digest_engine, ossl_prov_digest_load,
    ossl_prov_digest_load_from_params, ossl_prov_digest_md, ossl_prov_digest_reset, ProvDigest,
};
use crate::provider::util::{
    ossl_prov_cipher_cipher, ossl_prov_cipher_copy, ossl_prov_cipher_engine, ossl_prov_cipher_load,
    ossl_prov_cipher_reset, ProvCipher, OSSL_ALG_PARAM_DIGEST,
};
use crate::runtime::err::{err_sites, raise_site};
use crate::runtime::mem::{cleanse, CRYPTO_clear_free, CRYPTO_free, CRYPTO_malloc, CRYPTO_zalloc};

/// The allocation-tracking `file` argument for CMAC's allocations.
///
/// **No `../../src/openssl-3.6.4/` prefix**, because `cmac_prov.c` is generated from
/// `cmac_prov.c.in` and the compiler spells a generated file with its build-relative path only —
/// D235's finding, and the same one `FILE_HMAC`'s note records. The three `FILE_*` constants here,
/// `FILE_GMAC` and `FILE_SIPHASH` carried the prefix and this commit corrects them; the unit test
/// below compares each against the `file` of a raise site in the same authority unit, which is the
/// same `__FILE__` and therefore the same string.
///
/// The argument is inert on this profile in the sense that `OPENSSL_NO_CRYPTO_MDEBUG` means no
/// allocator records it — but it is not unobservable: `CRYPTO_set_mem_functions` hands an
/// application's own allocator the `file` pointer, and an application may compare it. So the string
/// is contract, which is why the constants exist rather than being folded into `LINE`'s `` "" `` .
const FILE: *const c_char = c"providers/implementations/macs/cmac_prov.c".as_ptr();
/// `__LINE__`, inert under `OPENSSL_NO_CRYPTO_MDEBUG`.
const LINE: c_int = 0;

/// `OSSL_OP_MAC` — `include/openssl/core_dispatch.h`.
pub(crate) const OSSL_OP_MAC: c_int = 3;

/// `OSSL_MAC_PARAM_SIZE` — `core_names.h:353` (`"size"`).
const OSSL_MAC_PARAM_SIZE: *const c_char = c"size".as_ptr();
/// `OSSL_MAC_PARAM_BLOCK_SIZE` — `core_names.h:338` (`"block-size"`).
const OSSL_MAC_PARAM_BLOCK_SIZE: *const c_char = c"block-size".as_ptr();
/// `OSSL_MAC_PARAM_CIPHER` — `core_names.h:339`, aliased to `OSSL_ALG_PARAM_CIPHER`.
const OSSL_MAC_PARAM_CIPHER: *const c_char = c"cipher".as_ptr();
/// `OSSL_MAC_PARAM_KEY` — `core_names.h:350` (`"key"`).
const OSSL_MAC_PARAM_KEY: *const c_char = c"key".as_ptr();
/// `OSSL_MAC_PARAM_PROPERTIES` — `core_names.h:351`, aliased to `OSSL_ALG_PARAM_PROPERTIES`.
const OSSL_MAC_PARAM_PROPERTIES: *const c_char = c"properties".as_ptr();
/// `OSSL_ALG_PARAM_ENGINE` — `core_names.h:129` (`"engine"`), a decoder key and deliberately
/// **not** a settable-list entry (`provider_util.h`'s `hidden` form in the generation spec).
const OSSL_ALG_PARAM_ENGINE: *const c_char = c"engine".as_ptr();
/// `EVP_CIPH_CBC_MODE` — `include/openssl/evp.h:315`. CMAC is defined over a CBC block cipher
/// and nothing else, so the row refuses every other mode with `PROV_R_INVALID_MODE`.
const EVP_CIPH_CBC_MODE: c_int = 2;

/// `int ossl_prov_is_running(void)` — `providers/prov_running.c`, as the cipher and digest halves
/// already spell it: the default provider is always in a happy state on this build.
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

/// `struct cmac_data_st` — `cmac_prov.c:55-60`. `OSSL_FIPS_IND_DECLARE` contributes no field when
/// `FIPS_MODULE` is undefined, so the three fields are the whole struct in this profile.
#[repr(C)]
pub(crate) struct CmacData {
    /// `void *provctx` — the creating provider's context, which `ctx` is derived from.
    pub provctx: *mut c_void,
    /// `CMAC_CTX *ctx`.
    pub ctx: *mut CmacCtx,
    /// `PROV_CIPHER cipher` — the construct's cipher, resolved from a *name*.
    pub cipher: ProvCipher,
}

/// The two keys `cmac_get_ctx_params_decoder` locates in this profile, each with the site of its
/// own repeated-parameter raise (`cmac_prov.c:245`, `:269`). The third key the authority's
/// generator emits, `fips-indicator`, is `# if defined(FIPS_MODULE)`-guarded and absent here.
const CMAC_GET_CTX_PARAMS_DECODER_KEYS: [(&err_sites::ErrSite, *const c_char); 2] = [
    (&err_sites::PROV_CMAC_PROV_245, OSSL_MAC_PARAM_BLOCK_SIZE),
    (&err_sites::PROV_CMAC_PROV_269, OSSL_MAC_PARAM_SIZE),
];

/// The four keys `cmac_set_ctx_params_decoder` locates in this profile, each with its raise site
/// (`cmac_prov.c:350`, `:382`, `:395`, `:406`). `encrypt-check` is the FIPS-guarded fifth.
const CMAC_SET_CTX_PARAMS_DECODER_KEYS: [(&err_sites::ErrSite, *const c_char); 4] = [
    (&err_sites::PROV_CMAC_PROV_350, OSSL_MAC_PARAM_CIPHER),
    (&err_sites::PROV_CMAC_PROV_382, OSSL_ALG_PARAM_ENGINE),
    (&err_sites::PROV_CMAC_PROV_395, OSSL_MAC_PARAM_KEY),
    (&err_sites::PROV_CMAC_PROV_406, OSSL_MAC_PARAM_PROPERTIES),
];

/// `static void *cmac_new(void *provctx)` — `cmac_prov.c:62-79`. Both allocations are checked
/// against one release: a `CMAC_CTX_new` failure frees the zalloc'd block, and a zalloc failure
/// makes the `OPENSSL_free` a no-op.
///
/// # Safety
/// The dispatch contract.
unsafe extern "C" fn cmac_new(provctx: *mut c_void) -> *mut c_void {
    // SAFETY: the caller's contract.
    unsafe {
        if is_running() == 0 {
            return ptr::null_mut();
        }

        let macctx = CRYPTO_zalloc(core::mem::size_of::<CmacData>(), FILE, LINE).cast::<CmacData>();
        if macctx.is_null() {
            return ptr::null_mut();
        }
        (*macctx).ctx = CMAC_CTX_new();
        if (*macctx).ctx.is_null() {
            CRYPTO_free(macctx.cast(), FILE, LINE);
            return ptr::null_mut();
        }
        (*macctx).provctx = provctx;
        macctx.cast()
    }
}

/// `static void cmac_free(void *vmacctx)` — `cmac_prov.c:81-90`. The `PROV_CIPHER` is reset as
/// well as freed: it may hold a *looked-up* cipher as well as a fetched one, and only the fetched
/// reference is the row's to release.
///
/// # Safety
/// The dispatch contract.
unsafe extern "C" fn cmac_free(vmacctx: *mut c_void) {
    // SAFETY: the caller's contract; `vmacctx` is a context `cmac_new` allocated.
    unsafe {
        if !vmacctx.is_null() {
            let macctx = vmacctx.cast::<CmacData>();
            CMAC_CTX_free((*macctx).ctx);
            ossl_prov_cipher_reset(ptr::addr_of_mut!((*macctx).cipher));
            CRYPTO_free(vmacctx, FILE, LINE);
        }
    }
}

/// `static void *cmac_dup(void *vsrc)` — `cmac_prov.c:92-110`.
///
/// # Safety
/// The dispatch contract.
unsafe extern "C" fn cmac_dup(vsrc: *mut c_void) -> *mut c_void {
    // SAFETY: the caller's contract.
    unsafe {
        let src = vsrc.cast::<CmacData>();

        if is_running() == 0 {
            return ptr::null_mut();
        }

        let dst = cmac_new((*src).provctx).cast::<CmacData>();
        if dst.is_null() {
            return ptr::null_mut();
        }
        if CMAC_CTX_copy((*dst).ctx, (*src).ctx) == 0
            || ossl_prov_cipher_copy(
                ptr::addr_of_mut!((*dst).cipher),
                ptr::addr_of!((*src).cipher),
            ) == 0
        {
            cmac_free(dst.cast());
            return ptr::null_mut();
        }
        dst.cast()
    }
}

/// `static size_t cmac_size(void *vmacctx)` — `cmac_prov.c:112-121`. A context with no cipher
/// answers 0 rather than the block size of nothing.
///
/// # Safety
/// The dispatch contract.
unsafe fn cmac_size(vmacctx: *mut c_void) -> usize {
    // SAFETY: the caller's contract.
    unsafe {
        let macctx = vmacctx.cast::<CmacData>();
        let cipherctx: *const EvpCipherCtx = CMAC_CTX_get0_cipher_ctx((*macctx).ctx);

        if EVP_CIPHER_CTX_get0_cipher(cipherctx).is_null() {
            return 0;
        }

        EVP_CIPHER_CTX_get_block_size(cipherctx) as usize
    }
}

/// `static int cmac_setkey(struct cmac_data_st *macctx, const unsigned char *key,
/// size_t keylen)` — `cmac_prov.c:155-174` without its FIPS arm.
///
/// The `PROV_CIPHER` is reset **after** the init whether it succeeded or not, which is what makes
/// the cipher a per-init parameter rather than per-context state.
///
/// # Safety
/// `key` is readable for `keylen` bytes.
unsafe fn cmac_setkey(macctx: *mut CmacData, key: *const c_uchar, keylen: usize) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        let rv = ossl_cmac_init(
            (*macctx).ctx,
            key.cast(),
            keylen,
            ossl_prov_cipher_cipher(ptr::addr_of!((*macctx).cipher)),
            ossl_prov_cipher_engine(ptr::addr_of!((*macctx).cipher)),
            ptr::null(),
        );
        ossl_prov_cipher_reset(ptr::addr_of_mut!((*macctx).cipher));
        rv
    }
}

/// `static const OSSL_PARAM cmac_get_ctx_params_list[]` — `cmac_prov.c:209-216`, the two keys
/// this profile's generator emits.
static CMAC_GETTABLE_CTX_PARAMS: [OsslParam; 3] = [
    param_size_t(OSSL_MAC_PARAM_SIZE),
    param_size_t(OSSL_MAC_PARAM_BLOCK_SIZE),
    END,
];

/// `static const OSSL_PARAM *cmac_gettable_ctx_params(void *ctx, void *provctx)` —
/// `cmac_prov.c:216-220`.
///
/// # Safety
/// The dispatch contract.
unsafe extern "C" fn cmac_gettable_ctx_params(
    _ctx: *mut c_void,
    _provctx: *mut c_void,
) -> *const OsslParam {
    CMAC_GETTABLE_CTX_PARAMS.as_ptr()
}

/// `static int cmac_get_ctx_params(void *vmacctx, OSSL_PARAM params[])` — `cmac_prov.c:222-240`.
/// Both keys answer the *same* number, which is the CMAC construction's block size rather than
/// the tag length: the tag is one block.
///
/// # Safety
/// The dispatch contract.
unsafe extern "C" fn cmac_get_ctx_params(vmacctx: *mut c_void, params: *mut OsslParam) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        if vmacctx.is_null() {
            return 0;
        }
        if let Some(site) = repeated_param_site(params, &CMAC_GET_CTX_PARAMS_DECODER_KEYS) {
            return fail_at(site);
        }

        let p = crate::params::OSSL_PARAM_locate(params, OSSL_MAC_PARAM_SIZE);
        if !p.is_null() && crate::params::OSSL_PARAM_set_size_t(p, cmac_size(vmacctx)) == 0 {
            return 0;
        }
        let p = crate::params::OSSL_PARAM_locate(params, OSSL_MAC_PARAM_BLOCK_SIZE);
        if !p.is_null() && crate::params::OSSL_PARAM_set_size_t(p, cmac_size(vmacctx)) == 0 {
            return 0;
        }
        1
    }
}

/// `static const OSSL_PARAM cmac_set_ctx_params_list[]` — `cmac_prov.c:311-319`, the three keys
/// this profile's generator emits. `engine` is **not** here: it is a `hidden` decoder key.
static CMAC_SETTABLE_CTX_PARAMS: [OsslParam; 4] = [
    param_utf8_string(OSSL_MAC_PARAM_CIPHER),
    param_utf8_string(OSSL_MAC_PARAM_PROPERTIES),
    param_octet_string(OSSL_MAC_PARAM_KEY),
    END,
];

/// `static const OSSL_PARAM *cmac_settable_ctx_params(void *ctx, void *provctx)` —
/// `cmac_prov.c:252-256`.
///
/// # Safety
/// The dispatch contract.
unsafe extern "C" fn cmac_settable_ctx_params(
    _ctx: *mut c_void,
    _provctx: *mut c_void,
) -> *const OsslParam {
    CMAC_SETTABLE_CTX_PARAMS.as_ptr()
}

/// `static int cmac_set_ctx_params(void *vmacctx, const OSSL_PARAM params[])` —
/// `cmac_prov.c:261-306` without its FIPS arm.
///
/// Three things are contract: the `cipher` arm resolves the name in
/// `PROV_LIBCTX_OF(macctx->provctx)` — the provider's own library context, not the global one —
/// and then refuses any mode but CBC with a *raised* `PROV_R_INVALID_MODE`; a `key` descriptor of
/// the wrong type is a bare `return 0` with no raise; and a `key` **is** applied here, so
/// `EVP_MAC_init` with both a cipher and a key sets them in one call.
///
/// # Safety
/// The dispatch contract.
unsafe extern "C" fn cmac_set_ctx_params(vmacctx: *mut c_void, params: *const OsslParam) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        if vmacctx.is_null() {
            return 0;
        }
        if let Some(site) = repeated_param_site(params, &CMAC_SET_CTX_PARAMS_DECODER_KEYS) {
            return fail_at(site);
        }

        let macctx = vmacctx.cast::<CmacData>();
        let ctx = prov_libctx_of((*macctx).provctx);

        let p = crate::params::OSSL_PARAM_locate_const(params, OSSL_MAC_PARAM_CIPHER);
        if !p.is_null() {
            let propq = crate::params::OSSL_PARAM_locate_const(params, OSSL_MAC_PARAM_PROPERTIES);
            let engine = crate::params::OSSL_PARAM_locate_const(params, OSSL_ALG_PARAM_ENGINE);

            if ossl_prov_cipher_load(ptr::addr_of_mut!((*macctx).cipher), p, propq, engine, ctx)
                == 0
            {
                return 0;
            }

            if EVP_CIPHER_get_mode(ossl_prov_cipher_cipher(ptr::addr_of!((*macctx).cipher)))
                != EVP_CIPH_CBC_MODE
            {
                return fail_at(&err_sites::PROV_CMAC_PROV_449);
            }
        }

        let p = crate::params::OSSL_PARAM_locate_const(params, OSSL_MAC_PARAM_KEY);
        if !p.is_null() {
            if (*p).data_type != OSSL_PARAM_OCTET_STRING {
                return 0;
            }
            return cmac_setkey(macctx, (*p).data.cast::<c_uchar>(), (*p).data_size);
        }
        1
    }
}

/// `static int cmac_init(void *vmacctx, const unsigned char *key, size_t keylen,
/// const OSSL_PARAM params[])` — `cmac_prov.c:176-187`.
///
/// The `key == NULL` arm is `CMAC_Init(ctx, NULL, 0, NULL, NULL)`, which *re-initialises* the
/// construct rather than failing, and it is the arm a caller reaches by calling
/// `EVP_MAC_init` twice.
///
/// # Safety
/// The dispatch contract.
unsafe extern "C" fn cmac_init(
    vmacctx: *mut c_void,
    key: *const c_uchar,
    keylen: usize,
    params: *const OsslParam,
) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        if is_running() == 0 || cmac_set_ctx_params(vmacctx, params) == 0 {
            return 0;
        }
        if !key.is_null() {
            return cmac_setkey(vmacctx.cast::<CmacData>(), key, keylen);
        }
        /* Reinitialize the CMAC context */
        CMAC_Init(
            (*vmacctx.cast::<CmacData>()).ctx,
            ptr::null(),
            0,
            ptr::null(),
            ptr::null_mut(),
        )
    }
}

/// `static int cmac_update(void *vmacctx, const unsigned char *data, size_t datalen)` —
/// `cmac_prov.c:189-195`.
///
/// # Safety
/// The dispatch contract.
unsafe extern "C" fn cmac_update(
    vmacctx: *mut c_void,
    data: *const c_uchar,
    datalen: usize,
) -> c_int {
    // SAFETY: the caller's contract.
    unsafe { CMAC_Update((*vmacctx.cast::<CmacData>()).ctx, data.cast(), datalen) }
}

/// `static int cmac_final(void *vmacctx, unsigned char *out, size_t *outl, size_t outsize)` —
/// `cmac_prov.c:197-206`. The running check precedes the final, so a stopped provider refuses
/// *before* the tag is written.
///
/// # Safety
/// The dispatch contract.
unsafe extern "C" fn cmac_final(
    vmacctx: *mut c_void,
    out: *mut c_uchar,
    outl: *mut usize,
    _outsize: usize,
) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        if is_running() == 0 {
            return 0;
        }
        CMAC_Final((*vmacctx.cast::<CmacData>()).ctx, out, outl)
    }
}

/// `const OSSL_DISPATCH ossl_cmac_functions[]` — `cmac_prov.c:308-322`, ten entries.
pub(crate) static ossl_cmac_functions: [OsslDispatch; 11] = [
    OsslDispatch {
        function_id: OSSL_FUNC_MAC_NEWCTX,
        function: cmac_new as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_MAC_DUPCTX,
        function: cmac_dup as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_MAC_FREECTX,
        function: cmac_free as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_MAC_INIT,
        function: cmac_init as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_MAC_UPDATE,
        function: cmac_update as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_MAC_FINAL,
        function: cmac_final as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_MAC_GETTABLE_CTX_PARAMS,
        function: cmac_gettable_ctx_params as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_MAC_GET_CTX_PARAMS,
        function: cmac_get_ctx_params as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_MAC_SETTABLE_CTX_PARAMS,
        function: cmac_settable_ctx_params as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_MAC_SET_CTX_PARAMS,
        function: cmac_set_ctx_params as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_DISPATCH_END,
        function: ptr::null_mut(),
    },
];

/// `static const OSSL_ALGORITHM deflt_macs[]` — `providers/defltprov.c:334-353`, restricted to
/// the rows this half implements, **in the authority's order**. `deflt_macs[]` carries nine rows
/// (`BLAKE2BMAC`, `BLAKE2SMAC`, `CMAC`, `GMAC`, `HMAC`, `KMAC-128`, `KMAC-256`, `SIPHASH`,
/// `POLY1305`), so the eight rows here are the authority's first, second, third, fifth, sixth,
/// seventh, eighth and ninth and are **not** appended: the census checks that what this table
/// publishes is a *subsequence* of the authority's order (D244). GMAC is `deferred` to Phase 9 with
/// its blocker named (D243) and its engine is transcribed, so it is the one row of the nine that is
/// absent — and the census's exact accounting is what keeps all of that true.
///
/// **The property definition is `"provider=default"` on every row.** `defltprov.c`'s `ALG` macro
/// expands through `ALGC(NAMES, FUNC, CHECK) { { NAMES, "provider=default", FUNC }, CHECK }`, and
/// D247 is what a NULL there cost: a fetch whose property query is `provider=default` stopped
/// resolving, and `provider!=default` resolved when it should not have.
pub(crate) static DEFLT_MACS: [OsslAlgorithm; 10] = [
    OsslAlgorithm {
        // `PROV_NAMES_BLAKE2BMAC` — `prov/names.h:322`. The OID is part of the row: the
        // census compares the whole alias sequence, not the primary name (D244).
        algorithm_names: c"BLAKE2BMAC:1.3.6.1.4.1.1722.12.2.1".as_ptr(),
        property_definition: c"provider=default".as_ptr(),
        implementation: blake2b_mac::FUNCTIONS.as_ptr().cast(),
        algorithm_description: ptr::null(),
    },
    OsslAlgorithm {
        // `PROV_NAMES_BLAKE2SMAC` — `prov/names.h:323`.
        algorithm_names: c"BLAKE2SMAC:1.3.6.1.4.1.1722.12.2.2".as_ptr(),
        property_definition: c"provider=default".as_ptr(),
        implementation: blake2s_mac::FUNCTIONS.as_ptr().cast(),
        algorithm_description: ptr::null(),
    },
    OsslAlgorithm {
        algorithm_names: c"CMAC".as_ptr(),
        property_definition: c"provider=default".as_ptr(),
        implementation: ossl_cmac_functions.as_ptr().cast(),
        algorithm_description: ptr::null(),
    },
    OsslAlgorithm {
        // `PROV_NAMES_GMAC` — `prov/names.h:319`. It carries the `1.0.9797.3.4` OID and no `id-`
        // spelling, and it sits between CMAC and HMAC in `defltprov.c:342`, where it was held
        // until the GCM ciphers it resolves landed (`src/provider/cipher_gcm.rs`).
        algorithm_names: c"GMAC:1.0.9797.3.4".as_ptr(),
        property_definition: c"provider=default".as_ptr(),
        implementation: GMAC_FUNCTIONS.as_ptr().cast(),
        algorithm_description: ptr::null(),
    },
    OsslAlgorithm {
        algorithm_names: c"HMAC".as_ptr(),
        property_definition: c"provider=default".as_ptr(),
        implementation: HMAC_FUNCTIONS.as_ptr().cast(),
        algorithm_description: ptr::null(),
    },
    OsslAlgorithm {
        // `PROV_NAMES_KMAC_128` — `prov/names.h:320`, the full alias sequence with its OID.
        algorithm_names: c"KMAC-128:KMAC128:2.16.840.1.101.3.4.2.19".as_ptr(),
        property_definition: c"provider=default".as_ptr(),
        implementation: KMAC128_FUNCTIONS.as_ptr().cast(),
        algorithm_description: ptr::null(),
    },
    OsslAlgorithm {
        // `PROV_NAMES_KMAC_256` — `prov/names.h:321`.
        algorithm_names: c"KMAC-256:KMAC256:2.16.840.1.101.3.4.2.20".as_ptr(),
        property_definition: c"provider=default".as_ptr(),
        implementation: KMAC256_FUNCTIONS.as_ptr().cast(),
        algorithm_description: ptr::null(),
    },
    OsslAlgorithm {
        algorithm_names: c"SIPHASH".as_ptr(),
        property_definition: c"provider=default".as_ptr(),
        implementation: SIPHASH_FUNCTIONS.as_ptr().cast(),
        algorithm_description: ptr::null(),
    },
    OsslAlgorithm {
        // `PROV_NAMES_POLY1305` — `prov/names.h`, which is the primary name alone: this row
        // carries no alias and no OID, unlike the two BLAKE2 rows (D256).
        //
        // It is the **last** row in `deflt_macs[]` (`defltprov.c:349-351`), after SIPHASH -- the
        // census rejects a candidate order that is not a subsequence of the authority's, and it
        // did reject this pair when POLY1305 came first here. The order is part of the row
        // identity, which is why it is stated rather than left to how the rows happen to be
        // written.
        algorithm_names: c"POLY1305".as_ptr(),
        property_definition: c"provider=default".as_ptr(),
        implementation: POLY1305_FUNCTIONS.as_ptr().cast(),
        algorithm_description: ptr::null(),
    },
    OsslAlgorithm {
        algorithm_names: ptr::null(),
        property_definition: ptr::null(),
        implementation: ptr::null(),
        algorithm_description: ptr::null(),
    },
];

/// `OSSL_MAC_PARAM_IV` — `core_names.h:344` (`"iv"`).
const OSSL_MAC_PARAM_IV: *const c_char = c"iv".as_ptr();
/// `OSSL_MAC_PARAM_C_ROUNDS` — `core_names.h:341` (`"c-rounds"`).
const OSSL_MAC_PARAM_C_ROUNDS: *const c_char = c"c-rounds".as_ptr();
/// `OSSL_MAC_PARAM_D_ROUNDS` — `core_names.h:345` (`"d-rounds"`).
const OSSL_MAC_PARAM_D_ROUNDS: *const c_char = c"d-rounds".as_ptr();
/// `OSSL_CIPHER_PARAM_AEAD_TAG` — `core_names.h:179` (`"tag"`). Repeated rather than re-exported
/// for the reason `src/provider/util.rs` repeats `EVP_ORIG_GLOBAL`: it is a string, not a symbol.
const OSSL_CIPHER_PARAM_AEAD_TAG: *const c_char = c"tag".as_ptr();
/// `EVP_CTRL_AEAD_SET_IVLEN` — also `EVP_CTRL_GCM_SET_IVLEN`. `src/evp/cipher_ctx.rs:164`
/// declares it for the `ctrl` walk; it is repeated here the same way.
const EVP_CTRL_AEAD_SET_IVLEN: c_int = 0x9;
/// `EVP_CIPH_GCM_MODE` — `include/openssl/evp.h`. GMAC is defined over GCM and nothing else, so
/// the `cipher` arm refuses every other mode with `PROV_R_INVALID_MODE`.
const EVP_CIPH_GCM_MODE: c_int = 0x6;
/// `EVP_GCM_TLS_TAG_LEN` — `include/openssl/evp.h`'s sixteen, which is both `gmac_size()`'s answer
/// and the tag length `gmac_final` asks the cipher context for.
const EVP_GCM_TLS_TAG_LEN: usize = 16;

/// The allocation-tracking `file` argument for the GMAC row's allocations: `gmac_prov.c`.
const FILE_GMAC: *const c_char = c"providers/implementations/macs/gmac_prov.c".as_ptr();

/// `struct gmac_data_st` — `gmac_prov.c:48-52`. Three fields, and the middle one is why the row
/// is a shell over `EVP_CIPHER`'s GCM path rather than over GHASH directly.
#[repr(C)]
pub(crate) struct GmacData {
    /// `void *provctx` — the creating provider's context.
    pub provctx: *mut c_void,
    /// `EVP_CIPHER_CTX *ctx` — the cipher context the tag is read out of.
    pub ctx: *mut EvpCipherCtx,
    /// `PROV_CIPHER cipher` — the construct's cipher, resolved from a *name*.
    pub cipher: ProvCipher,
}

/// The one key `gmac_get_params_decoder` locates (`gmac_prov.c:200`), which is the only decoder
/// in this unit with a single key.
const GMAC_GET_PARAMS_DECODER_KEYS: [(&err_sites::ErrSite, *const c_char); 1] =
    [(&err_sites::PROV_GMAC_PROV_200, OSSL_MAC_PARAM_SIZE)];

/// The five keys `gmac_set_ctx_params_decoder` locates, in the order the generated `switch`
/// raises for them (`gmac_prov.c:264`, `:275`, `:286`, `:297`, `:308`): `cipher`, `engine`, `iv`,
/// `key`, `properties`. `engine` is a decoder key and deliberately **not** a settable-list entry.
const GMAC_SET_CTX_PARAMS_DECODER_KEYS: [(&err_sites::ErrSite, *const c_char); 5] = [
    (&err_sites::PROV_GMAC_PROV_268, OSSL_MAC_PARAM_CIPHER),
    (&err_sites::PROV_GMAC_PROV_279, OSSL_ALG_PARAM_ENGINE),
    (&err_sites::PROV_GMAC_PROV_290, OSSL_MAC_PARAM_IV),
    (&err_sites::PROV_GMAC_PROV_301, OSSL_MAC_PARAM_KEY),
    (&err_sites::PROV_GMAC_PROV_312, OSSL_MAC_PARAM_PROPERTIES),
];

/// `static void gmac_free(void *vmacctx)` — `gmac_prov.c:54-63`. NULL-tolerant, because `gmac_new`
/// calls it on the half-built context it is about to abandon.
///
/// # Safety
/// The dispatch contract; `vmacctx` NULL or a live `GmacData`.
unsafe extern "C" fn gmac_free(vmacctx: *mut c_void) {
    // SAFETY: the caller's contract.
    unsafe {
        if !vmacctx.is_null() {
            let macctx = vmacctx.cast::<GmacData>();
            EVP_CIPHER_CTX_free((*macctx).ctx);
            ossl_prov_cipher_reset(ptr::addr_of_mut!((*macctx).cipher));
            CRYPTO_free(vmacctx, FILE_GMAC, LINE);
        }
    }
}

/// `static void *gmac_new(void *provctx)` — `gmac_prov.c:65-80`.
///
/// # Safety
/// The dispatch contract.
unsafe extern "C" fn gmac_new(provctx: *mut c_void) -> *mut c_void {
    // SAFETY: the caller's contract.
    unsafe {
        if is_running() == 0 {
            return ptr::null_mut();
        }
        let macctx =
            CRYPTO_zalloc(core::mem::size_of::<GmacData>(), FILE_GMAC, LINE).cast::<GmacData>();
        if macctx.is_null() {
            return ptr::null_mut();
        }
        (*macctx).ctx = EVP_CIPHER_CTX_new();
        if (*macctx).ctx.is_null() {
            gmac_free(macctx.cast());
            return ptr::null_mut();
        }
        (*macctx).provctx = provctx;
        macctx.cast()
    }
}

/// `static void *gmac_dup(void *vsrc)` — `gmac_prov.c:82-100`. The duplicate is built by
/// `gmac_new` and then filled, so a failure anywhere frees the whole half-built context.
///
/// # Safety
/// The dispatch contract.
unsafe extern "C" fn gmac_dup(vsrc: *mut c_void) -> *mut c_void {
    // SAFETY: the caller's contract.
    unsafe {
        if is_running() == 0 {
            return ptr::null_mut();
        }
        let src = vsrc.cast::<GmacData>();
        let dst = gmac_new((*src).provctx).cast::<GmacData>();
        if dst.is_null() {
            return ptr::null_mut();
        }
        if EVP_CIPHER_CTX_copy((*dst).ctx, (*src).ctx) == 0
            || ossl_prov_cipher_copy(
                ptr::addr_of_mut!((*dst).cipher),
                ptr::addr_of!((*src).cipher),
            ) == 0
        {
            gmac_free(dst.cast());
            return ptr::null_mut();
        }
        dst.cast()
    }
}

/// `static size_t gmac_size(void)` — `gmac_prov.c:102-105`. It takes no context and answers the
/// constant, because a GCM tag is sixteen octets whatever the cipher's key length is.
fn gmac_size() -> usize {
    EVP_GCM_TLS_TAG_LEN
}

/// `static int gmac_setkey(struct gmac_data_st *macctx, const unsigned char *key,
/// size_t keylen)` — `gmac_prov.c:107-119`.
///
/// # Safety
/// `macctx` is live; `key` is readable for `keylen` bytes.
unsafe fn gmac_setkey(macctx: *mut GmacData, key: *const c_uchar, keylen: usize) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        let ctx = (*macctx).ctx;
        if keylen != EVP_CIPHER_CTX_get_key_length(ctx) as usize {
            return fail_at(&err_sites::PROV_GMAC_PROV_111);
        }
        if EVP_EncryptInit_ex(ctx, ptr::null(), ptr::null_mut(), key, ptr::null()) == 0 {
            return 0;
        }
        1
    }
}

/// `static int gmac_init(void *vmacctx, const unsigned char *key, size_t keylen,
/// const OSSL_PARAM params[])` — `gmac_prov.c:121-131`.
///
/// `key == NULL` is `EVP_EncryptInit_ex(ctx, NULL, NULL, NULL, NULL)`, which is how a caller that
/// has already set the key through `params` finishes the initialisation; it is *not* a refusal,
/// and it is the arm `EVP_MAC_init` reaches twice.
///
/// # Safety
/// The dispatch contract.
unsafe extern "C" fn gmac_init(
    vmacctx: *mut c_void,
    key: *const c_uchar,
    keylen: usize,
    params: *const OsslParam,
) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        if is_running() == 0 || gmac_set_ctx_params(vmacctx, params) == 0 {
            return 0;
        }
        let macctx = vmacctx.cast::<GmacData>();
        if !key.is_null() {
            return gmac_setkey(macctx, key, keylen);
        }
        EVP_EncryptInit_ex(
            (*macctx).ctx,
            ptr::null(),
            ptr::null_mut(),
            ptr::null(),
            ptr::null(),
        )
    }
}

/// `static int gmac_update(void *vmacctx, const unsigned char *data, size_t datalen)` —
/// `gmac_prov.c:133-150`.
///
/// The `INT_MAX` loop is the authority's, and it is why an empty update is answered before the
/// loop rather than by it: `EVP_EncryptUpdate` with a NULL output pointer is GCM's AAD path, and
/// the loop has to be able to make progress.
///
/// # Safety
/// The dispatch contract; `data` is readable for `datalen` bytes.
unsafe extern "C" fn gmac_update(
    vmacctx: *mut c_void,
    data: *const c_uchar,
    datalen: usize,
) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        if datalen == 0 {
            return 1;
        }
        let ctx = (*vmacctx.cast::<GmacData>()).ctx;
        let mut outlen: c_int = 0;
        let mut data = data;
        let mut datalen = datalen;
        while datalen > c_int::MAX as usize {
            if EVP_EncryptUpdate(ctx, ptr::null_mut(), &mut outlen, data, c_int::MAX) == 0 {
                return 0;
            }
            data = data.add(c_int::MAX as usize);
            datalen -= c_int::MAX as usize;
        }
        EVP_EncryptUpdate(ctx, ptr::null_mut(), &mut outlen, data, datalen as c_int)
    }
}

/// `static int gmac_final(void *vmacctx, unsigned char *out, size_t *outl, size_t outsize)` —
/// `gmac_prov.c:152-173`.
///
/// Two things are contract. `EVP_EncryptFinal_ex` is called **into `out`** even though a GCM
/// encryption final writes nothing, because its return value is the running check; and `hlen` is
/// then *overwritten* with `gmac_size()`, so the tag length is not the length the final reported.
/// `outsize` is unused, as it is on the authority's line.
///
/// # Safety
/// The dispatch contract; `out` is writable for sixteen bytes and `outl` is writable.
unsafe extern "C" fn gmac_final(
    vmacctx: *mut c_void,
    out: *mut c_uchar,
    outl: *mut usize,
    _outsize: usize,
) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        if is_running() == 0 {
            return 0;
        }
        let ctx = (*vmacctx.cast::<GmacData>()).ctx;
        let mut hlen: c_int = 0;
        if EVP_EncryptFinal_ex(ctx, out, &mut hlen) == 0 {
            return 0;
        }
        hlen = gmac_size() as c_int;
        let mut params: [OsslParam; 2] = [END, END];
        params[0] = crate::params::OSSL_PARAM_construct_octet_string(
            OSSL_CIPHER_PARAM_AEAD_TAG,
            out.cast(),
            hlen as usize,
        );
        if EVP_CIPHER_CTX_get_params(ctx, params.as_mut_ptr()) == 0 {
            return 0;
        }
        *outl = hlen as usize;
        1
    }
}

/// `static const OSSL_PARAM gmac_get_params_list[]` — `gmac_prov.c:176-179`. This is the
/// **provider-level** list (`OSSL_FUNC_MAC_GETTABLE_PARAMS`), not a ctx-params list: GMAC has one
/// and CMAC does not.
static GMAC_GETTABLE_PARAMS: [OsslParam; 2] = [param_size_t(OSSL_MAC_PARAM_SIZE), END];

/// `static const OSSL_PARAM *gmac_gettable_params(void *provctx)` — `gmac_prov.c:181-184`.
///
/// # Safety
/// The dispatch contract.
unsafe extern "C" fn gmac_gettable_params(_provctx: *mut c_void) -> *const OsslParam {
    GMAC_GETTABLE_PARAMS.as_ptr()
}

/// `static int gmac_get_params(OSSL_PARAM params[])` — `gmac_prov.c:186-197`. Note the free
/// function in the authority is also called `gmac_get_params`; the *decoder* is the generated
/// `gmac_get_params_decoder`, and the one key it locates is `size`.
///
/// # Safety
/// The dispatch contract.
unsafe extern "C" fn gmac_get_params(params: *mut OsslParam) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        if let Some(site) = repeated_param_site(params, &GMAC_GET_PARAMS_DECODER_KEYS) {
            return fail_at(site);
        }
        let p = crate::params::OSSL_PARAM_locate(params, OSSL_MAC_PARAM_SIZE);
        if !p.is_null() && crate::params::OSSL_PARAM_set_size_t(p, gmac_size()) == 0 {
            return 0;
        }
        1
    }
}

/// `static const OSSL_PARAM gmac_set_ctx_params_list[]` — `gmac_prov.c:233-239`, the four keys
/// this profile's generator emits. `engine` is a `hidden` decoder key and is deliberately absent.
static GMAC_SETTABLE_CTX_PARAMS: [OsslParam; 5] = [
    param_utf8_string(OSSL_MAC_PARAM_CIPHER),
    param_utf8_string(OSSL_MAC_PARAM_PROPERTIES),
    param_octet_string(OSSL_MAC_PARAM_KEY),
    param_octet_string(OSSL_MAC_PARAM_IV),
    END,
];

/// `static const OSSL_PARAM *gmac_settable_ctx_params(void *ctx, void *provctx)` —
/// `gmac_prov.c:325-330`.
///
/// # Safety
/// The dispatch contract.
unsafe extern "C" fn gmac_settable_ctx_params(
    _ctx: *mut c_void,
    _provctx: *mut c_void,
) -> *const OsslParam {
    GMAC_SETTABLE_CTX_PARAMS.as_ptr()
}

/// `static int gmac_set_ctx_params(void *vmacctx, const OSSL_PARAM params[])` —
/// `gmac_prov.c:334-377`.
///
/// Four things are contract. `provctx` is `PROV_LIBCTX_OF(macctx->provctx)`, so the `cipher`
/// *name* is resolved in the provider's own library context; setting a cipher **re-initialises**
/// the context with `EVP_EncryptInit_ex(ctx, cipher, engine, NULL, NULL)` before any key is seen;
/// an `iv` is applied through `EVP_CTRL_AEAD_SET_IVLEN` and then a second `EVP_EncryptInit_ex`,
/// whose `<= 0` answer is a bare refusal rather than a raise; and a `key` is applied **last**, so
/// a caller that sets cipher, key and IV in one array gets them in that order.
///
/// # Safety
/// The dispatch contract.
unsafe extern "C" fn gmac_set_ctx_params(vmacctx: *mut c_void, params: *const OsslParam) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        if vmacctx.is_null() {
            return 0;
        }
        if let Some(site) = repeated_param_site(params, &GMAC_SET_CTX_PARAMS_DECODER_KEYS) {
            return fail_at(site);
        }

        let macctx = vmacctx.cast::<GmacData>();
        let ctx = (*macctx).ctx;
        if ctx.is_null() {
            return 0;
        }
        let provctx = prov_libctx_of((*macctx).provctx);

        let p = crate::params::OSSL_PARAM_locate_const(params, OSSL_MAC_PARAM_CIPHER);
        if !p.is_null() {
            let propq = crate::params::OSSL_PARAM_locate_const(params, OSSL_MAC_PARAM_PROPERTIES);
            let engine = crate::params::OSSL_PARAM_locate_const(params, OSSL_ALG_PARAM_ENGINE);

            if ossl_prov_cipher_load(
                ptr::addr_of_mut!((*macctx).cipher),
                p,
                propq,
                engine,
                provctx,
            ) == 0
            {
                return 0;
            }

            let cipher = ossl_prov_cipher_cipher(ptr::addr_of!((*macctx).cipher));
            if EVP_CIPHER_get_mode(cipher) != EVP_CIPH_GCM_MODE {
                return fail_at(&err_sites::PROV_GMAC_PROV_354);
            }
            if EVP_EncryptInit_ex(
                ctx,
                cipher,
                ossl_prov_cipher_engine(ptr::addr_of!((*macctx).cipher)),
                ptr::null(),
                ptr::null(),
            ) == 0
            {
                return 0;
            }
        }

        let p = crate::params::OSSL_PARAM_locate_const(params, OSSL_MAC_PARAM_KEY);
        if !p.is_null() {
            if (*p).data_type != OSSL_PARAM_OCTET_STRING {
                return 0;
            }
            if gmac_setkey(macctx, (*p).data.cast::<c_uchar>(), (*p).data_size) == 0 {
                return 0;
            }
        }

        let p = crate::params::OSSL_PARAM_locate_const(params, OSSL_MAC_PARAM_IV);
        if !p.is_null() {
            if (*p).data_type != OSSL_PARAM_OCTET_STRING {
                return 0;
            }
            if EVP_CIPHER_CTX_ctrl(
                ctx,
                EVP_CTRL_AEAD_SET_IVLEN,
                (*p).data_size as c_int,
                ptr::null_mut(),
            ) <= 0
            {
                return 0;
            }
            if EVP_EncryptInit_ex(
                ctx,
                ptr::null(),
                ptr::null_mut(),
                ptr::null(),
                (*p).data.cast::<c_uchar>(),
            ) == 0
            {
                return 0;
            }
        }
        1
    }
}

/// `const OSSL_DISPATCH ossl_gmac_functions[]` — `gmac_prov.c:265-278`, ten entries and the
/// terminator. Two of them are the *provider-level* pair, `GETTABLE_PARAMS` and `GET_PARAMS`,
/// which is the shape difference from `ossl_cmac_functions`.
///
/// **Transcribed and held until D419, then registered.** The table was deliberately absent from
/// [`DEFLT_MACS`] while GMAC's `cipher` resolution had nothing to resolve: GMAC refuses every mode
/// but GCM, and this profile's only GCM ciphers were `AES-{128,192,256}-GCM`, themselves Phase 9's
/// on `RAND_bytes_ex` (D234). Registering the row then would have made `EVP_MAC_fetch(NULL,
/// "GMAC", NULL)` answer 1 on both sides and then made every `EVP_MAC_init` fail where the
/// authority succeeds -- the `DES3-WRAP` class of invisible incompleteness, one operation over. The
/// ciphers landed in D417 and the row is registered in D419, at `defltprov.c:342`'s position
/// between `CMAC` and `HMAC`.
#[allow(dead_code)]
// The caller that will land: the row between CMAC and HMAC in `DEFLT_MACS` (`defltprov.c:342`,
// the authority's fourth MAC row), when the AES-GCM cipher rows land in
// Phase 9 and `EVP_MAC_fetch(NULL, "GMAC", NULL)` can be courted against the authority.
pub(crate) static GMAC_FUNCTIONS: [OsslDispatch; 11] = [
    OsslDispatch {
        function_id: OSSL_FUNC_MAC_NEWCTX,
        function: gmac_new as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_MAC_DUPCTX,
        function: gmac_dup as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_MAC_FREECTX,
        function: gmac_free as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_MAC_INIT,
        function: gmac_init as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_MAC_UPDATE,
        function: gmac_update as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_MAC_FINAL,
        function: gmac_final as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_MAC_GETTABLE_PARAMS,
        function: gmac_gettable_params as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_MAC_GET_PARAMS,
        function: gmac_get_params as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_MAC_SETTABLE_CTX_PARAMS,
        function: gmac_settable_ctx_params as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_MAC_SET_CTX_PARAMS,
        function: gmac_set_ctx_params as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_DISPATCH_END,
        function: ptr::null_mut(),
    },
];

/// The allocation-tracking `file` argument for the SipHash row's allocations: `siphash_prov.c`.
const FILE_SIPHASH: *const c_char = c"providers/implementations/macs/siphash_prov.c".as_ptr();

/// `struct siphash_data_st` — `siphash_prov.c:45-50`.
///
/// **Two contexts, not one, and the second is the whole point of the row.** `sipcopy` is the
/// initialised state saved by `siphash_setkey`, so `siphash_init` with a NULL key can *restart* a
/// message without the key by copying it back -- which is how `EVP_MAC_init(ctx, NULL, 0, NULL)`
/// re-runs a message. A transcription with one context would pass every one-shot vector and fail on
/// the second `EVP_MAC_init`.
#[repr(C)]
pub(crate) struct SiphashData {
    /// `void *provctx`.
    pub provctx: *mut c_void,
    /// `SIPHASH siphash`.
    pub siphash: Siphash,
    /// `SIPHASH sipcopy` — the restorable initialised state.
    pub sipcopy: Siphash,
    /// `unsigned int crounds, drounds` — zero means "the primitive's default", not zero rounds.
    pub crounds: c_uint,
    /// `unsigned int drounds`.
    pub drounds: c_uint,
}

/// `static unsigned int crounds(struct siphash_data_st *ctx)` — `siphash_prov.c:52-55`. Zero is the
/// *unset* value, which is what lets `SipHash_Init` supply `SIPHASH_C_ROUNDS`.
fn crounds(ctx: *const SiphashData) -> c_uint {
    // SAFETY: the caller passes a live context.
    let value = unsafe { (*ctx).crounds };
    if value != 0 {
        value
    } else {
        SIPHASH_C_ROUNDS
    }
}

/// `static unsigned int drounds(struct siphash_data_st *ctx)` — `siphash_prov.c:57-60`.
fn drounds(ctx: *const SiphashData) -> c_uint {
    // SAFETY: the caller passes a live context.
    let value = unsafe { (*ctx).drounds };
    if value != 0 {
        value
    } else {
        SIPHASH_D_ROUNDS
    }
}

/// `static void *siphash_new(void *provctx)` — `siphash_prov.c:62-72`. `OPENSSL_zalloc`, so a fresh
/// context has `hash_size == 0` in both copies and `SipHash_Init` will supply sixteen.
///
/// # Safety
/// The dispatch contract.
unsafe extern "C" fn siphash_new(provctx: *mut c_void) -> *mut c_void {
    // SAFETY: the caller's contract.
    unsafe {
        if is_running() == 0 {
            return ptr::null_mut();
        }
        let ctx = CRYPTO_zalloc(core::mem::size_of::<SiphashData>(), FILE_SIPHASH, LINE);
        if !ctx.is_null() {
            let ctx = ctx.cast::<SiphashData>();
            (*ctx).provctx = provctx;
        }
        ctx
    }
}

/// `static void siphash_free(void *vmacctx)` — `siphash_prov.c:74-77`. A plain free: the context
/// holds no owned pointers, which is why this row has no `reset` to get wrong.
///
/// # Safety
/// The dispatch contract; `vmacctx` NULL or live.
unsafe extern "C" fn siphash_free(vmacctx: *mut c_void) {
    // SAFETY: the caller's contract.
    unsafe {
        if !vmacctx.is_null() {
            CRYPTO_free(vmacctx, FILE_SIPHASH, LINE);
        }
    }
}

/// `static void *siphash_dup(void *vsrc)` — `siphash_prov.c:79-92`. A struct copy, because there is
/// nothing to up-ref: both contexts are by-value and the provider context pointer is shared.
///
/// # Safety
/// The dispatch contract.
unsafe extern "C" fn siphash_dup(vsrc: *mut c_void) -> *mut c_void {
    // SAFETY: the caller's contract.
    unsafe {
        if is_running() == 0 {
            return ptr::null_mut();
        }
        let dst = CRYPTO_malloc(core::mem::size_of::<SiphashData>(), FILE_SIPHASH, LINE)
            .cast::<SiphashData>();
        if dst.is_null() {
            return ptr::null_mut();
        }
        // SAFETY: both are live `SiphashData`s, and the copy C's `*sdst = *ssrc` performs.
        ptr::copy_nonoverlapping(vsrc.cast::<SiphashData>(), dst, 1);
        dst.cast()
    }
}

/// `static size_t siphash_size(void *vmacctx)` — `siphash_prov.c:94-99`. It reads the *context's*
/// hash size, so a fresh uninitialised context answers 0 rather than sixteen.
///
/// # Safety
/// `vmacctx` is live.
unsafe fn siphash_size(vmacctx: *mut c_void) -> usize {
    // SAFETY: the caller's contract.
    unsafe { SipHash_hash_size(ptr::addr_of_mut!((*vmacctx.cast::<SiphashData>()).siphash)) }
}

/// `static int siphash_setkey(struct siphash_data_st *ctx, const unsigned char *key,
/// size_t keylen)` — `siphash_prov.c:101-112`.
///
/// The sixteen-octet key length is a *bare* refusal with no raise, and on success the initialised
/// state is saved into `sipcopy`.
///
/// # Safety
/// `ctx` is live; `key` is readable for `keylen` bytes.
unsafe fn siphash_setkey(ctx: *mut SiphashData, key: *const c_uchar, keylen: usize) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        if keylen != SIPHASH_KEY_SIZE {
            return 0;
        }
        let ret = SipHash_Init(
            ptr::addr_of_mut!((*ctx).siphash),
            key,
            crounds(ctx) as c_int,
            drounds(ctx) as c_int,
        );
        if ret != 0 {
            (*ctx).sipcopy = (*ctx).siphash;
        }
        ret
    }
}

/// `static int siphash_init(void *vmacctx, const unsigned char *key, size_t keylen,
/// const OSSL_PARAM params[])` — `siphash_prov.c:114-130`.
///
/// The `key == NULL` arm restarts from `sipcopy` and returns 1 even when no key was ever set, which
/// is why a caller must set the key through `params` or a first `init` before this arm means
/// anything.
///
/// # Safety
/// The dispatch contract.
unsafe extern "C" fn siphash_init(
    vmacctx: *mut c_void,
    key: *const c_uchar,
    keylen: usize,
    params: *const OsslParam,
) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        if is_running() == 0 || siphash_set_params(vmacctx, params) == 0 {
            return 0;
        }
        let ctx = vmacctx.cast::<SiphashData>();
        if key.is_null() {
            (*ctx).siphash = (*ctx).sipcopy;
            return 1;
        }
        siphash_setkey(ctx, key, keylen)
    }
}

/// `static int siphash_update(void *vmacctx, const unsigned char *data, size_t datalen)` —
/// `siphash_prov.c:132-142`. `SipHash_Update` has no failure to report, so the only refusal here is
/// the empty-input shortcut.
///
/// # Safety
/// The dispatch contract; `data` is readable for `datalen` bytes.
unsafe extern "C" fn siphash_update(
    vmacctx: *mut c_void,
    data: *const c_uchar,
    datalen: usize,
) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        if datalen == 0 {
            return 1;
        }
        SipHash_Update(
            ptr::addr_of_mut!((*vmacctx.cast::<SiphashData>()).siphash),
            data,
            datalen,
        );
        1
    }
}

/// `static int siphash_final(void *vmacctx, unsigned char *out, size_t *outl, size_t outsize)` —
/// `siphash_prov.c:144-155`.
///
/// **`outsize < hlen` is the refusal, and it is checked before `*outl` is written.** `SipHash_Final`
/// itself also refuses an `outlen` that is not the context's `hash_size`, so the size is validated
/// twice -- once against the caller's buffer and once inside the primitive -- and a transcription
/// that dropped either would still pass a matching-size vector.
///
/// # Safety
/// The dispatch contract; `out` is writable for `outsize` bytes and `outl` is writable.
unsafe extern "C" fn siphash_final(
    vmacctx: *mut c_void,
    out: *mut c_uchar,
    outl: *mut usize,
    outsize: usize,
) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        let hlen = siphash_size(vmacctx);
        if is_running() == 0 || outsize < hlen {
            return 0;
        }
        *outl = hlen;
        SipHash_Final(
            ptr::addr_of_mut!((*vmacctx.cast::<SiphashData>()).siphash),
            out,
            hlen,
        )
    }
}

/// The three keys `siphash_get_ctx_params_decoder` locates, in the generated `switch`'s order
/// (`siphash_prov.c:190`, `:201`, `:212`): `c-rounds`, `d-rounds`, `size`.
const SIPHASH_GET_CTX_PARAMS_DECODER_KEYS: [(&err_sites::ErrSite, *const c_char); 3] = [
    (&err_sites::PROV_SIPHASH_PROV_190, OSSL_MAC_PARAM_C_ROUNDS),
    (&err_sites::PROV_SIPHASH_PROV_201, OSSL_MAC_PARAM_D_ROUNDS),
    (&err_sites::PROV_SIPHASH_PROV_212, OSSL_MAC_PARAM_SIZE),
];

/// The four keys `siphash_set_params_decoder` locates, in the generated `switch`'s order
/// (`siphash_prov.c:285`, `:296`, `:307`, `:318`). Note that this is **not** the settable list's
/// order: the `switch` is keyed on the first byte, so `c` and `d` come before `k` and `s`.
const SIPHASH_SET_PARAMS_DECODER_KEYS: [(&err_sites::ErrSite, *const c_char); 4] = [
    (&err_sites::PROV_SIPHASH_PROV_285, OSSL_MAC_PARAM_C_ROUNDS),
    (&err_sites::PROV_SIPHASH_PROV_296, OSSL_MAC_PARAM_D_ROUNDS),
    (&err_sites::PROV_SIPHASH_PROV_307, OSSL_MAC_PARAM_KEY),
    (&err_sites::PROV_SIPHASH_PROV_318, OSSL_MAC_PARAM_SIZE),
];

/// `static const OSSL_PARAM siphash_get_ctx_params_list[]` — `siphash_prov.c:157-162`.
static SIPHASH_GETTABLE_CTX_PARAMS: [OsslParam; 4] = [
    param_size_t(OSSL_MAC_PARAM_SIZE),
    param_uint(OSSL_MAC_PARAM_C_ROUNDS),
    param_uint(OSSL_MAC_PARAM_D_ROUNDS),
    END,
];

/// `static const OSSL_PARAM *siphash_gettable_ctx_params(void *ctx, void *provctx)` —
/// `siphash_prov.c:165-169`.
///
/// # Safety
/// The dispatch contract.
unsafe extern "C" fn siphash_gettable_ctx_params(
    _ctx: *mut c_void,
    _provctx: *mut c_void,
) -> *const OsslParam {
    SIPHASH_GETTABLE_CTX_PARAMS.as_ptr()
}

/// `static int siphash_get_ctx_params(void *vmacctx, OSSL_PARAM params[])` —
/// `siphash_prov.c:171-186`. All three answers are the *context's*: `size` is the hash size (0 on a
/// context whose key has never been set) and the round counts are the effective ones, so a caller
/// that never set `c-rounds` reads back 2 rather than 0.
///
/// # Safety
/// The dispatch contract.
unsafe extern "C" fn siphash_get_ctx_params(vmacctx: *mut c_void, params: *mut OsslParam) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        if vmacctx.is_null() {
            return 0;
        }
        if let Some(site) = repeated_param_site(params, &SIPHASH_GET_CTX_PARAMS_DECODER_KEYS) {
            return fail_at(site);
        }
        let ctx = vmacctx.cast::<SiphashData>();
        let p = crate::params::OSSL_PARAM_locate(params, OSSL_MAC_PARAM_SIZE);
        if !p.is_null() && crate::params::OSSL_PARAM_set_size_t(p, siphash_size(vmacctx)) == 0 {
            return 0;
        }
        let p = crate::params::OSSL_PARAM_locate(params, OSSL_MAC_PARAM_C_ROUNDS);
        if !p.is_null() && crate::params::OSSL_PARAM_set_uint(p, crounds(ctx)) == 0 {
            return 0;
        }
        let p = crate::params::OSSL_PARAM_locate(params, OSSL_MAC_PARAM_D_ROUNDS);
        if !p.is_null() && crate::params::OSSL_PARAM_set_uint(p, drounds(ctx)) == 0 {
            return 0;
        }
        1
    }
}

/// `static const OSSL_PARAM siphash_set_params_list[]` — `siphash_prov.c:188-194`.
static SIPHASH_SETTABLE_CTX_PARAMS: [OsslParam; 5] = [
    param_size_t(OSSL_MAC_PARAM_SIZE),
    param_octet_string(OSSL_MAC_PARAM_KEY),
    param_uint(OSSL_MAC_PARAM_C_ROUNDS),
    param_uint(OSSL_MAC_PARAM_D_ROUNDS),
    END,
];

/// `static const OSSL_PARAM *siphash_settable_ctx_params(void *ctx, void *provctx)` —
/// `siphash_prov.c:197-201`.
///
/// # Safety
/// The dispatch contract.
unsafe extern "C" fn siphash_settable_ctx_params(
    _ctx: *mut c_void,
    _provctx: *mut c_void,
) -> *const OsslParam {
    SIPHASH_SETTABLE_CTX_PARAMS.as_ptr()
}

/// `static int siphash_set_params(void *vmacctx, const OSSL_PARAM *params)` —
/// `siphash_prov.c:203-227`.
///
/// Three things are contract. A `size` sets **both** contexts' hash size, so the restorable copy
/// stays in step; a `size` that is neither 8 nor 16 is a bare refusal, and `SipHash_set_hash_size`'s
/// `v1 ^= 0xee` compensation is what makes setting it after the key equivalent to setting it before.
/// A `key` is applied last, and a non-octet-string descriptor for it is a bare refusal.
///
/// # Safety
/// The dispatch contract.
unsafe extern "C" fn siphash_set_params(vmacctx: *mut c_void, params: *const OsslParam) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        if vmacctx.is_null() {
            return 0;
        }
        if let Some(site) = repeated_param_site(params, &SIPHASH_SET_PARAMS_DECODER_KEYS) {
            return fail_at(site);
        }
        let ctx = vmacctx.cast::<SiphashData>();

        let p = crate::params::OSSL_PARAM_locate_const(params, OSSL_MAC_PARAM_SIZE);
        if !p.is_null() {
            let mut size: usize = 0;
            if crate::params::OSSL_PARAM_get_size_t(p, &mut size) == 0
                || SipHash_set_hash_size(ptr::addr_of_mut!((*ctx).siphash), size) == 0
                || SipHash_set_hash_size(ptr::addr_of_mut!((*ctx).sipcopy), size) == 0
            {
                return 0;
            }
        }
        let p = crate::params::OSSL_PARAM_locate_const(params, OSSL_MAC_PARAM_C_ROUNDS);
        if !p.is_null() && crate::params::OSSL_PARAM_get_uint(p, &mut (*ctx).crounds) == 0 {
            return 0;
        }
        let p = crate::params::OSSL_PARAM_locate_const(params, OSSL_MAC_PARAM_D_ROUNDS);
        if !p.is_null() && crate::params::OSSL_PARAM_get_uint(p, &mut (*ctx).drounds) == 0 {
            return 0;
        }
        let p = crate::params::OSSL_PARAM_locate_const(params, OSSL_MAC_PARAM_KEY);
        if !p.is_null() {
            if (*p).data_type != OSSL_PARAM_OCTET_STRING {
                return 0;
            }
            if siphash_setkey(ctx, (*p).data.cast::<c_uchar>(), (*p).data_size) == 0 {
                return 0;
            }
        }
        1
    }
}

/// `const OSSL_DISPATCH ossl_siphash_functions[]` — `siphash_prov.c:229-243`, ten entries and the
/// terminator. The same shape as `ossl_cmac_functions`: the ctx-params pair, not the provider-level one.
pub(crate) static SIPHASH_FUNCTIONS: [OsslDispatch; 11] = [
    OsslDispatch {
        function_id: OSSL_FUNC_MAC_NEWCTX,
        function: siphash_new as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_MAC_DUPCTX,
        function: siphash_dup as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_MAC_FREECTX,
        function: siphash_free as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_MAC_INIT,
        function: siphash_init as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_MAC_UPDATE,
        function: siphash_update as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_MAC_FINAL,
        function: siphash_final as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_MAC_GETTABLE_CTX_PARAMS,
        function: siphash_gettable_ctx_params as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_MAC_GET_CTX_PARAMS,
        function: siphash_get_ctx_params as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_MAC_SETTABLE_CTX_PARAMS,
        function: siphash_settable_ctx_params as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_MAC_SET_CTX_PARAMS,
        function: siphash_set_params as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_DISPATCH_END,
        function: ptr::null_mut(),
    },
];

// ---------------------------------------------------------------------------------------------
// `HMAC` — `providers/implementations/macs/hmac_prov.c`
// ---------------------------------------------------------------------------------------------

/// `OSSL_MAC_PARAM_TLS_DATA_SIZE` — `core_names.h:354` (`"tls-data-size"`). The parameter that
/// switches the row from the ordinary HMAC path to `ssl3_cbc_digest_record`.
const OSSL_MAC_PARAM_TLS_DATA_SIZE: *const c_char = c"tls-data-size".as_ptr();

/// The `file` argument of this unit's allocations.
///
/// **`hmac_prov.c` is generated from `hmac_prov.c.in`, so `__FILE__` carries only the
/// build-relative path.** That is D235's finding and it is checked, not asserted: a unit test below
/// compares this constant with the `file` of every `PROV_HMAC_PROV_*` raise site in the same unit,
/// because both are `__FILE__` and the two must therefore be one string. The three `FILE_*`
/// constants above it said otherwise and this commit corrects them.
const FILE_HMAC: *const c_char = c"providers/implementations/macs/hmac_prov.c".as_ptr();

/// `EVP_MAX_MD_SIZE` — `include/openssl/evp.h`, the width of `tls_mac_out`.
const EVP_MAX_MD_SIZE: usize = 64;

/// `struct hmac_data_st` — `hmac_prov.c:57-78`. `OSSL_FIPS_IND_DECLARE` contributes no field when
/// `FIPS_MODULE` is undefined, so these ten are the whole struct in this profile, and `internal` is
/// inside the same `#ifdef` and absent with it.
#[repr(C)]
pub(crate) struct HmacData {
    /// `void *provctx` — the creating provider's context, which the digest fetch is scoped to.
    pub provctx: *mut c_void,
    /// `HMAC_CTX *ctx` — `crypto/hmac/hmac.c`'s context, the row being a shell over it.
    pub ctx: *mut HmacCtx,
    /// `PROV_DIGEST digest` — the construct's digest, resolved from a *name*.
    pub digest: ProvDigest,
    /// `unsigned char *key` — *"Keep a copy of the key in case we need it for TLS HMAC"*.
    pub key: *mut c_uchar,
    /// `size_t keylen`.
    pub keylen: usize,
    /// `size_t tls_data_size` — *"Length of full TLS record including the MAC and any padding"*.
    pub tls_data_size: usize,
    /// `unsigned char tls_header[13]` — the first `update` call's payload in the TLS arm.
    pub tls_header: [c_uchar; 13],
    /// `int tls_header_set`.
    pub tls_header_set: c_int,
    /// `unsigned char tls_mac_out[EVP_MAX_MD_SIZE]`.
    pub tls_mac_out: [c_uchar; EVP_MAX_MD_SIZE],
    /// `size_t tls_mac_out_size`.
    pub tls_mac_out_size: usize,
}

/// The two keys `hmac_get_ctx_params_decoder` locates in this profile, each with the site of its own
/// repeated-parameter raise (`hmac_prov.c:313`, `:337`). The third the generator emits,
/// `fips-indicator`, is `# if defined(FIPS_MODULE)`-guarded and absent here.
const HMAC_GET_CTX_PARAMS_DECODER_KEYS: [(&err_sites::ErrSite, *const c_char); 2] = [
    (&err_sites::PROV_HMAC_PROV_313, OSSL_MAC_PARAM_BLOCK_SIZE),
    (&err_sites::PROV_HMAC_PROV_337, OSSL_MAC_PARAM_SIZE),
];

/// The five keys `hmac_set_ctx_params_decoder` locates in this profile, each with its raise site
/// (`hmac_prov.c:427`, `:438`, `:472`, `:485`, `:496`). The sixth is the FIPS `key-check`.
///
/// The `switch` orders them by first byte and then by prefix, so the array below is in the order
/// `repeated_param_site` matches rather than in the list's order — which for this decoder is the
/// same for all five, since the prefixes `digest`, `engine`, `key`, `properties`, `tls-data-size`
/// are distinguishable at their first byte except for the `k` pair, and `key` is the only one of
/// that pair this profile admits.
const HMAC_SET_CTX_PARAMS_DECODER_KEYS: [(&err_sites::ErrSite, *const c_char); 5] = [
    (&err_sites::PROV_HMAC_PROV_427, OSSL_ALG_PARAM_DIGEST),
    (&err_sites::PROV_HMAC_PROV_438, OSSL_ALG_PARAM_ENGINE),
    (&err_sites::PROV_HMAC_PROV_472, OSSL_MAC_PARAM_KEY),
    (&err_sites::PROV_HMAC_PROV_485, OSSL_MAC_PARAM_PROPERTIES),
    (&err_sites::PROV_HMAC_PROV_496, OSSL_MAC_PARAM_TLS_DATA_SIZE),
];

/// `static void *hmac_new(void *provctx)` — `hmac_prov.c:80-96`.
///
/// Both allocations are checked against one release. The `OPENSSL_free(macctx)` runs whether the
/// zalloc failed (making it a no-op) or the `HMAC_CTX_new` did, and in the second case `macctx->ctx`
/// is the NULL the assignment wrote.
///
/// # Safety
/// The dispatch contract.
unsafe extern "C" fn hmac_new(provctx: *mut c_void) -> *mut c_void {
    // SAFETY: the caller's contract.
    unsafe {
        if is_running() == 0 {
            return ptr::null_mut();
        }

        let macctx =
            CRYPTO_zalloc(core::mem::size_of::<HmacData>(), FILE_HMAC, LINE).cast::<HmacData>();
        if macctx.is_null() {
            return ptr::null_mut();
        }
        (*macctx).ctx = HMAC_CTX_new();
        if (*macctx).ctx.is_null() {
            CRYPTO_free(macctx.cast(), FILE_HMAC, LINE);
            return ptr::null_mut();
        }
        (*macctx).provctx = provctx;
        macctx.cast()
    }
}

/// `static void hmac_free(void *vmacctx)` — `hmac_prov.c:98-108`.
///
/// The key is **cleansed** as well as released, because it is the MAC key and not a parameter
/// buffer: `OPENSSL_clear_free(macctx->key, macctx->keylen)`.
///
/// # Safety
/// The dispatch contract.
unsafe extern "C" fn hmac_free(vmacctx: *mut c_void) {
    // SAFETY: the caller's contract; `vmacctx` is a context `hmac_new` allocated.
    unsafe {
        if !vmacctx.is_null() {
            let macctx = vmacctx.cast::<HmacData>();
            HMAC_CTX_free((*macctx).ctx);
            ossl_prov_digest_reset(ptr::addr_of_mut!((*macctx).digest));
            CRYPTO_clear_free((*macctx).key.cast(), (*macctx).keylen, FILE_HMAC, LINE);
            CRYPTO_free(vmacctx, FILE_HMAC, LINE);
        }
    }
}

/// `static void *hmac_dup(void *vsrc)` — `hmac_prov.c:110-143`.
///
/// **The whole struct is copied, and that is what makes a duplicated TLS context work.**
/// `*dst = *src` carries `tls_data_size`, `tls_header`, `tls_header_set`, `tls_mac_out` and
/// `tls_mac_out_size` across, then three fields are restored or cleared: the live `ctx` that
/// `hmac_new` just created, the `key` pointer (reallocated below rather than shared) and the
/// `digest` (zeroed, then copied properly by `ossl_prov_digest_copy`). Copying the struct *before*
/// the digest copy is what makes the failed-copy path free a context that is fully built.
///
/// Both `return 0` paths after the copy return NULL, and the `dst` they abandon is the one
/// `hmac_free` has already released.
///
/// # Safety
/// The dispatch contract.
unsafe extern "C" fn hmac_dup(vsrc: *mut c_void) -> *mut c_void {
    // SAFETY: the caller's contract.
    unsafe {
        let src = vsrc.cast::<HmacData>();

        if is_running() == 0 {
            return ptr::null_mut();
        }
        let dst = hmac_new((*src).provctx).cast::<HmacData>();
        if dst.is_null() {
            return ptr::null_mut();
        }

        let ctx = (*dst).ctx;
        // The authority's `*dst = *src`. `ptr::read`/`ptr::write` rather than an assignment: the
        // struct owns nothing that a bitwise copy would double-free, but saying "bitwise copy" is
        // what the C says and `HmacData` is deliberately not `Copy`.
        ptr::write(dst, ptr::read(src));
        (*dst).ctx = ctx;
        (*dst).key = ptr::null_mut();
        // `memset(&dst->digest, 0, sizeof(dst->digest))`.
        ptr::write_bytes(ptr::addr_of_mut!((*dst).digest), 0, 1);

        if HMAC_CTX_copy((*dst).ctx, (*src).ctx) == 0
            || ossl_prov_digest_copy(
                ptr::addr_of_mut!((*dst).digest),
                ptr::addr_of!((*src).digest),
            ) == 0
        {
            hmac_free(dst.cast());
            return ptr::null_mut();
        }
        if !(*src).key.is_null() {
            // `src->keylen > 0 ? src->keylen : 1` -- a zero-length request is still one byte here.
            (*dst).key = CRYPTO_malloc(
                if (*src).keylen > 0 { (*src).keylen } else { 1 },
                FILE_HMAC,
                LINE,
            )
            .cast::<c_uchar>();
            if (*dst).key.is_null() {
                hmac_free(dst.cast());
                return ptr::null_mut();
            }
            if (*src).keylen > 0 {
                ptr::copy_nonoverlapping((*src).key, (*dst).key, (*src).keylen);
            }
        }
        dst.cast()
    }
}

/// `static size_t hmac_size(struct hmac_data_st *macctx)` — `hmac_prov.c:145-148`. The digest's own
/// size, from the HMAC context rather than from the `PROV_DIGEST`.
///
/// # Safety
/// The dispatch contract.
unsafe fn hmac_size(macctx: *mut HmacData) -> usize {
    // SAFETY: the caller's contract.
    unsafe { HMAC_size((*macctx).ctx) }
}

/// `static int hmac_block_size(struct hmac_data_st *macctx)` — `hmac_prov.c:150-157`. A context with
/// no digest answers 0 rather than the block size of nothing.
///
/// # Safety
/// The dispatch contract.
unsafe fn hmac_block_size(macctx: *mut HmacData) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        let md = ossl_prov_digest_md(ptr::addr_of!((*macctx).digest));

        if md.is_null() {
            return 0;
        }
        // `EVP_MD_block_size`, which `include/openssl/evp.h:568` defines as
        // `EVP_MD_get_block_size`.
        EVP_MD_get_block_size(md)
    }
}

/// `static int hmac_setkey(struct hmac_data_st *macctx, const unsigned char *key,
/// size_t keylen)` — `hmac_prov.c:159-201` without its FIPS arm.
///
/// The stored key is replaced on **every** call, whether or not the HMAC init below succeeds, and
/// the init is skipped entirely when the caller passed no key *and* either this is a TLS context or
/// there is no digest yet — `HMAC_Init_ex` *"doesn't tolerate all zero params, so we must be
/// careful"*. The three-condition test is transcribed as three conditions rather than simplified.
///
/// # Safety
/// `key` is NULL or readable for `keylen` bytes.
unsafe fn hmac_setkey(macctx: *mut HmacData, key: *const c_uchar, keylen: usize) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        if !(*macctx).key.is_null() {
            CRYPTO_clear_free((*macctx).key.cast(), (*macctx).keylen, FILE_HMAC, LINE);
        }
        // `keylen > 0 ? keylen : 1`.
        (*macctx).key =
            CRYPTO_malloc(if keylen > 0 { keylen } else { 1 }, FILE_HMAC, LINE).cast::<c_uchar>();
        if (*macctx).key.is_null() {
            return 0;
        }
        if keylen > 0 {
            ptr::copy_nonoverlapping(key, (*macctx).key, keylen);
        }
        (*macctx).keylen = keylen;

        let digest = ossl_prov_digest_md(ptr::addr_of!((*macctx).digest));
        if !key.is_null() || ((*macctx).tls_data_size == 0 && !digest.is_null()) {
            return HMAC_Init_ex(
                (*macctx).ctx,
                key.cast(),
                keylen as c_int,
                digest,
                ossl_prov_digest_engine(ptr::addr_of!((*macctx).digest)),
            );
        }
        1
    }
}

/// `static int hmac_init(void *vmacctx, const unsigned char *key, size_t keylen,
/// const OSSL_PARAM params[])` — `hmac_prov.c:203-216`.
///
/// The `key == NULL` arm is `HMAC_Init_ex(ctx, NULL, 0, NULL, NULL)`, which *re-initialises* the
/// construct rather than failing, and it is the arm a caller reaches by calling `EVP_MAC_init`
/// twice.
///
/// # Safety
/// The dispatch contract.
unsafe extern "C" fn hmac_init(
    vmacctx: *mut c_void,
    key: *const c_uchar,
    keylen: usize,
    params: *const OsslParam,
) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        if is_running() == 0 || hmac_set_ctx_params(vmacctx, params) == 0 {
            return 0;
        }
        if !key.is_null() {
            return hmac_setkey(vmacctx.cast::<HmacData>(), key, keylen);
        }
        /* Just reinit the HMAC context */
        HMAC_Init_ex(
            (*vmacctx.cast::<HmacData>()).ctx,
            ptr::null(),
            0,
            ptr::null(),
            ptr::null_mut(),
        )
    }
}

/// `static int hmac_update(void *vmacctx, const unsigned char *data, size_t datalen)` —
/// `hmac_prov.c:218-250`.
///
/// **The TLS arm is a state machine over exactly two `update` calls.** The first must be the
/// 13-byte header and nothing else, and it is *stored* rather than hashed; the second is the record
/// body, whose MAC is computed by `ssl3_cbc_digest_record` over the stored header and the caller's
/// `tls_data_size`. A first call of any other length is a bare `return 0` with no raise, and so is a
/// body longer than `tls_data_size` — the second check is the one that keeps the constant-time
/// function's `data_plus_mac_plus_padding_size < 1024 * 1024` assertion out of reach of a caller.
///
/// # Safety
/// The dispatch contract.
unsafe extern "C" fn hmac_update(
    vmacctx: *mut c_void,
    data: *const c_uchar,
    datalen: usize,
) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        let macctx = vmacctx.cast::<HmacData>();

        if (*macctx).tls_data_size > 0 {
            /* We're doing a TLS HMAC */
            if (*macctx).tls_header_set == 0 {
                /* We expect the first update call to contain the TLS header */
                if datalen != core::mem::size_of::<[c_uchar; 13]>() {
                    return 0;
                }
                ptr::copy_nonoverlapping(data, (*macctx).tls_header.as_mut_ptr(), datalen);
                (*macctx).tls_header_set = 1;
                return 1;
            }
            /* macctx->tls_data_size is datalen plus the padding length */
            if (*macctx).tls_data_size < datalen {
                return 0;
            }

            return ssl3_cbc_digest_record(
                ossl_prov_digest_md(ptr::addr_of!((*macctx).digest)),
                (*macctx).tls_mac_out.as_mut_ptr(),
                ptr::addr_of_mut!((*macctx).tls_mac_out_size),
                (*macctx).tls_header.as_ptr(),
                data,
                datalen,
                (*macctx).tls_data_size,
                (*macctx).key,
                (*macctx).keylen,
                0,
            );
        }

        HMAC_Update((*macctx).ctx, data, datalen)
    }
}

/// `static int hmac_final(void *vmacctx, unsigned char *out, size_t *outl, size_t outsize)` —
/// `hmac_prov.c:252-272`. The running check precedes the TLS arm, so a stopped provider refuses
/// before anything is written.
///
/// **`*outl = hlen` is unconditional**, while the TLS arm guards the same write with `outl != NULL`.
/// That asymmetry is the authority's and it is transcribed: it is unreachable with a NULL through
/// `EVP_MAC_final`'s surface, because `evp_mac_final` always passes the address of its own local
/// (`crypto/evp/mac_lib.c:184`) — including from `EVP_MAC_finalXOF`, whose own `outl` is NULL. A
/// dispatch-table caller that passed NULL directly would be undefined on both sides.
///
/// # Safety
/// The dispatch contract.
unsafe extern "C" fn hmac_final(
    vmacctx: *mut c_void,
    out: *mut c_uchar,
    outl: *mut usize,
    _outsize: usize,
) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        let mut hlen: c_uint = 0;
        let macctx = vmacctx.cast::<HmacData>();

        if is_running() == 0 {
            return 0;
        }
        if (*macctx).tls_data_size > 0 {
            if (*macctx).tls_mac_out_size == 0 {
                return 0;
            }
            if !outl.is_null() {
                *outl = (*macctx).tls_mac_out_size;
            }
            ptr::copy_nonoverlapping(
                (*macctx).tls_mac_out.as_ptr(),
                out,
                (*macctx).tls_mac_out_size,
            );
            return 1;
        }
        if HMAC_Final((*macctx).ctx, out, ptr::addr_of_mut!(hlen)) == 0 {
            return 0;
        }
        *outl = hlen as usize;
        1
    }
}

/// `static const OSSL_PARAM hmac_get_ctx_params_list[]` — `hmac_prov.c:277-284`, the two keys this
/// profile's generator emits.
static HMAC_GETTABLE_CTX_PARAMS: [OsslParam; 3] = [
    param_size_t(OSSL_MAC_PARAM_SIZE),
    param_size_t(OSSL_MAC_PARAM_BLOCK_SIZE),
    END,
];

/// `static const OSSL_PARAM *hmac_gettable_ctx_params(void *ctx, void *provctx)` —
/// `hmac_prov.c:350-354`.
///
/// # Safety
/// The dispatch contract.
unsafe extern "C" fn hmac_gettable_ctx_params(
    _ctx: *mut c_void,
    _provctx: *mut c_void,
) -> *const OsslParam {
    HMAC_GETTABLE_CTX_PARAMS.as_ptr()
}

/// `static int hmac_get_ctx_params(void *vmacctx, OSSL_PARAM params[])` — `hmac_prov.c:356-381`.
///
/// **The two keys are written by two different setters.** `size` goes through
/// `OSSL_PARAM_set_size_t` and `block-size` through `OSSL_PARAM_set_int`, even though the *list*
/// declares both as `OSSL_PARAM_size_t`. That mismatch is the authority's at
/// `hmac_prov.c:367`, and CMAC's row does the opposite, so it is one of the places where two rows
/// that look the same are not.
///
/// # Safety
/// The dispatch contract.
unsafe extern "C" fn hmac_get_ctx_params(vmacctx: *mut c_void, params: *mut OsslParam) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        if vmacctx.is_null() {
            return 0;
        }
        if let Some(site) = repeated_param_site(params, &HMAC_GET_CTX_PARAMS_DECODER_KEYS) {
            return fail_at(site);
        }

        let macctx = vmacctx.cast::<HmacData>();
        let p = crate::params::OSSL_PARAM_locate(params, OSSL_MAC_PARAM_SIZE);
        if !p.is_null() && crate::params::OSSL_PARAM_set_size_t(p, hmac_size(macctx)) == 0 {
            return 0;
        }
        let p = crate::params::OSSL_PARAM_locate(params, OSSL_MAC_PARAM_BLOCK_SIZE);
        if !p.is_null() && crate::params::OSSL_PARAM_set_int(p, hmac_block_size(macctx)) == 0 {
            return 0;
        }
        1
    }
}

/// `static const OSSL_PARAM hmac_set_ctx_params_list[]` — `hmac_prov.c:386-395`, the four keys this
/// profile's generator emits. `engine` is **not** here: it is a `hidden` decoder key, exactly as it
/// is for CMAC and GMAC.
static HMAC_SETTABLE_CTX_PARAMS: [OsslParam; 5] = [
    param_utf8_string(OSSL_ALG_PARAM_DIGEST),
    param_utf8_string(OSSL_MAC_PARAM_PROPERTIES),
    param_octet_string(OSSL_MAC_PARAM_KEY),
    param_size_t(OSSL_MAC_PARAM_TLS_DATA_SIZE),
    END,
];

/// `static const OSSL_PARAM *hmac_settable_ctx_params(void *ctx, void *provctx)` —
/// `hmac_prov.c:509-513`.
///
/// # Safety
/// The dispatch contract.
unsafe extern "C" fn hmac_settable_ctx_params(
    _ctx: *mut c_void,
    _provctx: *mut c_void,
) -> *const OsslParam {
    HMAC_SETTABLE_CTX_PARAMS.as_ptr()
}

/// `static int hmac_set_ctx_params(void *vmacctx, const OSSL_PARAM params[])` —
/// `hmac_prov.c:518-549` without its FIPS arm.
///
/// **The library context is computed unconditionally and used by the digest arm.**
/// `PROV_LIBCTX_OF(macctx->provctx)` is a local here rather than a field, so it is not one of
/// `provider-algorithms.json`'s 26 carry sites — but it is not decorative either: it is the context
/// `ossl_prov_digest_load` resolves the digest *name* in, so a row created in a private
/// `OSSL_LIB_CTX` fetches its digest there and not from the global one. Losing the context would
/// make the row resolve a digest the authority's cannot see, which is the same class of difference
/// D241 recorded for the cipher rows.
///
/// **The `key` arm continues rather than returning.** Unlike CMAC, a `key` here does not end the
/// function: `tls-data-size` may still follow in the same array, and `hmac_setkey`'s decision to
/// init the HMAC depends on it.
///
/// # Safety
/// The dispatch contract.
unsafe extern "C" fn hmac_set_ctx_params(vmacctx: *mut c_void, params: *const OsslParam) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        if vmacctx.is_null() {
            return 0;
        }
        if let Some(site) = repeated_param_site(params, &HMAC_SET_CTX_PARAMS_DECODER_KEYS) {
            return fail_at(site);
        }

        let macctx = vmacctx.cast::<HmacData>();
        let ctx = prov_libctx_of((*macctx).provctx);

        let p = crate::params::OSSL_PARAM_locate_const(params, OSSL_ALG_PARAM_DIGEST);
        if !p.is_null() {
            let propq = crate::params::OSSL_PARAM_locate_const(params, OSSL_MAC_PARAM_PROPERTIES);
            let engine = crate::params::OSSL_PARAM_locate_const(params, OSSL_ALG_PARAM_ENGINE);

            if ossl_prov_digest_load(ptr::addr_of_mut!((*macctx).digest), p, propq, engine, ctx)
                == 0
            {
                return 0;
            }
        }

        let p = crate::params::OSSL_PARAM_locate_const(params, OSSL_MAC_PARAM_KEY);
        if !p.is_null() {
            if (*p).data_type != OSSL_PARAM_OCTET_STRING {
                return 0;
            }

            if hmac_setkey(macctx, (*p).data.cast::<c_uchar>(), (*p).data_size) == 0 {
                return 0;
            }
        }

        let p = crate::params::OSSL_PARAM_locate_const(params, OSSL_MAC_PARAM_TLS_DATA_SIZE);
        if !p.is_null()
            && crate::params::OSSL_PARAM_get_size_t(p, ptr::addr_of_mut!((*macctx).tls_data_size))
                == 0
        {
            return 0;
        }

        1
    }
}

/// `const OSSL_DISPATCH ossl_hmac_functions[]` — `hmac_prov.c:551-566`, ten entries and the
/// terminator. The FIPS-only `ossl_hmac_internal_functions[]` is inside `#ifdef FIPS_MODULE` and is
/// absent here with its `hmac_internal_new`.
pub(crate) static HMAC_FUNCTIONS: [OsslDispatch; 11] = [
    OsslDispatch {
        function_id: OSSL_FUNC_MAC_NEWCTX,
        function: hmac_new as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_MAC_DUPCTX,
        function: hmac_dup as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_MAC_FREECTX,
        function: hmac_free as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_MAC_INIT,
        function: hmac_init as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_MAC_UPDATE,
        function: hmac_update as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_MAC_FINAL,
        function: hmac_final as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_MAC_GETTABLE_CTX_PARAMS,
        function: hmac_gettable_ctx_params as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_MAC_GET_CTX_PARAMS,
        function: hmac_get_ctx_params as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_MAC_SETTABLE_CTX_PARAMS,
        function: hmac_settable_ctx_params as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_MAC_SET_CTX_PARAMS,
        function: hmac_set_ctx_params as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_DISPATCH_END,
        function: ptr::null_mut(),
    },
];

// ---------------------------------------------------------------------------------------------
// `BLAKE2BMAC` / `BLAKE2SMAC` — `providers/implementations/macs/blake2_mac_impl.c`
// ---------------------------------------------------------------------------------------------
//
// The authority writes this row once and instantiates it twice. `blake2b_mac.c` and
// `blake2s_mac.c` are thirty-four-line `#define` preambles -- the context type, the five widths and
// the names of the algorithm functions -- and each `#include`s `blake2_mac_impl.c`, which is the
// whole implementation. `macro_rules!` is the transcription of those `#define`s rather than a
// convenience, and `src/provider/digest.rs`'s `blake_row!` is the same shape for the digest rows.

/// `OSSL_MAC_PARAM_CUSTOM` — `core_names.h:340` (`"custom"`).
const OSSL_MAC_PARAM_CUSTOM: *const c_char = c"custom".as_ptr();
/// `OSSL_MAC_PARAM_SALT` — `core_names.h:352` (`"salt"`).
const OSSL_MAC_PARAM_SALT: *const c_char = c"salt".as_ptr();

/// The allocation `file` argument for both rows.
///
/// **This one carries the `../../src/openssl-3.6.4/` prefix, and the four rows of D252 do not.**
/// `blake2_mac_impl.c` is a *source-tree* file that the two preambles `#include`, while
/// `cmac_prov.c`, `gmac_prov.c`, `hmac_prov.c` and `siphash_prov.c` are generated from `.c.in`
/// templates into the build tree. The compiler spells an included source file with its source-tree
/// path and a generated file with its build-relative path, which is why the two groups differ; both
/// object files carry this exact string. The unit test below binds it to the `file` of a raise in
/// the same unit, which is the same `__FILE__`.
const FILE_BLAKE2_MAC: *const c_char =
    c"../../src/openssl-3.6.4/providers/implementations/macs/blake2_mac_impl.c".as_ptr();

/// The two keys `blake2_get_ctx_decoder` locates, each with the site of its own
/// repeated-parameter raise. The sites are in `blake2_params.inc`, which is generated into
/// `providers/implementations/include/prov/` and included by both preambles, so the six
/// coordinates are one set shared by the two rows (D254).
const BLAKE2_GET_CTX_DECODER_KEYS: [(&err_sites::ErrSite, *const c_char); 2] = [
    (&err_sites::PROV_BLAKE2_PARAMS_46, OSSL_MAC_PARAM_BLOCK_SIZE),
    (&err_sites::PROV_BLAKE2_PARAMS_57, OSSL_MAC_PARAM_SIZE),
];

/// The four keys `blake2_mac_set_ctx_decoder` locates, with their raise sites. `custom` and `salt`
/// both begin with `s`, and the generated `switch` separates them on the *second* byte, so this
/// array's order is not the switch's order -- what it has to do is pair each key with its own site,
/// which is what a duplicate has to report.
const BLAKE2_SET_CTX_DECODER_KEYS: [(&err_sites::ErrSite, *const c_char); 4] = [
    (&err_sites::PROV_BLAKE2_PARAMS_105, OSSL_MAC_PARAM_CUSTOM),
    (&err_sites::PROV_BLAKE2_PARAMS_116, OSSL_MAC_PARAM_KEY),
    (&err_sites::PROV_BLAKE2_PARAMS_131, OSSL_MAC_PARAM_SALT),
    (&err_sites::PROV_BLAKE2_PARAMS_142, OSSL_MAC_PARAM_SIZE),
];

/// `blake2_get_ctx_list` — `blake2_params.inc:22-27`: two `OSSL_PARAM_size_t` entries.
static BLAKE2_GETTABLE_CTX_PARAMS: [OsslParam; 3] = [
    param_size_t(OSSL_MAC_PARAM_SIZE),
    param_size_t(OSSL_MAC_PARAM_BLOCK_SIZE),
    END,
];

/// `blake2_mac_set_ctx_list` — `blake2_params.inc:76-83`. `size` is a `size_t` and the other three
/// are octet strings, and `RT-CIPHER` prints all three fields of every entry.
static BLAKE2_SETTABLE_CTX_PARAMS: [OsslParam; 5] = [
    param_size_t(OSSL_MAC_PARAM_SIZE),
    param_octet_string(OSSL_MAC_PARAM_KEY),
    param_octet_string(OSSL_MAC_PARAM_CUSTOM),
    param_octet_string(OSSL_MAC_PARAM_SALT),
    END,
];

macro_rules! blake2_mac_row {
    ($row:ident, $flavour:ident) => {
        pub(crate) mod $row {
            use super::*;
            use crate::digest::blake2::$flavour as b2;

            /// `struct blake2_mac_data_st` — `blake2_mac_impl.c:38-42`.
            ///
            /// The context keeps the whole parameter block beside the state, so a `size`, `custom`
            /// or `salt` set before `init` survives the re-initialisation. The key is kept at the
            /// **full** `KEYBYTES` width and zero-padded, because `init_key` copies exactly
            /// `key_length` bytes out of it and then feeds an entire block -- so the padding is
            /// part of what the algorithm hashes.
            #[repr(C)]
            pub(crate) struct MacData {
                /// `BLAKE2_CTX ctx`.
                pub ctx: b2::Ctx,
                /// `BLAKE2_PARAM params`.
                pub params: b2::Param,
                /// `unsigned char key[KEYBYTES]`.
                pub key: [c_uchar; b2::KEYBYTES],
            }

            /// `static void *blake2_mac_new(void *unused_provctx)` — `blake2_mac_impl.c:44-57`.
            ///
            /// # Safety
            /// The dispatch contract.
            unsafe extern "C" fn newctx(_provctx: *mut c_void) -> *mut c_void {
                // SAFETY: the caller's contract.
                unsafe {
                    if is_running() == 0 {
                        return ptr::null_mut();
                    }
                    let macctx =
                        CRYPTO_zalloc(core::mem::size_of::<MacData>(), FILE_BLAKE2_MAC, LINE)
                            .cast::<MacData>();
                    if !macctx.is_null() {
                        b2::param_init(&mut (*macctx).params);
                    }
                    macctx.cast()
                }
            }

            /// `static void *blake2_mac_dup(void *vsrc)` — `blake2_mac_impl.c:59-73`.
            ///
            /// **A fresh zalloc and a whole-struct copy.** Unlike `hmac_dup` this rebuilds nothing:
            /// the row owns no pointer of its own, so the copy *is* the duplicate. The `zalloc`
            /// before it is the authority's own redundancy -- the `*dst = *src` then overwrites
            /// every byte of the block -- and it is transcribed rather than simplified away,
            /// because a failed `zalloc` is an observable refusal.
            ///
            /// # Safety
            /// The dispatch contract.
            unsafe extern "C" fn dup(vsrc: *mut c_void) -> *mut c_void {
                // SAFETY: the caller's contract.
                unsafe {
                    if is_running() == 0 {
                        return ptr::null_mut();
                    }
                    let dst = CRYPTO_zalloc(core::mem::size_of::<MacData>(), FILE_BLAKE2_MAC, LINE)
                        .cast::<MacData>();
                    if dst.is_null() {
                        return ptr::null_mut();
                    }
                    ptr::copy_nonoverlapping(
                        vsrc.cast::<u8>(),
                        dst.cast::<u8>(),
                        core::mem::size_of::<MacData>(),
                    );
                    dst.cast()
                }
            }

            /// `static void blake2_mac_free(void *vmacctx)` — `blake2_mac_impl.c:75-83`. The key
            /// *member* is cleansed and then the struct is freed, which is not
            /// `CRYPTO_clear_free`'s cleanse-and-free of a single block.
            ///
            /// # Safety
            /// The dispatch contract.
            unsafe extern "C" fn free(vmacctx: *mut c_void) {
                // SAFETY: the caller's contract; `vmacctx` is a context `newctx` allocated.
                unsafe {
                    if !vmacctx.is_null() {
                        let macctx = vmacctx.cast::<MacData>();
                        cleanse((*macctx).key.as_mut_ptr(), b2::KEYBYTES);
                        CRYPTO_free(vmacctx, FILE_BLAKE2_MAC, LINE);
                    }
                }
            }

            /// `static size_t blake2_mac_size(void *vmacctx)` — `blake2_mac_impl.c:85-90`. The
            /// parameter block's first byte *is* the digest length, so a context reports the
            /// default before `init` rather than zero.
            ///
            /// # Safety
            /// The dispatch contract.
            unsafe fn mac_size(macctx: *mut MacData) -> usize {
                // SAFETY: the caller's contract.
                unsafe { (*macctx).params.b[0] as usize }
            }

            /// `static int blake2_setkey(struct blake2_mac_data_st *macctx, const unsigned char
            /// *key, size_t keylen)` — `blake2_mac_impl.c:92-105`.
            ///
            /// A zero-length key is refused as well as an over-long one, and the zero pad is
            /// written only when it is needed -- so the tail of the buffer otherwise still holds
            /// the previous key's bytes, and `init_key` reading `key_length` of them is what makes
            /// that unobservable rather than a leak.
            ///
            /// # Safety
            /// `macctx` is live; `key` readable for `keylen` bytes.
            unsafe fn setkey(macctx: *mut MacData, key: *const c_uchar, keylen: usize) -> c_int {
                // SAFETY: the caller's contract.
                unsafe {
                    if keylen > b2::KEYBYTES || keylen == 0 {
                        return fail_at(&err_sites::PROV_BLAKE2_MAC_IMPL_96);
                    }
                    ptr::copy_nonoverlapping(key, (*macctx).key.as_mut_ptr(), keylen);
                    if keylen < b2::KEYBYTES {
                        ptr::write_bytes(
                            (*macctx).key.as_mut_ptr().add(keylen),
                            0,
                            b2::KEYBYTES - keylen,
                        );
                    }
                    b2::param_set_key_length(&mut (*macctx).params, keylen as u8);
                    1
                }
            }

            /// `static int blake2_mac_init(void *vmacctx, const unsigned char *key, size_t keylen,
            /// const OSSL_PARAM params[])` — `blake2_mac_impl.c:107-123`.
            ///
            /// The `key == NULL` arm refuses when no key has been set *by any route*: the `params`
            /// array may have carried one, which is why the test is on the parameter block's
            /// `key_length` byte and not on the argument.
            ///
            /// # Safety
            /// The dispatch contract.
            unsafe extern "C" fn init(
                vmacctx: *mut c_void,
                key: *const c_uchar,
                keylen: usize,
                params: *const OsslParam,
            ) -> c_int {
                // SAFETY: the caller's contract.
                unsafe {
                    if is_running() == 0 || set_ctx_params(vmacctx, params) == 0 {
                        return 0;
                    }
                    let macctx = vmacctx.cast::<MacData>();
                    if !key.is_null() {
                        if setkey(macctx, key, keylen) == 0 {
                            return 0;
                        }
                    } else if (*macctx).params.b[1] == 0 {
                        return fail_at(&err_sites::PROV_BLAKE2_MAC_IMPL_119);
                    }
                    b2::init_key(
                        ptr::addr_of_mut!((*macctx).ctx),
                        ptr::addr_of!((*macctx).params),
                        (*macctx).key.as_ptr(),
                    )
                }
            }

            /// `static int blake2_mac_update(void *vmacctx, const unsigned char *data, size_t
            /// datalen)` — `blake2_mac_impl.c:125-134`. A zero-length update succeeds without
            /// touching the state.
            ///
            /// # Safety
            /// The dispatch contract.
            unsafe extern "C" fn update(
                vmacctx: *mut c_void,
                data: *const c_uchar,
                datalen: usize,
            ) -> c_int {
                // SAFETY: the caller's contract.
                unsafe {
                    if datalen == 0 {
                        return 1;
                    }
                    b2::update(
                        ptr::addr_of_mut!((*vmacctx.cast::<MacData>()).ctx),
                        data,
                        datalen,
                    )
                }
            }

            /// `static int blake2_mac_final(void *vmacctx, unsigned char *out, size_t *outl,
            /// size_t outsize)` — `blake2_mac_impl.c:136-147`.
            ///
            /// The length is written **before** the final runs and is never conditional, so a
            /// failed final still leaves the caller's `*outl` holding the size. That ordering is
            /// the authority's and it is observable through `EVP_MAC_final`, which copies the row's
            /// value even when the row returned 0.
            ///
            /// # Safety
            /// The dispatch contract.
            unsafe extern "C" fn final_(
                vmacctx: *mut c_void,
                out: *mut c_uchar,
                outl: *mut usize,
                _outsize: usize,
            ) -> c_int {
                // SAFETY: the caller's contract.
                unsafe {
                    if is_running() == 0 {
                        return 0;
                    }
                    let macctx = vmacctx.cast::<MacData>();
                    *outl = mac_size(macctx);
                    b2::final_(out, ptr::addr_of_mut!((*macctx).ctx))
                }
            }

            /// `static const OSSL_PARAM *blake2_gettable_ctx_params(void *ctx, void *provctx)` —
            /// `blake2_mac_impl.c:150-154`.
            ///
            /// # Safety
            /// The dispatch contract.
            unsafe extern "C" fn gettable_ctx_params(
                _ctx: *mut c_void,
                _provctx: *mut c_void,
            ) -> *const OsslParam {
                BLAKE2_GETTABLE_CTX_PARAMS.as_ptr()
            }

            /// `static int blake2_get_ctx_params(void *vmacctx, OSSL_PARAM params[])` —
            /// `blake2_mac_impl.c:156-172`. Both keys answer through `OSSL_PARAM_set_size_t`, and
            /// `block-size` answers the **constant** `BLOCKBYTES` rather than anything from the
            /// parameter block.
            ///
            /// # Safety
            /// The dispatch contract.
            unsafe extern "C" fn get_ctx_params(
                vmacctx: *mut c_void,
                params: *mut OsslParam,
            ) -> c_int {
                // SAFETY: the caller's contract.
                unsafe {
                    if vmacctx.is_null() {
                        return 0;
                    }
                    if let Some(site) = repeated_param_site(params, &BLAKE2_GET_CTX_DECODER_KEYS) {
                        return fail_at(site);
                    }
                    let macctx = vmacctx.cast::<MacData>();
                    let p = crate::params::OSSL_PARAM_locate(params, OSSL_MAC_PARAM_SIZE);
                    if !p.is_null()
                        && crate::params::OSSL_PARAM_set_size_t(p, mac_size(macctx)) == 0
                    {
                        return 0;
                    }
                    let p = crate::params::OSSL_PARAM_locate(params, OSSL_MAC_PARAM_BLOCK_SIZE);
                    if !p.is_null() && crate::params::OSSL_PARAM_set_size_t(p, b2::BLOCKBYTES) == 0
                    {
                        return 0;
                    }
                    1
                }
            }

            /// `static const OSSL_PARAM *blake2_mac_settable_ctx_params(void *ctx, void *p_ctx)`
            /// — `blake2_mac_impl.c:174-178`.
            ///
            /// # Safety
            /// The dispatch contract.
            unsafe extern "C" fn settable_ctx_params(
                _ctx: *mut c_void,
                _p_ctx: *mut c_void,
            ) -> *const OsslParam {
                BLAKE2_SETTABLE_CTX_PARAMS.as_ptr()
            }

            /// `static int blake2_mac_set_ctx_params(void *vmacctx, const OSSL_PARAM params[])` —
            /// `blake2_mac_impl.c:183-237`.
            ///
            /// Four things are contract. The `size` arm accepts the **range** `1..=OUTBYTES` and
            /// raises `PROV_R_NOT_XOF_OR_INVALID_LENGTH` outside it. `custom` and `salt` are
            /// bounded by their own widths with their own reasons. Both are applied to the
            /// parameter block without any setter indirection -- the descriptor's `data` and
            /// `data_size` are read directly, because `OSSL_PARAM` offers no setter for a
            /// fixed-width field, and the authority's comment says so. And a wrong `data_type` on
            /// any of the three is a bare zero with nothing queued.
            ///
            /// # Safety
            /// The dispatch contract.
            unsafe extern "C" fn set_ctx_params(
                vmacctx: *mut c_void,
                params: *const OsslParam,
            ) -> c_int {
                // SAFETY: the caller's contract.
                unsafe {
                    if vmacctx.is_null() {
                        return 0;
                    }
                    if let Some(site) = repeated_param_site(params, &BLAKE2_SET_CTX_DECODER_KEYS) {
                        return fail_at(site);
                    }
                    let macctx = vmacctx.cast::<MacData>();

                    let p = crate::params::OSSL_PARAM_locate_const(params, OSSL_MAC_PARAM_SIZE);
                    if !p.is_null() {
                        let mut size: usize = 0;
                        if crate::params::OSSL_PARAM_get_size_t(p, &mut size) == 0 {
                            return fail_at(&err_sites::PROV_BLAKE2_MAC_IMPL_197);
                        }
                        // The authority's literal `size < 1 || size > BLAKE2_OUTBYTES`, kept in
                        // the form it is written rather than rewritten as a `RangeInclusive`
                        // membership test -- the same call this crate makes wherever the
                        // arithmetic *is* the transcription.
                        #[allow(clippy::manual_range_contains)]
                        let out_of_range = size < 1 || size > b2::OUTBYTES;
                        if out_of_range {
                            return fail_at(&err_sites::PROV_BLAKE2_MAC_IMPL_197);
                        }
                        b2::param_set_digest_length(&mut (*macctx).params, size as u8);
                    }

                    let p = crate::params::OSSL_PARAM_locate_const(params, OSSL_MAC_PARAM_KEY);
                    if !p.is_null() {
                        if (*p).data_type != OSSL_PARAM_OCTET_STRING
                            || setkey(macctx, (*p).data.cast::<c_uchar>(), (*p).data_size) == 0
                        {
                            return 0;
                        }
                    }

                    let p = crate::params::OSSL_PARAM_locate_const(params, OSSL_MAC_PARAM_CUSTOM);
                    if !p.is_null() {
                        if (*p).data_type != OSSL_PARAM_OCTET_STRING {
                            return 0;
                        }
                        if (*p).data_size > b2::PERSONALBYTES {
                            return fail_at(&err_sites::PROV_BLAKE2_MAC_IMPL_216);
                        }
                        // SAFETY: the descriptor's `data` is readable for its own `data_size`,
                        // which the bound above has just checked against `PERSONALBYTES`.
                        let bytes =
                            core::slice::from_raw_parts((*p).data.cast::<u8>(), (*p).data_size);
                        b2::param_set_personal(&mut (*macctx).params, bytes);
                    }

                    let p = crate::params::OSSL_PARAM_locate_const(params, OSSL_MAC_PARAM_SALT);
                    if !p.is_null() {
                        if (*p).data_type != OSSL_PARAM_OCTET_STRING {
                            return 0;
                        }
                        if (*p).data_size > b2::SALTBYTES {
                            return fail_at(&err_sites::PROV_BLAKE2_MAC_IMPL_231);
                        }
                        // SAFETY: as above, against `SALTBYTES`.
                        let bytes =
                            core::slice::from_raw_parts((*p).data.cast::<u8>(), (*p).data_size);
                        b2::param_set_salt(&mut (*macctx).params, bytes);
                    }
                    1
                }
            }

            /// `const OSSL_DISPATCH ossl_blake2bmac_functions[]` /
            /// `ossl_blake2smac_functions[]` — `blake2_mac_impl.c:239-253`: ten entries and the
            /// terminator, identical in both instantiations because the table is inside the
            /// included body.
            pub(crate) static FUNCTIONS: [OsslDispatch; 11] = [
                OsslDispatch {
                    function_id: OSSL_FUNC_MAC_NEWCTX,
                    function: newctx as *mut c_void,
                },
                OsslDispatch {
                    function_id: OSSL_FUNC_MAC_DUPCTX,
                    function: dup as *mut c_void,
                },
                OsslDispatch {
                    function_id: OSSL_FUNC_MAC_FREECTX,
                    function: free as *mut c_void,
                },
                OsslDispatch {
                    function_id: OSSL_FUNC_MAC_INIT,
                    function: init as *mut c_void,
                },
                OsslDispatch {
                    function_id: OSSL_FUNC_MAC_UPDATE,
                    function: update as *mut c_void,
                },
                OsslDispatch {
                    function_id: OSSL_FUNC_MAC_FINAL,
                    function: final_ as *mut c_void,
                },
                OsslDispatch {
                    function_id: OSSL_FUNC_MAC_GETTABLE_CTX_PARAMS,
                    function: gettable_ctx_params as *mut c_void,
                },
                OsslDispatch {
                    function_id: OSSL_FUNC_MAC_GET_CTX_PARAMS,
                    function: get_ctx_params as *mut c_void,
                },
                OsslDispatch {
                    function_id: OSSL_FUNC_MAC_SETTABLE_CTX_PARAMS,
                    function: settable_ctx_params as *mut c_void,
                },
                OsslDispatch {
                    function_id: OSSL_FUNC_MAC_SET_CTX_PARAMS,
                    function: set_ctx_params as *mut c_void,
                },
                OsslDispatch {
                    function_id: OSSL_DISPATCH_END,
                    function: ptr::null_mut(),
                },
            ];
        }
    };
}

blake2_mac_row!(blake2b_mac, blake2b);
blake2_mac_row!(blake2s_mac, blake2s);

// ---------------------------------------------------------------------------------------------
// `POLY1305` — `providers/implementations/macs/poly1305_prov.c`
// ---------------------------------------------------------------------------------------------

/// The allocation `file` argument for this row: the build-relative spelling, because
/// `poly1305_prov.c` is generated from `poly1305_prov.c.in` (D235's rule, and the unit test below
/// binds it to a raise site in the same unit).
const FILE_POLY1305: *const c_char = c"providers/implementations/macs/poly1305_prov.c".as_ptr();

/// The one key `poly1305_get_params_decoder` locates, with its raise site. The generated decoder
/// compares the **whole** key (`strcmp("size", s + 0)`) rather than switching on the first byte,
/// because there is only one.
const POLY1305_GET_PARAMS_DECODER_KEYS: [(&err_sites::ErrSite, *const c_char); 1] =
    [(&err_sites::PROV_POLY1305_PROV_177, OSSL_MAC_PARAM_SIZE)];

/// The one key `poly1305_set_ctx_params_decoder` locates, with its raise site.
const POLY1305_SET_CTX_PARAMS_DECODER_KEYS: [(&err_sites::ErrSite, *const c_char); 1] =
    [(&err_sites::PROV_POLY1305_PROV_234, OSSL_MAC_PARAM_KEY)];

/// `poly1305_get_params_list` — `poly1305_prov.c:153-156`: **one** `OSSL_PARAM_size_t` entry, and
/// a *provider-level* list rather than a ctx-level one — the row publishes
/// `GETTABLE_PARAMS`/`GET_PARAMS` and no ctx-params getter at all, exactly as GMAC does and
/// differently from CMAC, HMAC, SIPHASH and BLAKE2.
static POLY1305_GETTABLE_PARAMS: [OsslParam; 2] = [param_size_t(OSSL_MAC_PARAM_SIZE), END];

/// `poly1305_set_ctx_params_list` — `poly1305_prov.c:210-213`: the key, and nothing else. There is
/// no `size`, `cipher`, `custom` or `salt` here.
static POLY1305_SETTABLE_CTX_PARAMS: [OsslParam; 2] = [param_octet_string(OSSL_MAC_PARAM_KEY), END];

/// `struct poly1305_data_st` — `poly1305_prov.c:44-49`.
///
/// The two flags are the row's own state machine and they are *not* interchangeable: `key_set` says
/// a key has ever been given, and `updated` says the context has been used since the last key.
/// `updated` is what makes a second `EVP_MAC_init` without a key refuse, and `key_set` is what makes
/// an `update` or a `final` refuse before that. The embedded `POLY1305` sits at offset 16 — the
/// layout is verified against the authority's own offsets (0, 8, 12, 16) and its total is 264 bytes,
/// which is the number an application's allocator is handed.
#[repr(C)]
pub(crate) struct Poly1305Data {
    /// `void *provctx` — stored and never read.
    pub provctx: *mut c_void,
    /// `int updated`.
    pub updated: c_int,
    /// `int key_set`.
    pub key_set: c_int,
    /// `POLY1305 poly1305`.
    pub poly1305: Poly1305,
}

/// `static void *poly1305_new(void *provctx)` — `poly1305_prov.c:51-61`.
///
/// # Safety
/// The dispatch contract.
unsafe extern "C" fn poly1305_new(provctx: *mut c_void) -> *mut c_void {
    // SAFETY: the caller's contract.
    unsafe {
        if is_running() == 0 {
            return ptr::null_mut();
        }
        let ctx = CRYPTO_zalloc(core::mem::size_of::<Poly1305Data>(), FILE_POLY1305, LINE)
            .cast::<Poly1305Data>();
        if !ctx.is_null() {
            (*ctx).provctx = provctx;
        }
        ctx.cast()
    }
}

/// `static void poly1305_free(void *vmacctx)` — `poly1305_prov.c:63-66`.
///
/// **A bare `OPENSSL_free`, with no cleanse.** The context holds a Poly1305 key schedule and a
/// partial block, and the authority does not scrub either — unlike `hmac_free`, which cleanses its
/// key, and unlike `Poly1305_Final`, which cleanses the inner context. Transcribed as written; the
/// asymmetry is the authority's.
///
/// # Safety
/// The dispatch contract.
unsafe extern "C" fn poly1305_free(vmacctx: *mut c_void) {
    // SAFETY: the caller's contract; `vmacctx` is a context `poly1305_new` allocated.
    unsafe { CRYPTO_free(vmacctx, FILE_POLY1305, LINE) }
}

/// `static void *poly1305_dup(void *vsrc)` — `poly1305_prov.c:68-81`.
///
/// `OPENSSL_malloc` here where `blake2_mac_dup` uses `OPENSSL_zalloc`, and then a whole-struct copy
/// that overwrites every byte either way. The difference is not observable and is transcribed
/// because the file spells it.
///
/// # Safety
/// The dispatch contract.
unsafe extern "C" fn poly1305_dup(vsrc: *mut c_void) -> *mut c_void {
    // SAFETY: the caller's contract.
    unsafe {
        if is_running() == 0 {
            return ptr::null_mut();
        }
        let dst = CRYPTO_malloc(core::mem::size_of::<Poly1305Data>(), FILE_POLY1305, LINE)
            .cast::<Poly1305Data>();
        if dst.is_null() {
            return ptr::null_mut();
        }
        ptr::copy_nonoverlapping(
            vsrc.cast::<u8>(),
            dst.cast::<u8>(),
            core::mem::size_of::<Poly1305Data>(),
        );
        dst.cast()
    }
}

/// `static size_t poly1305_size(void)` — `poly1305_prov.c:83-86`. A constant: Poly1305's tag is
/// always sixteen bytes, whatever the message.
fn poly1305_size() -> usize {
    POLY1305_DIGEST_SIZE
}

/// `static int poly1305_setkey(struct poly1305_data_st *ctx, const unsigned char *key,
/// size_t keylen)` — `poly1305_prov.c:88-99`.
///
/// **A NULL key is refused as well as a wrong length**, and the length must be exactly
/// `POLY1305_KEY_SIZE` — there is no padding and no truncation. Both flags are set here rather than
/// one: the key is now set, and the context has not been used since.
///
/// # Safety
/// `ctx` is live; `key` is NULL or readable for `keylen` bytes.
unsafe fn poly1305_setkey(ctx: *mut Poly1305Data, key: *const c_uchar, keylen: usize) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        if key.is_null() || keylen != POLY1305_KEY_SIZE {
            return fail_at(&err_sites::PROV_POLY1305_PROV_92);
        }
        Poly1305_Init(ptr::addr_of_mut!((*ctx).poly1305), key);
        (*ctx).updated = 0;
        (*ctx).key_set = 1;
        1
    }
}

/// `static int poly1305_init(void *vmacctx, const unsigned char *key, size_t keylen,
/// const OSSL_PARAM params[])` — `poly1305_prov.c:101-113`.
///
/// **The `key == NULL` arm is a refusal once the context has been used.** Given `updated` is set by
/// both `update` and `final`, a caller that hashed and then calls `EVP_MAC_init` without a key gets
/// 0, because Poly1305 cannot be re-keyed without a key and cannot be reused either. That is the
/// row's own rule and it is why a "just restart" re-init is not what happens here, in contrast with
/// HMAC's row.
///
/// # Safety
/// The dispatch contract.
unsafe extern "C" fn poly1305_init(
    vmacctx: *mut c_void,
    key: *const c_uchar,
    keylen: usize,
    params: *const OsslParam,
) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        if is_running() == 0 || poly1305_set_ctx_params(vmacctx, params) == 0 {
            return 0;
        }
        let ctx = vmacctx.cast::<Poly1305Data>();
        if !key.is_null() {
            return poly1305_setkey(ctx, key, keylen);
        }
        /* no reinitialization of context with the same key is allowed */
        ((*ctx).updated == 0) as c_int
    }
}

/// `static int poly1305_update(void *vmacctx, const unsigned char *data, size_t datalen)` —
/// `poly1305_prov.c:115-131`.
///
/// Note the order: the `key_set` test with its raise comes **first**, then `updated` is set, then a
/// zero-length update returns 1. So an update with no key raises and does *not* mark the context
/// used, which is what keeps a later `init` without a key possible.
///
/// # Safety
/// The dispatch contract.
unsafe extern "C" fn poly1305_update(
    vmacctx: *mut c_void,
    data: *const c_uchar,
    datalen: usize,
) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        let ctx = vmacctx.cast::<Poly1305Data>();
        if (*ctx).key_set == 0 {
            return fail_at(&err_sites::PROV_POLY1305_PROV_121);
        }
        (*ctx).updated = 1;
        if datalen == 0 {
            return 1;
        }
        /* poly1305 has nothing to return in its update function */
        Poly1305_Update(ptr::addr_of_mut!((*ctx).poly1305), data, datalen);
        1
    }
}

/// `static int poly1305_final(void *vmacctx, unsigned char *out, size_t *outl, size_t outsize)` —
/// `poly1305_prov.c:133-148`. The same `key_set` refusal as the update, with its own coordinate
/// because it is a different line, and the length is written **after** the tag.
///
/// # Safety
/// The dispatch contract.
unsafe extern "C" fn poly1305_final(
    vmacctx: *mut c_void,
    out: *mut c_uchar,
    outl: *mut usize,
    _outsize: usize,
) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        if is_running() == 0 {
            return 0;
        }
        let ctx = vmacctx.cast::<Poly1305Data>();
        if (*ctx).key_set == 0 {
            return fail_at(&err_sites::PROV_POLY1305_PROV_141);
        }
        (*ctx).updated = 1;
        Poly1305_Final(ptr::addr_of_mut!((*ctx).poly1305), out);
        *outl = poly1305_size();
        1
    }
}

/// `static const OSSL_PARAM *poly1305_gettable_params(void *provctx)` — `poly1305_prov.c:189-192`.
/// No context argument, because this is the provider-level list.
///
/// # Safety
/// The dispatch contract.
unsafe extern "C" fn poly1305_gettable_params(_provctx: *mut c_void) -> *const OsslParam {
    POLY1305_GETTABLE_PARAMS.as_ptr()
}

/// `static int poly1305_get_params(OSSL_PARAM params[])` — `poly1305_prov.c:194-205`. One key, and
/// it answers the constant 16.
///
/// # Safety
/// The dispatch contract.
unsafe extern "C" fn poly1305_get_params(params: *mut OsslParam) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        if let Some(site) = repeated_param_site(params, &POLY1305_GET_PARAMS_DECODER_KEYS) {
            return fail_at(site);
        }
        let p = crate::params::OSSL_PARAM_locate(params, OSSL_MAC_PARAM_SIZE);
        if !p.is_null() && crate::params::OSSL_PARAM_set_size_t(p, poly1305_size()) == 0 {
            return 0;
        }
        1
    }
}

/// `static const OSSL_PARAM *poly1305_settable_ctx_params(void *ctx, void *provctx)` —
/// `poly1305_prov.c:246-250`.
///
/// # Safety
/// The dispatch contract.
unsafe extern "C" fn poly1305_settable_ctx_params(
    _ctx: *mut c_void,
    _provctx: *mut c_void,
) -> *const OsslParam {
    POLY1305_SETTABLE_CTX_PARAMS.as_ptr()
}

/// `static int poly1305_set_ctx_params(void *vmacctx, const OSSL_PARAM *params)` —
/// `poly1305_prov.c:252-265`.
///
/// The `key` arm short-circuits on a wrong `data_type` *or* a failed `poly1305_setkey`, which is
/// the same shape HMAC's and BLAKE2's rows use — and note the declaration is
/// `const OSSL_PARAM *params` here rather than `const OSSL_PARAM params[]`, the same type spelled
/// two ways.
///
/// # Safety
/// The dispatch contract.
unsafe extern "C" fn poly1305_set_ctx_params(
    vmacctx: *mut c_void,
    params: *const OsslParam,
) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        if vmacctx.is_null() {
            return 0;
        }
        if let Some(site) = repeated_param_site(params, &POLY1305_SET_CTX_PARAMS_DECODER_KEYS) {
            return fail_at(site);
        }
        let p = crate::params::OSSL_PARAM_locate_const(params, OSSL_MAC_PARAM_KEY);
        if !p.is_null()
            && ((*p).data_type != OSSL_PARAM_OCTET_STRING
                || poly1305_setkey(
                    vmacctx.cast::<Poly1305Data>(),
                    (*p).data.cast::<c_uchar>(),
                    (*p).data_size,
                ) == 0)
        {
            return 0;
        }
        1
    }
}

/// `const OSSL_DISPATCH ossl_poly1305_functions[]` — `poly1305_prov.c:267-280`: ten entries and the
/// terminator. The fourth and fifth are the **provider-level** params pair, which is what makes this
/// row's getter surface different from the ctx-level one the other MAC rows publish.
pub(crate) static POLY1305_FUNCTIONS: [OsslDispatch; 11] = [
    OsslDispatch {
        function_id: OSSL_FUNC_MAC_NEWCTX,
        function: poly1305_new as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_MAC_DUPCTX,
        function: poly1305_dup as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_MAC_FREECTX,
        function: poly1305_free as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_MAC_INIT,
        function: poly1305_init as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_MAC_UPDATE,
        function: poly1305_update as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_MAC_FINAL,
        function: poly1305_final as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_MAC_GETTABLE_PARAMS,
        function: poly1305_gettable_params as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_MAC_GET_PARAMS,
        function: poly1305_get_params as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_MAC_SETTABLE_CTX_PARAMS,
        function: poly1305_settable_ctx_params as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_MAC_SET_CTX_PARAMS,
        function: poly1305_set_ctx_params as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_DISPATCH_END,
        function: ptr::null_mut(),
    },
];

// =====================================================================================
// `KMAC-128` and `KMAC-256` — `providers/implementations/macs/kmac_prov.c`
//
// The two rows the authority generates from `kmac_prov.c.in`, and the largest MAC unit in
// `deflt_macs[]`. **The row is a shell over the EVP digest layer rather than over Keccak**: the file's
// own comment says KMAC *"is implemented as a hash, which we can use instead of reimplementing the EVP
// functionality with direct use of keccak_mac_init() and friends"*, so `kmac_init` performs
// `EVP_DigestInit_ex` on the `KECCAK-KMAC-128`/`-256` digest this crate already publishes and the whole
// SP 800-185 construction is carried by the digest's cSHAKE parameter block and its XOF squeeze. What
// this unit adds is the **encoding layer** (`encode_string`, `right_encode`, `bytepad`), the state
// machine, and the parameterisation.
//
// Three things about it are unlike every other MAC row here.
//
// **The default customisation string is applied through the row's own setter, from inside `init`.**
// `kmac_init` calls `kmac_set_ctx_params(kctx, cparams)` with a one-entry array naming `custom` — so a
// row with no customisation still stores `encode_string("")` = `[0x01, 0x00]`, and `custom_len` becomes
// 2 rather than 0. The return value is discarded: a failure there is not a failure of the init.
//
// **`dupset` copies field by field, not the whole struct.** Where `hmac_dup` does `*dst = *src`,
// `kmac_dup` assigns four scalars and two arrays explicitly, so any field a later authority version
// adds to `kmac_data_st` would not survive a duplicate. The transcription follows the authority.
//
// **`final` ignores `outsize`.** The authority's `kmac_final` writes `kctx->out_len` bytes through
// `EVP_DigestFinalXOF` without consulting the size it was handed; the bound a caller sees comes from
// `evp_mac_final`'s `outsize < macsize` check, which asks *this row's* `get_ctx_params` for `size`. So
// `EVP_MAC_final(ctx, out, &outl, 7)` on a 32-byte KMAC-128 refuses at the EVP layer with
// `EVP_R_BUFFER_TOO_SMALL` and never reaches the row, while `EVP_MAC_final(ctx, out, &outl, 32)` does.
//
// **The FIPS arms are absent from this profile's build, as they are from every other MAC unit's.**
// `FIPS_MODULE` is undefined, so `OSSL_FIPS_IND_DECLARE` contributes no field, `OSSL_FIPS_IND_INIT`
// and `OSSL_FIPS_IND_COPY` expand to nothing and `OSSL_FIPS_IND_{GET,SET}_CTX_FROM_PARAM` to the
// literal `1`; the generated decoders `# if defined(FIPS_MODULE)`-guard the `fips-indicator`,
// `fips-key-check` and `fips-no-short-mac` keys, so a caller passing `fips-key-check` twice is
// **silently ignored** on both sides rather than refused, and the `ossl_mac_check_key_size` /
// short-output arms are inside `#ifdef FIPS_MODULE` blocks. Five of the unit's twenty-one raise sites
// (288, 446, 574, 598, 682) are inside those blocks and are therefore unreachable here; they are named
// in D260 rather than transcribed.
//
// Four more are unreachable by *arithmetic* rather than by configuration, and that is worth stating
// because the sites are transcribed anyway:
//
//   * `kmac_init`'s `ERR_R_INTERNAL_ERROR` at `:351` needs `bytepad(NULL, …)` to fail, and the NULL
//     branch fails only when `out_len` is NULL, which it is not here.
//   * `right_encode`'s `PROV_R_LENGTH_TOO_LARGE` at `:741` needs a four-byte length, and `size` is
//     capped at `KMAC_MAX_OUTPUT_LEN` = 2097151, whose bit length times eight is 16777208 < 2^24, so
//     `get_encode_size` never exceeds 3 into a 4-byte buffer.
//   * `encode_string`'s `PROV_R_LENGTH_TOO_LARGE` at `:778` needs `1 + len + in_len > 516`, and both
//     of its callers bound `in_len` first — the `custom` arm refuses anything over
//     `KMAC_MAX_CUSTOM` = 512, and `kmac_bytepad_encode_key`'s key is refused over `KMAC_MAX_KEY` =
//     512 — so the largest encoding is `1 + 2 + 512` = 515.
//   * `bytepad`'s `ERR_R_PASSED_NULL_PARAMETER` at `:811` needs both pointers NULL, and every call
//     site passes exactly one.
//
// `KMAC_FLAG_XOF_MODE` (`kmac_prov.c.in:121`) is defined and never used by the authority's own text,
// so there is nothing to transcribe; `kctx->xof_mode` is what carries the flag.
// =====================================================================================

/// `KMAC_MAX_BLOCKSIZE` — `kmac_prov.c:89`, spelled as the authority spells it: `(1600 - 128 * 2) / 8`
/// is Keccak-256's rate, and `KMAC_MAX_KEY_ENCODED` is four of them.
const KMAC_MAX_BLOCKSIZE: usize = 168;

/// `KMAC_MAX_OUTPUT_LEN` — `kmac_prov.c:95` (`0xFFFFFF / 8`). The authority's comment explains the
/// bound: the length encoding is a one-byte size plus at most three bytes of length in **bits**, giving
/// `0..0xFFFFFF` bits.
const KMAC_MAX_OUTPUT_LEN: usize = 0x00FF_FFFF / 8;

/// `KMAC_MAX_ENCODED_HEADER_LEN` — `kmac_prov.c:96` (`1 + 3`).
const KMAC_MAX_ENCODED_HEADER_LEN: usize = 1 + 3;

/// `KMAC_MAX_CUSTOM` — `kmac_prov.c:102`. A cap on the customisation string, and a *different* cap
/// from the one its own encoding would need; see the module note above.
const KMAC_MAX_CUSTOM: usize = 512;

/// `KMAC_MAX_CUSTOM_ENCODED` — `kmac_prov.c:105`, and the width of `custom[]`.
const KMAC_MAX_CUSTOM_ENCODED: usize = KMAC_MAX_CUSTOM + KMAC_MAX_ENCODED_HEADER_LEN;

/// `KMAC_MAX_KEY` — `kmac_prov.c:108`.
const KMAC_MAX_KEY: usize = 512;

/// `KMAC_MIN_KEY` — `kmac_prov.c:109`. Four bytes, which is the SP 800-185 minimum and is *checked*,
/// unlike Poly1305's fixed 32.
const KMAC_MIN_KEY: usize = 4;

/// `KMAC_MAX_KEY_ENCODED` — `kmac_prov.c:115` (`KMAC_MAX_BLOCKSIZE * 4`), and the width of `key[]`.
const KMAC_MAX_KEY_ENCODED: usize = KMAC_MAX_BLOCKSIZE * 4;

/// `static const unsigned char kmac_string[]` — `kmac_prov.c:118-120`. It is `encode_string("KMAC")`:
/// a one-byte left-encoded length of `0x20` bits, then the four bytes.
static KMAC_STRING: [c_uchar; 6] = [0x01, 0x20, 0x4B, 0x4D, 0x41, 0x43];

/// `OSSL_MAC_PARAM_XOF` — `core_names.h:355` (`"xof"`).
const OSSL_MAC_PARAM_XOF: *const c_char = c"xof".as_ptr();

/// `OSSL_DIGEST_NAME_KECCAK_KMAC128` — `core_names.h:53`.
const OSSL_DIGEST_NAME_KECCAK_KMAC128: *const c_char = c"KECCAK-KMAC-128".as_ptr();

/// `sizeof(OSSL_DIGEST_NAME_KECCAK_KMAC128)` — the literal **with** its NUL, which is what
/// `kmac128_params` passes as `data_size`.
///
/// **Fifteen** characters plus one, not the thirteen a careless reading of `KECCAK-KMAC-128` gives:
/// the unit test below binds this number to the literal, and it caught the miscount on the first run.
const OSSL_DIGEST_NAME_KECCAK_KMAC128_SIZE: usize = 16;

/// `OSSL_DIGEST_NAME_KECCAK_KMAC256` — `core_names.h:54`.
const OSSL_DIGEST_NAME_KECCAK_KMAC256: *const c_char = c"KECCAK-KMAC-256".as_ptr();

/// `sizeof(OSSL_DIGEST_NAME_KECCAK_KMAC256)` — fifteen characters plus one, as above.
const OSSL_DIGEST_NAME_KECCAK_KMAC256_SIZE: usize = 16;

/// The allocation-tracking `file` argument for the KMAC rows' allocations:
/// `providers/implementations/macs/kmac_prov.c`, with no `../../src/openssl-3.6.4/` prefix because the
/// unit is generated from `kmac_prov.c.in` and the compiler spells a generated file build-relative.
/// D235's rule, and the same one `FILE_POLY1305` records.
const FILE_KMAC: *const c_char = c"providers/implementations/macs/kmac_prov.c".as_ptr();

/// `struct kmac_data_st` — `kmac_prov.c:123-142` **without** its `#ifdef FIPS_MODULE` field, which
/// `OSSL_FIPS_IND_DECLARE` expands to nothing here.
///
/// `key` is stored **encoded** rather than raw, which is the row's central design decision: the
/// bytepad-with-length form is what `init` feeds to the digest, so `key_len` is the encoded length and
/// the `key` a caller supplies is consumed once, at set time, and never retained.
#[repr(C)]
pub(crate) struct KmacData {
    /// `void *provctx` — the provider context, whose library context the digest is resolved in.
    pub provctx: *mut c_void,
    /// `EVP_MD_CTX *ctx` — the hash the construction is carried by.
    pub ctx: *mut EvpMdCtx,
    /// `PROV_DIGEST digest` — the `KECCAK-KMAC-128`/`-256` method, fetched at `new`.
    pub digest: ProvDigest,
    /// `size_t out_len` — the requested output length, defaulted from the digest's size.
    pub out_len: usize,
    /// `size_t key_len` — the length of `key` **in its encoded form**.
    pub key_len: usize,
    /// `size_t custom_len` — the length of `custom` in its encoded form.
    pub custom_len: usize,
    /// `int xof_mode` — whether `right_encode(0)` rather than `right_encode(out_len * 8)` is fed.
    pub xof_mode: c_int,
    /// `unsigned char key[KMAC_MAX_KEY_ENCODED]`.
    pub key: [c_uchar; KMAC_MAX_KEY_ENCODED],
    /// `unsigned char custom[KMAC_MAX_CUSTOM_ENCODED]`.
    pub custom: [c_uchar; KMAC_MAX_CUSTOM_ENCODED],
}

/// The two keys `kmac_get_ctx_params_decoder` locates in this profile, each with the site of its own
/// repeated-parameter raise (`kmac_prov.c:434`, `:458`). The third the generator emits,
/// `fips-indicator`, is `# if defined(FIPS_MODULE)`-guarded and absent here.
const KMAC_GET_CTX_PARAMS_DECODER_KEYS: [(&err_sites::ErrSite, *const c_char); 2] = [
    (&err_sites::PROV_KMAC_PROV_434, OSSL_MAC_PARAM_BLOCK_SIZE),
    (&err_sites::PROV_KMAC_PROV_458, OSSL_MAC_PARAM_SIZE),
];

/// The four keys `kmac_set_ctx_params_decoder` locates in this profile, each with its raise site
/// (`kmac_prov.c:550`, `:584`, `:610`, `:621`). The fifth and sixth are the FIPS `fips-key-check` and
/// `fips-no-short-mac`, guarded and absent.
///
/// The generated `switch` orders these by first byte and then by prefix — `c`utom, `k`ey, `s`ize,
/// `x`of — which is also the order this array is in. `custom` is the only `c`, `key` the only `k` of
/// the pair this profile admits, and `size`/`xof` are single cases, so the array order and the switch
/// order agree for all four.
const KMAC_SET_CTX_PARAMS_DECODER_KEYS: [(&err_sites::ErrSite, *const c_char); 4] = [
    (&err_sites::PROV_KMAC_PROV_550, OSSL_MAC_PARAM_CUSTOM),
    (&err_sites::PROV_KMAC_PROV_584, OSSL_MAC_PARAM_KEY),
    (&err_sites::PROV_KMAC_PROV_610, OSSL_MAC_PARAM_SIZE),
    (&err_sites::PROV_KMAC_PROV_621, OSSL_MAC_PARAM_XOF),
];

/// `static const OSSL_PARAM kmac_get_ctx_params_list[]` — `kmac_prov.c:398-404`, the two keys this
/// profile's generator emits.
///
/// **Both entries are `size_t`, and `block-size` is written by `OSSL_PARAM_set_int` anyway.** The
/// mismatch is the authority's, at `kmac_prov.c:490`, and it is HMAC's row's mismatch too — so a
/// caller that passes an eight-byte `size_t` for `block-size` gets four bytes written and the high
/// half of its buffer left alone, on both sides, because both sides go through the same
/// `OSSL_PARAM_set_int`.
static KMAC_GETTABLE_CTX_PARAMS: [OsslParam; 3] = [
    param_size_t(OSSL_MAC_PARAM_SIZE),
    param_size_t(OSSL_MAC_PARAM_BLOCK_SIZE),
    END,
];

/// `static const OSSL_PARAM kmac_set_ctx_params_list[]` — `kmac_prov.c:504-517`, the four keys this
/// profile's generator emits, in the produced order.
///
/// `xof` is **`OSSL_PARAM_int`**, which is the authority's declaration and not a guess: it is read
/// with `OSSL_PARAM_get_int` into an `int` field, so a caller that hands an unsigned integer here is
/// refused by `params.c` rather than converted.
static KMAC_SETTABLE_CTX_PARAMS: [OsslParam; 5] = [
    param_int(OSSL_MAC_PARAM_XOF),
    param_size_t(OSSL_MAC_PARAM_SIZE),
    param_octet_string(OSSL_MAC_PARAM_KEY),
    param_octet_string(OSSL_MAC_PARAM_CUSTOM),
    END,
];

/// `static const OSSL_PARAM kmac128_params[]` — `kmac_prov.c:205-209`. A one-entry list naming the
/// digest the row is defined over, with `data_size` = `sizeof` of the literal so the NUL is included.
static KMAC128_PARAMS: [OsslParam; 2] = [
    param_utf8_string_with(
        OSSL_ALG_PARAM_DIGEST,
        OSSL_DIGEST_NAME_KECCAK_KMAC128 as *mut c_void,
        OSSL_DIGEST_NAME_KECCAK_KMAC128_SIZE,
    ),
    END,
];

/// `static const OSSL_PARAM kmac256_params[]` — `kmac_prov.c:215-219`.
static KMAC256_PARAMS: [OsslParam; 2] = [
    param_utf8_string_with(
        OSSL_ALG_PARAM_DIGEST,
        OSSL_DIGEST_NAME_KECCAK_KMAC256 as *mut c_void,
        OSSL_DIGEST_NAME_KECCAK_KMAC256_SIZE,
    ),
    END,
];

/// The `custom` descriptor `kmac_init` uses to install the default when none was set:
/// `OSSL_PARAM_octet_string(OSSL_MAC_PARAM_CUSTOM, "", 0)` (`kmac_prov.c:345`).
///
/// The `data` is a **non-NULL** pointer to a zero-length string, and that is the whole point of the
/// static existing: `encode_string` answers `[0x01, 0x00]` for a non-NULL empty input and leaves
/// `custom_len` at 0 for a NULL one, so a NULL here would silently change every tag the row produces.
static KMAC_EMPTY_CUSTOM: [c_uchar; 1] = [0];

/// `static unsigned int get_encode_size(size_t bits)` — `kmac_prov.c:523-535`.
///
/// Shifts by **eight** bits at a time, so it answers the number of *bytes* a length occupies, and
/// answers 1 rather than 0 for a zero length.
fn get_encode_size(bits: usize) -> c_uint {
    let mut cnt: c_uint = 0;
    let cap: c_uint = core::mem::size_of::<usize>() as c_uint;
    let mut bits = bits;

    while bits != 0 && cnt < cap {
        cnt += 1;
        bits >>= 8;
    }
    if cnt == 0 {
        cnt = 1;
    }
    cnt
}

/// `static int right_encode(unsigned char *out, size_t out_max_len, size_t *out_len, size_t bits)` —
/// `kmac_prov.c:544-566`.
///
/// SP 800-185's `right_encode(x)`: the byte string is the big-endian integer followed by **its own
/// byte length**, which is the opposite end from `encode_string`'s left encoding.
///
/// The refusal is `len >= out_max_len` rather than `>`, because the trailing length byte needs a slot
/// of its own. It is unreachable through `kmac_final` — see the module note — but the coordinate is
/// the authority's and the arm is written as the authority writes it.
///
/// # Safety
/// `out` is writable for at least `out_max_len` bytes when the call succeeds; `out_len` is writable.
unsafe fn right_encode(
    out: *mut c_uchar,
    out_max_len: usize,
    out_len: *mut usize,
    bits: usize,
) -> c_int {
    let len = get_encode_size(bits) as usize;
    let mut bits = bits;

    if len >= out_max_len {
        return fail_at(&err_sites::PROV_KMAC_PROV_741);
    }

    // MSBs at the start of the array: the last byte written is the least significant.
    // SAFETY: `len < out_max_len` was just established, so every index below is in bounds.
    unsafe {
        let mut i = len;
        while i > 0 {
            i -= 1;
            *out.add(i) = (bits & 0xFF) as c_uchar;
            bits >>= 8;
        }
        // The length is tacked onto the **end**, and is included in `*out_len`.
        *out.add(len) = len as c_uchar;
    }
    // SAFETY: the caller's contract; `out_len` is writable.
    unsafe { *out_len = len + 1 };
    1
}

/// `static int encode_string(unsigned char *out, size_t out_max_len, size_t *out_len,
/// const unsigned char *in, size_t in_len)` — `kmac_prov.c:572-601`.
///
/// SP 800-185's `encode_string(S)`: a left-encoded bit length followed by the bytes. A **NULL** `in`
/// is not an error: it answers `*out_len = 0` and leaves the buffer untouched, which is what
/// distinguishes "no customisation" from "empty customisation" in the authority's own encoding — the
/// reason `KMAC_EMPTY_CUSTOM` above is non-NULL.
///
/// `sz = 1 + len + in_len` is `size_t` arithmetic and is transcribed with wrapping operations for the
/// same reason every other `size_t` sum here is: `overflow-checks` is on, and C would wrap.
///
/// # Safety
/// `out` is writable for `out_max_len` bytes; `in` is readable for `in_len` bytes or NULL; `out_len`
/// is writable.
unsafe fn encode_string(
    out: *mut c_uchar,
    out_max_len: usize,
    out_len: *mut usize,
    in_: *const c_uchar,
    in_len: usize,
) -> c_int {
    if in_.is_null() {
        // SAFETY: the caller's contract; `out_len` is writable.
        unsafe { *out_len = 0 };
        return 1;
    }

    // `bits = 8 * in_len` is `size_t`, so it wraps rather than saturating.
    let mut bits = in_len.wrapping_mul(8);
    let len = get_encode_size(bits) as usize;
    let sz = 1usize.wrapping_add(len).wrapping_add(in_len);

    if sz > out_max_len {
        return fail_at(&err_sites::PROV_KMAC_PROV_778);
    }

    // SAFETY: the caller's contract; `out` is writable for `out_max_len >= sz > len` bytes and `in`
    // for `in_len`.
    unsafe {
        *out = len as c_uchar;
        let mut i = len;
        while i > 0 {
            *out.add(i) = (bits & 0xFF) as c_uchar;
            bits >>= 8;
            i -= 1;
        }
        core::ptr::copy_nonoverlapping(in_, out.add(len + 1), in_len);
        *out_len = sz;
    }
    1
}

/// `static int bytepad(unsigned char *out, size_t *out_len, const unsigned char *in1, size_t in1_len,
/// const unsigned char *in2, size_t in2_len, size_t w)` — `kmac_prov.c:610-654`.
///
/// SP 800-185's `bytepad(X, w)` = `left_encode(w) || X`, zero-padded to a multiple of `w`.
///
/// **The `out == NULL` form is the sizing query**, and it is how the authority learns how many bytes to
/// allocate before calling again with a real buffer. The two arithmetic expressions are `size_t` and
/// transcribed with wrapping operations; neither can overflow at the call sites this crate has, and
/// `w` is never 0 there because both callers check the digest's block size for `<= 0` first, so the
/// divisions are safe.
///
/// `!ossl_assert(w <= 255)` is a live guard under `NDEBUG` — it is `!((w <= 255) != 0)` — so a `w`
/// above 255 is a quiet 0 rather than an abort (D167's rule).
///
/// # Safety
/// `out` is NULL or writable for the padded length; `out_len` is NULL or writable; `in1`/`in2` are
/// readable for their lengths or NULL for `in2`.
#[allow(clippy::too_many_arguments)] // mirrors the authority's signature exactly
unsafe fn bytepad(
    out: *mut c_uchar,
    out_len: *mut usize,
    in1: *const c_uchar,
    in1_len: usize,
    in2: *const c_uchar,
    in2_len: usize,
    w: usize,
) -> c_int {
    if out.is_null() {
        if out_len.is_null() {
            return fail_at(&err_sites::PROV_KMAC_PROV_811);
        }
        let sz = 2usize
            .wrapping_add(in1_len)
            .wrapping_add(if in2.is_null() { 0 } else { in2_len });
        // SAFETY: `out_len` was just checked non-NULL.
        unsafe { *out_len = sz.wrapping_add(w).wrapping_sub(1) / w * w };
        return 1;
    }

    if w > 255 {
        return 0;
    }

    // SAFETY: the caller's contract; `out` is writable for the padded length, which is at least
    // `2 + in1_len + in2_len`, and both inputs are readable for their own lengths.
    unsafe {
        let mut p = out;
        // Left encoded w: a one-byte length of one, then w itself.
        *p = 1;
        p = p.add(1);
        *p = w as c_uchar;
        p = p.add(1);
        /* || in1 */
        core::ptr::copy_nonoverlapping(in1, p, in1_len);
        p = p.add(in1_len);
        /* [ || in2 ] */
        if !in2.is_null() && in2_len > 0 {
            core::ptr::copy_nonoverlapping(in2, p, in2_len);
            p = p.add(in2_len);
        }
        let len = p.offset_from(out) as usize;
        let sz = len.wrapping_add(w).wrapping_sub(1) / w * w;
        if sz != len {
            core::ptr::write_bytes(p, 0, sz - len);
        }
        if !out_len.is_null() {
            *out_len = sz;
        }
    }
    1
}

/// `static int kmac_bytepad_encode_key(unsigned char *out, size_t out_max_len, size_t *out_len,
/// const unsigned char *in, size_t in_len, size_t w)` — `kmac_prov.c:657-671`.
///
/// `bytepad(encode_string(key), w)` — the key's two-layer encoding, and the reason `key[]` holds 672
/// bytes rather than 512.
///
/// The intermediate buffer is the authority's `unsigned char tmp[KMAC_MAX_KEY +
/// KMAC_MAX_ENCODED_HEADER_LEN]`, a **stack** array, so it is one here too.
///
/// # Safety
/// `out` is writable for `out_max_len`; `in` is readable for `in_len`; `out_len` is writable.
unsafe fn kmac_bytepad_encode_key(
    out: *mut c_uchar,
    out_max_len: usize,
    out_len: *mut usize,
    in_: *const c_uchar,
    in_len: usize,
    w: usize,
) -> c_int {
    let mut tmp = [0 as c_uchar; KMAC_MAX_KEY + KMAC_MAX_ENCODED_HEADER_LEN];
    let mut tmp_len: usize = 0;

    // SAFETY: `tmp` is a live local of the length passed.
    unsafe {
        if encode_string(tmp.as_mut_ptr(), tmp.len(), &mut tmp_len, in_, in_len) == 0 {
            return 0;
        }
        if bytepad(
            ptr::null_mut(),
            out_len,
            tmp.as_ptr(),
            tmp_len,
            ptr::null(),
            0,
            w,
        ) == 0
        {
            return 0;
        }
        // `!ossl_assert(*out_len <= out_max_len)` under `NDEBUG` is `*out_len > out_max_len`.
        if *out_len > out_max_len {
            return 0;
        }
        bytepad(
            out,
            ptr::null_mut(),
            tmp.as_ptr(),
            tmp_len,
            ptr::null(),
            0,
            w,
        )
    }
}

/// `static void kmac_free(void *vmacctx)` — `kmac_prov.c:157-168`.
///
/// NULL-tolerant, because `kmac_new` calls it on a half-built context. The key and the customisation
/// string are **cleansed** before the block is released — `OPENSSL_cleanse` on each, then a bare
/// `OPENSSL_free` — and each is cleansed for its *encoded* length, which is what the field holds.
///
/// # Safety
/// The dispatch contract; `vmacctx` NULL or a live `KmacData`.
unsafe extern "C" fn kmac_free(vmacctx: *mut c_void) {
    // SAFETY: the caller's contract.
    unsafe {
        if vmacctx.is_null() {
            return;
        }
        let kctx = vmacctx.cast::<KmacData>();
        EVP_MD_CTX_free((*kctx).ctx);
        ossl_prov_digest_reset(ptr::addr_of_mut!((*kctx).digest));
        cleanse((*kctx).key.as_mut_ptr().cast(), (*kctx).key_len);
        cleanse((*kctx).custom.as_mut_ptr().cast(), (*kctx).custom_len);
        CRYPTO_free(vmacctx, FILE_KMAC, LINE);
    }
}

/// `static struct kmac_data_st *kmac_new(void *provctx)` — `kmac_prov.c:172-187`.
///
/// **Two allocations against one release.** The `||` short-circuit is load-bearing: a failed
/// `OPENSSL_zalloc` leaves `kctx` NULL and never evaluates `EVP_MD_CTX_new`, and `kmac_free(NULL)` is
/// a no-op, so the failure path needs no separate spelling. `provctx` is assigned only once both
/// succeed, so it is **not** set on the context `kmac_free` is about to release.
///
/// # Safety
/// `provctx` is the provider's context, passed through unchanged.
unsafe fn kmac_new(provctx: *mut c_void) -> *mut KmacData {
    // SAFETY: the caller's contract; the allocation is released by `kmac_free` on every path.
    unsafe {
        if is_running() == 0 {
            return ptr::null_mut();
        }

        let kctx =
            CRYPTO_zalloc(core::mem::size_of::<KmacData>(), FILE_KMAC, LINE).cast::<KmacData>();
        if kctx.is_null() {
            return ptr::null_mut();
        }
        (*kctx).ctx = EVP_MD_CTX_new();
        if (*kctx).ctx.is_null() {
            kmac_free(kctx.cast());
            return ptr::null_mut();
        }
        (*kctx).provctx = provctx;
        kctx
    }
}

/// `static void *kmac_fetch_new(void *provctx, const OSSL_PARAM *params)` — `kmac_prov.c:189-206`.
///
/// The one place this row resolves a name, and it resolves it in `PROV_LIBCTX_OF(provctx)` — the
/// **argument's** context, not `kctx->provctx`'s, which is the same pointer here but is a distinction
/// the authority makes twice in this file.
///
/// `md_size <= 0` is a failure rather than a zero-length output: the digest has a size by
/// construction, so a non-positive answer means the fetch did not produce the method the row expects.
///
/// # Safety
/// `provctx` is the provider's context; `params` is a terminated array.
unsafe fn kmac_fetch_new(provctx: *mut c_void, params: *const OsslParam) -> *mut c_void {
    // SAFETY: the caller's contract; every failure path releases the context it built.
    unsafe {
        let kctx = kmac_new(provctx);
        if kctx.is_null() {
            return ptr::null_mut();
        }
        if ossl_prov_digest_load_from_params(
            ptr::addr_of_mut!((*kctx).digest),
            params,
            prov_libctx_of(provctx),
        ) == 0
        {
            kmac_free(kctx.cast());
            return ptr::null_mut();
        }

        let md_size = EVP_MD_get_size(ossl_prov_digest_md(ptr::addr_of!((*kctx).digest)));
        if md_size <= 0 {
            kmac_free(kctx.cast());
            return ptr::null_mut();
        }
        (*kctx).out_len = md_size as usize;
        kctx.cast()
    }
}

/// `static void *kmac128_new(void *provctx)` — `kmac_prov.c:208-214`.
///
/// # Safety
/// The dispatch contract.
unsafe extern "C" fn kmac128_new(provctx: *mut c_void) -> *mut c_void {
    // SAFETY: the caller's contract; `KMAC128_PARAMS` is a terminated static array.
    unsafe { kmac_fetch_new(provctx, KMAC128_PARAMS.as_ptr()) }
}

/// `static void *kmac256_new(void *provctx)` — `kmac_prov.c:216-222`.
///
/// # Safety
/// The dispatch contract.
unsafe extern "C" fn kmac256_new(provctx: *mut c_void) -> *mut c_void {
    // SAFETY: the caller's contract; `KMAC256_PARAMS` is a terminated static array.
    unsafe { kmac_fetch_new(provctx, KMAC256_PARAMS.as_ptr()) }
}

/// `static void *kmac_dup(void *vsrc)` — `kmac_prov.c:224-262`.
///
/// **Six explicit copies and no struct assignment**, which is what separates this from `hmac_dup`. The
/// `||` short-circuit means a failed `EVP_MD_CTX_copy` never evaluates the digest copy, and the
/// `kmac_free` on that path releases a context whose `digest` is still the one `kmac_new`'s fetch
/// installed — a *different* method from the source's, not a null one, because `kmac_new` fetched it.
///
/// The two `memcpy`s are bounded by the source's lengths rather than by the array widths, and they are
/// the last thing that happens: on either of the earlier failures neither buffer is written at all.
///
/// # Safety
/// The dispatch contract; `vsrc` is a live `KmacData`.
unsafe extern "C" fn kmac_dup(vsrc: *mut c_void) -> *mut c_void {
    // SAFETY: the caller's contract.
    unsafe {
        if is_running() == 0 {
            return ptr::null_mut();
        }
        let src = vsrc.cast::<KmacData>();
        let dst = kmac_new((*src).provctx);
        if dst.is_null() {
            return ptr::null_mut();
        }

        if EVP_MD_CTX_copy((*dst).ctx, (*src).ctx) == 0
            || ossl_prov_digest_copy(
                ptr::addr_of_mut!((*dst).digest),
                ptr::addr_of!((*src).digest),
            ) == 0
        {
            kmac_free(dst.cast());
            return ptr::null_mut();
        }
        (*dst).out_len = (*src).out_len;
        (*dst).key_len = (*src).key_len;
        (*dst).custom_len = (*src).custom_len;
        (*dst).xof_mode = (*src).xof_mode;
        core::ptr::copy_nonoverlapping(
            (*src).key.as_ptr(),
            (*dst).key.as_mut_ptr(),
            (*src).key_len,
        );
        core::ptr::copy_nonoverlapping(
            (*src).custom.as_ptr(),
            (*dst).custom.as_mut_ptr(),
            (*src).custom_len,
        );

        dst.cast()
    }
}

/// `static int kmac_setkey(struct kmac_data_st *kctx, const unsigned char *key, size_t keylen)` —
/// `kmac_prov.c:264-303` without its FIPS arm.
///
/// The key length is bounded at **both** ends and the refusal is one coordinate: `keylen <
/// KMAC_MIN_KEY || keylen > KMAC_MAX_KEY` is a single `ERR_raise` at `:272`.
///
/// The block-size check comes **after** the key-length check, so a row whose digest has no block size
/// still refuses an over-long key with the key-length reason rather than the digest one — an ordering
/// a "validate the digest first" transcription would reverse.
///
/// # Safety
/// `kctx` is live; `key` is readable for `keylen` bytes.
unsafe fn kmac_setkey(kctx: *mut KmacData, key: *const c_uchar, keylen: usize) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        let digest = ossl_prov_digest_md(ptr::addr_of!((*kctx).digest));
        let w = EVP_MD_get_block_size(digest);

        // The authority's literal `keylen < KMAC_MIN_KEY || keylen > KMAC_MAX_KEY`, kept in the form
        // it is written rather than rewritten as a `RangeInclusive` membership test -- the same call
        // this crate makes wherever the arithmetic *is* the transcription.
        #[allow(clippy::manual_range_contains)]
        let too_short_or_long = keylen < KMAC_MIN_KEY || keylen > KMAC_MAX_KEY;
        if too_short_or_long {
            return fail_at(&err_sites::PROV_KMAC_PROV_272);
        }
        if w <= 0 {
            return fail_at(&err_sites::PROV_KMAC_PROV_295);
        }
        if kmac_bytepad_encode_key(
            (*kctx).key.as_mut_ptr(),
            (*kctx).key.len(),
            ptr::addr_of_mut!((*kctx).key_len),
            key,
            keylen,
            w as usize,
        ) == 0
        {
            return 0;
        }
        1
    }
}

/// `static int kmac_init(void *vmacctx, const unsigned char *key, size_t keylen,
/// const OSSL_PARAM params[])` — `kmac_prov.c:309-367`.
///
/// **The `key == NULL` arm is a refusal only when nothing has encoded a key yet.** `kctx->key_len == 0`
/// is the test, so a second init without a key succeeds and reuses the stored encoding; the row has no
/// "already updated" flag, unlike Poly1305's.
///
/// **The default customisation string is installed from inside init**, through the row's own
/// `set_ctx_params`, and the return value is discarded. That is why `custom_len` is 2 rather than 0 on
/// a row nobody configured — and why the row's *setter* is a callee of its *init*, which is unusual
/// enough to be worth following once.
///
/// **`bytepad` is called twice on the same inputs**: once with `out == NULL` to size the buffer, and
/// once to fill it. The sized buffer is `OPENSSL_malloc`'d and released before the function returns, so
/// nothing of it survives except what the digest consumed.
///
/// # Safety
/// The dispatch contract; `key` is readable for `keylen` bytes or NULL; `params` is a terminated array.
unsafe extern "C" fn kmac_init(
    vmacctx: *mut c_void,
    key: *const c_uchar,
    keylen: usize,
    params: *const OsslParam,
) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        let kctx = vmacctx.cast::<KmacData>();
        let ctx = (*kctx).ctx;

        if is_running() == 0 || kmac_set_ctx_params(vmacctx, params) == 0 {
            return 0;
        }

        if !key.is_null() {
            if kmac_setkey(kctx, key, keylen) == 0 {
                return 0;
            }
        } else if (*kctx).key_len == 0 {
            return fail_at(&err_sites::PROV_KMAC_PROV_326);
        }
        if EVP_DigestInit_ex(
            (*kctx).ctx,
            ossl_prov_digest_md(ptr::addr_of!((*kctx).digest)),
            ptr::null_mut(),
        ) == 0
        {
            return 0;
        }

        let t = EVP_MD_get_block_size(ossl_prov_digest_md(ptr::addr_of!((*kctx).digest)));
        if t <= 0 {
            return fail_at(&err_sites::PROV_KMAC_PROV_335);
        }
        let block_len = t as usize;

        /* Set default custom string if it is not already set */
        if (*kctx).custom_len == 0 {
            let cparams = [
                param_octet_string_with(
                    OSSL_MAC_PARAM_CUSTOM,
                    KMAC_EMPTY_CUSTOM.as_ptr() as *mut c_void,
                    0,
                ),
                END,
            ];
            /* The answer is deliberately dropped: the authority writes `(void)`. */
            let _ = kmac_set_ctx_params(vmacctx, cparams.as_ptr());
        }

        let mut out_len: usize = 0;
        if bytepad(
            ptr::null_mut(),
            &mut out_len,
            KMAC_STRING.as_ptr(),
            KMAC_STRING.len(),
            (*kctx).custom.as_ptr(),
            (*kctx).custom_len,
            block_len,
        ) == 0
        {
            return fail_at(&err_sites::PROV_KMAC_PROV_351);
        }
        let out = CRYPTO_malloc(out_len, FILE_KMAC, LINE).cast::<c_uchar>();
        if out.is_null() {
            return 0;
        }
        let res = bytepad(
            out,
            ptr::null_mut(),
            KMAC_STRING.as_ptr(),
            KMAC_STRING.len(),
            (*kctx).custom.as_ptr(),
            (*kctx).custom_len,
            block_len,
        ) != 0
            && EVP_DigestUpdate(ctx, out.cast(), out_len) != 0
            && EVP_DigestUpdate(ctx, (*kctx).key.as_ptr().cast(), (*kctx).key_len) != 0;
        CRYPTO_free(out.cast(), FILE_KMAC, LINE);
        res as c_int
    }
}

/// `static int kmac_update(void *vmacctx, const unsigned char *data, size_t datalen)` —
/// `kmac_prov.c:369-375`.
///
/// A bare forward, with no state of its own: everything the record adds is in the digest context
/// `init` prepared. Nothing here refuses an update before a key was set, unlike Poly1305's row — the
/// digest refuses a zero-length update with 1 and a non-empty one on an uninitialised context itself.
///
/// # Safety
/// The dispatch contract.
unsafe extern "C" fn kmac_update(
    vmacctx: *mut c_void,
    data: *const c_uchar,
    datalen: usize,
) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        let kctx = vmacctx.cast::<KmacData>();
        EVP_DigestUpdate((*kctx).ctx, data.cast(), datalen)
    }
}

/// `static int kmac_final(void *vmacctx, unsigned char *out, size_t *outl, size_t outsize)` —
/// `kmac_prov.c:377-394`.
///
/// **The requested length is right-encoded and fed, then the digest is squeezed.** `xof_mode` swaps the
/// encoded length for zero, which is the whole difference between `KMAC128` and `KMAC128XOF` at this
/// layer — the same context, the same key encoding, and one word of the trailer.
///
/// **`*outl` is written unconditionally**, including on the failure path, because the authority assigns
/// it outside the `ok` expression. A caller of a failed final therefore still sees a length.
///
/// **`outsize` is unused.** The bound is enforced by `evp_mac_final`, which asks this row's
/// `get_ctx_params` for `size` and refuses with `EVP_R_BUFFER_TOO_SMALL` before the row is called.
///
/// # Safety
/// The dispatch contract; `out` is writable for `kctx->out_len` bytes; `outl` is writable.
unsafe extern "C" fn kmac_final(
    vmacctx: *mut c_void,
    out: *mut c_uchar,
    outl: *mut usize,
    _outsize: usize,
) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        let kctx = vmacctx.cast::<KmacData>();
        let ctx = (*kctx).ctx;

        if is_running() == 0 {
            return 0;
        }

        /* KMAC XOF mode sets the encoded length to 0 */
        let lbits = if (*kctx).xof_mode != 0 {
            0
        } else {
            (*kctx).out_len.wrapping_mul(8)
        };

        let mut encoded_outlen = [0 as c_uchar; KMAC_MAX_ENCODED_HEADER_LEN];
        let mut len: usize = 0;
        let ok = right_encode(
            encoded_outlen.as_mut_ptr(),
            encoded_outlen.len(),
            &mut len,
            lbits,
        ) != 0
            && EVP_DigestUpdate(ctx, encoded_outlen.as_ptr().cast(), len) != 0
            && EVP_DigestFinalXOF(ctx, out, (*kctx).out_len) != 0;
        *outl = (*kctx).out_len;
        ok as c_int
    }
}

/// `static const OSSL_PARAM *kmac_gettable_ctx_params(void *ctx, void *provctx)` —
/// `kmac_prov.c:469-474`.
///
/// # Safety
/// The dispatch contract.
unsafe extern "C" fn kmac_gettable_ctx_params(
    _ctx: *mut c_void,
    _provctx: *mut c_void,
) -> *const OsslParam {
    KMAC_GETTABLE_CTX_PARAMS.as_ptr()
}

/// `static int kmac_get_ctx_params(void *vmacctx, OSSL_PARAM params[])` — `kmac_prov.c:476-499`
/// without its FIPS arm.
///
/// `size` is `kctx->out_len` — the *current* request, which `set_ctx_params` can change after the
/// init — and it is what `evp_mac_final` reads to bound a caller's buffer. `block-size` is the digest's,
/// written with `OSSL_PARAM_set_int` into a descriptor whose list entry declares `size_t`.
///
/// # Safety
/// The dispatch contract.
unsafe extern "C" fn kmac_get_ctx_params(vmacctx: *mut c_void, params: *mut OsslParam) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        if vmacctx.is_null() {
            return 0;
        }
        if let Some(site) = repeated_param_site(params, &KMAC_GET_CTX_PARAMS_DECODER_KEYS) {
            return fail_at(site);
        }

        let kctx = vmacctx.cast::<KmacData>();
        let p = crate::params::OSSL_PARAM_locate(params, OSSL_MAC_PARAM_SIZE);
        if !p.is_null() && crate::params::OSSL_PARAM_set_size_t(p, (*kctx).out_len) == 0 {
            return 0;
        }
        let p = crate::params::OSSL_PARAM_locate(params, OSSL_MAC_PARAM_BLOCK_SIZE);
        if !p.is_null() {
            let sz = EVP_MD_get_block_size(ossl_prov_digest_md(ptr::addr_of!((*kctx).digest)));
            if crate::params::OSSL_PARAM_set_int(p, sz) == 0 {
                return 0;
            }
        }
        1
    }
}

/// `static const OSSL_PARAM *kmac_settable_ctx_params(void *ctx, void *provctx)` —
/// `kmac_prov.c:632-637`.
///
/// # Safety
/// The dispatch contract.
unsafe extern "C" fn kmac_settable_ctx_params(
    _ctx: *mut c_void,
    _provctx: *mut c_void,
) -> *const OsslParam {
    KMAC_SETTABLE_CTX_PARAMS.as_ptr()
}

/// `static int kmac_set_ctx_params(void *vmacctx, const OSSL_PARAM params[])` —
/// `kmac_prov.c:648-710` without its FIPS arms.
///
/// **`xof` is the one key this row reads with `OSSL_PARAM_get_int`,** into an `int` field, so a
/// descriptor of any other numeric flavour is refused by the params layer rather than converted — and
/// that refusal queues `ERR_LIB_CRYPTO`'s not-integer error, which the court observes.
///
/// **`size` is capped, and the cap has a raise of its own** (`PROV_R_INVALID_OUTPUT_LENGTH`), distinct
/// from the type refusal `OSSL_PARAM_get_size_t` would produce. The `out_len` is assigned only after
/// the cap passes, so a refused size leaves the previous length in place.
///
/// **`key` and `custom` short-circuit on their `data_type`.** A wrong type is a bare 0 with no raise
/// for either; the *length* refusals that follow are raised and are two different reasons
/// (`PROV_R_INVALID_KEY_LENGTH` from `kmac_setkey`, `PROV_R_INVALID_CUSTOM_LENGTH` here).
///
/// `custom` is re-encoded on every call, so setting it twice keeps the last one rather than appending.
///
/// # Safety
/// The dispatch contract.
unsafe extern "C" fn kmac_set_ctx_params(vmacctx: *mut c_void, params: *const OsslParam) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        if vmacctx.is_null() {
            return 0;
        }
        if let Some(site) = repeated_param_site(params, &KMAC_SET_CTX_PARAMS_DECODER_KEYS) {
            return fail_at(site);
        }

        let kctx = vmacctx.cast::<KmacData>();

        let p = crate::params::OSSL_PARAM_locate_const(params, OSSL_MAC_PARAM_XOF);
        if !p.is_null()
            && crate::params::OSSL_PARAM_get_int(p, ptr::addr_of_mut!((*kctx).xof_mode)) == 0
        {
            return 0;
        }

        let p = crate::params::OSSL_PARAM_locate_const(params, OSSL_MAC_PARAM_SIZE);
        if !p.is_null() {
            let mut sz: usize = 0;

            if crate::params::OSSL_PARAM_get_size_t(p, &mut sz) == 0 {
                return 0;
            }
            if sz > KMAC_MAX_OUTPUT_LEN {
                return fail_at(&err_sites::PROV_KMAC_PROV_672);
            }
            (*kctx).out_len = sz;
        }

        let p = crate::params::OSSL_PARAM_locate_const(params, OSSL_MAC_PARAM_KEY);
        if !p.is_null()
            && ((*p).data_type != OSSL_PARAM_OCTET_STRING
                || kmac_setkey(kctx, (*p).data.cast(), (*p).data_size) == 0)
        {
            return 0;
        }

        let p = crate::params::OSSL_PARAM_locate_const(params, OSSL_MAC_PARAM_CUSTOM);
        if !p.is_null() {
            if (*p).data_type != OSSL_PARAM_OCTET_STRING {
                return 0;
            }
            if (*p).data_size > KMAC_MAX_CUSTOM {
                return fail_at(&err_sites::PROV_KMAC_PROV_699);
            }
            if encode_string(
                (*kctx).custom.as_mut_ptr(),
                (*kctx).custom.len(),
                ptr::addr_of_mut!((*kctx).custom_len),
                (*p).data.cast(),
                (*p).data_size,
            ) == 0
            {
                return 0;
            }
        }

        1
    }
}

/// `const OSSL_DISPATCH ossl_kmac128_functions[]` — `kmac_prov.c:684-696` via the authority's
/// `KMAC_TABLE(128)`.
///
/// The ctx-level params pair, unlike GMAC's and POLY1305's provider-level one: this row *does* publish
/// a getter, which is what `EVP_MAC_CTX_get_mac_size` reads and therefore what bounds a caller's final
/// buffer. The two rows differ only in `NEWCTX`, which is what the authority's `newname` parameter to
/// `IMPLEMENT_KMAC_TABLE` selects.
pub(crate) static KMAC128_FUNCTIONS: [OsslDispatch; 11] = [
    OsslDispatch {
        function_id: OSSL_FUNC_MAC_NEWCTX,
        function: kmac128_new as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_MAC_DUPCTX,
        function: kmac_dup as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_MAC_FREECTX,
        function: kmac_free as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_MAC_INIT,
        function: kmac_init as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_MAC_UPDATE,
        function: kmac_update as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_MAC_FINAL,
        function: kmac_final as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_MAC_GETTABLE_CTX_PARAMS,
        function: kmac_gettable_ctx_params as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_MAC_GET_CTX_PARAMS,
        function: kmac_get_ctx_params as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_MAC_SETTABLE_CTX_PARAMS,
        function: kmac_settable_ctx_params as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_MAC_SET_CTX_PARAMS,
        function: kmac_set_ctx_params as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_DISPATCH_END,
        function: ptr::null_mut(),
    },
];

/// `const OSSL_DISPATCH ossl_kmac256_functions[]` — `kmac_prov.c:697-709` via `KMAC_TABLE(256)`.
pub(crate) static KMAC256_FUNCTIONS: [OsslDispatch; 11] = [
    OsslDispatch {
        function_id: OSSL_FUNC_MAC_NEWCTX,
        function: kmac256_new as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_MAC_DUPCTX,
        function: kmac_dup as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_MAC_FREECTX,
        function: kmac_free as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_MAC_INIT,
        function: kmac_init as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_MAC_UPDATE,
        function: kmac_update as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_MAC_FINAL,
        function: kmac_final as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_MAC_GETTABLE_CTX_PARAMS,
        function: kmac_gettable_ctx_params as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_MAC_GET_CTX_PARAMS,
        function: kmac_get_ctx_params as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_MAC_SETTABLE_CTX_PARAMS,
        function: kmac_settable_ctx_params as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_MAC_SET_CTX_PARAMS,
        function: kmac_set_ctx_params as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_DISPATCH_END,
        function: ptr::null_mut(),
    },
];

#[cfg(test)]
mod tests {
    use super::*;
    use crate::context::dispatch::OSSL_DISPATCH_END as END_ID;

    #[test]
    fn the_mac_table_names_its_rows_in_the_authoritys_order() {
        // The authority's nine rows, in its order and **not** appended: `defltprov.c:334-353`
        // lists BLAKE2BMAC 1st, BLAKE2SMAC 2nd, CMAC 3rd, GMAC 4th, HMAC 5th, KMAC-128 6th,
        // KMAC-256 7th, SIPHASH 8th and POLY1305 9th, and the census requires the crate's rows to
        // be a subsequence of it (D244). GMAC is fourth, between CMAC and HMAC, where `defltprov.c`
        // puts it; it was `open` on Phase 9 until the GCM ciphers it resolves landed (D243, D419).
        //
        // This test asserted the crate's own array and not the authority's, so it stayed green
        // while SIPHASH and POLY1305 were transposed; `gen_provider_algorithms.py` caught it
        // because *its* oracle is `defltprov.c`. The expected sequence below is therefore read off
        // the authority's line numbers rather than off this file.
        assert_eq!(DEFLT_MACS.len(), 10);
        // SAFETY: the terminator's name is NULL by construction, and each landed row's is a
        // `'static` C string.
        unsafe {
            assert!(DEFLT_MACS[9].algorithm_names.is_null());
            assert!(DEFLT_MACS[9].property_definition.is_null());
            assert!(DEFLT_MACS[9].implementation.is_null());
            for (row, want) in [
                (
                    &DEFLT_MACS[0],
                    b"BLAKE2BMAC:1.3.6.1.4.1.1722.12.2.1".as_slice(),
                ),
                (&DEFLT_MACS[1], b"BLAKE2SMAC:1.3.6.1.4.1.1722.12.2.2"),
                (&DEFLT_MACS[2], b"CMAC"),
                (&DEFLT_MACS[3], b"GMAC:1.0.9797.3.4"),
                (&DEFLT_MACS[4], b"HMAC"),
                (&DEFLT_MACS[5], b"KMAC-128:KMAC128:2.16.840.1.101.3.4.2.19"),
                (&DEFLT_MACS[6], b"KMAC-256:KMAC256:2.16.840.1.101.3.4.2.20"),
                (&DEFLT_MACS[7], b"SIPHASH"),
                (&DEFLT_MACS[8], b"POLY1305"),
            ] {
                let name = core::ffi::CStr::from_ptr(row.algorithm_names);
                assert_eq!(name.to_bytes(), want);
                // `ALGC(NAMES, FUNC, CHECK) { { NAMES, "provider=default", FUNC }, CHECK }`.
                let props = core::ffi::CStr::from_ptr(row.property_definition);
                assert_eq!(props.to_bytes(), b"provider=default");
                assert!(!row.implementation.is_null());
                assert!(row.algorithm_description.is_null());
            }
        }
    }

    /// **The allocation `file` string is contract, and the authority's own raise coordinates are the
    /// oracle for it.** `CRYPTO_malloc`'s `file` and `ERR_raise`'s `OPENSSL_FILE` are the same
    /// `__FILE__`, so a `PROV_<UNIT>_*` raise site in a unit and the `FILE_*` constant for that unit
    /// must be one string -- and the raise sites are generated from the authority's compiler, so they
    /// cannot be transcribed wrongly.
    ///
    /// This exists because three of the four were wrong: `cmac_prov.c`, `gmac_prov.c` and
    /// `siphash_prov.c` are generated from `.c.in` templates and carry **no**
    /// `../../src/openssl-3.6.4/` prefix, which D235 established when the same mistake appeared in
    /// the err-site generator. The mistake's second appearance is the reason this is a test rather
    /// than a comment.
    #[test]
    fn every_allocation_file_constant_is_the_authoritys_own_string() {
        let cases: [(&str, *const c_char, &err_sites::ErrSite); 7] = [
            ("cmac", FILE, &err_sites::PROV_CMAC_PROV_245),
            ("gmac", FILE_GMAC, &err_sites::PROV_GMAC_PROV_200),
            ("hmac", FILE_HMAC, &err_sites::PROV_HMAC_PROV_313),
            (
                "poly1305",
                FILE_POLY1305,
                &err_sites::PROV_POLY1305_PROV_177,
            ),
            ("siphash", FILE_SIPHASH, &err_sites::PROV_SIPHASH_PROV_190),
            // The two BLAKE2 rows allocate from `blake2_mac_impl.c`, which is *included* rather
            // than generated, so its `__FILE__` carries the source-tree prefix the four above do
            // not -- and both rows share this one constant because both include the one file.
            (
                "blake2bmac",
                FILE_BLAKE2_MAC,
                &err_sites::PROV_BLAKE2_MAC_IMPL_96,
            ),
            (
                "blake2smac",
                FILE_BLAKE2_MAC,
                &err_sites::PROV_BLAKE2_MAC_IMPL_96,
            ),
        ];
        for (unit, file, site) in cases {
            // SAFETY: `file` is a `'static` literal and is NUL-terminated.
            let crate_file = unsafe { core::ffi::CStr::from_ptr(file) };
            assert_eq!(
                crate_file.to_bytes(),
                site.file.to_bytes(),
                "{unit}: the allocation file must be the unit's __FILE__"
            );
        }
    }

    #[test]
    fn the_siphash_dispatch_carries_the_ctx_params_pair_and_terminates() {
        let ids: Vec<c_int> = SIPHASH_FUNCTIONS.iter().map(|d| d.function_id).collect();
        assert_eq!(ids.len(), 11);
        assert_eq!(ids[10], END_ID);
        // The same shape as `ossl_cmac_functions`: the ctx-params pair, not the provider-level one that
        // `GMAC_FUNCTIONS` uses.
        assert_eq!(
            ids[..10],
            [
                OSSL_FUNC_MAC_NEWCTX,
                OSSL_FUNC_MAC_DUPCTX,
                OSSL_FUNC_MAC_FREECTX,
                OSSL_FUNC_MAC_INIT,
                OSSL_FUNC_MAC_UPDATE,
                OSSL_FUNC_MAC_FINAL,
                OSSL_FUNC_MAC_GETTABLE_CTX_PARAMS,
                OSSL_FUNC_MAC_GET_CTX_PARAMS,
                OSSL_FUNC_MAC_SETTABLE_CTX_PARAMS,
                OSSL_FUNC_MAC_SET_CTX_PARAMS,
            ]
        );
        assert!(SIPHASH_FUNCTIONS[..10]
            .iter()
            .all(|d| !d.function.is_null()));
    }

    #[test]
    fn the_siphash_decoder_key_order_is_the_switches_not_the_lists() {
        // The generated decoder is a `switch` on the key's first byte, so it raises for `c-rounds`
        // and `d-rounds` before `key` and `size` -- while the *settable* list reads `size`, `key`,
        // `c-rounds`, `d-rounds`. Two different orders in the same file, and a transcription that
        // used one for both would misattribute every repeated-parameter raise.
        let mut keys: Vec<&[u8]> = Vec::new();
        for (_, k) in SIPHASH_SET_PARAMS_DECODER_KEYS.iter() {
            // SAFETY: every key in each table is a `'static` C string literal.
            keys.push(unsafe { core::ffi::CStr::from_ptr(*k) }.to_bytes());
        }
        assert_eq!(
            keys,
            [
                b"c-rounds".as_slice(),
                b"d-rounds".as_slice(),
                b"key".as_slice(),
                b"size".as_slice(),
            ]
        );
        let mut listed: Vec<&[u8]> = Vec::new();
        for p in SIPHASH_SETTABLE_CTX_PARAMS[..4].iter() {
            // SAFETY: every key in each table is a `'static` C string literal.
            listed.push(unsafe { core::ffi::CStr::from_ptr(p.key.cast()) }.to_bytes());
        }
        assert_eq!(
            listed,
            [
                b"size".as_slice(),
                b"key".as_slice(),
                b"c-rounds".as_slice(),
                b"d-rounds".as_slice(),
            ]
        );
        assert!(SIPHASH_SETTABLE_CTX_PARAMS[4].key.is_null());
        let mut get_keys: Vec<&[u8]> = Vec::new();
        for (_, k) in SIPHASH_GET_CTX_PARAMS_DECODER_KEYS.iter() {
            // SAFETY: every key in each table is a `'static` C string literal.
            get_keys.push(unsafe { core::ffi::CStr::from_ptr(*k) }.to_bytes());
        }
        assert_eq!(
            get_keys,
            [
                b"c-rounds".as_slice(),
                b"d-rounds".as_slice(),
                b"size".as_slice()
            ]
        );
    }

    #[test]
    fn a_fresh_siphash_context_answers_zero_size_and_the_default_round_counts() {
        // SAFETY: the dispatch contract, with a NULL provctx which `siphash_new` accepts.
        unsafe {
            let ctx = siphash_new(ptr::null_mut()).cast::<SiphashData>();
            assert!(!ctx.is_null());
            // Zero, not sixteen: `hash_size` is only adjusted by `SipHash_Init` or a `size`.
            assert_eq!(siphash_size(ctx.cast()), 0);
            assert_eq!((*ctx).crounds, 0);
            assert_eq!(crounds(ctx), SIPHASH_C_ROUNDS);
            assert_eq!(drounds(ctx), SIPHASH_D_ROUNDS);
            (*ctx).crounds = 4;
            (*ctx).drounds = 8;
            assert_eq!(crounds(ctx), 4);
            assert_eq!(drounds(ctx), 8);
            siphash_free(ctx.cast());
        }
    }

    #[test]
    fn a_null_key_init_restarts_from_the_saved_copy() {
        // `sipcopy` is the whole reason this row has two contexts. Run a message, re-init with a
        // NULL key, run it again, and the tag must equal a fresh one-shot -- which it cannot if the
        // row restarts from the *partially consumed* state instead of the saved one.
        let key = [0x5au8; 16];
        let msg = [0x11u8; 40];
        // SAFETY: locals, and every pointer is derived from a live context.
        unsafe {
            let ctx = siphash_new(ptr::null_mut()).cast::<SiphashData>();
            assert_eq!(siphash_setkey(ctx, key.as_ptr(), 16), 1);
            assert_eq!(siphash_size(ctx.cast()), 16);
            siphash_update(ctx.cast(), msg.as_ptr(), msg.len());

            assert_eq!(siphash_init(ctx.cast(), ptr::null(), 0, ptr::null()), 1);
            siphash_update(ctx.cast(), msg.as_ptr(), msg.len());
            let mut out = [0u8; 16];
            let mut outl = 0usize;
            assert_eq!(
                siphash_final(ctx.cast(), out.as_mut_ptr(), &mut outl, 16),
                1
            );
            assert_eq!(outl, 16);

            let fresh = siphash_new(ptr::null_mut()).cast::<SiphashData>();
            assert_eq!(siphash_setkey(fresh, key.as_ptr(), 16), 1);
            siphash_update(fresh.cast(), msg.as_ptr(), msg.len());
            let mut want = [0u8; 16];
            let mut wantl = 0usize;
            assert_eq!(
                siphash_final(fresh.cast(), want.as_mut_ptr(), &mut wantl, 16),
                1
            );
            assert_eq!(out, want, "the restarted message must equal the one-shot");

            siphash_free(ctx.cast());
            siphash_free(fresh.cast());
        }
    }

    #[test]
    fn a_short_final_buffer_is_refused_before_the_length_is_written() {
        // SAFETY: locals and a live context.
        unsafe {
            let ctx = siphash_new(ptr::null_mut()).cast::<SiphashData>();
            let key = [0u8; 32];
            // The key length is exactly `SIPHASH_KEY_SIZE`, and both neighbours are bare refusals.
            assert_eq!(siphash_setkey(ctx, key.as_ptr(), 15), 0);
            assert_eq!(siphash_setkey(ctx, key.as_ptr(), 17), 0);
            assert_eq!(siphash_setkey(ctx, key.as_ptr(), 16), 1);

            let mut out = [0u8; 16];
            let mut outl = 7usize;
            // `outsize < hlen` is checked *before* `*outl = hlen`, so the caller's value survives.
            assert_eq!(
                siphash_final(ctx.cast(), out.as_mut_ptr(), &mut outl, 15),
                0
            );
            assert_eq!(outl, 7);
            assert_eq!(
                siphash_final(ctx.cast(), out.as_mut_ptr(), &mut outl, 16),
                1
            );
            assert_eq!(outl, 16);

            // A duplicate raises, and the raise is the decoder's own site.
            let size = OSSL_MAC_PARAM_SIZE;
            let dup = [param_size_t(size), param_size_t(size), END];
            assert_eq!(
                siphash_get_ctx_params(ctx.cast(), dup.as_ptr() as *mut _),
                0
            );
            assert_eq!(siphash_set_params(ctx.cast(), dup.as_ptr()), 0);
            siphash_free(ctx.cast());
        }
    }

    #[test]
    fn the_dispatch_table_carries_ten_entries_and_terminates() {
        let ids: Vec<c_int> = ossl_cmac_functions.iter().map(|d| d.function_id).collect();
        assert_eq!(ids.len(), 11);
        assert_eq!(ids[10], END_ID);
        // The ten the authority's table lists, in its order.
        assert_eq!(
            ids[..10],
            [
                OSSL_FUNC_MAC_NEWCTX,
                OSSL_FUNC_MAC_DUPCTX,
                OSSL_FUNC_MAC_FREECTX,
                OSSL_FUNC_MAC_INIT,
                OSSL_FUNC_MAC_UPDATE,
                OSSL_FUNC_MAC_FINAL,
                OSSL_FUNC_MAC_GETTABLE_CTX_PARAMS,
                OSSL_FUNC_MAC_GET_CTX_PARAMS,
                OSSL_FUNC_MAC_SETTABLE_CTX_PARAMS,
                OSSL_FUNC_MAC_SET_CTX_PARAMS,
            ]
        );
        // Every entry before the terminator has a callable.
        assert!(ossl_cmac_functions[..10]
            .iter()
            .all(|d| !d.function.is_null()));
    }

    #[test]
    fn a_fresh_context_has_no_cipher_and_so_no_size() {
        // `cmac_new` allocates and leaves `PROV_CIPHER` zeroed, so `cmac_size` answers 0 because
        // the cipher context has no cipher rather than because it has none *yet*.
        // SAFETY: the dispatch contract, with a NULL provctx which `cmac_new` accepts.
        unsafe {
            let ctx = cmac_new(ptr::null_mut());
            assert!(!ctx.is_null());
            assert_eq!(cmac_size(ctx), 0);
            cmac_free(ctx);
        }
    }

    #[test]
    fn the_gmac_dispatch_table_carries_the_provider_level_pair_and_terminates() {
        let ids: Vec<c_int> = GMAC_FUNCTIONS.iter().map(|d| d.function_id).collect();
        assert_eq!(ids.len(), 11);
        assert_eq!(ids[10], END_ID);
        // The one shape difference from `ossl_cmac_functions`: GMAC's two getters are the
        // **provider-level** `GETTABLE_PARAMS`/`GET_PARAMS`, so `gmac_prov.c`'s table is not the
        // same ten ids in the same order.
        assert_eq!(
            ids[..10],
            [
                OSSL_FUNC_MAC_NEWCTX,
                OSSL_FUNC_MAC_DUPCTX,
                OSSL_FUNC_MAC_FREECTX,
                OSSL_FUNC_MAC_INIT,
                OSSL_FUNC_MAC_UPDATE,
                OSSL_FUNC_MAC_FINAL,
                OSSL_FUNC_MAC_GETTABLE_PARAMS,
                OSSL_FUNC_MAC_GET_PARAMS,
                OSSL_FUNC_MAC_SETTABLE_CTX_PARAMS,
                OSSL_FUNC_MAC_SET_CTX_PARAMS,
            ]
        );
        assert!(GMAC_FUNCTIONS[..10].iter().all(|d| !d.function.is_null()));
    }

    #[test]
    fn the_set_ctx_decoder_keys_are_the_five_the_generated_switch_raises_for() {
        // The order is the decoder's `switch` order, not the argument order of the generator's
        // spec, and both differ from the settable list: `engine` is a decoder key only.
        let keys: Vec<&[u8]> = GMAC_SET_CTX_PARAMS_DECODER_KEYS
            .iter()
            .map(|(_, k)| {
                // SAFETY: every key is a `'static` C string literal.
                unsafe { core::ffi::CStr::from_ptr(*k) }.to_bytes()
            })
            .collect();
        assert_eq!(
            keys,
            [
                b"cipher".as_slice(),
                b"engine".as_slice(),
                b"iv".as_slice(),
                b"key".as_slice(),
                b"properties".as_slice(),
            ]
        );
        // And the settable list deliberately omits `engine`.
        let settable: Vec<&[u8]> = GMAC_SETTABLE_CTX_PARAMS[..4]
            .iter()
            .map(|p| {
                // SAFETY: every key is a `'static` C string literal.
                unsafe { core::ffi::CStr::from_ptr(p.key.cast()) }.to_bytes()
            })
            .collect();
        assert_eq!(
            settable,
            [
                b"cipher".as_slice(),
                b"properties".as_slice(),
                b"key".as_slice(),
                b"iv".as_slice(),
            ]
        );
        assert!(GMAC_SETTABLE_CTX_PARAMS[4].key.is_null());
    }

    #[test]
    fn a_fresh_gmac_context_answers_sixteen_without_a_cipher() {
        // The opposite shape from `cmac_size`: GMAC's tag length is the GCM constant and does not
        // depend on the context at all, so a fresh context answers 16 where CMAC answers 0.
        // SAFETY: the dispatch contract, with a NULL provctx which `gmac_new` accepts.
        unsafe {
            let ctx = gmac_new(ptr::null_mut());
            assert!(!ctx.is_null());
            assert_eq!(gmac_size(), 16);
            gmac_free(ctx);
        }
    }

    #[test]
    fn the_gmac_get_params_list_carries_size_alone() {
        // GMAC has no `block-size` key and no ctx-params getter: one key, in the provider-level
        // list. A transcription that had copied CMAC's two keys would pass every cipher court and
        // still answer `EVP_MAC_gettable_params` wrongly.
        // SAFETY: every key is a `'static` C string literal, and the terminator's is NULL.
        unsafe {
            let first = core::ffi::CStr::from_ptr(GMAC_GETTABLE_PARAMS[0].key.cast());
            assert_eq!(first.to_bytes(), b"size");
            assert_eq!(GMAC_GETTABLE_PARAMS[0].data_type, 2); // OSSL_PARAM_UNSIGNED_INTEGER
                                                              // `OSSL_PARAM_size_t`, so 8 rather than `OSSL_PARAM_uint`'s 4.
            assert_eq!(
                GMAC_GETTABLE_PARAMS[0].data_size,
                core::mem::size_of::<usize>()
            );
            assert!(GMAC_GETTABLE_PARAMS[1].key.is_null());
        }
    }

    /// The two macros the row's `digest` descriptor is built from, bound to their literals rather than
    /// to a count kept by hand. `kmac128_new` passes `sizeof(OSSL_DIGEST_NAME_KECCAK_KMAC128)`, so the
    /// size **includes** the NUL, and a transcription that passed `strlen` would hand
    /// `ossl_prov_digest_load` a 13-byte string that is not NUL-terminated.
    #[test]
    fn the_kmac_digest_names_and_their_sizes_are_the_authoritys() {
        // SAFETY: both are `'static` C string literals of known length.
        unsafe {
            for (name, size, want) in [
                (
                    OSSL_DIGEST_NAME_KECCAK_KMAC128,
                    OSSL_DIGEST_NAME_KECCAK_KMAC128_SIZE,
                    b"KECCAK-KMAC-128".as_slice(),
                ),
                (
                    OSSL_DIGEST_NAME_KECCAK_KMAC256,
                    OSSL_DIGEST_NAME_KECCAK_KMAC256_SIZE,
                    b"KECCAK-KMAC-256",
                ),
            ] {
                let s = core::ffi::CStr::from_ptr(name).to_bytes();
                assert_eq!(s, want);
                assert_eq!(size, s.len() + 1);
            }
        }
        // The two descriptors themselves carry the same data and size, which is the half a caller can
        // read back through `ossl_prov_digest_load_from_params`.
        for (params, want) in [
            (&KMAC128_PARAMS, b"KECCAK-KMAC-128".as_slice()),
            (&KMAC256_PARAMS, b"KECCAK-KMAC-256"),
        ] {
            assert_eq!(params.len(), 2);
            // SAFETY: the keys and the data pointers are `'static`.
            unsafe {
                let key = core::ffi::CStr::from_ptr(params[0].key.cast());
                assert_eq!(key.to_bytes(), b"digest");
                assert_eq!(params[0].data_type, 4); // OSSL_PARAM_UTF8_STRING
                assert_eq!(params[0].data_size, want.len() + 1);
                let data =
                    core::slice::from_raw_parts(params[0].data.cast::<c_uchar>(), want.len());
                assert_eq!(data, want);
                assert!(params[1].key.is_null());
            }
        }
    }

    /// **The encoding layer's own arithmetic, which no MAC tag can reveal.** `encode_string` and
    /// `right_encode` are SP 800-185's two primitives and their whole observable is the byte array
    /// they produce; a transcription that put the length at the wrong end, or used `strlen` instead of
    /// `sizeof`, would still produce *a* tag, and only the authority would disagree.
    #[test]
    fn encode_string_and_right_encode_put_their_lengths_at_opposite_ends() {
        // `encode_string("KMAC")` is the authority's own `kmac_string` constant, so the preimage and
        // the expected bytes are both the authority's rather than a constructed example.
        let mut out = [0xAA_u8; 8];
        let mut out_len: usize = 0;
        // SAFETY: `out` is writable for its length and the input is a literal.
        unsafe {
            assert_eq!(
                encode_string(
                    out.as_mut_ptr(),
                    out.len(),
                    &mut out_len,
                    b"KMAC".as_ptr(),
                    4
                ),
                1
            );
        }
        assert_eq!(out_len, 6);
        assert_eq!(&out[..6], &KMAC_STRING);
        // The tail is untouched: the encoder writes `1 + len + in_len` bytes and no more.
        assert_eq!(&out[6..], &[0xAA, 0xAA]);

        // A NULL input is the "no customisation" case and leaves the buffer alone.
        let mut null_len: usize = 7;
        // SAFETY: a NULL input takes the early arm and writes only `out_len`.
        unsafe {
            assert_eq!(
                encode_string(out.as_mut_ptr(), out.len(), &mut null_len, ptr::null(), 0),
                1
            );
        }
        assert_eq!(null_len, 0);

        // A non-NULL empty input is the *default customisation* case, and it is not the same thing:
        // `left_encode(0)` is two bytes. `KMAC_EMPTY_CUSTOM` is what `kmac_init` passes.
        let mut empty_len: usize = 0;
        // SAFETY: the static is readable for one byte and `data_size` is zero.
        unsafe {
            assert_eq!(
                encode_string(
                    out.as_mut_ptr(),
                    out.len(),
                    &mut empty_len,
                    KMAC_EMPTY_CUSTOM.as_ptr(),
                    0,
                ),
                1
            );
        }
        assert_eq!(empty_len, 2);
        assert_eq!(&out[..2], &[0x01, 0x00]);

        // `right_encode(32)` and `right_encode(0)` — the two lengths the fixed and XOF modes feed.
        // Both occupy **two** bytes: a length whose value fits in one byte still carries its own
        // one-byte length, which is why `right_encode(0)` is `{0x00, 0x01}` and not `{0x00}`.
        let mut right = [0_u8; KMAC_MAX_ENCODED_HEADER_LEN];
        let mut len: usize = 0;
        // SAFETY: the buffer is the authority's own four bytes.
        unsafe {
            assert_eq!(
                right_encode(right.as_mut_ptr(), right.len(), &mut len, 32),
                1
            );
        }
        assert_eq!(len, 2);
        assert_eq!(right, [0x20, 0x01, 0, 0]);
        // SAFETY: as above.
        unsafe {
            assert_eq!(
                right_encode(right.as_mut_ptr(), right.len(), &mut len, 0),
                1
            );
        }
        assert_eq!(len, 2);
        // Only the first two bytes are written: the encoder writes `len + 1` bytes and the tail of the
        // caller's buffer keeps whatever was there, which for this array is the previous call's
        // untouched third byte.
        assert_eq!(right, [0x00, 0x01, 0x00, 0x00]);

        // `get_encode_size` counts **bytes**, so a length whose top byte is zero still occupies the
        // bytes below it; this is the pair that a `while bits { bits >>= 1 }` transcription gets wrong.
        assert_eq!(get_encode_size(0), 1);
        assert_eq!(get_encode_size(1), 1);
        assert_eq!(get_encode_size(255), 1);
        assert_eq!(get_encode_size(256), 2);
        assert_eq!(get_encode_size(0xFFFFFF), 3);
    }

    /// **`bytepad`'s sizing query and its fill agree**, and the pad is zeros to a multiple of `w`.
    ///
    /// The authority calls `bytepad(NULL, …)` to size and then `bytepad(out, NULL, …)` to fill; the two
    /// must produce the same length or the fill writes past the allocation, so the pair is asserted
    /// here rather than trusted.
    #[test]
    fn bytepad_sizes_and_fills_to_the_same_length() {
        // The authority's own `kmac_init` feeds `kctx->custom`, which on an unconfigured row is
        // `encode_string("")` = `{0x01, 0x00}` — a **two**-byte encoding, and not the one-byte
        // `KMAC_EMPTY_CUSTOM` the *input* of that encoding lives in. Passing the input where the
        // encoding belongs was the first version of this test and read past its static.
        let custom = [0x01_u8, 0x00_u8];
        let mut sized: usize = 0;
        // SAFETY: the sizing form writes only `out_len`.
        unsafe {
            assert_eq!(
                bytepad(
                    ptr::null_mut(),
                    &mut sized,
                    KMAC_STRING.as_ptr(),
                    KMAC_STRING.len(),
                    custom.as_ptr(),
                    custom.len(),
                    168,
                ),
                1
            );
        }
        // `2 + 6 + 2` is ten bytes in, so one 168-byte block.
        assert_eq!(sized, 168);

        let mut buf = [0xFF_u8; 168];
        let mut filled: usize = 0;
        // SAFETY: `buf` is exactly the length the sizing form answered.
        unsafe {
            assert_eq!(
                bytepad(
                    buf.as_mut_ptr(),
                    &mut filled,
                    KMAC_STRING.as_ptr(),
                    KMAC_STRING.len(),
                    custom.as_ptr(),
                    custom.len(),
                    168,
                ),
                1
            );
        }
        assert_eq!(filled, sized);
        // `left_encode(168)` = `{0x01, 0xA8}`, then `kmac_string`, then the default custom encoding.
        assert_eq!(&buf[..2], &[0x01, 0xA8]);
        assert_eq!(&buf[2..8], &KMAC_STRING);
        assert_eq!(&buf[8..10], &custom);
        // Everything past the inputs is a zero pad, not the buffer's initial contents.
        assert!(buf[10..].iter().all(|b| *b == 0));

        // A `w` above 255 is a quiet refusal — the live `ossl_assert` under `NDEBUG` — and the NULL
        // `out_len` with a NULL `out` is the only path that raises.
        // SAFETY: the out buffer is real; only `w` is out of range.
        unsafe {
            assert_eq!(
                bytepad(
                    buf.as_mut_ptr(),
                    ptr::null_mut(),
                    KMAC_STRING.as_ptr(),
                    KMAC_STRING.len(),
                    ptr::null(),
                    0,
                    256,
                ),
                0
            );
            assert_eq!(
                bytepad(
                    ptr::null_mut(),
                    ptr::null_mut(),
                    KMAC_STRING.as_ptr(),
                    KMAC_STRING.len(),
                    ptr::null(),
                    0,
                    168,
                ),
                0
            );
        }
    }

    /// The two rows publish the **ctx-level** params pair, not the provider-level one, and the two
    /// lists name four keys and two. Checked because `deflt_macs[]` carries three different parameter
    /// shapes across its rows — CMAC's and HMAC's ctx-level pair, GMAC's and POLY1305's provider-level
    /// pair, and this one's ctx-level pair with an `int` where every other row has a `size_t`.
    #[test]
    fn the_kmac_rows_publish_the_ctx_level_pair_with_an_int_xof() {
        // SAFETY: every key is a `'static` C string literal, and the terminator's is NULL.
        unsafe {
            assert_eq!(KMAC_GETTABLE_CTX_PARAMS.len(), 3);
            let k0 = core::ffi::CStr::from_ptr(KMAC_GETTABLE_CTX_PARAMS[0].key.cast());
            let k1 = core::ffi::CStr::from_ptr(KMAC_GETTABLE_CTX_PARAMS[1].key.cast());
            assert_eq!(k0.to_bytes(), b"size");
            assert_eq!(k1.to_bytes(), b"block-size");
            // Both declared `size_t`, even though `block-size` is written with `set_int`.
            assert_eq!(KMAC_GETTABLE_CTX_PARAMS[1].data_size, 8);
            assert!(KMAC_GETTABLE_CTX_PARAMS[2].key.is_null());

            assert_eq!(KMAC_SETTABLE_CTX_PARAMS.len(), 5);
            for (i, want) in [b"xof".as_slice(), b"size", b"key", b"custom"]
                .into_iter()
                .enumerate()
            {
                let k = core::ffi::CStr::from_ptr(KMAC_SETTABLE_CTX_PARAMS[i].key.cast());
                assert_eq!(k.to_bytes(), want);
            }
            // `xof` is the one `int` in either MAC list.
            assert_eq!(KMAC_SETTABLE_CTX_PARAMS[0].data_size, 4);
            assert!(KMAC_SETTABLE_CTX_PARAMS[4].key.is_null());
        }

        // The dispatch tables are the ten functions plus the terminator, and the two differ only in
        // `NEWCTX`; asserting that is what makes "one implementation, two rows" checkable.
        assert_eq!(KMAC128_FUNCTIONS.len(), 11);
        assert_eq!(KMAC256_FUNCTIONS.len(), 11);
        for i in 1..KMAC128_FUNCTIONS.len() {
            assert_eq!(
                KMAC128_FUNCTIONS[i].function_id,
                KMAC256_FUNCTIONS[i].function_id
            );
            assert_eq!(
                KMAC128_FUNCTIONS[i].function as usize,
                KMAC256_FUNCTIONS[i].function as usize
            );
        }
        assert_ne!(
            KMAC128_FUNCTIONS[0].function as usize,
            KMAC256_FUNCTIONS[0].function as usize
        );
    }

    /// The context's layout is contract for the same reason every other row's is: the allocation a
    /// `CRYPTO_set_mem_functions` application sees is `sizeof(struct kmac_data_st)`, and the two arrays
    /// in it are `KMAC_MAX_KEY_ENCODED` and `KMAC_MAX_CUSTOM_ENCODED` bytes wide rather than the raw
    /// `KMAC_MAX_KEY` and `KMAC_MAX_CUSTOM`.
    #[test]
    fn the_kmac_context_is_the_authoritys_size() {
        assert_eq!(KMAC_MAX_BLOCKSIZE, 168);
        assert_eq!(KMAC_MAX_KEY_ENCODED, 672);
        assert_eq!(KMAC_MAX_CUSTOM_ENCODED, 516);
        assert_eq!(KMAC_MAX_OUTPUT_LEN, 2097151);
        // provctx 8 + ctx 8 + PROV_DIGEST 24 + three size_t 24 + int 4 = 68 bytes of fields, then
        // 672 + 516 = 1188 bytes of arrays, then padding to the eight-byte alignment. The authority's
        // own `sizeof` is 1256 and the embedded `POLY1305`-style sub-objects are absent, so this is
        // the number `CRYPTO_zalloc` receives.
        assert_eq!(core::mem::size_of::<KmacData>(), 1256);
        assert_eq!(core::mem::align_of::<KmacData>(), 8);
    }
}
