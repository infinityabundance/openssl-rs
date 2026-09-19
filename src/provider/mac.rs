//! Phase 8.3 — the default provider's MAC rows: `providers/implementations/macs/cmac_prov.c`
//! (the `CMAC` row), `siphash_prov.c` (`SIPHASH`), `hmac_prov.c` (`HMAC`) and `gmac_prov.c`
//! (`GMAC`, transcribed and held for Phase 9).
//!
//! **Why these rows land with the ciphers rather than with a MAC stratum.** CMAC is the first
//! `OSSL_OP_MAC` row anything in this crate needs: `crypto/modes/siv128.c` implements RFC 5297's
//! S2V with `EVP_MAC_fetch(…, "CMAC", …)`, and D239 measured that the crate published no
//! `OSSL_OP_MAC` row at all, so `EVP_MAC_fetch(NULL, "CMAC", NULL)` answered 0 where the
//! authority answers 1. The rows are Phase 8's own obligation — `deflt_macs[]`'s nine rows are
//! `open`/`owning_phase: 8` in `forensics/atlas/provider-algorithms.json` — so the SIV rows wait
//! on CMAC rather than on another stratum. **GMAC's engine is transcribed in the same unit and its
//! registration is not**, which is a measurement rather than a caution: `gmac_set_ctx_params`
//! resolves a `cipher` name and then refuses every mode but `EVP_CIPH_GCM_MODE`, and this
//! profile's only GCM ciphers are `AES-{128,192,256}-GCM`, themselves Phase 9's on `RAND_bytes_ex`
//! (D234). Publishing the row would make `EVP_MAC_fetch(NULL, "GMAC", NULL)` answer 1 on both
//! sides and then make every `EVP_MAC_init` fail where the authority succeeds — worse than not
//! publishing it, because the difference would be invisible to a fetch-only observation. So the
//! row is Phase 9's with its blocker named in `provider-algorithm-plans.json` (D243).
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

use core::ffi::{c_char, c_int, c_uchar, c_uint, c_void};
use core::ptr;

use crate::context::dispatch::{OsslDispatch, OSSL_DISPATCH_END};
use crate::evp::cipher::EVP_CIPHER_get_mode;
use crate::evp::cipher_ctx::{
    EVP_CIPHER_CTX_copy, EVP_CIPHER_CTX_ctrl, EVP_CIPHER_CTX_free, EVP_CIPHER_CTX_get0_cipher,
    EVP_CIPHER_CTX_get_block_size, EVP_CIPHER_CTX_get_key_length, EVP_CIPHER_CTX_get_params,
    EVP_CIPHER_CTX_new, EVP_EncryptFinal_ex, EVP_EncryptInit_ex, EVP_EncryptUpdate, EvpCipherCtx,
};
use crate::evp::digest::EVP_MD_get_block_size;
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
use crate::mac::siphash::{
    SipHash_Final, SipHash_Init, SipHash_Update, SipHash_hash_size, SipHash_set_hash_size, Siphash,
    SIPHASH_C_ROUNDS, SIPHASH_D_ROUNDS, SIPHASH_KEY_SIZE,
};
use crate::mac::ssl3_cbc::ssl3_cbc_digest_record;
use crate::params::{OsslParam, END, OSSL_PARAM_OCTET_STRING};
use crate::provider::activate::OsslAlgorithm;
use crate::provider::cipher::{
    param_octet_string, param_size_t, param_uint, param_utf8_string, repeated_param_site,
};
use crate::provider::ctx::prov_libctx_of;
use crate::provider::util::prov_digest::{
    ossl_prov_digest_copy, ossl_prov_digest_engine, ossl_prov_digest_load, ossl_prov_digest_md,
    ossl_prov_digest_reset, ProvDigest,
};
use crate::provider::util::{
    ossl_prov_cipher_cipher, ossl_prov_cipher_copy, ossl_prov_cipher_engine, ossl_prov_cipher_load,
    ossl_prov_cipher_reset, ProvCipher, OSSL_ALG_PARAM_DIGEST,
};
use crate::runtime::err::{err_sites, raise_site};
use crate::runtime::mem::{CRYPTO_clear_free, CRYPTO_free, CRYPTO_malloc, CRYPTO_zalloc};

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
pub(crate) static CMAC_FUNCTIONS: [OsslDispatch; 11] = [
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
/// (`BLAKE2BMAC`, `BLAKE2SMAC`, `CMAC`, `GMAC`, `HMAC`, `KMAC-128`, `KMAC-256`, `POLY1305`,
/// `SIPHASH`), so `HMAC` and `SIPHASH` are not appended: they are the authority's fifth and ninth
/// rows, and the census checks that the rows this table publishes are a **subsequence** of the
/// authority's order (D244). GMAC is `deferred` to Phase 9 with its blocker named (D243) and its
/// engine is transcribed; `BLAKE2BMAC`, `BLAKE2SMAC`, `KMAC-128`, `KMAC-256` and `POLY1305` stay
/// `open` with `owning_phase: 8`, and the census's exact accounting is what keeps all of that true.
///
/// **The property definition is `"provider=default"` on every row.** `defltprov.c`'s `ALG` macro
/// expands through `ALGC(NAMES, FUNC, CHECK) { { NAMES, "provider=default", FUNC }, CHECK }`, and
/// D247 is what a NULL there cost: a fetch whose property query is `provider=default` stopped
/// resolving, and `provider!=default` resolved when it should not have.
pub(crate) static DEFLT_MACS: [OsslAlgorithm; 4] = [
    OsslAlgorithm {
        algorithm_names: c"CMAC".as_ptr(),
        property_definition: c"provider=default".as_ptr(),
        implementation: CMAC_FUNCTIONS.as_ptr().cast(),
        algorithm_description: ptr::null(),
    },
    OsslAlgorithm {
        algorithm_names: c"HMAC".as_ptr(),
        property_definition: c"provider=default".as_ptr(),
        implementation: HMAC_FUNCTIONS.as_ptr().cast(),
        algorithm_description: ptr::null(),
    },
    OsslAlgorithm {
        algorithm_names: c"SIPHASH".as_ptr(),
        property_definition: c"provider=default".as_ptr(),
        implementation: SIPHASH_FUNCTIONS.as_ptr().cast(),
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
/// which is the shape difference from `CMAC_FUNCTIONS`.
///
/// **Transcribed and held, not registered.** This table is deliberately absent from
/// [`DEFLT_MACS`]: GMAC resolves a `cipher` name and then refuses every mode but GCM, and this
/// profile's only GCM ciphers are `AES-{128,192,256}-GCM`, which are Phase 9's on `RAND_bytes_ex`
/// (D234). Registering the row now would make `EVP_MAC_fetch(NULL, "GMAC", NULL)` answer 1 on
/// both sides and then make every `EVP_MAC_init` fail where the authority succeeds — the
/// `DES3-WRAP` class of invisible incompleteness, one operation over. The row is Phase 9's with
/// the blocker named in `forensics/atlas/provider-algorithm-plans.json`, and the unit tests below
/// are what keep the transcription honest until then (D243).
#[allow(dead_code)]
// The caller that will land: `DEFLT_MACS`'s third row, when the AES-GCM cipher rows land in
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
/// terminator. The same shape as `CMAC_FUNCTIONS`: the ctx-params pair, not the provider-level one.
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::context::dispatch::OSSL_DISPATCH_END as END_ID;

    #[test]
    fn the_mac_table_names_its_rows_in_the_authoritys_order() {
        // CMAC then HMAC then SIPHASH, and **not** appended: `defltprov.c` lists HMAC fifth and
        // SIPHASH ninth, after GMAC, and the census requires the crate's rows to be a subsequence of
        // the authority's order (D244). GMAC's engine is transcribed and its registration is held for
        // Phase 9 (D243), so it is absent here rather than in the wrong place.
        assert_eq!(DEFLT_MACS.len(), 4);
        // SAFETY: the terminator's name is NULL by construction, and each landed row's is a
        // `'static` C string.
        unsafe {
            assert!(DEFLT_MACS[3].algorithm_names.is_null());
            assert!(DEFLT_MACS[3].property_definition.is_null());
            assert!(DEFLT_MACS[3].implementation.is_null());
            for (row, want) in [
                (&DEFLT_MACS[0], b"CMAC".as_slice()),
                (&DEFLT_MACS[1], b"HMAC"),
                (&DEFLT_MACS[2], b"SIPHASH"),
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
        let cases: [(&str, *const c_char, &err_sites::ErrSite); 4] = [
            ("cmac", FILE, &err_sites::PROV_CMAC_PROV_245),
            ("gmac", FILE_GMAC, &err_sites::PROV_GMAC_PROV_200),
            ("hmac", FILE_HMAC, &err_sites::PROV_HMAC_PROV_313),
            ("siphash", FILE_SIPHASH, &err_sites::PROV_SIPHASH_PROV_190),
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
        // The same shape as `CMAC_FUNCTIONS`: the ctx-params pair, not the provider-level one that
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
        let ids: Vec<c_int> = CMAC_FUNCTIONS.iter().map(|d| d.function_id).collect();
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
        assert!(CMAC_FUNCTIONS[..10].iter().all(|d| !d.function.is_null()));
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
        // The one shape difference from `CMAC_FUNCTIONS`: GMAC's two getters are the
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
}
