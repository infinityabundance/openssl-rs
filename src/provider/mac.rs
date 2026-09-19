//! Phase 8.3 — the default provider's MAC rows: `providers/implementations/macs/cmac_prov.c`
//! (the `CMAC` row, landed) and `gmac_prov.c` (`GMAC`, transcribed and held for Phase 9).
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
//! `properties`). Every raise site that remains reachable in either unit is transcribed, and
//! `RT-MAC` courts the refusals.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_char, c_int, c_uchar, c_void};
use core::ptr;

use crate::context::dispatch::{OsslDispatch, OSSL_DISPATCH_END};
use crate::evp::cipher::EVP_CIPHER_get_mode;
use crate::evp::cipher_ctx::{
    EVP_CIPHER_CTX_copy, EVP_CIPHER_CTX_ctrl, EVP_CIPHER_CTX_free, EVP_CIPHER_CTX_get0_cipher,
    EVP_CIPHER_CTX_get_block_size, EVP_CIPHER_CTX_get_key_length, EVP_CIPHER_CTX_get_params,
    EVP_CIPHER_CTX_new, EVP_EncryptFinal_ex, EVP_EncryptInit_ex, EVP_EncryptUpdate, EvpCipherCtx,
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
use crate::params::{
    OsslParam, END, OSSL_PARAM_OCTET_STRING, OSSL_PARAM_UNSIGNED_INTEGER, OSSL_PARAM_UTF8_STRING,
};
use crate::provider::activate::OsslAlgorithm;
use crate::provider::cipher::{param, repeated_param_site};
use crate::provider::ctx::prov_libctx_of;
use crate::provider::util::{
    ossl_prov_cipher_cipher, ossl_prov_cipher_copy, ossl_prov_cipher_engine, ossl_prov_cipher_load,
    ossl_prov_cipher_reset, ProvCipher,
};
use crate::runtime::err::{err_sites, raise_site};
use crate::runtime::mem::{CRYPTO_free, CRYPTO_zalloc};

/// The allocation-tracking `file` argument for this unit's allocations: `cmac_prov.c` (the
/// build-generated spelling, as the compiler recorded it).
const FILE: *const c_char =
    c"../../src/openssl-3.6.4/providers/implementations/macs/cmac_prov.c".as_ptr();
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
    param(OSSL_MAC_PARAM_SIZE, OSSL_PARAM_UNSIGNED_INTEGER),
    param(OSSL_MAC_PARAM_BLOCK_SIZE, OSSL_PARAM_UNSIGNED_INTEGER),
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
    param(OSSL_MAC_PARAM_CIPHER, OSSL_PARAM_UTF8_STRING),
    param(OSSL_MAC_PARAM_PROPERTIES, OSSL_PARAM_UTF8_STRING),
    param(OSSL_MAC_PARAM_KEY, OSSL_PARAM_OCTET_STRING),
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
/// the rows this half implements, in the authority's order. `deflt_macs[]` carries nine rows
/// (`BLAKE2BMAC`, `BLAKE2SMAC`, `CMAC`, `GMAC`, `HMAC`, `KMAC-128`, `KMAC-256`, `POLY1305`,
/// `SIPHASH`); seven stay `open` in `forensics/atlas/provider-algorithms.json` with
/// `owning_phase: 8`, GMAC is `deferred` to Phase 9 with its blocker named (D243), and the
/// census's exact accounting is what keeps both true.
pub(crate) static DEFLT_MACS: [OsslAlgorithm; 2] = [
    OsslAlgorithm {
        algorithm_names: c"CMAC".as_ptr(),
        property_definition: c"provider=default".as_ptr(),
        implementation: CMAC_FUNCTIONS.as_ptr().cast(),
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
const FILE_GMAC: *const c_char =
    c"../../src/openssl-3.6.4/providers/implementations/macs/gmac_prov.c".as_ptr();

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
static GMAC_GETTABLE_PARAMS: [OsslParam; 2] =
    [param(OSSL_MAC_PARAM_SIZE, OSSL_PARAM_UNSIGNED_INTEGER), END];

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
    param(OSSL_MAC_PARAM_CIPHER, OSSL_PARAM_UTF8_STRING),
    param(OSSL_MAC_PARAM_PROPERTIES, OSSL_PARAM_UTF8_STRING),
    param(OSSL_MAC_PARAM_KEY, OSSL_PARAM_OCTET_STRING),
    param(OSSL_MAC_PARAM_IV, OSSL_PARAM_OCTET_STRING),
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::context::dispatch::OSSL_DISPATCH_END as END_ID;

    #[test]
    fn the_mac_table_terminates_and_names_its_one_registered_row() {
        // Two entries, not three: GMAC's engine is transcribed and its *registration* is held for
        // Phase 9 with the blocker named (D243). A test that asserted three would be asserting a
        // row that cannot work.
        assert_eq!(DEFLT_MACS.len(), 2);
        // SAFETY: the terminator's name is NULL by construction, and each landed row's is a
        // `'static` C string.
        unsafe {
            assert!(DEFLT_MACS[1].algorithm_names.is_null());
            assert!(DEFLT_MACS[1].property_definition.is_null());
            assert!(DEFLT_MACS[1].implementation.is_null());
            let first = core::ffi::CStr::from_ptr(DEFLT_MACS[0].algorithm_names);
            assert_eq!(first.to_bytes(), b"CMAC");
            let props = core::ffi::CStr::from_ptr(DEFLT_MACS[0].property_definition);
            assert_eq!(props.to_bytes(), b"provider=default");
            assert!(!DEFLT_MACS[0].implementation.is_null());
            assert!(DEFLT_MACS[0].algorithm_description.is_null());
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
            assert_eq!(
                GMAC_GETTABLE_PARAMS[0].data_type,
                OSSL_PARAM_UNSIGNED_INTEGER
            );
            assert!(GMAC_GETTABLE_PARAMS[1].key.is_null());
        }
    }
}
