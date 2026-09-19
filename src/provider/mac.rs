//! Phase 8.3 — `providers/implementations/macs/cmac_prov.c`, the `OSSL_OP_MAC` row `CMAC`.
//!
//! **Why this row lands with the ciphers rather than with a MAC stratum.** It is the first
//! `OSSL_OP_MAC` row anything in this crate needs: `crypto/modes/siv128.c` implements RFC 5297's
//! S2V with `EVP_MAC_fetch(…, "CMAC", …)`, and D239 measured that the crate published no
//! `OSSL_OP_MAC` row at all, so `EVP_MAC_fetch(NULL, "CMAC", NULL)` answered 0 where the
//! authority answers 1. The row is Phase 8's own obligation — `deflt_macs[]`'s nine rows are
//! `open`/`owning_phase: 8` in `forensics/atlas/provider-algorithms.json` — so the six SIV rows
//! wait on this one rather than on another stratum.
//!
//! **The row is a shell over landed machinery.** `CMAC_CTX_new`/`_free`/`_copy`/
//! `_get0_cipher_ctx`, `CMAC_Init`/`Update`/`Final` and `ossl_cmac_init` are `src/mac/cmac.rs`'s,
//! transcribed in Phase 7 with the deprecated public API and courted by `RT-CMAC`. What this unit
//! adds is the two things a provider row owns: the `OSSL_FUNC_MAC_*` dispatch table, and the
//! *parameterisation* — `cmac_set_ctx_params` turns a `cipher` **name** into an `EVP_CIPHER`
//! through `ossl_prov_cipher_load` in `PROV_LIBCTX_OF(macctx->provctx)`, which is why
//! `src/provider/util.rs` and `src/provider/ctx.rs` land beside it.
//!
//! **The FIPS arms are absent, and they are absent from the authority's own build too.** Every
//! `OSSL_FIPS_IND_*` macro is a no-op or a literal `1` when `FIPS_MODULE` is undefined
//! (`providers/fips/include/fips/fipsindicator.h`'s `#else` block), and the generated decoders
//! `# if defined(FIPS_MODULE)`-guard the two `fips` keys, so this profile's `cmac_prov.c` has:
//! two get-decoder keys (`block-size`, `size`), four set-decoder keys (`cipher`, `engine`, `key`,
//! `properties`), no `tdes_check_param`, and no `EVP_CIPHER_is_a` allow-list. The three raise
//! sites that remain reachable — `PROV_R_REPEATED_PARAMETER` at the two decoders and
//! `PROV_R_INVALID_MODE` — are all transcribed and all courted.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_char, c_int, c_uchar, c_void};
use core::ptr;

use crate::context::dispatch::{OsslDispatch, OSSL_DISPATCH_END};
use crate::evp::cipher::EVP_CIPHER_get_mode;
use crate::evp::cipher_ctx::{
    EVP_CIPHER_CTX_get0_cipher, EVP_CIPHER_CTX_get_block_size, EvpCipherCtx,
};
use crate::evp::mac::{
    OSSL_FUNC_MAC_DUPCTX, OSSL_FUNC_MAC_FINAL, OSSL_FUNC_MAC_FREECTX,
    OSSL_FUNC_MAC_GETTABLE_CTX_PARAMS, OSSL_FUNC_MAC_GET_CTX_PARAMS, OSSL_FUNC_MAC_INIT,
    OSSL_FUNC_MAC_NEWCTX, OSSL_FUNC_MAC_SETTABLE_CTX_PARAMS, OSSL_FUNC_MAC_SET_CTX_PARAMS,
    OSSL_FUNC_MAC_UPDATE,
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
/// `SIPHASH`); the other eight stay `open` in `forensics/atlas/provider-algorithms.json` with
/// `owning_phase: 8`, and the census's exact accounting is what keeps that true.
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::context::dispatch::OSSL_DISPATCH_END as END_ID;

    #[test]
    fn the_mac_table_terminates_and_names_its_one_row() {
        assert_eq!(DEFLT_MACS.len(), 2);
        // SAFETY: the terminator's name is NULL by construction, and the first row's is a
        // `'static` C string.
        unsafe {
            assert!(DEFLT_MACS[1].algorithm_names.is_null());
            let first = core::ffi::CStr::from_ptr(DEFLT_MACS[0].algorithm_names);
            assert_eq!(first.to_bytes(), b"CMAC");
            let props = core::ffi::CStr::from_ptr(DEFLT_MACS[0].property_definition);
            assert_eq!(props.to_bytes(), b"provider=default");
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
}
