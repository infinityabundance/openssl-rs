//! Phase 10.1/10.6 — `providers/implementations/encode_decode/encode_key2ms.c`: the provider's
//! **MSBLOB and PVK encoders**, one `OSSL_OP_ENCODER` table per key type and output format,
//! published by both the `default` and the `base` provider.
//!
//! This is one of `docs/PHASE-10-SUBPHASES.md` §1a's eleven row-publishing units (`4 tables`, `8
//! rows`). D435 held it `pending` because its writers `i2b_PublicKey_bio`/`i2b_PrivateKey_bio`/
//! `i2b_PVK_bio_ex` live in `crypto/pem/pvkfmt.c`, which 10.6 lands; with that unit in place the
//! closure is complete.
//!
//! ## The engine is shared and the table is the row
//!
//! `key2ms_newctx`/`freectx`/`does_selection` are one each; `key2msblob_encode` and
//! `key2pvk_encode` are the two shared engines the four `MAKE_MS_ENCODER` expansions name; and
//! `key2pvk_set_ctx_params` is the `pvk` rows' only extra slot, carrying
//! `OSSL_ENCODER_PARAM_ENCRYPT_LEVEL` into the default `2` the context starts with. The rows
//! differ only by their key type and their `output=msblob`/`output=pvk` property.
//!
//! ## A PVK write is the one encoder here with a passphrase
//!
//! `key2pvk_encode` installs the caller's `OSSL_PASSPHRASE_CALLBACK` into the context's
//! `ossl_passphrase_data_st` and `write_pvk` reads the PVK encryption level the caller set;
//! `RT-CODEC` drives the unencrypted level (`encrypt-level = 0`), because the encrypted arm needs
//! the `legacy` provider's `PVKKDF`/`RC4` rows, which are not landed (see `src/pem/pvkfmt.rs`).
//!
//! SPDX-License-Identifier: Apache-2.0

#![allow(unreachable_pub)]

use core::ffi::{c_char, c_int, c_void};
use core::ptr;

use crate::context::dispatch::{OsslDispatch, OSSL_DISPATCH_END};
use crate::dsa::Dsa;
use crate::encoder_meth::{
    OSSL_FUNC_ENCODER_DOES_SELECTION, OSSL_FUNC_ENCODER_ENCODE, OSSL_FUNC_ENCODER_FREECTX,
    OSSL_FUNC_ENCODER_FREE_OBJECT, OSSL_FUNC_ENCODER_IMPORT_OBJECT, OSSL_FUNC_ENCODER_NEWCTX,
    OSSL_FUNC_ENCODER_SETTABLE_CTX_PARAMS, OSSL_FUNC_ENCODER_SET_CTX_PARAMS,
};
use crate::evp::p_legacy_assign::EVP_PKEY_set1_RSA;
use crate::evp::pkey::{EVP_PKEY_free, EVP_PKEY_new, EVP_PKEY_set1_DSA, EvpPkey};
use crate::params::{OSSL_PARAM_get_int, OsslParam, OSSL_PARAM_INTEGER, OSSL_PARAM_UNMODIFIED};
use crate::passphrase::{
    ossl_pw_clear_passphrase_data, ossl_pw_pvk_password, ossl_pw_set_ossl_passphrase_cb,
    OsslPassphraseCallback, OsslPassphraseData,
};
use crate::pem::pvkfmt::{i2b_PVK_bio_ex, i2b_PrivateKey_bio, i2b_PublicKey_bio};
use crate::provider::ctx::prov_libctx_of;
use crate::provider::endecoder_common::{ossl_prov_free_key, ossl_prov_import_key};
use crate::rsa::Rsa;
use crate::runtime::bio::core_bio::ossl_bio_new_from_core_bio;
use crate::runtime::bio::BIO_free;
use crate::runtime::err::{err_sites, raise_site};
use crate::runtime::mem::{CRYPTO_free, CRYPTO_zalloc};

/// `OSSL_KEYMGMT_SELECT_PRIVATE_KEY`/`_PUBLIC_KEY` — `core_dispatch.h:640-641`. `pkey.rs` keeps its
/// copies private, so the pair is spelled here as the two encoders' selection tests read them.
const OSSL_KEYMGMT_SELECT_PRIVATE_KEY: c_int = 0x01;
const OSSL_KEYMGMT_SELECT_PUBLIC_KEY: c_int = 0x02;
/// `OSSL_KEYMGMT_SELECT_KEYPAIR` — `core_dispatch.h:649`, the pair `does_selection` reads.
const OSSL_KEYMGMT_SELECT_KEYPAIR: c_int =
    OSSL_KEYMGMT_SELECT_PRIVATE_KEY | OSSL_KEYMGMT_SELECT_PUBLIC_KEY;
/// `OSSL_ENCODER_PARAM_ENCRYPT_LEVEL` — `core_names.h`, `"encrypt-level"`.
const OSSL_ENCODER_PARAM_ENCRYPT_LEVEL: *const c_char = c"encrypt-level".as_ptr();

unsafe extern "C" {
    /// The C library's `strcmp`, the generated parameter decoder's own comparison.
    fn strcmp(a: *const c_char, b: *const c_char) -> c_int;
}

/// `struct key2ms_ctx_st` — `encode_key2ms.c:37-43`.
#[repr(C)]
struct Key2msCtx {
    provctx: *mut c_void,
    pvk_encr_level: c_int,
    pwdata: OsslPassphraseData,
}

/// `static void *key2ms_newctx(void *provctx)` — `encode_key2ms.c:79-89`.
///
/// # Safety
/// The encoder `newctx` dispatch contract.
unsafe extern "C" fn key2ms_newctx(provctx: *mut c_void) -> *mut c_void {
    // SAFETY: `CRYPTO_zalloc` takes a size and answers a zeroed block or NULL.
    let ctx = CRYPTO_zalloc(core::mem::size_of::<Key2msCtx>(), ptr::null(), 0).cast::<Key2msCtx>();
    if !ctx.is_null() {
        // SAFETY: `ctx` is this call's fresh allocation.
        unsafe {
            (*ctx).provctx = provctx;
            /* This is the strongest encryption level */
            (*ctx).pvk_encr_level = 2;
        }
    }
    ctx.cast::<c_void>()
}

/// `static void key2ms_freectx(void *vctx)` — `encode_key2ms.c:91-97`.
///
/// # Safety
/// The encoder `freectx` dispatch contract.
unsafe extern "C" fn key2ms_freectx(vctx: *mut c_void) {
    if vctx.is_null() {
        return;
    }
    let ctx = vctx.cast::<Key2msCtx>();
    // SAFETY: `ctx` is the live context this call owns.
    unsafe { ossl_pw_clear_passphrase_data(&raw mut (*ctx).pwdata) };
    // SAFETY: `ctx` is this call's allocation.
    unsafe { CRYPTO_free(vctx, ptr::null(), 0) };
}

/// `key2pvk_set_ctx_params_list[]` — the generated settable list, one `OSSL_PARAM_int`.
static KEY2PVK_SET_CTX_PARAMS_LIST: [OsslParam; 2] = [
    OsslParam {
        key: OSSL_ENCODER_PARAM_ENCRYPT_LEVEL,
        data_type: OSSL_PARAM_INTEGER,
        data: ptr::null_mut(),
        data_size: core::mem::size_of::<c_int>(),
        return_size: OSSL_PARAM_UNMODIFIED,
    },
    crate::params::END,
];

/// `static const OSSL_PARAM *key2pvk_settable_ctx_params(void *provctx)` — `encode_key2ms.c:105-108`.
///
/// # Safety
/// The encoder `settable_ctx_params` dispatch contract.
unsafe extern "C" fn key2pvk_settable_ctx_params(_provctx: *mut c_void) -> *const OsslParam {
    KEY2PVK_SET_CTX_PARAMS_LIST.as_ptr()
}

/// `static int key2pvk_set_ctx_params(void *vctx, const OSSL_PARAM params[])` —
/// `encode_key2ms.c:110-121`, over the generated decoder.
///
/// # Safety
/// The encoder `set_ctx_params` dispatch contract.
unsafe extern "C" fn key2pvk_set_ctx_params(vctx: *mut c_void, params: *const OsslParam) -> c_int {
    let ctx = vctx.cast::<Key2msCtx>();
    if ctx.is_null() {
        return 0;
    }
    let mut enclvl: *const OsslParam = ptr::null();
    if !params.is_null() {
        let mut p = params;
        // SAFETY: `p` walks a `key == NULL`-terminated array.
        while !unsafe { (*p).key }.is_null() {
            // SAFETY: each key is NUL-terminated and the literal is too.
            if unsafe { strcmp((*p).key, OSSL_ENCODER_PARAM_ENCRYPT_LEVEL) } == 0 {
                if !enclvl.is_null() {
                    /* The generated decoder would raise PROV_R_REPEATED_PARAMETER; the generated
                     * file is not an authority source the error atlas covers, so the refusal is
                     * the plain 0 the framework treats as failure. */
                    return 0;
                }
                enclvl = p;
            }
            // SAFETY: the array is terminated, so the step stays within it.
            p = unsafe { p.add(1) };
        }
    }
    if !enclvl.is_null()
        // SAFETY: `enclvl` is live and `ctx` is the caller's.
        && unsafe { OSSL_PARAM_get_int(enclvl, &raw mut (*ctx).pvk_encr_level) } == 0
    {
        return 0;
    }
    1
}

/// `static int key2ms_does_selection(void *vctx, int selection)` — `encode_key2ms.c:123-126`.
fn key2ms_does_selection(selection: c_int) -> c_int {
    c_int::from((selection & OSSL_KEYMGMT_SELECT_KEYPAIR) != 0)
}

/// `static int write_msblob(struct key2ms_ctx_st *ctx, OSSL_CORE_BIO *cout, EVP_PKEY *pkey,
/// int ispub)` — `encode_key2ms.c:45-57`.
///
/// # Safety
/// `cout` the core BIO this encode owns; `pkey` live.
unsafe fn write_msblob(cout: *mut c_void, pkey: *mut EvpPkey, ispub: c_int) -> c_int {
    // SAFETY: `cout` is the core BIO this encode owns.
    let out = unsafe { ossl_bio_new_from_core_bio(cout.cast()) };
    if out.is_null() {
        return 0;
    }
    let ret = if ispub != 0 {
        // SAFETY: `out` is live and `pkey` is live.
        unsafe { i2b_PublicKey_bio(out, pkey) }
    } else {
        // SAFETY: `out` is live and `pkey` is live.
        unsafe { i2b_PrivateKey_bio(out, pkey) }
    };
    // SAFETY: `out` is live and this call owns the reference the bridge took.
    unsafe { BIO_free(out) };
    ret
}

/// `static int write_pvk(struct key2ms_ctx_st *ctx, OSSL_CORE_BIO *cout, EVP_PKEY *pkey)` —
/// `encode_key2ms.c:59-73`.
///
/// # Safety
/// `ctx` a live context; `cout` the core BIO; `pkey` live.
unsafe fn write_pvk(ctx: *mut Key2msCtx, cout: *mut c_void, pkey: *mut EvpPkey) -> c_int {
    // SAFETY: `ctx` is live.
    let libctx = unsafe { prov_libctx_of((*ctx).provctx) };

    // SAFETY: `cout` is the core BIO this encode owns.
    let out = unsafe { ossl_bio_new_from_core_bio(cout.cast()) };
    if out.is_null() {
        return 0;
    }
    // SAFETY: every argument is live and `ctx`'s own; the passphrase data is the context's.
    let ret = unsafe {
        i2b_PVK_bio_ex(
            out,
            pkey,
            (*ctx).pvk_encr_level,
            Some(ossl_pw_pvk_password),
            (&raw mut (*ctx).pwdata).cast::<c_void>(),
            libctx,
            ptr::null(),
        )
    };
    // SAFETY: `out` is live and this call owns the reference the bridge took.
    unsafe { BIO_free(out) };
    ret
}

/// `#define rsa_set1 (evp_pkey_set1_fn *)EVP_PKEY_set1_RSA`.
///
/// # Safety
/// `key` must be a live `RSA *`.
unsafe extern "C" fn rsa_set1(pkey: *mut EvpPkey, key: *const c_void) -> c_int {
    // SAFETY: the caller's contract, restated in the typed assignment's terms.
    unsafe { EVP_PKEY_set1_RSA(pkey, key.cast::<Rsa>().cast_mut()) }
}

/// `#define dsa_set1 (evp_pkey_set1_fn *)EVP_PKEY_set1_DSA`.
///
/// # Safety
/// `key` must be a live `DSA *`.
unsafe extern "C" fn dsa_set1(pkey: *mut EvpPkey, key: *const c_void) -> c_int {
    // SAFETY: the caller's contract, restated in the typed assignment's terms.
    unsafe { EVP_PKEY_set1_DSA(pkey, key.cast::<Dsa>().cast_mut()) }
}

/// One `MAKE_MS_ENCODER(impl, output, type)` expansion for the `msblob` output
/// (`encode_key2ms.c:190-236` with the empty `msblob_set_params`). Seven named slots.
macro_rules! make_msblob_encoder {
    ($encode:ident, $import:ident, $free:ident, $does:ident, $table:ident, $keymgmt:path, $set1:ident, $raise:path) => {
        /// `import_object` — `ossl_prov_import_key(<keymgmt>, ctx, selection, params)`.
        ///
        /// # Safety
        /// The encoder `import_object` dispatch contract.
        unsafe extern "C" fn $import(
            ctx: *mut c_void,
            selection: c_int,
            params: *const OsslParam,
        ) -> *mut c_void {
            // SAFETY: the table is the key type's own and the arguments are the caller's.
            unsafe { ossl_prov_import_key($keymgmt.as_ptr(), ctx, selection, params) }
        }

        /// `free_object` — `ossl_prov_free_key(<keymgmt>, key)`.
        ///
        /// # Safety
        /// The encoder `free_object` dispatch contract.
        unsafe extern "C" fn $free(key: *mut c_void) {
            // SAFETY: the table is the key type's own and `key` is its object.
            unsafe { ossl_prov_free_key($keymgmt.as_ptr(), key) }
        }

        /// `does_selection` — the unit's `key2ms_does_selection`.
        ///
        /// # Safety
        /// The encoder `does_selection` dispatch contract.
        unsafe extern "C" fn $does(_ctx: *mut c_void, selection: c_int) -> c_int {
            key2ms_does_selection(selection)
        }

        /// `encode` — refuse an abstract object, else run `key2msblob_encode`.
        ///
        /// # Safety
        /// The encoder `encode` dispatch contract.
        unsafe extern "C" fn $encode(
            vctx: *mut c_void,
            cout: *mut c_void,
            key: *const c_void,
            key_abstract: *const OsslParam,
            selection: c_int,
            _cb: Option<OsslPassphraseCallback>,
            _cbarg: *mut c_void,
        ) -> c_int {
            if !key_abstract.is_null() {
                // SAFETY: a compile-time-constant site.
                unsafe { raise_site(&$raise) };
                return 0;
            }
            // SAFETY: the encoder contract is the caller's; the engine is this unit's own.
            unsafe { key2msblob_encode(vctx, key, selection, cout, $set1) }
        }

        pub(crate) static $table: [OsslDispatch; 7] = [
            OsslDispatch {
                function_id: OSSL_FUNC_ENCODER_NEWCTX,
                function: key2ms_newctx as *mut c_void,
            },
            OsslDispatch {
                function_id: OSSL_FUNC_ENCODER_FREECTX,
                function: key2ms_freectx as *mut c_void,
            },
            OsslDispatch {
                function_id: OSSL_FUNC_ENCODER_DOES_SELECTION,
                function: $does as *mut c_void,
            },
            OsslDispatch {
                function_id: OSSL_FUNC_ENCODER_IMPORT_OBJECT,
                function: $import as *mut c_void,
            },
            OsslDispatch {
                function_id: OSSL_FUNC_ENCODER_FREE_OBJECT,
                function: $free as *mut c_void,
            },
            OsslDispatch {
                function_id: OSSL_FUNC_ENCODER_ENCODE,
                function: $encode as *mut c_void,
            },
            OsslDispatch {
                function_id: OSSL_DISPATCH_END,
                function: ptr::null_mut(),
            },
        ];
    };
}

/// One `MAKE_MS_ENCODER(impl, pvk, type)` expansion (`encode_key2ms.c:190-236` with the `pvk` row's
/// two `pvk_set_params` slots). Nine named slots.
macro_rules! make_pvk_encoder {
    ($encode:ident, $import:ident, $free:ident, $does:ident, $table:ident, $keymgmt:path, $set1:ident, $raise:path) => {
        /// `import_object` — `ossl_prov_import_key(<keymgmt>, ctx, selection, params)`.
        ///
        /// # Safety
        /// The encoder `import_object` dispatch contract.
        unsafe extern "C" fn $import(
            ctx: *mut c_void,
            selection: c_int,
            params: *const OsslParam,
        ) -> *mut c_void {
            // SAFETY: the table is the key type's own and the arguments are the caller's.
            unsafe { ossl_prov_import_key($keymgmt.as_ptr(), ctx, selection, params) }
        }

        /// `free_object` — `ossl_prov_free_key(<keymgmt>, key)`.
        ///
        /// # Safety
        /// The encoder `free_object` dispatch contract.
        unsafe extern "C" fn $free(key: *mut c_void) {
            // SAFETY: the table is the key type's own and `key` is its object.
            unsafe { ossl_prov_free_key($keymgmt.as_ptr(), key) }
        }

        /// `does_selection` — the unit's `key2ms_does_selection`.
        ///
        /// # Safety
        /// The encoder `does_selection` dispatch contract.
        unsafe extern "C" fn $does(_ctx: *mut c_void, selection: c_int) -> c_int {
            key2ms_does_selection(selection)
        }

        /// `encode` — refuse an abstract object, else run `key2pvk_encode`.
        ///
        /// # Safety
        /// The encoder `encode` dispatch contract.
        unsafe extern "C" fn $encode(
            vctx: *mut c_void,
            cout: *mut c_void,
            key: *const c_void,
            key_abstract: *const OsslParam,
            selection: c_int,
            cb: Option<OsslPassphraseCallback>,
            cbarg: *mut c_void,
        ) -> c_int {
            if !key_abstract.is_null() {
                // SAFETY: a compile-time-constant site.
                unsafe { raise_site(&$raise) };
                return 0;
            }
            // SAFETY: the encoder contract is the caller's; the engine is this unit's own.
            unsafe { key2pvk_encode(vctx, key, selection, cout, $set1, cb, cbarg) }
        }

        pub(crate) static $table: [OsslDispatch; 9] = [
            OsslDispatch {
                function_id: OSSL_FUNC_ENCODER_NEWCTX,
                function: key2ms_newctx as *mut c_void,
            },
            OsslDispatch {
                function_id: OSSL_FUNC_ENCODER_FREECTX,
                function: key2ms_freectx as *mut c_void,
            },
            OsslDispatch {
                function_id: OSSL_FUNC_ENCODER_DOES_SELECTION,
                function: $does as *mut c_void,
            },
            OsslDispatch {
                function_id: OSSL_FUNC_ENCODER_IMPORT_OBJECT,
                function: $import as *mut c_void,
            },
            OsslDispatch {
                function_id: OSSL_FUNC_ENCODER_FREE_OBJECT,
                function: $free as *mut c_void,
            },
            OsslDispatch {
                function_id: OSSL_FUNC_ENCODER_ENCODE,
                function: $encode as *mut c_void,
            },
            OsslDispatch {
                function_id: OSSL_FUNC_ENCODER_SETTABLE_CTX_PARAMS,
                function: key2pvk_settable_ctx_params as *mut c_void,
            },
            OsslDispatch {
                function_id: OSSL_FUNC_ENCODER_SET_CTX_PARAMS,
                function: key2pvk_set_ctx_params as *mut c_void,
            },
            OsslDispatch {
                function_id: OSSL_DISPATCH_END,
                function: ptr::null_mut(),
            },
        ];
    };
}

/// `static int key2msblob_encode(void *vctx, const void *key, int selection, OSSL_CORE_BIO *cout,
/// evp_pkey_set1_fn *set1_key, OSSL_PASSPHRASE_CALLBACK *pw_cb, void *pw_cbarg)` —
/// `encode_key2ms.c:139-159`.
///
/// # Safety
/// `vctx` a live context; `key` the keymgmt's object; `cout` the core BIO.
unsafe fn key2msblob_encode(
    _vctx: *mut c_void,
    key: *const c_void,
    selection: c_int,
    cout: *mut c_void,
    set1_key: unsafe extern "C" fn(*mut EvpPkey, *const c_void) -> c_int,
) -> c_int {
    let ispub = if (selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0 {
        0
    } else if (selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0 {
        1
    } else {
        return 0;
    };
    let mut ok = 0;
    // SAFETY: no preconditions.
    let pkey = unsafe { EVP_PKEY_new() };
    if !pkey.is_null() {
        // SAFETY: `pkey` is live and `key` is the keymgmt's object.
        if unsafe { set1_key(pkey, key) } != 0 {
            // SAFETY: `cout` and `pkey` are live.
            ok = unsafe { write_msblob(cout, pkey, ispub) };
        }
    }
    // SAFETY: `pkey` is NULL or live and this call owns it.
    unsafe { EVP_PKEY_free(pkey) };
    ok
}

/// `static int key2pvk_encode(void *vctx, const void *key, int selection, OSSL_CORE_BIO *cout,
/// evp_pkey_set1_fn *set1_key, OSSL_PASSPHRASE_CALLBACK *pw_cb, void *pw_cbarg)` —
/// `encode_key2ms.c:161-178`.
///
/// # Safety
/// `vctx` a live context; `key` the keymgmt's object; `cout` the core BIO.
unsafe fn key2pvk_encode(
    vctx: *mut c_void,
    key: *const c_void,
    selection: c_int,
    cout: *mut c_void,
    set1_key: unsafe extern "C" fn(*mut EvpPkey, *const c_void) -> c_int,
    pw_cb: Option<OsslPassphraseCallback>,
    pw_cbarg: *mut c_void,
) -> c_int {
    let ctx = vctx.cast::<Key2msCtx>();
    if (selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) == 0 {
        return 0;
    }
    let mut ok = 0;
    // SAFETY: no preconditions.
    let pkey = unsafe { EVP_PKEY_new() };
    if !pkey.is_null()
        // SAFETY: `pkey` is live and `key` is the keymgmt's object.
        && unsafe { set1_key(pkey, key) } != 0
        && (pw_cb.is_none()
            // SAFETY: `ctx` is live and the callback arguments are the caller's.
            || unsafe {
                ossl_pw_set_ossl_passphrase_cb(&raw mut (*ctx).pwdata, pw_cb, pw_cbarg)
            } != 0)
    {
        // SAFETY: `ctx`, `cout`, `pkey` are live.
        ok = unsafe { write_pvk(ctx, cout, pkey) };
    }
    // SAFETY: `pkey` is NULL or live and this call owns it.
    unsafe { EVP_PKEY_free(pkey) };
    ok
}

// The four expansions, in the authority's order (`:239-244`). `SM2` does not appear: the unit's
// `pvk`/`msblob` inputs are RSA and DSA only.
make_pvk_encoder!(
    dsa2pvk_encode,
    dsa2pvk_import_object,
    dsa2pvk_free_object,
    dsa2pvk_does_selection,
    DSA_TO_PVK_FUNCTIONS,
    crate::provider::dsa_kmgmt::DSA_KEYMGMT_FUNCTIONS,
    dsa_set1,
    err_sites::PROV_ENCODE_KEY2MS_270
);
make_msblob_encoder!(
    dsa2msblob_encode,
    dsa2msblob_import_object,
    dsa2msblob_free_object,
    dsa2msblob_does_selection,
    DSA_TO_MSBLOB_FUNCTIONS,
    crate::provider::dsa_kmgmt::DSA_KEYMGMT_FUNCTIONS,
    dsa_set1,
    err_sites::PROV_ENCODE_KEY2MS_271
);
make_pvk_encoder!(
    rsa2pvk_encode,
    rsa2pvk_import_object,
    rsa2pvk_free_object,
    rsa2pvk_does_selection,
    RSA_TO_PVK_FUNCTIONS,
    crate::provider::rsa_kmgmt::RSA_KEYMGMT_FUNCTIONS,
    rsa_set1,
    err_sites::PROV_ENCODE_KEY2MS_274
);
make_msblob_encoder!(
    rsa2msblob_encode,
    rsa2msblob_import_object,
    rsa2msblob_free_object,
    rsa2msblob_does_selection,
    RSA_TO_MSBLOB_FUNCTIONS,
    crate::provider::rsa_kmgmt::RSA_KEYMGMT_FUNCTIONS,
    rsa_set1,
    err_sites::PROV_ENCODE_KEY2MS_275
);
