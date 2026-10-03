//! Phase 16.1 — the legacy provider module (`providers/legacyprov.c`).
//!
//! `EVP_MD_fetch(NULL, "MD4", "provider=legacy")` resolves through the `legacy` provider's
//! `OSSL_OP_DIGEST` query once the module is loaded, and the loadable module the candidate ships
//! as `ossl-modules/legacy.so` is this unit's `OSSL_provider_init`. The authority's
//! `providers/legacyprov.c` publishes **39 registration rows** across four operations:
//! `legacy_digests` (MD4, MDC2, WHIRLPOOL, RIPEMD-160), `legacy_ciphers` (the 32 CAST5, BF, IDEA,
//! SEED, RC2, RC4, DESX and DES rows), `legacy_kdfs` (PBKDF1, PVKKDF) and `legacy_skeymgmt`
//! (`GENERIC-SECRET`).
//!
//! ## What this subphase lands, and in how many slices
//!
//! This module lands **slice 1**: the loadable-module contract itself
//! (`legacy_gettable_params`, `legacy_get_params`, `legacy_query`, `legacy_teardown` and the
//! `legacy_dispatch_table`, transcribed from `legacyprov.c:63-205`), the `legacy_digests` table
//! (`legacyprov.c:87-104`, all four rows) and the `legacy_skeymgmt` table (`legacyprov.c:170-173`,
//! its one row). Five of the authority's 39 rows are therefore published and the census reads them
//! `implemented`; the remaining 34 stay `unimplemented` and the cipher and KDF arms return `NULL`,
//! exactly as an unlanded table does.
//!
//! **The remaining slices are ordered and named, not silently dropped.** Slice 2 is the 32
//! `legacy_ciphers` rows (`legacyprov.c:106-162`): their provider engines are
//! `providers/implementations/ciphers/cipher_cast5.c`, `cipher_blowfish.c`, `cipher_idea.c`,
//! `cipher_seed.c`, `cipher_rc2.c`, `cipher_rc4.c`, `cipher_rc4_hmac_md5.c`, `cipher_des.c` and
//! `cipher_desx.c`, each a thin instantiation of the crate's already-landed generic cipher engine
//! (`src/provider/cipher.rs`) whose per-algorithm `*_hw.c` key-schedule hook is not yet
//! transcribed. Slice 3 is the two `legacy_kdfs` rows (`legacyprov.c:164-168`):
//! `providers/implementations/kdfs/pbkdf1.c.in` and `pvkkdf.c.in`, which drive `PROV_DIGEST` and
//! so are bounded by the same `ossl_prov_digest_*` surface `src/provider/kdf.rs` already uses.
//! Both slices are absent here rather than stubbed: a stub table would make a fetch answer
//! non-`NULL` for an algorithm nothing implements, which is worse than the `NULL` the authority
//! answers when a row is not compiled in.
//!
//! ## The primitives, and which of them are present
//!
//! Each landed digest row reuses the primitive the crate already carries: `src/digest/md4.rs`
//! (`MD4_*`), `src/digest/mdc2.rs` (`MDC2_*`, whose `Mdc2Ctx::pad_type` the row's `set_ctx_params`
//! drives) and `src/digest/wp.rs` (`WHIRLPOOL_*`). `RIPEMD-160` is the fourth: the crate's
//! `src/digest/ripemd.rs` primitive is reused, but its provider dispatch table is defined here
//! rather than reused from `src/provider/digest.rs`, whose `ripemd160` module is private to that
//! unit and whose `deflt_digests` row is the *default* provider's. The primitive list this
//! subphase was handed also names `src/rc5` and `src/pbkdf1`/`src/kdf`; **RC5 is absent from this
//! profile** (`OPENSSL_NO_RC5`, so the authority compiles the four RC5 rows out and they are not
//! among the 39), and the PBKDF1/PVKKDF provider units are slice 3 above.
//!
//! ## The module's build, and the one recorded divergence
//!
//! `providers/legacyprov.c` compiles to a self-contained `legacy.so` that carries its own copies
//! of the legacy primitives and reaches libcrypto only through the core dispatch its
//! `OSSL_provider_init` receives. This crate is monolithic (`Cargo.toml`: one implementation
//! crate, no component crates), so `forensics/tools/build_phase2.sh` builds `legacy.so` from the
//! crate's own archive instead of a second copy of the algorithms. The module's `OSSL_provider_init`
//! below is the same entry point the authority exports, and the loadable contract
//! (`NEEDED libcrypto.so.3`, exactly one exported symbol) is unchanged; the divergence is that the
//! candidate's module links the whole crate archive where the authority's links a minimal object
//! set. `docs/PHASE-16-SUBPHASES.md` §3 records it. The module keeps the core up-call walk the
//! authority does for its `ERR_*` wrappers (`legacyprov.c:217-254`) only to the extent it is
//! load-bearing here; the crate raises through its own error surface, which is the divergence
//! `docs/DECISIONS.md` names for every provider unit.
//!
//! SPDX-License-Identifier: Apache-2.0

// The module's `OSSL_provider_init` is `pub` because the authority exports it as a symbol, while
// the enclosing `provider::legacyprov` is a `pub(crate)` module, so `unreachable_pub` (a *warn* in
// this crate) would fire on a faithful transcription. The authority's own `OSSL_provider_init` has
// external linkage and so does this one; the attribute is a label, not a widening.
#![allow(unreachable_pub)]

use core::ffi::{c_char, c_int, c_uchar, c_void};
use core::ptr;

use crate::context::dispatch::{OsslDispatch, OSSL_DISPATCH_END};
use crate::digest::md4::{MD4_Final, MD4_Init, MD4_Update, Md4Ctx};
use crate::digest::mdc2::{
    MDC2_Final, MDC2_Init, MDC2_Update, Mdc2Ctx, MDC2_BLOCK, MDC2_DIGEST_LENGTH,
};
use crate::digest::ripemd::{RIPEMD160_Final, RIPEMD160_Init, RIPEMD160_Update, Ripemd160Ctx};
use crate::digest::wp::{WHIRLPOOL_Final, WHIRLPOOL_Init, WHIRLPOOL_Update, WhirlpoolCtx};
use crate::evp::algorithm::OSSL_OP_DIGEST;
use crate::evp::digest::{
    OSSL_FUNC_DIGEST_COPYCTX, OSSL_FUNC_DIGEST_DUPCTX, OSSL_FUNC_DIGEST_FINAL,
    OSSL_FUNC_DIGEST_FREECTX, OSSL_FUNC_DIGEST_GETTABLE_PARAMS, OSSL_FUNC_DIGEST_GET_PARAMS,
    OSSL_FUNC_DIGEST_INIT, OSSL_FUNC_DIGEST_NEWCTX, OSSL_FUNC_DIGEST_SETTABLE_CTX_PARAMS,
    OSSL_FUNC_DIGEST_SET_CTX_PARAMS, OSSL_FUNC_DIGEST_UPDATE,
};
use crate::params::{
    OSSL_PARAM_get_uint, OSSL_PARAM_locate, OSSL_PARAM_locate_const, OsslParam, END,
};
use crate::provider::activate::OsslAlgorithm;
use crate::provider::cipher::{param_integer_defn, param_uint, param_utf8_ptr};
use crate::provider::digest::{
    ossl_digest_default_get_params, ossl_digest_default_gettable_params,
};
use crate::provider::init::{
    FUNC_PROVIDER_GETTABLE_PARAMS, FUNC_PROVIDER_GET_PARAMS, FUNC_PROVIDER_QUERY_OPERATION,
    FUNC_PROVIDER_TEARDOWN,
};
use crate::provider::skeymgmt::GENERIC_SKEYMGMT_FUNCTIONS;
use crate::runtime::init::VERSION_STRING;
use crate::runtime::mem::{CRYPTO_clear_free, CRYPTO_malloc, CRYPTO_zalloc};

/// The authority's translation unit, for the allocation-tracking `file` argument.
const FILE: *const c_char = c"providers/legacyprov.c".as_ptr();
/// One allocation-tracking line for every call this module makes.
const LINE: c_int = 0;

/// `OSSL_PROV_PARAM_NAME` — `include/openssl/core_names.h`.
const OSSL_PROV_PARAM_NAME: *const c_char = c"name".as_ptr();
/// `OSSL_PROV_PARAM_VERSION` — `core_names.h`.
const OSSL_PROV_PARAM_VERSION: *const c_char = c"version".as_ptr();
/// `OSSL_PROV_PARAM_BUILDINFO` — `core_names.h`.
const OSSL_PROV_PARAM_BUILDINFO: *const c_char = c"buildinfo".as_ptr();
/// `OSSL_PROV_PARAM_STATUS` — `core_names.h`.
const OSSL_PROV_PARAM_STATUS: *const c_char = c"status".as_ptr();

/// `OSSL_DIGEST_PARAM_PAD_TYPE` — `include/openssl/core_names.h`.
const OSSL_DIGEST_PARAM_PAD_TYPE: *const c_char = c"pad-type".as_ptr();

/// `OSSL_OP_CIPHER` — `include/openssl/core_dispatch.h`. The legacy cipher arm is slice 2 and
/// answers `NULL` here; the constant is named so the arm is written the authority's way and the
/// census reads the operation the arm belongs to.
const OSSL_OP_CIPHER: c_int = 2;
/// `OSSL_OP_KDF` — `core_dispatch.h`. The legacy KDF arm is slice 3 and answers `NULL`.
const OSSL_OP_KDF: c_int = 4;
/// `OSSL_OP_SKEYMGMT` — `core_dispatch.h`.
const OSSL_OP_SKEYMGMT: c_int = 15;

/// `#define ALG(NAMES, FUNC) { NAMES, "provider=legacy", FUNC }` — `legacyprov.c:30`.
const LEGACY_PROPERTIES: *const c_char = c"provider=legacy".as_ptr();

/// `int ossl_prov_is_running(void)` — `providers/prov_running.c`. The legacy provider is always in
/// a happy state on this build, so the status the module reports is 1.
#[inline]
fn ossl_prov_is_running() -> c_int {
    1
}

/// `static const OSSL_PARAM legacy_param_types[]` — `legacyprov.c:55-61`.
static LEGACY_PARAM_TYPES: [OsslParam; 5] = [
    param_utf8_ptr(OSSL_PROV_PARAM_NAME),
    param_utf8_ptr(OSSL_PROV_PARAM_VERSION),
    param_utf8_ptr(OSSL_PROV_PARAM_BUILDINFO),
    param_integer_defn(OSSL_PROV_PARAM_STATUS),
    END,
];

/// `static const OSSL_PARAM *legacy_gettable_params(void *provctx)` — `legacyprov.c:63-66`.
unsafe extern "C" fn legacy_gettable_params(_provctx: *mut c_void) -> *const OsslParam {
    LEGACY_PARAM_TYPES.as_ptr()
}

/// `static int legacy_get_params(void *provctx, OSSL_PARAM params[])` — `legacyprov.c:68-85`.
///
/// # Safety
/// `params` must be NULL or a `key`-terminated array of live, writable [`OsslParam`].
unsafe extern "C" fn legacy_get_params(_provctx: *mut c_void, params: *mut OsslParam) -> c_int {
    // SAFETY: `params` is the caller's array; `OSSL_PARAM_locate` walks it to its terminator.
    let p = unsafe { OSSL_PARAM_locate(params, OSSL_PROV_PARAM_NAME) };
    if !p.is_null() {
        // SAFETY: `p` is a live, writable entry of the caller's array.
        if unsafe { crate::params::OSSL_PARAM_set_utf8_ptr(p, c"OpenSSL Legacy Provider".as_ptr()) }
            == 0
        {
            return 0;
        }
    }
    // SAFETY: as above, one arm per key `legacy_param_types` advertises.
    let p = unsafe { OSSL_PARAM_locate(params, OSSL_PROV_PARAM_VERSION) };
    if !p.is_null() {
        // SAFETY: `p` is a live, writable entry of the caller's array.
        if unsafe { crate::params::OSSL_PARAM_set_utf8_ptr(p, VERSION_STRING.as_ptr()) } == 0 {
            return 0;
        }
    }
    // SAFETY: as above.
    let p = unsafe { OSSL_PARAM_locate(params, OSSL_PROV_PARAM_BUILDINFO) };
    if !p.is_null() {
        // SAFETY: `p` is a live, writable entry of the caller's array.
        if unsafe { crate::params::OSSL_PARAM_set_utf8_ptr(p, VERSION_STRING.as_ptr()) } == 0 {
            return 0;
        }
    }
    // SAFETY: as above, for an entry the caller made for an `int`. `legacyprov.c:82`.
    let p = unsafe { OSSL_PARAM_locate(params, OSSL_PROV_PARAM_STATUS) };
    if !p.is_null() {
        // SAFETY: `p` is a live, writable entry of the caller's array.
        if unsafe { crate::params::OSSL_PARAM_set_int(p, ossl_prov_is_running()) } == 0 {
            return 0;
        }
    }
    1
}

// ---------------------------------------------------------------------------------------------
// The digest rows — `legacy_digests[]`, `legacyprov.c:87-104`
// ---------------------------------------------------------------------------------------------

/// `IMPLEMENT_digest_functions`' shape — `prov/digestcommon.h`, one invocation per construction.
///
/// A Rust macro here for the same reason `src/provider/digest.rs`'s is one: the authority's macro
/// is one body instantiated once per construction. Its output is ordinary `pub(crate)` functions
/// and a `'static` table — **no exported symbol** — so the project's ban on
/// `macro_rules!`-generated exports is not engaged.
macro_rules! legacy_digest_impl {
    ($module:ident, $ctx:ty, $init:path, $update:path, $final:path, $blksz:expr, $dgstsz:expr) => {
        mod $module {
            use super::*;

            unsafe extern "C" fn newctx(_provctx: *mut c_void) -> *mut c_void {
                if ossl_prov_is_running() == 0 {
                    return ptr::null_mut();
                }
                CRYPTO_zalloc(core::mem::size_of::<$ctx>(), FILE, LINE)
            }

            unsafe extern "C" fn freectx(vctx: *mut c_void) {
                // SAFETY: `vctx` is what `newctx` allocated or NULL, for which this is a no-op.
                unsafe {
                    CRYPTO_clear_free(vctx, core::mem::size_of::<$ctx>(), FILE, LINE);
                }
            }

            unsafe extern "C" fn dupctx(ctx: *mut c_void) -> *mut c_void {
                if ossl_prov_is_running() == 0 || ctx.is_null() {
                    return ptr::null_mut();
                }
                let ret = CRYPTO_malloc(core::mem::size_of::<$ctx>(), FILE, LINE);
                if !ret.is_null() {
                    // SAFETY: both regions are `size_of::<$ctx>()` bytes and distinct.
                    unsafe {
                        ptr::copy_nonoverlapping(
                            ctx.cast::<u8>(),
                            ret.cast::<u8>(),
                            core::mem::size_of::<$ctx>(),
                        );
                    }
                }
                ret
            }

            unsafe extern "C" fn copyctx(outctx: *mut c_void, inctx: *mut c_void) {
                // SAFETY: both regions are `size_of::<$ctx>()` bytes and distinct.
                unsafe {
                    ptr::copy_nonoverlapping(
                        inctx.cast::<u8>(),
                        outctx.cast::<u8>(),
                        core::mem::size_of::<$ctx>(),
                    );
                }
            }

            unsafe extern "C" fn internal_init(
                ctx: *mut c_void,
                _params: *const OsslParam,
            ) -> c_int {
                if ossl_prov_is_running() == 0 {
                    return 0;
                }
                // SAFETY: `ctx` is what `newctx` allocated for this construction.
                c_int::from(unsafe { $init(ctx.cast::<$ctx>()) } != 0)
            }

            unsafe extern "C" fn internal_final(
                ctx: *mut c_void,
                out: *mut u8,
                outl: *mut usize,
                outsz: usize,
            ) -> c_int {
                if ossl_prov_is_running() == 0 || outsz < $dgstsz {
                    return 0;
                }
                // SAFETY: `ctx` is this construction's and `out` is writable for `outsz`.
                if unsafe { $final(out, ctx.cast::<$ctx>()) } != 0 {
                    // SAFETY: `outl` is the caller's output slot.
                    unsafe { *outl = $dgstsz };
                    return 1;
                }
                0
            }

            unsafe extern "C" fn update(
                ctx: *mut c_void,
                in_: *const c_uchar,
                inl: usize,
            ) -> c_int {
                // SAFETY: `ctx` is this construction's and `in_` is readable for `inl` bytes.
                c_int::from(unsafe { $update(ctx.cast::<$ctx>(), in_.cast(), inl) } != 0)
            }

            unsafe extern "C" fn get_params(params: *mut OsslParam) -> c_int {
                // SAFETY: the caller's contract is `ossl_digest_default_get_params`'s.
                unsafe { ossl_digest_default_get_params(params, $blksz, $dgstsz, 0) }
            }

            pub(super) static FUNCTIONS: [OsslDispatch; 10] = [
                OsslDispatch {
                    function_id: OSSL_FUNC_DIGEST_NEWCTX,
                    function: newctx as *mut c_void,
                },
                OsslDispatch {
                    function_id: OSSL_FUNC_DIGEST_UPDATE,
                    function: update as *mut c_void,
                },
                OsslDispatch {
                    function_id: OSSL_FUNC_DIGEST_FINAL,
                    function: internal_final as *mut c_void,
                },
                OsslDispatch {
                    function_id: OSSL_FUNC_DIGEST_FREECTX,
                    function: freectx as *mut c_void,
                },
                OsslDispatch {
                    function_id: OSSL_FUNC_DIGEST_DUPCTX,
                    function: dupctx as *mut c_void,
                },
                OsslDispatch {
                    function_id: OSSL_FUNC_DIGEST_COPYCTX,
                    function: copyctx as *mut c_void,
                },
                OsslDispatch {
                    function_id: OSSL_FUNC_DIGEST_GET_PARAMS,
                    function: get_params as *mut c_void,
                },
                OsslDispatch {
                    function_id: OSSL_FUNC_DIGEST_GETTABLE_PARAMS,
                    function: ossl_digest_default_gettable_params as *mut c_void,
                },
                OsslDispatch {
                    function_id: OSSL_FUNC_DIGEST_INIT,
                    function: internal_init as *mut c_void,
                },
                OsslDispatch {
                    function_id: OSSL_DISPATCH_END,
                    function: ptr::null_mut(),
                },
            ];
        }
    };
}

legacy_digest_impl!(md4, Md4Ctx, MD4_Init, MD4_Update, MD4_Final, 64usize, 16usize);
legacy_digest_impl!(
    wp,
    WhirlpoolCtx,
    WHIRLPOOL_Init,
    WHIRLPOOL_Update,
    WHIRLPOOL_Final,
    64usize,
    64usize
);
legacy_digest_impl!(
    ripemd160,
    Ripemd160Ctx,
    RIPEMD160_Init,
    RIPEMD160_Update,
    RIPEMD160_Final,
    64usize,
    20usize
);

/// `known_mdc2_settable_ctx_params[]` — `mdc2_prov.c:28-31`.
static MDC2_SETTABLE_CTX_PARAMS: [OsslParam; 2] = [param_uint(OSSL_DIGEST_PARAM_PAD_TYPE), END];

/// `mdc2_settable_ctx_params` — `mdc2_prov.c:33-37`.
unsafe extern "C" fn mdc2_settable_ctx_params(
    _ctx: *mut c_void,
    _provctx: *mut c_void,
) -> *const OsslParam {
    MDC2_SETTABLE_CTX_PARAMS.as_ptr()
}

/// `mdc2_set_ctx_params` — `mdc2_prov.c:39-55`.
///
/// # Safety
/// `vctx` is NULL or a live context from this row's `newctx`; `params` is NULL or a
/// key-terminated array.
unsafe extern "C" fn mdc2_set_ctx_params(vctx: *mut c_void, params: *const OsslParam) -> c_int {
    if vctx.is_null() {
        return 0;
    }
    if params.is_null() {
        return 1;
    }
    // SAFETY: `params` is non-NULL and key-terminated per the caller's contract, so its first
    // entry is readable.
    if unsafe { (*params).key.is_null() } {
        return 1;
    }
    // SAFETY: `params` is a key-terminated array per the contract.
    let p = unsafe { OSSL_PARAM_locate_const(params, OSSL_DIGEST_PARAM_PAD_TYPE) };
    if !p.is_null() {
        // SAFETY: `vctx` is this row's `Mdc2Ctx`; `p` is a live descriptor for a `uint`.
        if unsafe { OSSL_PARAM_get_uint(p, ptr::addr_of_mut!((*vctx.cast::<Mdc2Ctx>()).pad_type)) }
            == 0
        {
            return 0;
        }
    }
    1
}

/// `mdc2_prov.c`'s `IMPLEMENT_digest_functions_with_settable_ctx` — the one legacy digest
/// construction whose dispatch also publishes the `SETTABLE_CTX_PARAMS`/`SET_CTX_PARAMS` slots,
/// because its `Mdc2Ctx::pad_type` is caller-set.
mod mdc2 {
    use super::*;

    unsafe extern "C" fn newctx(_provctx: *mut c_void) -> *mut c_void {
        if ossl_prov_is_running() == 0 {
            return ptr::null_mut();
        }
        CRYPTO_zalloc(core::mem::size_of::<Mdc2Ctx>(), FILE, LINE)
    }

    unsafe extern "C" fn freectx(vctx: *mut c_void) {
        // SAFETY: `vctx` is what `newctx` allocated or NULL.
        unsafe {
            CRYPTO_clear_free(vctx, core::mem::size_of::<Mdc2Ctx>(), FILE, LINE);
        }
    }

    unsafe extern "C" fn dupctx(ctx: *mut c_void) -> *mut c_void {
        if ossl_prov_is_running() == 0 || ctx.is_null() {
            return ptr::null_mut();
        }
        let ret = CRYPTO_malloc(core::mem::size_of::<Mdc2Ctx>(), FILE, LINE);
        if !ret.is_null() {
            // SAFETY: both regions are `size_of::<Mdc2Ctx>()` bytes and distinct.
            unsafe {
                ptr::copy_nonoverlapping(
                    ctx.cast::<u8>(),
                    ret.cast::<u8>(),
                    core::mem::size_of::<Mdc2Ctx>(),
                );
            }
        }
        ret
    }

    unsafe extern "C" fn copyctx(outctx: *mut c_void, inctx: *mut c_void) {
        // SAFETY: both regions are `size_of::<Mdc2Ctx>()` bytes and distinct.
        unsafe {
            ptr::copy_nonoverlapping(
                inctx.cast::<u8>(),
                outctx.cast::<u8>(),
                core::mem::size_of::<Mdc2Ctx>(),
            );
        }
    }

    unsafe extern "C" fn internal_init(ctx: *mut c_void, _params: *const OsslParam) -> c_int {
        if ossl_prov_is_running() == 0 {
            return 0;
        }
        // SAFETY: `ctx` is what `newctx` allocated for this construction.
        c_int::from(unsafe { MDC2_Init(ctx.cast::<Mdc2Ctx>()) } != 0)
    }

    unsafe extern "C" fn internal_final(
        ctx: *mut c_void,
        out: *mut u8,
        outl: *mut usize,
        outsz: usize,
    ) -> c_int {
        if ossl_prov_is_running() == 0 || outsz < MDC2_DIGEST_LENGTH {
            return 0;
        }
        // SAFETY: `ctx` is this construction's and `out` is writable for `outsz`.
        if unsafe { MDC2_Final(out, ctx.cast::<Mdc2Ctx>()) } != 0 {
            // SAFETY: `outl` is the caller's output slot.
            unsafe { *outl = MDC2_DIGEST_LENGTH };
            return 1;
        }
        0
    }

    unsafe extern "C" fn update(ctx: *mut c_void, in_: *const c_uchar, inl: usize) -> c_int {
        // SAFETY: `ctx` is this construction's and `in_` is readable for `inl` bytes.
        c_int::from(unsafe { MDC2_Update(ctx.cast::<Mdc2Ctx>(), in_, inl) } != 0)
    }

    unsafe extern "C" fn get_params(params: *mut OsslParam) -> c_int {
        // SAFETY: the caller's contract is `ossl_digest_default_get_params`'s.
        unsafe { ossl_digest_default_get_params(params, MDC2_BLOCK, MDC2_DIGEST_LENGTH, 0) }
    }

    pub(super) static FUNCTIONS: [OsslDispatch; 12] = [
        OsslDispatch {
            function_id: OSSL_FUNC_DIGEST_NEWCTX,
            function: newctx as *mut c_void,
        },
        OsslDispatch {
            function_id: OSSL_FUNC_DIGEST_UPDATE,
            function: update as *mut c_void,
        },
        OsslDispatch {
            function_id: OSSL_FUNC_DIGEST_FINAL,
            function: internal_final as *mut c_void,
        },
        OsslDispatch {
            function_id: OSSL_FUNC_DIGEST_FREECTX,
            function: freectx as *mut c_void,
        },
        OsslDispatch {
            function_id: OSSL_FUNC_DIGEST_DUPCTX,
            function: dupctx as *mut c_void,
        },
        OsslDispatch {
            function_id: OSSL_FUNC_DIGEST_COPYCTX,
            function: copyctx as *mut c_void,
        },
        OsslDispatch {
            function_id: OSSL_FUNC_DIGEST_GET_PARAMS,
            function: get_params as *mut c_void,
        },
        OsslDispatch {
            function_id: OSSL_FUNC_DIGEST_GETTABLE_PARAMS,
            function: ossl_digest_default_gettable_params as *mut c_void,
        },
        OsslDispatch {
            function_id: OSSL_FUNC_DIGEST_SETTABLE_CTX_PARAMS,
            function: mdc2_settable_ctx_params as *mut c_void,
        },
        OsslDispatch {
            function_id: OSSL_FUNC_DIGEST_SET_CTX_PARAMS,
            function: mdc2_set_ctx_params as *mut c_void,
        },
        OsslDispatch {
            function_id: OSSL_FUNC_DIGEST_INIT,
            function: internal_init as *mut c_void,
        },
        OsslDispatch {
            function_id: OSSL_DISPATCH_END,
            function: ptr::null_mut(),
        },
    ];
}

// ---------------------------------------------------------------------------------------------
// The digest rows — `legacy_digests[]`, `legacyprov.c:87-104`
// ---------------------------------------------------------------------------------------------

/// A row's alias string, verbatim from `providers/implementations/include/prov/names.h`.
macro_rules! alias {
    ($name:ident, $value:literal) => {
        const $name: *const c_char = concat!($value, "\0").as_ptr().cast();
    };
}
alias!(N_MD4, "MD4:1.2.840.113549.2.4");
alias!(N_MDC2, "MDC2:2.5.8.3.101");
alias!(N_WHIRLPOOL, "WHIRLPOOL:1.0.10118.3.0.55");
alias!(
    N_RIPEMD_160,
    "RIPEMD-160:RIPEMD160:RIPEMD:RMD160:1.3.36.3.2.1"
);
alias!(N_GENERIC_SECRET, "GENERIC-SECRET");

/// A `legacy_digests[]`/`legacy_skeymgmt[]` row — `ALG(NAMES, FUNC)`, `legacyprov.c:30`.
const fn row(names: *const c_char, implementation: *const c_void) -> OsslAlgorithm {
    OsslAlgorithm {
        algorithm_names: names,
        property_definition: LEGACY_PROPERTIES,
        implementation,
        algorithm_description: ptr::null(),
    }
}

/// `static const OSSL_ALGORITHM legacy_digests[]` — `legacyprov.c:87-104`, in the authority's
/// order, with the `OPENSSL_NO_MD2` row absent because this profile compiles it out.
static LEGACY_DIGESTS: [OsslAlgorithm; 5] = [
    row(N_MD4, md4::FUNCTIONS.as_ptr().cast()),
    row(N_MDC2, mdc2::FUNCTIONS.as_ptr().cast()),
    row(N_WHIRLPOOL, wp::FUNCTIONS.as_ptr().cast()),
    row(N_RIPEMD_160, ripemd160::FUNCTIONS.as_ptr().cast()),
    OsslAlgorithm {
        algorithm_names: ptr::null(),
        property_definition: ptr::null(),
        implementation: ptr::null(),
        algorithm_description: ptr::null(),
    },
];

/// `static const OSSL_ALGORITHM legacy_skeymgmt[]` — `legacyprov.c:170-173`. The row's engine is
/// the same `providers/implementations/skeymgmt/generic.c` unit the default provider publishes
/// (`src/provider/skeymgmt.rs`), so there is exactly one transcription of it.
static LEGACY_SKEYMGMT: [OsslAlgorithm; 2] = [
    row(N_GENERIC_SECRET, GENERIC_SKEYMGMT_FUNCTIONS.as_ptr().cast()),
    OsslAlgorithm {
        algorithm_names: ptr::null(),
        property_definition: ptr::null(),
        implementation: ptr::null(),
        algorithm_description: ptr::null(),
    },
];

/// `static const OSSL_ALGORITHM *legacy_query(void *provctx, int operation_id, int *no_cache)` —
/// `legacyprov.c:175-190`.
///
/// The `OSSL_OP_DIGEST` and `OSSL_OP_SKEYMGMT` arms return the two tables slice 1 publishes. The
/// `OSSL_OP_CIPHER` and `OSSL_OP_KDF` arms are the authority's other two **and return `NULL`
/// because their rows are not landed yet** (module header, slices 2 and 3); the census reads a
/// `NULL` arm as "publishes nothing", so those rows stay `unimplemented` rather than being
/// silently counted.
///
/// # Safety
/// `no_cache` must be writable; `provctx` is ignored.
unsafe extern "C" fn legacy_query(
    _provctx: *mut c_void,
    operation_id: c_int,
    no_cache: *mut c_int,
) -> *const OsslAlgorithm {
    // SAFETY: `no_cache` is writable per the contract.
    unsafe { *no_cache = 0 };
    if operation_id == OSSL_OP_DIGEST {
        return LEGACY_DIGESTS.as_ptr();
    }
    if operation_id == OSSL_OP_CIPHER {
        return ptr::null();
    }
    if operation_id == OSSL_OP_KDF {
        return ptr::null();
    }
    if operation_id == OSSL_OP_SKEYMGMT {
        return LEGACY_SKEYMGMT.as_ptr();
    }
    ptr::null()
}

/// `static void legacy_teardown(void *provctx)` — `legacyprov.c:192-196`, without its
/// `OSSL_LIB_CTX_free(PROV_LIBCTX_OF(provctx))` because the crate's teardown follows the default
/// and base providers' shape and frees the context alone (`src/provider/ctx.rs`).
///
/// # Safety
/// The dispatch contract: `provctx` is what `OSSL_provider_init` published, or NULL.
unsafe extern "C" fn legacy_teardown(provctx: *mut c_void) {
    // SAFETY: the caller's contract; `ossl_prov_ctx_free` accepts NULL.
    unsafe { crate::provider::ctx::ossl_prov_ctx_free(provctx.cast()) };
}

/// `static const OSSL_DISPATCH legacy_dispatch_table[]` — `legacyprov.c:199-205`, in the
/// authority's order (`TEARDOWN`, `GETTABLE_PARAMS`, `GET_PARAMS`, `QUERY_OPERATION`).
static LEGACY_DISPATCH_TABLE: [OsslDispatch; 5] = [
    OsslDispatch {
        function_id: FUNC_PROVIDER_TEARDOWN,
        function: legacy_teardown as *mut c_void,
    },
    OsslDispatch {
        function_id: FUNC_PROVIDER_GETTABLE_PARAMS,
        function: legacy_gettable_params as *mut c_void,
    },
    OsslDispatch {
        function_id: FUNC_PROVIDER_GET_PARAMS,
        function: legacy_get_params as *mut c_void,
    },
    OsslDispatch {
        function_id: FUNC_PROVIDER_QUERY_OPERATION,
        function: legacy_query as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_DISPATCH_END,
        function: ptr::null_mut(),
    },
];

/// `int ossl_legacy_provider_init(const OSSL_CORE_HANDLE *handle, const OSSL_DISPATCH *in,
/// const OSSL_DISPATCH **out, void **provctx)` — `legacyprov.c:207-269`.
///
/// The authority spells this `OSSL_provider_init` in a non-`STATIC_LEGACY` build and spells the
/// same body `ossl_legacy_provider_init` under `STATIC_LEGACY` (`legacyprov.c:32-35`). This crate
/// keeps the `STATIC_LEGACY` spelling at the crate entry point and the generated module shell
/// (`shell/legacy.shell.rs`) exports `OSSL_provider_init` and forwards to it, so the loadable
/// module exports exactly the one symbol the authority's does while libcrypto's own (hidden) copy
/// is not the module's entry.
///
/// The authority walks `in` for seven `ERR_*` up-calls and stores them in file-static pointers;
/// this crate raises through its own error surface, so the walk is not load-bearing and is not
/// reproduced (module header). The context is built with `ossl_prov_ctx_new` and a child library
/// context from `OSSL_LIB_CTX_new_child`, exactly as `legacyprov.c:256-263` does.
///
/// # Safety
/// `out` and `provctx` must be writable; `handle` names the live provider and `in_` is the core
/// dispatch table the registry handed over.
#[no_mangle]
pub unsafe extern "C" fn ossl_legacy_provider_init(
    handle: *const c_void,
    in_: *const OsslDispatch,
    out: *mut *const OsslDispatch,
    provctx: *mut *mut c_void,
) -> c_int {
    // SAFETY: `in_` is the core's own terminated table; `handle` is the provider it expects.
    unsafe {
        if out.is_null() || provctx.is_null() {
            return 0;
        }

        let ctx = crate::provider::ctx::ossl_prov_ctx_new();
        if ctx.is_null() {
            return 0;
        }
        let libctx = crate::context::OSSL_LIB_CTX_new_child(handle, in_);
        if libctx.is_null() {
            crate::provider::ctx::ossl_prov_ctx_free(ctx.cast());
            return 0;
        }
        crate::provider::ctx::ossl_prov_ctx_set0_libctx(ctx, libctx);
        crate::provider::ctx::ossl_prov_ctx_set0_handle(ctx, handle);

        *out = LEGACY_DISPATCH_TABLE.as_ptr();
        *provctx = ctx.cast();
    }
    1
}
