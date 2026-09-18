//! Phase 8.1b — the digest half of the default provider.
//!
//! `EVP_MD_fetch(NULL, "SHA256", NULL)` resolves through the default library context, the
//! default provider's `OSSL_OP_DIGEST` query, and `evp_md_from_algorithm`'s dispatch walk.
//! Until this module lands, `ossl_default_provider_init` did not exist, so the fallback walk
//! created a `default` provider with no init function, took `provider_init` down the module
//! branch, and failed at `DSO_load`. That is the residual `docs/DECISIONS.md` D117 records.
//!
//! ## What this lands, and what it deliberately does not
//!
//! This is the **digest half** of `providers/defltprov.c`:
//!
//! * `providers/implementations/digests/digestcommon.c`'s
//!   `ossl_digest_default_get_params`/`ossl_digest_default_gettable_params`;
//! * the `IMPLEMENT_digest_functions` dispatch shape from `prov/digestcommon.h`, one table per
//!   construction, in the order the macro publishes;
//! * `deflt_digests[]`'s rows for the constructions 8.1a transcribed — SHA-1, the four SHA-2
//!   `sha.h` widths, MD5, RIPEMD-160, MD4 and Whirlpool — and
//! * `ossl_default_provider_init` itself, with the `deflt_query` arm for `OSSL_OP_DIGEST`.
//!
//! Everything else the authority's default provider publishes is **other halves of other
//! subphases** and is absent here rather than stubbed: the cipher, MAC, KDF, RAND, keymgmt,
//! signature, asym-cipher, KEM, encoder, decoder, store and skeymgmt tables (8.2 and later),
//! `deflt_get_params`/`deflt_gettable_params` and `ossl_prov_get_capabilities` (the provider
//! params half), and the `provctx` that `ossl_prov_ctx_new`/`ossl_bio_prov_init_bio_method`
//! build — the digest query needs none of them, so `provctx` is NULL and `deflt_query` ignores
//! it exactly as the authority's answer for `OSSL_OP_DIGEST` does.
//!
//! Three rows of the authority's `deflt_digests[]` are also absent, and their absence is a
//! statement rather than an omission: SHA3/KECCAK/SHAKE (`sha3_prov.c`'s 693-line template),
//! BLAKE2 (`blake2*_prov.c`, handed to Phase 13 by 7.3g), SM3 (`sm3_prov.c`) and the two
//! combined/NULL digests (`md5_sha1_prov.c`, `null_prov.c`). None of their constructions exists
//! in this crate, so a row naming one could only publish a table with no body. The plan's §3.5
//! requires exactly this to be said out loud; `docs/DECISIONS.md` D204 records it.
//!
//! ## Why the source is a macro here when the constructions were not
//!
//! `IMPLEMENT_digest_functions` in `prov/digestcommon.h` is itself a macro: one body, fourteen
//! instantiations, differing only in the context type and the four low-level entry points. A
//! Rust macro is that macro's transcription, and its output is ordinary `pub(crate)` function
//! items and `'static` dispatch tables — **no exported symbol**, so the project's ban on
//! `macro_rules!`-generated exports is not engaged.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_char, c_int, c_uchar, c_ulong, c_void};
use core::ptr;

use crate::context::dispatch::{OsslDispatch, OSSL_DISPATCH_END};
use crate::digest::md4::{MD4_Final, MD4_Init, MD4_Update, Md4Ctx};
use crate::digest::md5::{MD5_Final, MD5_Init, MD5_Update, Md5Ctx};
use crate::digest::ripemd::{RIPEMD160_Final, RIPEMD160_Init, RIPEMD160_Update, Ripemd160Ctx};
use crate::digest::sha1::{ossl_sha1_ctrl, SHA1_Final, SHA1_Init, SHA1_Update, ShaCtx};
use crate::digest::sha2::{
    SHA224_Final, SHA224_Init, SHA224_Update, SHA256_Final, SHA256_Init, SHA256_Update,
    SHA384_Final, SHA384_Init, SHA384_Update, SHA512_Final, SHA512_Init, SHA512_Update, Sha256Ctx,
    Sha512Ctx,
};
use crate::digest::wp::{WHIRLPOOL_Final, WHIRLPOOL_Init, WHIRLPOOL_Update, WhirlpoolCtx};
use crate::evp::algorithm::OSSL_OP_DIGEST;
use crate::evp::digest::{
    OSSL_FUNC_DIGEST_COPYCTX, OSSL_FUNC_DIGEST_DUPCTX, OSSL_FUNC_DIGEST_FINAL,
    OSSL_FUNC_DIGEST_FREECTX, OSSL_FUNC_DIGEST_GETTABLE_PARAMS, OSSL_FUNC_DIGEST_GET_PARAMS,
    OSSL_FUNC_DIGEST_INIT, OSSL_FUNC_DIGEST_NEWCTX, OSSL_FUNC_DIGEST_SETTABLE_CTX_PARAMS,
    OSSL_FUNC_DIGEST_SET_CTX_PARAMS, OSSL_FUNC_DIGEST_UPDATE,
};
use crate::params::{
    OsslParam, END, OSSL_PARAM_INTEGER, OSSL_PARAM_OCTET_STRING, OSSL_PARAM_UNMODIFIED,
    OSSL_PARAM_UNSIGNED_INTEGER,
};
use crate::provider::activate::OsslAlgorithm;
use crate::provider::init::FUNC_PROVIDER_QUERY_OPERATION;
use crate::runtime::mem::{CRYPTO_clear_free, CRYPTO_malloc, CRYPTO_zalloc};

/// The authority's translation unit, for the allocation-tracking `file` argument.
const FILE: *const c_char =
    c"../../src/openssl-3.6.4/providers/implementations/digests/digestcommon.c".as_ptr();
/// One allocation-tracking line for every call this module makes: the machinery records it but
/// nothing reads it, and every allocation here is one of the authority's four macro bodies.
const LINE: c_int = 0;

/// `PROV_DIGEST_FLAG_XOF` — `prov/digestcommon.h`.
const PROV_DIGEST_FLAG_XOF: c_ulong = 0x0001;
/// `PROV_DIGEST_FLAG_ALGID_ABSENT` — `prov/digestcommon.h`. Every `sha.h` construction carries
/// it (`sha2_prov.c`'s `SHA2_FLAGS`), so the provider reports no OID for them.
const PROV_DIGEST_FLAG_ALGID_ABSENT: c_ulong = 0x0002;

/// `OSSL_DIGEST_PARAM_BLOCK_SIZE` — `include/openssl/core_names.h`.
const OSSL_DIGEST_PARAM_BLOCK_SIZE: *const c_char = c"blocksize".as_ptr();
/// `OSSL_DIGEST_PARAM_SIZE` — `include/openssl/core_names.h`.
const OSSL_DIGEST_PARAM_SIZE: *const c_char = c"size".as_ptr();
/// `OSSL_DIGEST_PARAM_XOF` — `include/openssl/core_names.h`.
const OSSL_DIGEST_PARAM_XOF: *const c_char = c"xof".as_ptr();
/// `OSSL_DIGEST_PARAM_ALGID_ABSENT` — `include/openssl/core_names.h`.
const OSSL_DIGEST_PARAM_ALGID_ABSENT: *const c_char = c"algid-absent".as_ptr();
/// `OSSL_DIGEST_PARAM_SSL3_MS` — `include/openssl/core_names.h`.
const OSSL_DIGEST_PARAM_SSL3_MS: *const c_char = c"ssl3-ms".as_ptr();
/// `EVP_CTRL_SSL3_MASTER_SECRET` — `include/openssl/evp.h`.
const EVP_CTRL_SSL3_MASTER_SECRET: c_int = 0x1d;

/// `int ossl_prov_is_running(void)` — `providers/prov_running.c`.
///
/// The authority's default providers "are always in a happy state": the build's
/// `ossl_set_error_state` is a no-op and this answers 1 unconditionally. The type is `c_int`
/// because every caller writes `ossl_prov_is_running() && ...`.
fn ossl_prov_is_running() -> c_int {
    1
}

/// `static ossl_inline int ossl_param_is_empty(const OSSL_PARAM params[])` —
/// `include/internal/common.h`. An empty array is one whose first key is NULL; a NULL array is
/// empty too.
///
/// # Safety
/// `params` must be NULL or a key-terminated `OSSL_PARAM` array.
unsafe fn ossl_param_is_empty(params: *const OsslParam) -> bool {
    params.is_null() || unsafe { (*params).key.is_null() }
}

/// `digest_default_get_params_list` — the four keys `digestcommon.c`'s generated decoder
/// locates, with the types `produce_param_decoder` assigns them.
static DIGEST_DEFAULT_GETTABLE_PARAMS: [OsslParam; 5] = [
    OsslParam {
        key: OSSL_DIGEST_PARAM_BLOCK_SIZE,
        data_type: OSSL_PARAM_UNSIGNED_INTEGER,
        data: ptr::null_mut(),
        data_size: 0,
        return_size: OSSL_PARAM_UNMODIFIED,
    },
    OsslParam {
        key: OSSL_DIGEST_PARAM_SIZE,
        data_type: OSSL_PARAM_UNSIGNED_INTEGER,
        data: ptr::null_mut(),
        data_size: 0,
        return_size: OSSL_PARAM_UNMODIFIED,
    },
    OsslParam {
        key: OSSL_DIGEST_PARAM_XOF,
        data_type: OSSL_PARAM_INTEGER,
        data: ptr::null_mut(),
        data_size: 0,
        return_size: OSSL_PARAM_UNMODIFIED,
    },
    OsslParam {
        key: OSSL_DIGEST_PARAM_ALGID_ABSENT,
        data_type: OSSL_PARAM_INTEGER,
        data: ptr::null_mut(),
        data_size: 0,
        return_size: OSSL_PARAM_UNMODIFIED,
    },
    END,
];

/// `int ossl_digest_default_get_params(OSSL_PARAM params[], size_t blksz, size_t paramsz,
/// unsigned long flags)` — `providers/implementations/digests/digestcommon.c`.
///
/// # Safety
/// `params` must be NULL or a key-terminated `OSSL_PARAM` array, and every entry it holds must
/// be a descriptor whose `data` is writable for its `data_size`.
pub(crate) unsafe extern "C" fn ossl_digest_default_get_params(
    params: *mut OsslParam,
    blksz: usize,
    paramsz: usize,
    flags: c_ulong,
) -> c_int {
    let mut key = OSSL_DIGEST_PARAM_BLOCK_SIZE;
    for i in 0..4 {
        let value: Option<(usize, bool)> = match i {
            0 => Some((blksz, false)),
            1 => Some((paramsz, false)),
            2 => Some((usize::from(flags & PROV_DIGEST_FLAG_XOF != 0), true)),
            _ => Some((
                usize::from(flags & PROV_DIGEST_FLAG_ALGID_ABSENT != 0),
                true,
            )),
        };
        let Some((v, is_int)) = value else { continue };
        // SAFETY: `params` is a key-terminated array per the contract and `key` is a literal
        // with a terminator.
        let p = unsafe { crate::params::OSSL_PARAM_locate_const(params, key) };
        if !p.is_null() {
            // SAFETY: the array entry was found through `params`, which the caller guaranteed
            // writable, and the setter's contract is the entry's own `data_size`.
            let ok = unsafe {
                if is_int {
                    crate::params::OSSL_PARAM_set_int(p.cast_mut(), v as c_int)
                } else {
                    crate::params::OSSL_PARAM_set_size_t(p.cast_mut(), v)
                }
            };
            if ok == 0 {
                // The authority raises `PROV_R_FAILED_TO_SET_PARAMETER`. That error string is
                // the default provider's, which this half does not carry; the refusal is the
                // observable, and it is returned.
                return 0;
            }
        }
        key = match i {
            0 => OSSL_DIGEST_PARAM_SIZE,
            1 => OSSL_DIGEST_PARAM_XOF,
            _ => OSSL_DIGEST_PARAM_ALGID_ABSENT,
        };
    }
    1
}

/// `const OSSL_PARAM *ossl_digest_default_gettable_params(void *provctx)`.
pub(crate) unsafe extern "C" fn ossl_digest_default_gettable_params(
    _provctx: *mut c_void,
) -> *const OsslParam {
    DIGEST_DEFAULT_GETTABLE_PARAMS.as_ptr()
}

/// `IMPLEMENT_digest_functions`' dispatch-table body — `prov/digestcommon.h`.
///
/// One invocation per construction, exactly as `md4_prov.c`, `md5_prov.c`, `ripemd_prov.c`,
/// `wp_prov.c` and `sha2_prov.c` invoke it. `blksz` and `dgstsz` are the header constants the
/// authority passes, and `flags` is `SHA2_FLAGS` for the `sha.h` rows and 0 for the rest.
macro_rules! digest_impl {
    ($module:ident, $ctx:ty, $init:ident, $update:ident, $final:ident, $blksz:expr, $dgstsz:expr,
     $flags:expr) => {
        mod $module {
            use super::*;

            unsafe extern "C" fn newctx(_provctx: *mut c_void) -> *mut c_void {
                if ossl_prov_is_running() == 0 {
                    return ptr::null_mut();
                }
                CRYPTO_zalloc(core::mem::size_of::<$ctx>(), FILE, LINE)
            }

            unsafe extern "C" fn freectx(vctx: *mut c_void) {
                // `OPENSSL_clear_free(ctx, sizeof(*ctx))` — the context holds a chaining state.
                // SAFETY: `vctx` is what `newctx` allocated or NULL, for which the releaser is
                // a no-op in this crate.
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
                    // `*ret = *in` is a copy of `sizeof(*ctx)` bytes; both sides are that size.
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
                // SAFETY: both regions are `size_of::<$ctx>()` bytes and distinct per the
                // caller's contract.
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
                // SAFETY: `ctx` is this construction's, `out` is writable for `outsz >= dgstsz`,
                // and `outl` is the caller's output slot.
                if unsafe { $final(out, ctx.cast::<$ctx>()) } != 0 {
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
                // SAFETY: `ctx` is this construction's; `in_` is readable for `inl` bytes per
                // the caller, and the authority's `_Update` takes it as `const void *`.
                c_int::from(unsafe { $update(ctx.cast::<$ctx>(), in_.cast::<c_void>(), inl) } != 0)
            }

            unsafe extern "C" fn get_params(params: *mut OsslParam) -> c_int {
                // SAFETY: the caller's contract is `ossl_digest_default_get_params`'s.
                unsafe { ossl_digest_default_get_params(params, $blksz, $dgstsz, $flags) }
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

/// `IMPLEMENT_digest_functions_with_settable_ctx` — SHA-1's row, which is the one construction
/// whose provider `init` also consults `set_ctx_params` (`sha2_prov.c`'s `sha1_set_ctx_params`).
mod sha1 {
    use super::*;

    /// `known_sha1_settable_ctx_params` — `sha2_prov.c`.
    static SETTABLE: [OsslParam; 2] = [
        OsslParam {
            key: OSSL_DIGEST_PARAM_SSL3_MS,
            data_type: OSSL_PARAM_OCTET_STRING,
            data: ptr::null_mut(),
            data_size: 0,
            return_size: OSSL_PARAM_UNMODIFIED,
        },
        END,
    ];

    unsafe extern "C" fn settable_ctx_params(
        _ctx: *mut c_void,
        _provctx: *mut c_void,
    ) -> *const OsslParam {
        SETTABLE.as_ptr()
    }

    /// `static int sha1_set_ctx_params(void *vctx, const OSSL_PARAM params[])`.
    unsafe extern "C" fn set_ctx_params(vctx: *mut c_void, params: *const OsslParam) -> c_int {
        if vctx.is_null() {
            return 0;
        }
        // SAFETY: `params` is the caller's array, NULL or key-terminated.
        if unsafe { ossl_param_is_empty(params) } {
            return 1;
        }
        // SAFETY: `params` is key-terminated per the contract and the key is a literal.
        let p =
            unsafe { crate::params::OSSL_PARAM_locate_const(params, OSSL_DIGEST_PARAM_SSL3_MS) };
        if !p.is_null() {
            // SAFETY: `p` is a live entry of the caller's array.
            let is_octet = unsafe { (*p).data_type } == OSSL_PARAM_OCTET_STRING;
            if is_octet {
                // SAFETY: the entry is an octet string, so `data`/`data_size` describe bytes.
                let (data, size) = unsafe { ((*p).data, (*p).data_size) };
                // SAFETY: `vctx` is the SHA-1 context the provider allocated; `data` is readable
                // for `size` bytes per the parameter's own contract.
                return unsafe {
                    ossl_sha1_ctrl(
                        vctx.cast::<ShaCtx>(),
                        EVP_CTRL_SSL3_MASTER_SECRET,
                        size as c_int,
                        data,
                    )
                };
            }
        }
        1
    }

    unsafe extern "C" fn newctx(_provctx: *mut c_void) -> *mut c_void {
        if ossl_prov_is_running() == 0 {
            return ptr::null_mut();
        }
        CRYPTO_zalloc(core::mem::size_of::<ShaCtx>(), FILE, LINE)
    }

    unsafe extern "C" fn freectx(vctx: *mut c_void) {
        // SAFETY: `vctx` is what `newctx` allocated or NULL.
        unsafe {
            CRYPTO_clear_free(vctx, core::mem::size_of::<ShaCtx>(), FILE, LINE);
        }
    }

    unsafe extern "C" fn dupctx(ctx: *mut c_void) -> *mut c_void {
        if ossl_prov_is_running() == 0 || ctx.is_null() {
            return ptr::null_mut();
        }
        let ret = CRYPTO_malloc(core::mem::size_of::<ShaCtx>(), FILE, LINE);
        if !ret.is_null() {
            // SAFETY: both regions are `size_of::<ShaCtx>()` bytes and distinct.
            unsafe {
                ptr::copy_nonoverlapping(
                    ctx.cast::<u8>(),
                    ret.cast::<u8>(),
                    core::mem::size_of::<ShaCtx>(),
                );
            }
        }
        ret
    }

    unsafe extern "C" fn copyctx(outctx: *mut c_void, inctx: *mut c_void) {
        // SAFETY: both regions are `size_of::<ShaCtx>()` bytes and distinct.
        unsafe {
            ptr::copy_nonoverlapping(
                inctx.cast::<u8>(),
                outctx.cast::<u8>(),
                core::mem::size_of::<ShaCtx>(),
            );
        }
    }

    unsafe extern "C" fn internal_init(ctx: *mut c_void, params: *const OsslParam) -> c_int {
        if ossl_prov_is_running() == 0 {
            return 0;
        }
        // SAFETY: `ctx` is the SHA-1 context the provider allocated.
        if unsafe { SHA1_Init(ctx.cast::<ShaCtx>()) } == 0 {
            return 0;
        }
        // SAFETY: `params` is the caller's array, NULL or key-terminated.
        unsafe { set_ctx_params(ctx, params) }
    }

    unsafe extern "C" fn internal_final(
        ctx: *mut c_void,
        out: *mut u8,
        outl: *mut usize,
        outsz: usize,
    ) -> c_int {
        if ossl_prov_is_running() == 0 || outsz < SHA_DIGEST_LENGTH {
            return 0;
        }
        // SAFETY: `ctx` is a SHA-1 context; `out` is writable for `outsz >= 20`.
        if unsafe { SHA1_Final(out, ctx.cast::<ShaCtx>()) } != 0 {
            // SAFETY: `outl` is the caller's output slot.
            unsafe { *outl = SHA_DIGEST_LENGTH };
            return 1;
        }
        0
    }

    unsafe extern "C" fn update(ctx: *mut c_void, in_: *const c_uchar, inl: usize) -> c_int {
        // SAFETY: `ctx` is a SHA-1 context; `in_` is readable for `inl` bytes.
        c_int::from(unsafe { SHA1_Update(ctx.cast::<ShaCtx>(), in_.cast::<c_void>(), inl) } != 0)
    }

    unsafe extern "C" fn get_params(params: *mut OsslParam) -> c_int {
        // SAFETY: the caller's contract is `ossl_digest_default_get_params`'s.
        unsafe { ossl_digest_default_get_params(params, SHA_CBLOCK, SHA_DIGEST_LENGTH, SHA2_FLAGS) }
    }

    unsafe extern "C" fn gettable_params(_provctx: *mut c_void) -> *const OsslParam {
        DIGEST_DEFAULT_GETTABLE_PARAMS.as_ptr()
    }

    unsafe extern "C" fn gettable_params(_provctx: *mut c_void) -> *const OsslParam {
        DIGEST_DEFAULT_GETTABLE_PARAMS.as_ptr()
    }

    /// `SHA_DIGEST_LENGTH` — `include/openssl/sha.h`.
    const SHA_DIGEST_LENGTH: usize = 20;
    /// `SHA_CBLOCK` — `include/openssl/sha.h`.
    const SHA_CBLOCK: usize = 64;
    /// `SHA2_FLAGS` — `sha2_prov.c`'s `PROV_DIGEST_FLAG_ALGID_ABSENT`.
    const SHA2_FLAGS: c_ulong = PROV_DIGEST_FLAG_ALGID_ABSENT;

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
            function: gettable_params as *mut c_void,
        },
        OsslDispatch {
            function_id: OSSL_FUNC_DIGEST_INIT,
            function: internal_init as *mut c_void,
        },
        OsslDispatch {
            function_id: OSSL_FUNC_DIGEST_SETTABLE_CTX_PARAMS,
            function: settable_ctx_params as *mut c_void,
        },
        OsslDispatch {
            function_id: OSSL_FUNC_DIGEST_SET_CTX_PARAMS,
            function: set_ctx_params as *mut c_void,
        },
        OsslDispatch {
            function_id: OSSL_DISPATCH_END,
            function: ptr::null_mut(),
        },
    ];
}

digest_impl!(
    md4,
    Md4Ctx,
    MD4_Init,
    MD4_Update,
    MD4_Final,
    64usize,
    16usize,
    0u64 as c_ulong
);
digest_impl!(
    md5,
    Md5Ctx,
    MD5_Init,
    MD5_Update,
    MD5_Final,
    64usize,
    16usize,
    0u64 as c_ulong
);
digest_impl!(
    ripemd160,
    Ripemd160Ctx,
    RIPEMD160_Init,
    RIPEMD160_Update,
    RIPEMD160_Final,
    64usize,
    20usize,
    0u64 as c_ulong
);
digest_impl!(
    sha224,
    Sha256Ctx,
    SHA224_Init,
    SHA224_Update,
    SHA224_Final,
    64usize,
    28usize,
    PROV_DIGEST_FLAG_ALGID_ABSENT
);
digest_impl!(
    sha256,
    Sha256Ctx,
    SHA256_Init,
    SHA256_Update,
    SHA256_Final,
    64usize,
    32usize,
    PROV_DIGEST_FLAG_ALGID_ABSENT
);
digest_impl!(
    sha384,
    Sha512Ctx,
    SHA384_Init,
    SHA384_Update,
    SHA384_Final,
    128usize,
    48usize,
    PROV_DIGEST_FLAG_ALGID_ABSENT
);
digest_impl!(
    sha512,
    Sha512Ctx,
    SHA512_Init,
    SHA512_Update,
    SHA512_Final,
    128usize,
    64usize,
    PROV_DIGEST_FLAG_ALGID_ABSENT
);
digest_impl!(
    whirlpool,
    WhirlpoolCtx,
    WHIRLPOOL_Init,
    WHIRLPOOL_Update,
    WHIRLPOOL_Final,
    64usize,
    64usize,
    0u64 as c_ulong
);

/// The property string every row of `deflt_digests[]` carries.
const DEFAULT_PROPERTIES: *const c_char = c"provider=default".as_ptr();

/// `static const OSSL_ALGORITHM deflt_digests[]` — `providers/defltprov.c`, restricted to the
/// constructions 8.1a transcribed. The alias lists are `prov/names.h`'s, verbatim.
static DEFLT_DIGESTS: [OsslAlgorithm; 10] = [
    OsslAlgorithm {
        algorithm_names: c"SHA1:SHA-1:SSL3-SHA1:1.3.14.3.2.26".as_ptr(),
        property_definition: DEFAULT_PROPERTIES,
        implementation: sha1::FUNCTIONS.as_ptr() as *const c_void,
        algorithm_description: ptr::null(),
    },
    OsslAlgorithm {
        algorithm_names: c"SHA2-224:SHA-224:SHA224:2.16.840.1.101.3.4.2.4".as_ptr(),
        property_definition: DEFAULT_PROPERTIES,
        implementation: sha224::FUNCTIONS.as_ptr() as *const c_void,
        algorithm_description: ptr::null(),
    },
    OsslAlgorithm {
        algorithm_names: c"SHA2-256:SHA-256:SHA256:2.16.840.1.101.3.4.2.1".as_ptr(),
        property_definition: DEFAULT_PROPERTIES,
        implementation: sha256::FUNCTIONS.as_ptr() as *const c_void,
        algorithm_description: ptr::null(),
    },
    OsslAlgorithm {
        algorithm_names: c"SHA2-384:SHA-384:SHA384:2.16.840.1.101.3.4.2.2".as_ptr(),
        property_definition: DEFAULT_PROPERTIES,
        implementation: sha384::FUNCTIONS.as_ptr() as *const c_void,
        algorithm_description: ptr::null(),
    },
    OsslAlgorithm {
        algorithm_names: c"SHA2-512:SHA-512:SHA512:2.16.840.1.101.3.4.2.3".as_ptr(),
        property_definition: DEFAULT_PROPERTIES,
        implementation: sha512::FUNCTIONS.as_ptr() as *const c_void,
        algorithm_description: ptr::null(),
    },
    OsslAlgorithm {
        algorithm_names: c"MD5:SSL3-MD5:1.2.840.113549.2.5".as_ptr(),
        property_definition: DEFAULT_PROPERTIES,
        implementation: md5::FUNCTIONS.as_ptr() as *const c_void,
        algorithm_description: ptr::null(),
    },
    OsslAlgorithm {
        algorithm_names: c"RIPEMD-160:RIPEMD160:RIPEMD:1.3.36.3.2.1".as_ptr(),
        property_definition: DEFAULT_PROPERTIES,
        implementation: ripemd160::FUNCTIONS.as_ptr() as *const c_void,
        algorithm_description: ptr::null(),
    },
    OsslAlgorithm {
        algorithm_names: c"MD4:1.2.840.113549.2.4".as_ptr(),
        property_definition: DEFAULT_PROPERTIES,
        implementation: md4::FUNCTIONS.as_ptr() as *const c_void,
        algorithm_description: ptr::null(),
    },
    OsslAlgorithm {
        algorithm_names: c"WHIRLPOOL:1.0.10118.3.0.55".as_ptr(),
        property_definition: DEFAULT_PROPERTIES,
        implementation: whirlpool::FUNCTIONS.as_ptr() as *const c_void,
        algorithm_description: ptr::null(),
    },
    OsslAlgorithm {
        algorithm_names: ptr::null(),
        property_definition: ptr::null(),
        implementation: ptr::null(),
        algorithm_description: ptr::null(),
    },
];

/// `static const OSSL_ALGORITHM *deflt_query(void *provctx, int operation_id, int *no_cache)` —
/// `providers/defltprov.c`, with every arm but `OSSL_OP_DIGEST` absent.
///
/// # Safety
/// `no_cache` must be writable; `provctx` is ignored by this arm.
unsafe extern "C" fn deflt_query(
    _provctx: *mut c_void,
    operation_id: c_int,
    no_cache: *mut c_int,
) -> *const OsslAlgorithm {
    // SAFETY: `no_cache` is writable per the caller's contract.
    unsafe { *no_cache = 0 };
    if operation_id == OSSL_OP_DIGEST {
        return DEFLT_DIGESTS.as_ptr();
    }
    ptr::null()
}

/// `int ossl_default_provider_init(const OSSL_CORE_HANDLE *handle, const OSSL_DISPATCH *in,
/// const OSSL_DISPATCH **out, void **provctx)` — `providers/defltprov.c`.
///
/// **The digest half only.** The authority's body walks `in` for `CORE_GET_LIBCTX` and
/// `CORE_GET_PARAMS`, builds a `provctx` with `ossl_prov_ctx_new` and a core BIO method, stores
/// the handle in it, publishes `deflt_get_params`/`deflt_gettable_params` and
/// `ossl_prov_get_capabilities`, and caches the exported cipher algorithm table. None of that
/// is reachable from `OSSL_OP_DIGEST`: the digest query ignores `provctx`, so this init
/// publishes the two entries the digest half uses — `QUERY_OPERATION`, and nothing else — and
/// leaves `provctx` NULL.
///
/// # Safety
/// `out` and `provctx` must be writable; `handle` and `in_` are unused by this half.
pub(crate) unsafe extern "C" fn ossl_default_provider_init(
    _handle: *const c_void,
    _in: *const OsslDispatch,
    out: *mut *const OsslDispatch,
    provctx: *mut *mut c_void,
) -> c_int {
    if out.is_null() || provctx.is_null() {
        return 0;
    }
    // SAFETY: both out-parameters are writable per the contract, and the table is `'static`.
    unsafe {
        *out = DEFLT_DISPATCH.as_ptr();
        *provctx = ptr::null_mut();
    }
    1
}

/// `deflt_dispatch_table` — `providers/defltprov.c`, restricted to the entry the digest half
/// needs. The authority also publishes `TEARDOWN`, `GETTABLE_PARAMS`, `GET_PARAMS` and
/// `GET_CAPABILITIES`; those are the provider-params half, absent here by design.
static DEFLT_DISPATCH: [OsslDispatch; 2] = [
    OsslDispatch {
        function_id: FUNC_PROVIDER_QUERY_OPERATION,
        function: deflt_query as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_DISPATCH_END,
        function: ptr::null_mut(),
    },
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_digest_query_answers_only_for_digest_and_terminates() {
        let mut no_cache: c_int = -1;
        // SAFETY: the query's contract; `provctx` is NULL and this arm ignores it.
        let table = unsafe { deflt_query(ptr::null_mut(), OSSL_OP_DIGEST, &mut no_cache) };
        assert!(!table.is_null());
        assert_eq!(no_cache, 0, "the digest arm caches");
        // SAFETY: the returned table is `DEFLT_DIGESTS`, terminated by a NULL name.
        assert!(unsafe { (*table).algorithm_names.is_null() } == false);
        // SAFETY: every entry up to the terminator is initialised.
        let mut n = 0usize;
        while !unsafe { (*table.add(n)).algorithm_names }.is_null() {
            n += 1;
        }
        assert_eq!(n, 9, "the nine constructions 8.1a transcribed");

        // SAFETY: the query's contract; an operation this half does not answer.
        let none = unsafe { deflt_query(ptr::null_mut(), 14, &mut no_cache) };
        assert!(none.is_null(), "only OSSL_OP_DIGEST is answered");
    }

    #[test]
    fn the_default_init_publishes_the_query_entry() {
        let mut out: *const OsslDispatch = ptr::null();
        let mut provctx: *mut c_void = 0x1 as *mut c_void;
        // SAFETY: both slots are this frame's and writable.
        let ok =
            unsafe { ossl_default_provider_init(ptr::null(), ptr::null(), &mut out, &mut provctx) };
        assert_eq!(ok, 1);
        assert!(provctx.is_null());
        // SAFETY: `out` is the published `'static` table.
        assert_eq!(unsafe { (*out).function_id }, FUNC_PROVIDER_QUERY_OPERATION);
        // SAFETY: the entry after it is the terminator.
        assert_eq!(unsafe { (*out.add(1)).function_id }, OSSL_DISPATCH_END);
    }

    #[test]
    fn sha256_provider_reports_the_size_and_blocksize_it_has() {
        let mut size: usize = 0;
        let mut block: usize = 0;
        let mut params: [OsslParam; 3] = [END; 3];
        params[0] = unsafe {
            crate::params::OSSL_PARAM_construct_size_t(OSSL_DIGEST_PARAM_SIZE, &mut size)
        };
        params[1] = unsafe {
            crate::params::OSSL_PARAM_construct_size_t(OSSL_DIGEST_PARAM_BLOCK_SIZE, &mut block)
        };
        // SAFETY: the array is terminated and its buffers are this frame's.
        let ok = unsafe { ossl_digest_default_get_params(params.as_mut_ptr(), 64, 32, 2) };
        assert_eq!(ok, 1);
        assert_eq!((size, block), (32, 64));
    }
}
