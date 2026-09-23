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
//! * `deflt_digests[]`'s rows for every construction this crate has: SHA-1, the four `sha.h`
//!   SHA-2 widths, the truncated SHA-2 spellings (`SHA2-256/192`, `SHA2-512/224`, `SHA2-512/256`),
//!   SHA-3/KECCAK/SHAKE, SM3, BLAKE2S-256/BLAKE2B-512, `MD5`, `MD5-SHA1`, `RIPEMD-160` and
//!   `NULL` — every row `providers/defltprov.c` publishes. **MD4 and Whirlpool are the
//!   exception**, and they are the reason the table is reviewed against `defltprov.c` rather
//!   than against the constructions that happen to exist: see below — and
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
//! **The rows `deflt_digests[]` carries and this half does not, restated after 8.1c.** There are
//! none left that this crate has a construction for. The eleven 8.1c landed — SHA-3/KECCAK/SHAKE
//! (`sha3_prov.c`), SM3 (`sm3_prov.c`), BLAKE2 (`blake2s_prov.c`/`blake2b_prov.c`), the two
//! truncated SHA-512 spellings and SHA2-256/192 (`sha2_prov.c`), and the combined/NULL digests
//! (`md5_sha1_prov.c`, `null_prov.c`) — each publishes its `defltprov.c` row now (`docs/DECISIONS.md`
//! D207). **MD4 and Whirlpool are the other case, and they are why the table was reviewed
//! against `defltprov.c` rather than against the constructions 8.1a had landed:** their
//! constructions do exist here, but the authority publishes them from `legacyprov.c` — Phase
//! 13's, per `forensics/prerequisites.json` — and *not* from the default provider, so a
//! default-provider row would make `EVP_MD_fetch(NULL, "MD4", NULL)` and
//! `EVP_MD_fetch(NULL, "WHIRLPOOL", NULL)` succeed where the authority answers NULL. Their two
//! provider tables are not written here either, so no `digest_impl!` invocation is left unused.
//! The `RT-DIGEST` provider section observes the pair and fails on both sides' disagreement. The
//! plan's §3.5 requires exactly this to be said out loud; `docs/DECISIONS.md` D204, D206 and
//! D207 record it.
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

use core::ffi::{c_char, c_int, c_uchar, c_uint, c_ulong, c_void};
use core::ptr;

use crate::context::dispatch::{OsslDispatch, OSSL_DISPATCH_END};
use crate::digest::md5::{MD5_Final, MD5_Init, MD5_Update, Md5Ctx};
use crate::digest::md5_sha1::{
    ossl_md5_sha1_ctrl, ossl_md5_sha1_final, ossl_md5_sha1_init, ossl_md5_sha1_update, Md5Sha1Ctx,
    MD5_SHA1_CBLOCK, MD5_SHA1_DIGEST_LENGTH,
};
use crate::digest::ripemd::{RIPEMD160_Final, RIPEMD160_Init, RIPEMD160_Update, Ripemd160Ctx};
use crate::digest::sha1::{ossl_sha1_ctrl, SHA1_Final, SHA1_Init, SHA1_Update, ShaCtx};
use crate::digest::sha2::{
    ossl_sha256_192_init, sha512_224_init, sha512_256_init, SHA224_Final, SHA224_Init,
    SHA224_Update, SHA256_Final, SHA256_Init, SHA256_Update, SHA384_Final, SHA384_Init,
    SHA384_Update, SHA512_Final, SHA512_Init, SHA512_Update, Sha256Ctx, Sha512Ctx,
};
use crate::digest::sm3::{
    ossl_sm3_final, ossl_sm3_init, ossl_sm3_update, Sm3Ctx, SM3_CBLOCK, SM3_DIGEST_LENGTH,
};
use crate::evp::algorithm::OSSL_OP_DIGEST;
use crate::evp::digest::{
    OSSL_FUNC_DIGEST_COPYCTX, OSSL_FUNC_DIGEST_DUPCTX, OSSL_FUNC_DIGEST_FINAL,
    OSSL_FUNC_DIGEST_FREECTX, OSSL_FUNC_DIGEST_GETTABLE_CTX_PARAMS,
    OSSL_FUNC_DIGEST_GETTABLE_PARAMS, OSSL_FUNC_DIGEST_GET_CTX_PARAMS, OSSL_FUNC_DIGEST_GET_PARAMS,
    OSSL_FUNC_DIGEST_INIT, OSSL_FUNC_DIGEST_NEWCTX, OSSL_FUNC_DIGEST_SETTABLE_CTX_PARAMS,
    OSSL_FUNC_DIGEST_SET_CTX_PARAMS, OSSL_FUNC_DIGEST_SQUEEZE, OSSL_FUNC_DIGEST_UPDATE,
};
use crate::params::{OsslParam, END, OSSL_PARAM_OCTET_STRING, OSSL_PARAM_UNMODIFIED};

use crate::provider::activate::OsslAlgorithm;
use crate::provider::cipher::{param_int, param_size_t, param_uint};
use crate::provider::init::FUNC_PROVIDER_QUERY_OPERATION;
use crate::runtime::err::{err_sites, raise_site};
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
    if params.is_null() {
        return true;
    }
    // SAFETY: `params` is non-NULL and, per the contract, points at a key-terminated array, so
    // its first entry is readable.
    unsafe { (*params).key.is_null() }
}

/// `digest_default_get_params_list` — the four keys `digestcommon.c`'s generated decoder
/// locates, with the types `produce_param_decoder` assigns them.
static DIGEST_DEFAULT_GETTABLE_PARAMS: [OsslParam; 5] = [
    param_size_t(OSSL_DIGEST_PARAM_BLOCK_SIZE),
    param_size_t(OSSL_DIGEST_PARAM_SIZE),
    param_int(OSSL_DIGEST_PARAM_XOF),
    param_int(OSSL_DIGEST_PARAM_ALGID_ABSENT),
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
    // `digest_default_get_params_decoder` runs first in the authority, and its repeated-key
    // refusal is a coordinate of its own (`digestcommon.c:56-89`). This crate locates the keys
    // directly instead of transcribing the generated decoder, so the scan is kept here and
    // reports the decoder's site.
    // SAFETY: `params` is a key-terminated array per this function's caller contract, which is
    // exactly what `repeated_digest_param_site` walks.
    if let Some(site) = unsafe { repeated_digest_param_site(params) } {
        return fail_at(site);
    }

    // The body, in the authority's order, one recorded coordinate per arm.
    let arms: [(*const c_char, usize, bool, &err_sites::ErrSite); 4] = [
        (
            OSSL_DIGEST_PARAM_BLOCK_SIZE,
            blksz,
            false,
            &err_sites::PROV_DIGESTCOMMON_111,
        ),
        (
            OSSL_DIGEST_PARAM_SIZE,
            paramsz,
            false,
            &err_sites::PROV_DIGESTCOMMON_115,
        ),
        (
            OSSL_DIGEST_PARAM_XOF,
            usize::from(flags & PROV_DIGEST_FLAG_XOF != 0),
            true,
            &err_sites::PROV_DIGESTCOMMON_120,
        ),
        (
            OSSL_DIGEST_PARAM_ALGID_ABSENT,
            usize::from(flags & PROV_DIGEST_FLAG_ALGID_ABSENT != 0),
            true,
            &err_sites::PROV_DIGESTCOMMON_125,
        ),
    ];
    for (key, v, is_int, site) in arms {
        // SAFETY: `params` is a key-terminated array per the contract and `key` is a literal
        // with a terminator.
        let p = unsafe { crate::params::OSSL_PARAM_locate_const(params, key) };
        if p.is_null() {
            continue;
        }
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
            return fail_at(site);
        }
    }
    1
}

/// `ERR_raise(lib, reason)` at a recorded authority site: the refusal *and* the queued error.
///
/// A path where the authority raises and this crate does not is an `ERROR_PASS` failure
/// (`docs/PARITY_MODEL.md` §3.5), so the digest provider's refusals queue the authority's own
/// coordinate rather than returning bare.
#[inline]
fn fail_at(site: &err_sites::ErrSite) -> c_int {
    // SAFETY: `site` is a generated compile-time constant whose three string pointers are
    // `'static`; no caller state is touched.
    unsafe { raise_site(site) };
    0
}

/// `digest_default_get_params_decoder`'s repeated-key refusal, in the authority's own order.
///
/// The four keys and their raise sites are `digestcommon.c:56-89`: `algid-absent`, `blocksize`,
/// `size`, `xof`. The first repeated key in array order is the one the decoder reports.
///
/// # Safety
/// `params` is NULL or a key-terminated array.
unsafe fn repeated_digest_param_site(
    params: *mut OsslParam,
) -> Option<&'static err_sites::ErrSite> {
    const KEYS: [(*const c_char, &err_sites::ErrSite); 4] = [
        (
            OSSL_DIGEST_PARAM_ALGID_ABSENT,
            &err_sites::PROV_DIGESTCOMMON_56,
        ),
        (
            OSSL_DIGEST_PARAM_BLOCK_SIZE,
            &err_sites::PROV_DIGESTCOMMON_67,
        ),
        (OSSL_DIGEST_PARAM_SIZE, &err_sites::PROV_DIGESTCOMMON_78),
        (OSSL_DIGEST_PARAM_XOF, &err_sites::PROV_DIGESTCOMMON_89),
    ];
    if params.is_null() {
        return None;
    }
    // SAFETY: the caller guarantees a key-terminated array; the walk stops at the NULL key.
    unsafe {
        let mut seen: u32 = 0;
        let mut p = params;
        while !(*p).key.is_null() {
            let k = core::ffi::CStr::from_ptr((*p).key).to_bytes();
            for (i, (name, site)) in KEYS.iter().enumerate() {
                if core::ffi::CStr::from_ptr(*name).to_bytes() == k {
                    if seen & (1u32 << i) != 0 {
                        return Some(site);
                    }
                    seen |= 1u32 << i;
                    break;
                }
            }
            p = p.add(1);
        }
    }
    None
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
                    // SAFETY: `outl` is the caller's output slot, writable per the contract.
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

// The three `sha2_prov.c` rows 8.1a left out because their constructions had no exported
// spelling: SHA2-256/192 (`ossl_sha256_192_init`), SHA2-512/224 (`sha512_224_init`) and
// SHA2-512/256 (`sha512_256_init`). Each is the width's own `_Update`/`_Final` with the truncating
// init, exactly as `sha2_prov.c:74-96` spells them.
digest_impl!(
    sha256_192_internal,
    Sha256Ctx,
    ossl_sha256_192_init,
    SHA256_Update,
    SHA256_Final,
    64usize,
    24usize,
    PROV_DIGEST_FLAG_ALGID_ABSENT
);
digest_impl!(
    sha512_224,
    Sha512Ctx,
    sha512_224_init,
    SHA512_Update,
    SHA512_Final,
    128usize,
    28usize,
    PROV_DIGEST_FLAG_ALGID_ABSENT
);
digest_impl!(
    sha512_256,
    Sha512Ctx,
    sha512_256_init,
    SHA512_Update,
    SHA512_Final,
    128usize,
    32usize,
    PROV_DIGEST_FLAG_ALGID_ABSENT
);

// `sm3_prov.c:16-18` — `IMPLEMENT_digest_functions(sm3, SM3_CTX, SM3_CBLOCK, SM3_DIGEST_LENGTH, 0,
// ossl_sm3_init, ossl_sm3_update, ossl_sm3_final)`. Flags 0: SM3 carries no `ALGID_ABSENT` and
// the header gives it a real OID.
digest_impl!(
    sm3,
    Sm3Ctx,
    ossl_sm3_init,
    ossl_sm3_update,
    ossl_sm3_final,
    SM3_CBLOCK,
    SM3_DIGEST_LENGTH,
    0u64 as c_ulong
);

/// `NULLMD_CTX` — `null_prov.c:14-16`. One byte, because the authority's three entry points are
/// no-ops and only the allocation's existence is observable.
///
/// `null_prov.c` is the one digest construction whose provider row is written by hand rather than
/// through `IMPLEMENT_digest_functions`: with `dgstsize == 0`, the macro's `outsz < dgstsize`
/// guard is a comparison the compiler can fold away (the authority's file says so at `:33-48`),
/// and the final there is overridden to drop it. `digest_impl!` cannot express that removal, so
/// this module is the override's own transcription.
mod nullmd {
    use super::*;

    /// `NULLMD_CTX` — `null_prov.c:14-16`.
    #[repr(C)]
    struct NullMdCtx {
        /// `unsigned char nothing`.
        nothing: u8,
    }

    /// `static int null_init(NULLMD_CTX *ctx)` — `null_prov.c:18-21`.
    unsafe extern "C" fn ctx_init(_ctx: *mut NullMdCtx) -> c_int {
        1
    }
    /// `static int null_update(NULLMD_CTX *ctx, const void *data, size_t datalen)` —
    /// `null_prov.c:23-26`.
    unsafe extern "C" fn ctx_update(
        _ctx: *mut NullMdCtx,
        _data: *const c_void,
        _datalen: usize,
    ) -> c_int {
        1
    }
    /// `static int null_final(unsigned char *md, NULLMD_CTX *ctx)` — `null_prov.c:28-31`.
    unsafe extern "C" fn ctx_final(_md: *mut u8, _ctx: *mut NullMdCtx) -> c_int {
        1
    }

    unsafe extern "C" fn newctx(_provctx: *mut c_void) -> *mut c_void {
        if ossl_prov_is_running() == 0 {
            return ptr::null_mut();
        }
        CRYPTO_zalloc(core::mem::size_of::<NullMdCtx>(), FILE, LINE)
    }

    unsafe extern "C" fn freectx(vctx: *mut c_void) {
        // SAFETY: `vctx` is what `newctx` allocated or NULL.
        unsafe {
            CRYPTO_clear_free(vctx, core::mem::size_of::<NullMdCtx>(), FILE, LINE);
        }
    }

    unsafe extern "C" fn dupctx(ctx: *mut c_void) -> *mut c_void {
        if ossl_prov_is_running() == 0 || ctx.is_null() {
            return ptr::null_mut();
        }
        let ret = CRYPTO_malloc(core::mem::size_of::<NullMdCtx>(), FILE, LINE);
        if !ret.is_null() {
            // SAFETY: both regions are `size_of::<NullMdCtx>()` bytes and distinct.
            unsafe {
                ptr::copy_nonoverlapping(
                    ctx.cast::<u8>(),
                    ret.cast::<u8>(),
                    core::mem::size_of::<NullMdCtx>(),
                );
            }
        }
        ret
    }

    unsafe extern "C" fn copyctx(outctx: *mut c_void, inctx: *mut c_void) {
        // SAFETY: both regions are `size_of::<NullMdCtx>()` bytes and distinct.
        unsafe {
            ptr::copy_nonoverlapping(
                inctx.cast::<u8>(),
                outctx.cast::<u8>(),
                core::mem::size_of::<NullMdCtx>(),
            );
        }
    }

    unsafe extern "C" fn internal_init(ctx: *mut c_void, _params: *const OsslParam) -> c_int {
        if ossl_prov_is_running() == 0 {
            return 0;
        }
        // SAFETY: `ctx` is the context the provider allocated.
        c_int::from(unsafe { ctx_init(ctx.cast::<NullMdCtx>()) } != 0)
    }

    /// `null_prov.c`'s overridden `PROV_FUNC_DIGEST_FINAL`: no `outsz` comparison, because
    /// `dgstsize` is zero and the guard the shared macro writes is vacuous.
    unsafe extern "C" fn internal_final(
        ctx: *mut c_void,
        out: *mut u8,
        outl: *mut usize,
        _outsz: usize,
    ) -> c_int {
        if ossl_prov_is_running() == 0 {
            return 0;
        }
        // SAFETY: `ctx` is the context the provider allocated; `outl` is the caller's slot.
        if unsafe { ctx_final(out, ctx.cast::<NullMdCtx>()) } != 0 {
            // SAFETY: `outl` is the caller's output slot.
            unsafe { *outl = 0 };
            return 1;
        }
        0
    }

    unsafe extern "C" fn update(ctx: *mut c_void, in_: *const c_uchar, inl: usize) -> c_int {
        // SAFETY: `ctx` is the context the provider allocated; the authority ignores the bytes.
        c_int::from(unsafe { ctx_update(ctx.cast::<NullMdCtx>(), in_.cast::<c_void>(), inl) } != 0)
    }

    unsafe extern "C" fn get_params(params: *mut OsslParam) -> c_int {
        // SAFETY: the caller's contract is `ossl_digest_default_get_params`'s.
        unsafe { ossl_digest_default_get_params(params, 0, 0, 0) }
    }

    unsafe extern "C" fn gettable_params(_provctx: *mut c_void) -> *const OsslParam {
        DIGEST_DEFAULT_GETTABLE_PARAMS.as_ptr()
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
            function: gettable_params as *mut c_void,
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

/// `md5_sha1_prov.c`'s `IMPLEMENT_digest_functions_with_settable_ctx` body — the concatenated
/// `MD5-SHA1` row, with the SSLv3 master-secret `set_ctx_params` arm.
mod md5_sha1 {
    use super::*;

    /// `known_md5_sha1_settable_ctx_params` — `md5_sha1_prov.c:28-31`.
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

    /// `static int md5_sha1_set_ctx_params(void *vctx, const OSSL_PARAM params[])` —
    /// `md5_sha1_prov.c:40-55`.
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
                // SAFETY: `vctx` is the context the provider allocated and `data` is readable for
                // `size` bytes per the parameter's own contract.
                return unsafe {
                    ossl_md5_sha1_ctrl(
                        vctx.cast::<Md5Sha1Ctx>(),
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
        CRYPTO_zalloc(core::mem::size_of::<Md5Sha1Ctx>(), FILE, LINE)
    }

    unsafe extern "C" fn freectx(vctx: *mut c_void) {
        // SAFETY: `vctx` is what `newctx` allocated or NULL.
        unsafe {
            CRYPTO_clear_free(vctx, core::mem::size_of::<Md5Sha1Ctx>(), FILE, LINE);
        }
    }

    unsafe extern "C" fn dupctx(ctx: *mut c_void) -> *mut c_void {
        if ossl_prov_is_running() == 0 || ctx.is_null() {
            return ptr::null_mut();
        }
        let ret = CRYPTO_malloc(core::mem::size_of::<Md5Sha1Ctx>(), FILE, LINE);
        if !ret.is_null() {
            // SAFETY: both regions are `size_of::<Md5Sha1Ctx>()` bytes and distinct.
            unsafe {
                ptr::copy_nonoverlapping(
                    ctx.cast::<u8>(),
                    ret.cast::<u8>(),
                    core::mem::size_of::<Md5Sha1Ctx>(),
                );
            }
        }
        ret
    }

    unsafe extern "C" fn copyctx(outctx: *mut c_void, inctx: *mut c_void) {
        // SAFETY: both regions are `size_of::<Md5Sha1Ctx>()` bytes and distinct.
        unsafe {
            ptr::copy_nonoverlapping(
                inctx.cast::<u8>(),
                outctx.cast::<u8>(),
                core::mem::size_of::<Md5Sha1Ctx>(),
            );
        }
    }

    unsafe extern "C" fn internal_init(ctx: *mut c_void, params: *const OsslParam) -> c_int {
        if ossl_prov_is_running() == 0 {
            return 0;
        }
        // SAFETY: `ctx` is the context the provider allocated.
        if unsafe { ossl_md5_sha1_init(ctx.cast::<Md5Sha1Ctx>()) } == 0 {
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
        if ossl_prov_is_running() == 0 || outsz < MD5_SHA1_DIGEST_LENGTH {
            return 0;
        }
        // SAFETY: `ctx` is a live context and `out` is writable for `outsz >= 36`.
        if unsafe { ossl_md5_sha1_final(out, ctx.cast::<Md5Sha1Ctx>()) } != 0 {
            // SAFETY: `outl` is the caller's output slot.
            unsafe { *outl = MD5_SHA1_DIGEST_LENGTH };
            return 1;
        }
        0
    }

    unsafe extern "C" fn update(ctx: *mut c_void, in_: *const c_uchar, inl: usize) -> c_int {
        // SAFETY: `ctx` is the context the provider allocated; `in_` is readable for `inl` bytes.
        c_int::from(unsafe {
            ossl_md5_sha1_update(ctx.cast::<Md5Sha1Ctx>(), in_.cast::<c_void>(), inl) != 0
        })
    }

    unsafe extern "C" fn get_params(params: *mut OsslParam) -> c_int {
        // SAFETY: the caller's contract is `ossl_digest_default_get_params`'s.
        unsafe {
            ossl_digest_default_get_params(params, MD5_SHA1_CBLOCK, MD5_SHA1_DIGEST_LENGTH, 0)
        }
    }

    unsafe extern "C" fn gettable_params(_provctx: *mut c_void) -> *const OsslParam {
        DIGEST_DEFAULT_GETTABLE_PARAMS.as_ptr()
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

/// `sha3_prov.c`'s twelve rows — the fixed-width `SHA3`/`KECCAK` eight and the `SHAKE`/
/// `KECCAK-KMAC` XOF four. `PROV_FUNC_SHA3_DIGEST` and `PROV_FUNC_SHAKE_DIGEST` differ only in the
/// `squeeze` entry and the `xoflen` ctx-param entries, which is what the two macros transcribe.
mod sha3 {
    use super::*;
    use crate::digest::sha3::{
        kmac_mdsize, ossl_keccak_init, ossl_sha3_final, ossl_sha3_init, ossl_sha3_reset,
        ossl_sha3_squeeze, ossl_sha3_update, sha3_blocksize, sha3_mdsize, KeccakCtx,
    };

    /// `OSSL_DIGEST_PARAM_XOFLEN` — `include/openssl/core_names.h`.
    const OSSL_DIGEST_PARAM_XOFLEN: *const c_char = c"xoflen".as_ptr();

    /// `SHA3_FLAGS` — `sha3_prov.c:27`.
    const SHA3_FLAGS: c_ulong = PROV_DIGEST_FLAG_ALGID_ABSENT;
    /// `SHAKE_FLAGS` — `sha3_prov.c:28`.
    const SHAKE_FLAGS: c_ulong = PROV_DIGEST_FLAG_XOF | PROV_DIGEST_FLAG_ALGID_ABSENT;
    /// `KMAC_FLAGS` — `sha3_prov.c:29`.
    const KMAC_FLAGS: c_ulong = PROV_DIGEST_FLAG_XOF;

    /// `SHA3_newctx`/`SHAKE_newctx`/`KMAC_newctx` — one body, differing in what `mdlen` is.
    unsafe fn new_keccak(pad: u8, bitlen: usize, mdlen: Option<usize>) -> *mut c_void {
        if ossl_prov_is_running() == 0 {
            return ptr::null_mut();
        }
        let raw = CRYPTO_zalloc(core::mem::size_of::<KeccakCtx>(), FILE, LINE);
        if raw.is_null() {
            return raw;
        }
        let c = raw.cast::<KeccakCtx>();
        // SAFETY: `c` is a freshly zeroed `KeccakCtx` the provider owns.
        unsafe {
            match mdlen {
                None => {
                    ossl_sha3_init(c, pad, bitlen);
                }
                Some(m) => {
                    ossl_keccak_init(c, pad, bitlen, m);
                    if m == 0 {
                        (*c).md_size = usize::MAX;
                    }
                }
            }
        }
        raw
    }

    unsafe extern "C" fn freectx(vctx: *mut c_void) {
        // SAFETY: `vctx` is what `new_keccak` allocated or NULL.
        unsafe {
            CRYPTO_clear_free(vctx, core::mem::size_of::<KeccakCtx>(), FILE, LINE);
        }
    }

    unsafe extern "C" fn dupctx(ctx: *mut c_void) -> *mut c_void {
        if ossl_prov_is_running() == 0 || ctx.is_null() {
            return ptr::null_mut();
        }
        let ret = CRYPTO_malloc(core::mem::size_of::<KeccakCtx>(), FILE, LINE);
        if !ret.is_null() {
            // SAFETY: both regions are `size_of::<KeccakCtx>()` bytes and distinct.
            unsafe {
                ptr::copy_nonoverlapping(
                    ctx.cast::<u8>(),
                    ret.cast::<u8>(),
                    core::mem::size_of::<KeccakCtx>(),
                );
            }
        }
        ret
    }

    unsafe extern "C" fn copyctx(outctx: *mut c_void, inctx: *mut c_void) {
        // SAFETY: both regions are `size_of::<KeccakCtx>()` bytes and distinct.
        unsafe {
            ptr::copy_nonoverlapping(
                inctx.cast::<u8>(),
                outctx.cast::<u8>(),
                core::mem::size_of::<KeccakCtx>(),
            );
        }
    }

    unsafe extern "C" fn init(ctx: *mut c_void, _params: *const OsslParam) -> c_int {
        if ossl_prov_is_running() == 0 {
            return 0;
        }
        // `keccak_init` — `sha3_prov.c:63-70`: `newctx` fixed the rate and the pad, so INIT only
        // resets the state.
        // SAFETY: `ctx` is the provider's `KeccakCtx`.
        unsafe { ossl_sha3_reset(ctx.cast::<KeccakCtx>()) };
        1
    }

    unsafe extern "C" fn update(ctx: *mut c_void, in_: *const c_uchar, inl: usize) -> c_int {
        // SAFETY: `ctx` is the provider's context; `in_` is readable for `inl` bytes.
        unsafe { ossl_sha3_update(ctx.cast::<KeccakCtx>(), in_, inl) }
    }

    /// `keccak_final` — `sha3_prov.c:115-132`.
    unsafe extern "C" fn keccak_final(
        ctx: *mut c_void,
        out: *mut u8,
        outl: *mut usize,
        outlen: usize,
    ) -> c_int {
        if ossl_prov_is_running() == 0 {
            return 0;
        }
        let c = ctx.cast::<KeccakCtx>();
        // SAFETY: `c` is the provider's context.
        if unsafe { (*c).md_size } == usize::MAX {
            return 0;
        }
        let mut ret = 1;
        // SAFETY: `c` is live and `out` is writable for `outlen`.
        unsafe {
            if outlen > 0 {
                ret = ossl_sha3_final(c, out, (*c).md_size);
            }
            *outl = (*c).md_size;
        }
        ret
    }

    /// `shake_squeeze` — `sha3_prov.c:134-149`.
    unsafe extern "C" fn shake_squeeze(
        ctx: *mut c_void,
        out: *mut u8,
        outl: *mut usize,
        outlen: usize,
    ) -> c_int {
        if ossl_prov_is_running() == 0 {
            return 0;
        }
        let mut ret = 1;
        // SAFETY: `ctx` is the provider's context and `out` is writable for `outlen`.
        unsafe {
            if outlen > 0 {
                ret = ossl_sha3_squeeze(ctx.cast::<KeccakCtx>(), out, outlen);
            }
            *outl = outlen;
        }
        ret
    }

    /// The `KECCAK-KMAC` rows' squeeze callback — the authority's `shake_squeeze` when the
    /// selected `PROV_SHA3_METHOD` has no `squeeze`. `KMAC_SET_MD` installs `sha3_generic_md`,
    /// whose third member is NULL (`sha3_prov.c:174-178`), while `SHAKE_SET_MD` installs
    /// `shake_generic_md`, whose third member is `generic_sha3_squeeze` (`:180-185`). So a
    /// `EVP_DigestSqueeze` on a `KECCAK-KMAC-*` method is refused, and this is that refusal.
    unsafe extern "C" fn refuse_squeeze(
        _ctx: *mut c_void,
        _out: *mut u8,
        _outl: *mut usize,
        _outlen: usize,
    ) -> c_int {
        if ossl_prov_is_running() == 0 {
            return 0;
        }
        0
    }

    /// `shake_set_ctx_params` — `sha3_prov.c:726-740` with its generated decoder collapsed to
    /// the two keys the decoder accepts. Both map to `ctx->md_size`; a repeated key is refused.
    unsafe extern "C" fn shake_set_ctx_params(
        vctx: *mut c_void,
        params: *const OsslParam,
    ) -> c_int {
        let c = vctx.cast::<KeccakCtx>();
        if c.is_null() {
            return 0;
        }
        // SAFETY: `params` is the caller's array, NULL or key-terminated.
        if unsafe { ossl_param_is_empty(params) } {
            return 1;
        }
        // SAFETY: `params` is key-terminated and both keys are literals.
        let xoflen =
            unsafe { crate::params::OSSL_PARAM_locate_const(params, OSSL_DIGEST_PARAM_XOFLEN) };
        // SAFETY: as above.
        let size =
            unsafe { crate::params::OSSL_PARAM_locate_const(params, OSSL_DIGEST_PARAM_SIZE) };
        if !xoflen.is_null() && !size.is_null() {
            return 0;
        }
        let p = if !xoflen.is_null() { xoflen } else { size };
        if !p.is_null() {
            let mut v: usize = 0;
            // SAFETY: `p` is a live entry of the caller's array; `v` is this frame's slot.
            if unsafe { crate::params::OSSL_PARAM_get_size_t(p, &mut v) } == 0 {
                return 0;
            }
            // SAFETY: `c` is the provider's context.
            unsafe { (*c).md_size = v };
        }
        1
    }

    /// `shake_get_ctx_params` — `sha3_prov.c:644-662`.
    unsafe extern "C" fn shake_get_ctx_params(vctx: *mut c_void, params: *mut OsslParam) -> c_int {
        let c = vctx.cast::<KeccakCtx>();
        if c.is_null() {
            return 0;
        }
        // SAFETY: `params` is key-terminated and both keys are literals.
        let xoflen =
            unsafe { crate::params::OSSL_PARAM_locate_const(params, OSSL_DIGEST_PARAM_XOFLEN) };
        // SAFETY: as above.
        let size =
            unsafe { crate::params::OSSL_PARAM_locate_const(params, OSSL_DIGEST_PARAM_SIZE) };
        if !xoflen.is_null() && !size.is_null() {
            return 0;
        }
        let p = if !xoflen.is_null() { xoflen } else { size };
        if !p.is_null() {
            // SAFETY: `p` is the caller's own writable entry.
            if unsafe { crate::params::OSSL_PARAM_set_size_t(p.cast_mut(), (*c).md_size) } == 0 {
                return 0;
            }
        }
        1
    }

    /// `shake_get_ctx_params_list` / `shake_set_ctx_params_list` — `sha3_prov.c:584-588`.
    static CTX_PARAMS: [OsslParam; 3] = [
        param_size_t(c"xoflen".as_ptr()),
        param_size_t(c"size".as_ptr()),
        END,
    ];

    unsafe extern "C" fn settable_ctx_params(
        _ctx: *mut c_void,
        _provctx: *mut c_void,
    ) -> *const OsslParam {
        CTX_PARAMS.as_ptr()
    }

    /// `keccak_init_params` — `sha3_prov.c:72-76`.
    unsafe extern "C" fn keccak_init_params(vctx: *mut c_void, params: *const OsslParam) -> c_int {
        if ossl_prov_is_running() == 0 {
            return 0;
        }
        // SAFETY: `vctx` is the provider's context.
        unsafe { ossl_sha3_reset(vctx.cast::<KeccakCtx>()) };
        // SAFETY: `vctx` is the provider's context and `params` the caller's array.
        unsafe { shake_set_ctx_params(vctx, params) }
    }

    macro_rules! sha3_fixed_row {
        ($module:ident, $pad:expr, $bitlen:expr, $blksz:expr, $dgstsz:expr, $flags:expr) => {
            pub(super) mod $module {
                use super::*;

                unsafe extern "C" fn newctx(_provctx: *mut c_void) -> *mut c_void {
                    // SAFETY: `super` is the `sha3` provider module.
                    unsafe { super::new_keccak($pad, $bitlen, None) }
                }

                unsafe extern "C" fn get_params(params: *mut OsslParam) -> c_int {
                    // SAFETY: the caller's contract is `ossl_digest_default_get_params`'s.
                    unsafe { ossl_digest_default_get_params(params, $blksz, $dgstsz, $flags) }
                }

                pub(crate) static FUNCTIONS: [OsslDispatch; 10] = [
                    OsslDispatch {
                        function_id: OSSL_FUNC_DIGEST_NEWCTX,
                        function: newctx as *mut c_void,
                    },
                    OsslDispatch {
                        function_id: OSSL_FUNC_DIGEST_UPDATE,
                        function: super::update as *mut c_void,
                    },
                    OsslDispatch {
                        function_id: OSSL_FUNC_DIGEST_FINAL,
                        function: super::keccak_final as *mut c_void,
                    },
                    OsslDispatch {
                        function_id: OSSL_FUNC_DIGEST_FREECTX,
                        function: super::freectx as *mut c_void,
                    },
                    OsslDispatch {
                        function_id: OSSL_FUNC_DIGEST_DUPCTX,
                        function: super::dupctx as *mut c_void,
                    },
                    OsslDispatch {
                        function_id: OSSL_FUNC_DIGEST_COPYCTX,
                        function: super::copyctx as *mut c_void,
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
                        function: super::init as *mut c_void,
                    },
                    OsslDispatch {
                        function_id: OSSL_DISPATCH_END,
                        function: ptr::null_mut(),
                    },
                ];
            }
        };
    }

    macro_rules! sha3_xof_row {
        ($module:ident, $pad:expr, $bitlen:expr, $mdlen:expr, $blksz:expr, $dgstsz:expr,
         $flags:expr, $squeeze:ident) => {
            pub(super) mod $module {
                use super::*;

                unsafe extern "C" fn newctx(_provctx: *mut c_void) -> *mut c_void {
                    // SAFETY: `super` is the `sha3` provider module.
                    unsafe { super::new_keccak($pad, $bitlen, Some($mdlen)) }
                }

                unsafe extern "C" fn get_params(params: *mut OsslParam) -> c_int {
                    // SAFETY: the caller's contract is `ossl_digest_default_get_params`'s.
                    unsafe { ossl_digest_default_get_params(params, $blksz, $dgstsz, $flags) }
                }

                pub(crate) static FUNCTIONS: [OsslDispatch; 15] = [
                    OsslDispatch {
                        function_id: OSSL_FUNC_DIGEST_NEWCTX,
                        function: newctx as *mut c_void,
                    },
                    OsslDispatch {
                        function_id: OSSL_FUNC_DIGEST_UPDATE,
                        function: super::update as *mut c_void,
                    },
                    OsslDispatch {
                        function_id: OSSL_FUNC_DIGEST_FINAL,
                        function: super::keccak_final as *mut c_void,
                    },
                    OsslDispatch {
                        function_id: OSSL_FUNC_DIGEST_FREECTX,
                        function: super::freectx as *mut c_void,
                    },
                    OsslDispatch {
                        function_id: OSSL_FUNC_DIGEST_DUPCTX,
                        function: super::dupctx as *mut c_void,
                    },
                    OsslDispatch {
                        function_id: OSSL_FUNC_DIGEST_COPYCTX,
                        function: super::copyctx as *mut c_void,
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
                        function_id: OSSL_FUNC_DIGEST_SQUEEZE,
                        function: super::$squeeze as *mut c_void,
                    },
                    OsslDispatch {
                        function_id: OSSL_FUNC_DIGEST_INIT,
                        function: super::keccak_init_params as *mut c_void,
                    },
                    OsslDispatch {
                        function_id: OSSL_FUNC_DIGEST_SET_CTX_PARAMS,
                        function: super::shake_set_ctx_params as *mut c_void,
                    },
                    OsslDispatch {
                        function_id: OSSL_FUNC_DIGEST_SETTABLE_CTX_PARAMS,
                        function: super::settable_ctx_params as *mut c_void,
                    },
                    OsslDispatch {
                        function_id: OSSL_FUNC_DIGEST_GET_CTX_PARAMS,
                        function: super::shake_get_ctx_params as *mut c_void,
                    },
                    OsslDispatch {
                        function_id: OSSL_FUNC_DIGEST_GETTABLE_CTX_PARAMS,
                        function: super::settable_ctx_params as *mut c_void,
                    },
                    OsslDispatch {
                        function_id: OSSL_DISPATCH_END,
                        function: ptr::null_mut(),
                    },
                ];
            }
        };
    }

    // `IMPLEMENT_SHA3_functions` / `IMPLEMENT_KECCAK_functions` / `IMPLEMENT_SHAKE_functions` /
    // `IMPLEMENT_KMAC_functions` — `sha3_prov.c:742-790`, with `SHA3_BLOCKSIZE(bitlen)`
    // expanded.
    sha3_fixed_row!(
        sha3_224,
        0x06,
        224,
        sha3_blocksize(224),
        sha3_mdsize(224),
        SHA3_FLAGS
    );
    sha3_fixed_row!(
        sha3_256,
        0x06,
        256,
        sha3_blocksize(256),
        sha3_mdsize(256),
        SHA3_FLAGS
    );
    sha3_fixed_row!(
        sha3_384,
        0x06,
        384,
        sha3_blocksize(384),
        sha3_mdsize(384),
        SHA3_FLAGS
    );
    sha3_fixed_row!(
        sha3_512,
        0x06,
        512,
        sha3_blocksize(512),
        sha3_mdsize(512),
        SHA3_FLAGS
    );
    sha3_fixed_row!(
        keccak_224,
        0x01,
        224,
        sha3_blocksize(224),
        sha3_mdsize(224),
        SHA3_FLAGS
    );
    sha3_fixed_row!(
        keccak_256,
        0x01,
        256,
        sha3_blocksize(256),
        sha3_mdsize(256),
        SHA3_FLAGS
    );
    sha3_fixed_row!(
        keccak_384,
        0x01,
        384,
        sha3_blocksize(384),
        sha3_mdsize(384),
        SHA3_FLAGS
    );
    sha3_fixed_row!(
        keccak_512,
        0x01,
        512,
        sha3_blocksize(512),
        sha3_mdsize(512),
        SHA3_FLAGS
    );
    sha3_xof_row!(
        shake_128,
        0x1f,
        128,
        0,
        sha3_blocksize(128),
        0,
        SHAKE_FLAGS,
        shake_squeeze
    );
    sha3_xof_row!(
        shake_256,
        0x1f,
        256,
        0,
        sha3_blocksize(256),
        0,
        SHAKE_FLAGS,
        shake_squeeze
    );
    sha3_xof_row!(
        keccak_kmac_128,
        0x04,
        128,
        2 * 128,
        sha3_blocksize(128),
        kmac_mdsize(128),
        KMAC_FLAGS,
        refuse_squeeze
    );
    sha3_xof_row!(
        keccak_kmac_256,
        0x04,
        256,
        2 * 256,
        sha3_blocksize(256),
        kmac_mdsize(256),
        KMAC_FLAGS,
        refuse_squeeze
    );
}

/// `blake2_prov.c`'s `IMPLEMENT_BLAKE_functions` body — the two rows `defltprov.c:140-141`
/// publishes. The `size` ctx parameter is the one the provider's `blake_get_ctx_params`/
/// `blake_set_ctx_params` carry; everything else is the default-parameter path.
mod blake2 {
    use super::*;
    use crate::digest::blake2::{blake2b, blake2s};

    /// `blake_get_ctx_params_list` — `blake2_prov.c:29-32`.
    static CTX_PARAMS: [OsslParam; 2] = [
        // `blake_get_ctx_params_list` declares `size` with `OSSL_PARAM_uint`, not
        // `OSSL_PARAM_size_t`: the same `UNSIGNED_INTEGER` type and a *different* size.
        param_uint(OSSL_DIGEST_PARAM_SIZE),
        END,
    ];

    unsafe extern "C" fn settable_ctx_params(
        _ctx: *mut c_void,
        _provctx: *mut c_void,
    ) -> *const OsslParam {
        CTX_PARAMS.as_ptr()
    }

    macro_rules! blake_row {
        ($row:ident, $flavour:ident, $blksz:expr, $outbytes:expr, $dgstsz:expr) => {
            pub(super) mod $row {
                use super::*;

                unsafe extern "C" fn newctx(_provctx: *mut c_void) -> *mut c_void {
                    if ossl_prov_is_running() == 0 {
                        return ptr::null_mut();
                    }
                    CRYPTO_zalloc(core::mem::size_of::<$flavour::MdData>(), FILE, LINE)
                }

                unsafe extern "C" fn freectx(vctx: *mut c_void) {
                    // SAFETY: `vctx` is what `newctx` allocated or NULL.
                    unsafe {
                        CRYPTO_clear_free(
                            vctx,
                            core::mem::size_of::<$flavour::MdData>(),
                            FILE,
                            LINE,
                        );
                    }
                }

                unsafe extern "C" fn dupctx(ctx: *mut c_void) -> *mut c_void {
                    if ossl_prov_is_running() == 0 || ctx.is_null() {
                        return ptr::null_mut();
                    }
                    let ret = CRYPTO_malloc(core::mem::size_of::<$flavour::MdData>(), FILE, LINE);
                    if !ret.is_null() {
                        // SAFETY: both regions are the same size and distinct.
                        unsafe {
                            ptr::copy_nonoverlapping(
                                ctx.cast::<u8>(),
                                ret.cast::<u8>(),
                                core::mem::size_of::<$flavour::MdData>(),
                            );
                        }
                    }
                    ret
                }

                unsafe extern "C" fn copyctx(outctx: *mut c_void, inctx: *mut c_void) {
                    // SAFETY: both regions are the same size and distinct.
                    unsafe {
                        ptr::copy_nonoverlapping(
                            inctx.cast::<u8>(),
                            outctx.cast::<u8>(),
                            core::mem::size_of::<$flavour::MdData>(),
                        );
                    }
                }

                /// `blake_set_ctx_params` — `blake2_prov.c:136-160`'s generated body, collapsed
                /// to the one key the decoder accepts.
                unsafe extern "C" fn set_ctx_params(
                    ctx: *mut c_void,
                    params: *const OsslParam,
                ) -> c_int {
                    if ctx.is_null() {
                        return 0;
                    }
                    // SAFETY: `params` is NULL or key-terminated per the caller's contract.
                    if params.is_null() || unsafe { ossl_param_is_empty(params) } {
                        return 1;
                    }
                    // SAFETY: `params` is key-terminated and the key is a literal.
                    let p = unsafe {
                        crate::params::OSSL_PARAM_locate_const(params, OSSL_DIGEST_PARAM_SIZE)
                    };
                    if !p.is_null() {
                        let mut size: c_uint = 0;
                        // SAFETY: `p` is a live entry of the caller's array.
                        if unsafe { crate::params::OSSL_PARAM_get_uint(p, &mut size) } == 0 {
                            return 0;
                        }
                        if size < 1 || size as usize > $outbytes {
                            return 0;
                        }
                        // SAFETY: `ctx` is the provider's context.
                        unsafe {
                            $flavour::param_set_digest_length(
                                &mut *ptr::addr_of_mut!((*ctx.cast::<$flavour::MdData>()).params),
                                size as u8,
                            );
                        }
                    }
                    1
                }

                /// `blake_get_ctx_params` — `blake2_prov.c:117-134`.
                unsafe extern "C" fn get_ctx_params(
                    ctx: *mut c_void,
                    params: *mut OsslParam,
                ) -> c_int {
                    if ctx.is_null() {
                        return 0;
                    }
                    // SAFETY: `params` is NULL or key-terminated.
                    let p = unsafe {
                        crate::params::OSSL_PARAM_locate_const(params, OSSL_DIGEST_PARAM_SIZE)
                    };
                    if !p.is_null() {
                        // SAFETY: `ctx` is the provider's context.
                        let size = unsafe { (*ctx.cast::<$flavour::MdData>()).params.b[0] };
                        // SAFETY: `p` is the caller's own writable entry.
                        if unsafe {
                            crate::params::OSSL_PARAM_set_uint(p.cast_mut(), size as c_uint)
                        } == 0
                        {
                            return 0;
                        }
                    }
                    1
                }

                /// `blake_init` — `blake2_prov.c:162-171`: re-initialise the parameters but keep
                /// a `size` the caller set before `init`.
                unsafe extern "C" fn internal_init(
                    ctx: *mut c_void,
                    params: *const OsslParam,
                ) -> c_int {
                    if ossl_prov_is_running() == 0 {
                        return 0;
                    }
                    // SAFETY: `ctx` is the provider's context and `params` the caller's array.
                    if unsafe { set_ctx_params(ctx, params) } == 0 {
                        return 0;
                    }
                    let md = ctx.cast::<$flavour::MdData>();
                    // SAFETY: `md` is the provider's context.
                    let digest_length = unsafe { (*md).params.b[0] };
                    // SAFETY: `md` is the provider's context.
                    unsafe {
                        $flavour::param_init(&mut (*md).params);
                        if digest_length != 0 {
                            (*md).params.b[0] = digest_length;
                        }
                        $flavour::init(ptr::addr_of_mut!((*md).ctx), ptr::addr_of!((*md).params));
                    }
                    1
                }

                unsafe extern "C" fn update(
                    ctx: *mut c_void,
                    in_: *const c_uchar,
                    inl: usize,
                ) -> c_int {
                    // SAFETY: the md-data struct's `ctx` field is first, so the provider pointer
                    // is the context pointer, as the authority's cast assumes.
                    c_int::from(unsafe {
                        $flavour::update(ctx.cast::<$flavour::Ctx>(), in_, inl) != 0
                    })
                }

                /// `blake_internal_final` — `blake2_prov.c:222-243`.
                unsafe extern "C" fn internal_final(
                    ctx: *mut c_void,
                    out: *mut u8,
                    outl: *mut usize,
                    outsz: usize,
                ) -> c_int {
                    if ossl_prov_is_running() == 0 {
                        return 0;
                    }
                    let md = ctx.cast::<$flavour::MdData>();
                    // SAFETY: `md` is the provider's context and `outl` the caller's slot.
                    let outlen = unsafe {
                        let outlen = (*md).ctx.outlen;
                        *outl = outlen;
                        outlen
                    };
                    if outsz == 0 {
                        return 1;
                    }
                    if outsz < outlen {
                        return 0;
                    }
                    // SAFETY: `out` is writable for `outsz >= outlen`.
                    unsafe { $flavour::final_(out, ctx.cast::<$flavour::Ctx>()) }
                }

                unsafe extern "C" fn get_params(params: *mut OsslParam) -> c_int {
                    // SAFETY: the caller's contract is `ossl_digest_default_get_params`'s.
                    unsafe { ossl_digest_default_get_params(params, $blksz, $dgstsz, 0) }
                }

                pub(crate) static FUNCTIONS: [OsslDispatch; 14] = [
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
                        function_id: OSSL_FUNC_DIGEST_GETTABLE_CTX_PARAMS,
                        function: settable_ctx_params as *mut c_void,
                    },
                    OsslDispatch {
                        function_id: OSSL_FUNC_DIGEST_SETTABLE_CTX_PARAMS,
                        function: settable_ctx_params as *mut c_void,
                    },
                    OsslDispatch {
                        function_id: OSSL_FUNC_DIGEST_GET_CTX_PARAMS,
                        function: get_ctx_params as *mut c_void,
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
        };
    }

    // `IMPLEMENT_BLAKE_functions(blake2s256, s, s)` and `(blake2b512, b, b)` — the two rows
    // `defltprov.c:140-141` publishes.
    blake_row!(
        blake2s256,
        blake2s,
        blake2s::BLOCKBYTES,
        blake2s::OUTBYTES,
        blake2s::OUTBYTES
    );
    blake_row!(
        blake2b512,
        blake2b,
        blake2b::BLOCKBYTES,
        blake2b::OUTBYTES,
        blake2b::OUTBYTES
    );
}

/// The property string every row of `deflt_digests[]` carries.
const DEFAULT_PROPERTIES: *const c_char = c"provider=default".as_ptr();

/// `static const OSSL_ALGORITHM deflt_digests[]` — `providers/defltprov.c`, restricted to the
/// constructions 8.1 has landed **and** that file publishes. The alias lists are `prov/names.h`'s,
/// verbatim.
static DEFLT_DIGESTS: [OsslAlgorithm; 28] = [
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
        algorithm_names: c"SHA2-256/192:SHA-256/192:SHA256-192".as_ptr(),
        property_definition: DEFAULT_PROPERTIES,
        implementation: sha256_192_internal::FUNCTIONS.as_ptr() as *const c_void,
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
        algorithm_names: c"SHA2-512/224:SHA-512/224:SHA512-224:2.16.840.1.101.3.4.2.5".as_ptr(),
        property_definition: DEFAULT_PROPERTIES,
        implementation: sha512_224::FUNCTIONS.as_ptr() as *const c_void,
        algorithm_description: ptr::null(),
    },
    OsslAlgorithm {
        algorithm_names: c"SHA2-512/256:SHA-512/256:SHA512-256:2.16.840.1.101.3.4.2.6".as_ptr(),
        property_definition: DEFAULT_PROPERTIES,
        implementation: sha512_256::FUNCTIONS.as_ptr() as *const c_void,
        algorithm_description: ptr::null(),
    },
    OsslAlgorithm {
        algorithm_names: c"SHA3-224:2.16.840.1.101.3.4.2.7".as_ptr(),
        property_definition: DEFAULT_PROPERTIES,
        implementation: sha3::sha3_224::FUNCTIONS.as_ptr() as *const c_void,
        algorithm_description: ptr::null(),
    },
    OsslAlgorithm {
        algorithm_names: c"SHA3-256:2.16.840.1.101.3.4.2.8".as_ptr(),
        property_definition: DEFAULT_PROPERTIES,
        implementation: sha3::sha3_256::FUNCTIONS.as_ptr() as *const c_void,
        algorithm_description: ptr::null(),
    },
    OsslAlgorithm {
        algorithm_names: c"SHA3-384:2.16.840.1.101.3.4.2.9".as_ptr(),
        property_definition: DEFAULT_PROPERTIES,
        implementation: sha3::sha3_384::FUNCTIONS.as_ptr() as *const c_void,
        algorithm_description: ptr::null(),
    },
    OsslAlgorithm {
        algorithm_names: c"SHA3-512:2.16.840.1.101.3.4.2.10".as_ptr(),
        property_definition: DEFAULT_PROPERTIES,
        implementation: sha3::sha3_512::FUNCTIONS.as_ptr() as *const c_void,
        algorithm_description: ptr::null(),
    },
    OsslAlgorithm {
        algorithm_names: c"KECCAK-224".as_ptr(),
        property_definition: DEFAULT_PROPERTIES,
        implementation: sha3::keccak_224::FUNCTIONS.as_ptr() as *const c_void,
        algorithm_description: ptr::null(),
    },
    OsslAlgorithm {
        algorithm_names: c"KECCAK-256".as_ptr(),
        property_definition: DEFAULT_PROPERTIES,
        implementation: sha3::keccak_256::FUNCTIONS.as_ptr() as *const c_void,
        algorithm_description: ptr::null(),
    },
    OsslAlgorithm {
        algorithm_names: c"KECCAK-384".as_ptr(),
        property_definition: DEFAULT_PROPERTIES,
        implementation: sha3::keccak_384::FUNCTIONS.as_ptr() as *const c_void,
        algorithm_description: ptr::null(),
    },
    OsslAlgorithm {
        algorithm_names: c"KECCAK-512".as_ptr(),
        property_definition: DEFAULT_PROPERTIES,
        implementation: sha3::keccak_512::FUNCTIONS.as_ptr() as *const c_void,
        algorithm_description: ptr::null(),
    },
    OsslAlgorithm {
        algorithm_names: c"KECCAK-KMAC-128:KECCAK-KMAC128".as_ptr(),
        property_definition: DEFAULT_PROPERTIES,
        implementation: sha3::keccak_kmac_128::FUNCTIONS.as_ptr() as *const c_void,
        algorithm_description: ptr::null(),
    },
    OsslAlgorithm {
        algorithm_names: c"KECCAK-KMAC-256:KECCAK-KMAC256".as_ptr(),
        property_definition: DEFAULT_PROPERTIES,
        implementation: sha3::keccak_kmac_256::FUNCTIONS.as_ptr() as *const c_void,
        algorithm_description: ptr::null(),
    },
    OsslAlgorithm {
        algorithm_names: c"SHAKE-128:SHAKE128:2.16.840.1.101.3.4.2.11".as_ptr(),
        property_definition: DEFAULT_PROPERTIES,
        implementation: sha3::shake_128::FUNCTIONS.as_ptr() as *const c_void,
        algorithm_description: ptr::null(),
    },
    OsslAlgorithm {
        algorithm_names: c"SHAKE-256:SHAKE256:2.16.840.1.101.3.4.2.12".as_ptr(),
        property_definition: DEFAULT_PROPERTIES,
        implementation: sha3::shake_256::FUNCTIONS.as_ptr() as *const c_void,
        algorithm_description: ptr::null(),
    },
    OsslAlgorithm {
        algorithm_names: c"BLAKE2S-256:BLAKE2s256:1.3.6.1.4.1.1722.12.2.2.8".as_ptr(),
        property_definition: DEFAULT_PROPERTIES,
        implementation: blake2::blake2s256::FUNCTIONS.as_ptr() as *const c_void,
        algorithm_description: ptr::null(),
    },
    OsslAlgorithm {
        algorithm_names: c"BLAKE2B-512:BLAKE2b512:1.3.6.1.4.1.1722.12.2.1.16".as_ptr(),
        property_definition: DEFAULT_PROPERTIES,
        implementation: blake2::blake2b512::FUNCTIONS.as_ptr() as *const c_void,
        algorithm_description: ptr::null(),
    },
    OsslAlgorithm {
        algorithm_names: c"SM3:1.2.156.10197.1.401".as_ptr(),
        property_definition: DEFAULT_PROPERTIES,
        implementation: sm3::FUNCTIONS.as_ptr() as *const c_void,
        algorithm_description: ptr::null(),
    },
    OsslAlgorithm {
        algorithm_names: c"MD5:SSL3-MD5:1.2.840.113549.2.5".as_ptr(),
        property_definition: DEFAULT_PROPERTIES,
        implementation: md5::FUNCTIONS.as_ptr() as *const c_void,
        algorithm_description: ptr::null(),
    },
    OsslAlgorithm {
        algorithm_names: c"MD5-SHA1".as_ptr(),
        property_definition: DEFAULT_PROPERTIES,
        implementation: md5_sha1::FUNCTIONS.as_ptr() as *const c_void,
        algorithm_description: ptr::null(),
    },
    OsslAlgorithm {
        algorithm_names: c"RIPEMD-160:RIPEMD160:RIPEMD:RMD160:1.3.36.3.2.1".as_ptr(),
        property_definition: DEFAULT_PROPERTIES,
        implementation: ripemd160::FUNCTIONS.as_ptr() as *const c_void,
        algorithm_description: ptr::null(),
    },
    OsslAlgorithm {
        algorithm_names: c"NULL".as_ptr(),
        property_definition: DEFAULT_PROPERTIES,
        implementation: nullmd::FUNCTIONS.as_ptr() as *const c_void,
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
/// `providers/defltprov.c`, with the `OSSL_OP_DIGEST`, `OSSL_OP_CIPHER`, `OSSL_OP_MAC`,
/// `OSSL_OP_KDF`, `OSSL_OP_RAND`, `OSSL_OP_KEYMGMT`, `OSSL_OP_KEYEXCH` and `OSSL_OP_SKEYMGMT` arms.
///
/// The other operations the authority answers are other subphases' and are absent, not stubbed.
/// The arms are in the authority's own `switch` order (`defltprov.c:702-731`), where `SKEYMGMT` is
/// the last arm before the fall-through.
/// **The `OSSL_OP_KEYMGMT` arm is the gate D385 measured**: with no arm here the `DH`/`ECX`/KDF
/// key types cannot be fetched, so no `OSSL_OP_KEYEXCH`, `OSSL_OP_SIGNATURE`, `OSSL_OP_KEM` or
/// `OSSL_OP_ASYM_CIPHER` row is reachable — `EVP_PKEY_CTX_new_from_name(NULL, "DH", NULL)`
/// fetches the `DH` **keymgmt** row first. It answers `DEFLT_KEYMGMT` (`src/provider/keymgmt.rs`).
/// **The `OSSL_OP_CIPHER` arm answers `exported_ciphers`, not `deflt_ciphers`** — the
/// capability-filtered copy `ossl_prov_cache_exported_algorithms` fills at provider init, reached
/// through `crate::provider::cipher::exported_ciphers`. The two tables are equal while every landed
/// row's `capable` is `None`, and they stop being equal on the commit that lands the first `ALGC`
/// row (D275).
///
/// # Safety
/// `no_cache` must be writable; `provctx` is ignored by all six arms.
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
    if operation_id == crate::provider::cipher::OSSL_OP_CIPHER {
        return crate::provider::cipher::exported_ciphers();
    }
    if operation_id == crate::provider::mac::OSSL_OP_MAC {
        return crate::provider::mac::DEFLT_MACS.as_ptr();
    }
    if operation_id == crate::provider::kdf::OSSL_OP_KDF {
        return crate::provider::kdf::DEFLT_KDFS.as_ptr();
    }
    if operation_id == crate::evp::rand::OSSL_OP_RAND {
        return crate::provider::rand::DEFLT_RANDS.as_ptr();
    }
    if operation_id == crate::evp::keymgmt::OSSL_OP_KEYMGMT {
        return crate::provider::keymgmt::DEFLT_KEYMGMT.as_ptr();
    }
    if operation_id == crate::evp::exchange::OSSL_OP_KEYEXCH {
        return crate::provider::exchange::DEFLT_KEYEXCH.as_ptr();
    }
    if operation_id == crate::evp::skeymgmt::OSSL_OP_SKEYMGMT {
        return crate::provider::skeymgmt::DEFLT_SKEYMGMT.as_ptr();
    }
    if operation_id == crate::evp::kem::OSSL_OP_KEM {
        return crate::provider::kem::DEFLT_ASYM_KEM.as_ptr();
    }
    ptr::null()
}

/// `static void deflt_teardown(void *provctx)` — `providers/defltprov.c:735-739`, without its
/// `BIO_meth_free` of the core BIO method, which this crate does not build (see
/// `src/provider/ctx.rs`). Freeing the context is what keeps a provider that is registered and
/// then dropped from leaking it.
///
/// # Safety
/// The dispatch contract: `provctx` is what `ossl_default_provider_init` published.
unsafe extern "C" fn deflt_teardown(provctx: *mut c_void) {
    // SAFETY: the caller's contract; `ossl_prov_ctx_free` accepts NULL.
    unsafe { crate::provider::ctx::ossl_prov_ctx_free(provctx.cast()) };
}

/// `int ossl_default_provider_init(const OSSL_CORE_HANDLE *handle, const OSSL_DISPATCH *in,
/// const OSSL_DISPATCH **out, void **provctx)` — `providers/defltprov.c:754-807`.
///
/// **The provider context is why this function exists at all rather than publishing `NULL`.**
/// The authority's comment says it directly: "We want to make sure that all calls from this
/// provider that requires a library context use the same context as the one used to call our
/// functions. We do that by passing it along in the provider context." `PROV_LIBCTX_OF(provctx)`
/// is what `ossl_cipher_generic_initkey` stores on `ctx->libctx` and what every provider
/// sub-fetch resolves against, so a NULL context here would make a private-`OSSL_LIB_CTX`
/// application silently reach the global one. D240 recorded that as a measured obligation;
/// `RT-CIPHER`'s private-libctx arm is what takes the observation where it discriminates.
///
/// Four things the authority does are **absent, and named**:
///
/// * `ossl_prov_bio_from_dispatch(in)` / `ossl_prov_seeding_from_dispatch(in)` are the first two
///   calls in the authority's body, and their units (`providers/common/bio_prov.c` and
///   `providers/common/provider_seeding.c`) are not transcribed. What they install is the core
///   `BIO_METHOD` and the seeding callbacks, which the BIO and RAND strata need; the
///   `||`-short-circuit they form is the *only* thing skipped, and nothing in this crate's
///   landed rows reaches either callback;
/// * `ossl_bio_prov_init_bio_method()` and the `corebiometh` field it fills;
/// * `deflt_get_params`/`deflt_gettable_params` and their `OSSL_PROV_PARAM_*` keys;
/// * `ossl_prov_get_capabilities` and `ossl_prov_cache_exported_algorithms`.
///
/// All four remain the D117 residual, and `(*prov).provctx` becoming non-NULL is the part that
/// matters for correctness now: `OSSL_PROVIDER_get0_provider_ctx` on the default provider
/// answers a real context, as the authority's does.
///
/// # Safety
/// `out` and `provctx` must be writable; `handle` names the live provider and `in_` is the core
/// dispatch table the registry handed over.
pub(crate) unsafe extern "C" fn ossl_default_provider_init(
    handle: *const c_void,
    in_: *const OsslDispatch,
    out: *mut *const OsslDispatch,
    provctx: *mut *mut c_void,
) -> c_int {
    // SAFETY: `in_` is the core's own terminated table; every entry read is within it.
    unsafe {
        if out.is_null() || provctx.is_null() {
            return 0;
        }

        // The authority's first two statements are `ossl_prov_bio_from_dispatch(in) ||
        // ossl_prov_seeding_from_dispatch(in)`, and **the seeding half is load-bearing**: it
        // records the eight `OSSL_FUNC_{GET,CLEANUP}_{USER_,}{ENTROPY,NONCE}` callbacks this
        // crate now publishes, and without them a DRBG's instantiate cannot get a nonce or
        // entropy — it is refused with `PROV_R_ERROR_RETRIEVING_NONCE`/`..._ENTROPY`.
        // `ossl_prov_bio_from_dispatch` remains absent: it installs the core `BIO_METHOD`, and
        // this crate builds no provider-side BIO method (see the `deflt_teardown` note above).
        // Failing here would abort provider activation, so the answer is checked as the
        // authority checks it.
        if crate::provider::seeding::ossl_prov_seeding_from_dispatch(in_) == 0 {
            return 0;
        }

        let mut c_get_libctx: *const c_void = ptr::null();
        let mut c_get_params: *const c_void = ptr::null();
        let mut d = in_;
        while !d.is_null() && (*d).function_id != OSSL_DISPATCH_END {
            match (*d).function_id {
                crate::provider::core_dispatch::FUNC_CORE_GET_PARAMS => {
                    c_get_params = (*d).function
                }
                crate::provider::core_dispatch::FUNC_CORE_GET_LIBCTX => {
                    c_get_libctx = (*d).function
                }
                _ => {} // Just ignore anything we don't understand
            }
            d = d.add(1);
        }

        if c_get_libctx.is_null() {
            return 0;
        }

        let ctx = crate::provider::ctx::ossl_prov_ctx_new();
        if ctx.is_null() {
            return 0;
        }
        // SAFETY: `c_get_libctx` is the core's own `OSSL_FUNC_core_get_libctx_fn`, which the
        // registry published with this exact signature, and `handle` is the provider it expects.
        let get_libctx: unsafe extern "C" fn(*const c_void) -> *mut c_void =
            core::mem::transmute(c_get_libctx);
        let libctx = get_libctx(handle);

        crate::provider::ctx::ossl_prov_ctx_set0_libctx(ctx, libctx);
        crate::provider::ctx::ossl_prov_ctx_set0_handle(ctx, handle);
        crate::provider::ctx::ossl_prov_ctx_set0_core_get_params(ctx, c_get_params.cast_mut());

        // `ossl_prov_cache_exported_algorithms(deflt_ciphers, exported_ciphers)` --
        // `defltprov.c:804`, and **this is the ordering the call has to keep**: the filter reads
        // each row's capability predicate, and `deflt_query`'s `OSSL_OP_CIPHER` arm answers the
        // destination. Filling it here rather than lazily in the query is the authority's own
        // choice and the one that avoids a data race, because the write precedes the provider
        // being published to the core.
        // SAFETY: this is the single writer, and it runs before `*out` is assigned below.
        crate::provider::cipher::cache_exported_ciphers();

        *out = DEFLT_DISPATCH.as_ptr();
        *provctx = ctx.cast();
    }
    1
}

/// `deflt_dispatch_table` — `providers/defltprov.c`, restricted to the two entries reachable
/// without the provider-params and cache halves. The authority also publishes
/// `GETTABLE_PARAMS`, `GET_PARAMS` and `GET_CAPABILITIES`; those are the D117 residual named
/// above, and they are absent rather than stubbed.
static DEFLT_DISPATCH: [OsslDispatch; 3] = [
    OsslDispatch {
        function_id: FUNC_PROVIDER_QUERY_OPERATION,
        function: deflt_query as *mut c_void,
    },
    OsslDispatch {
        function_id: crate::provider::init::FUNC_PROVIDER_TEARDOWN,
        function: deflt_teardown as *mut c_void,
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
        assert!(!unsafe { (*table).algorithm_names.is_null() });
        let mut n = 0usize;
        loop {
            // SAFETY: every entry up to the terminator is initialised, and `n` walks in bounds
            // until the terminator is read.
            let names = unsafe { (*table.add(n)).algorithm_names };
            if names.is_null() {
                break;
            }
            n += 1;
        }
        assert_eq!(
            n, 27,
            "the twenty-seven default-provider digest rows 8.1 has landed"
        );

        // SAFETY: the query's contract; an operation no arm answers. `OSSL_OP_HIGHEST` (22) is the
        // authority's own max sentinel and is not an operation any provider publishes.
        let none = unsafe {
            deflt_query(
                ptr::null_mut(),
                crate::evp::algorithm::OSSL_OP_HIGHEST,
                &mut no_cache,
            )
        };
        assert!(
            none.is_null(),
            "only OSSL_OP_DIGEST, OSSL_OP_CIPHER, OSSL_OP_MAC, OSSL_OP_KDF, OSSL_OP_RAND, \
             OSSL_OP_KEYMGMT, OSSL_OP_KEYEXCH, OSSL_OP_KEM and OSSL_OP_SKEYMGMT are answered"
        );

        // The cipher half answers too, and its table starts at `deflt_ciphers[]`'s first row.
        // SAFETY: the query's contract; `provctx` is NULL and this arm ignores it.
        let ciphers = unsafe {
            deflt_query(
                ptr::null_mut(),
                crate::provider::cipher::OSSL_OP_CIPHER,
                &mut no_cache,
            )
        };
        assert!(!ciphers.is_null());
        // SAFETY: the returned table's first row is initialised.
        let first = unsafe { core::ffi::CStr::from_ptr((*ciphers).algorithm_names) };
        assert_eq!(first.to_bytes(), b"NULL");

        // The RAND arm answers `deflt_rands[]`, whose first row is CTR-DRBG.
        // SAFETY: the query's contract; `provctx` is NULL and this arm ignores it.
        let rands = unsafe {
            deflt_query(
                ptr::null_mut(),
                crate::evp::rand::OSSL_OP_RAND,
                &mut no_cache,
            )
        };
        assert!(!rands.is_null());
        // SAFETY: the returned table's first row is initialised.
        let first = unsafe { core::ffi::CStr::from_ptr((*rands).algorithm_names) };
        assert_eq!(first.to_bytes(), b"CTR-DRBG");

        // The KEYMGMT arm answers `deflt_keymgmt[]`, whose first landed row is the `DH` key type
        // (D387; the authority's `deflt_keymgmt[]` puts `DH` and `DHX` first).
        // SAFETY: the query's contract; `provctx` is NULL and this arm ignores it.
        let keymgmts = unsafe {
            deflt_query(
                ptr::null_mut(),
                crate::evp::keymgmt::OSSL_OP_KEYMGMT,
                &mut no_cache,
            )
        };
        assert!(!keymgmts.is_null());
        // SAFETY: the returned table's first row is initialised.
        let first = unsafe { core::ffi::CStr::from_ptr((*keymgmts).algorithm_names) };
        assert_eq!(first.to_bytes(), b"DH:dhKeyAgreement:1.2.840.113549.1.3.1");

        // The KEYEXCH arm answers `deflt_keyexch[]`, whose first landed row is the `DH` exchange
        // (D387).
        // SAFETY: the query's contract; `provctx` is NULL and this arm ignores it.
        let keyexchs = unsafe {
            deflt_query(
                ptr::null_mut(),
                crate::evp::exchange::OSSL_OP_KEYEXCH,
                &mut no_cache,
            )
        };
        assert!(!keyexchs.is_null());
        // SAFETY: the returned table's first row is initialised.
        let first = unsafe { core::ffi::CStr::from_ptr((*keyexchs).algorithm_names) };
        assert_eq!(first.to_bytes(), b"DH:dhKeyAgreement:1.2.840.113549.1.3.1");

        // The KEM arm answers `deflt_asym_kem[]`, whose first landed row is the `X25519` DHKEM
        // (this pass; the authority's `deflt_asym_kem[]` puts `RSA` first and `X25519` next).
        // SAFETY: the query's contract; `provctx` is NULL and this arm ignores it.
        let kems =
            unsafe { deflt_query(ptr::null_mut(), crate::evp::kem::OSSL_OP_KEM, &mut no_cache) };
        assert!(!kems.is_null());
        // SAFETY: the returned table's first row is initialised.
        let first = unsafe { core::ffi::CStr::from_ptr((*kems).algorithm_names) };
        assert_eq!(first.to_bytes(), b"X25519:1.3.101.110");

        // The SKEYMGMT arm answers `deflt_skeymgmt[]`, whose first row is the AES key type.
        // SAFETY: the query's contract; `provctx` is NULL and this arm ignores it.
        let skeymgmts = unsafe {
            deflt_query(
                ptr::null_mut(),
                crate::evp::skeymgmt::OSSL_OP_SKEYMGMT,
                &mut no_cache,
            )
        };
        assert!(!skeymgmts.is_null());
        // SAFETY: the returned table's first row is initialised.
        let first = unsafe { core::ffi::CStr::from_ptr((*skeymgmts).algorithm_names) };
        assert_eq!(first.to_bytes(), b"AES:2.16.840.1.101.3.4.1");
    }

    #[test]
    fn the_default_init_publishes_the_query_entry() {
        let mut out: *const OsslDispatch = ptr::null();
        let mut sentinel: c_int = 1;
        let mut provctx: *mut c_void = ptr::addr_of_mut!(sentinel).cast::<c_void>();

        // The authority's init returns 0 when the core did not offer `CORE_GET_LIBCTX`, which is
        // the one lookup it cannot do without: every provider sub-fetch resolves against the
        // context it yields. That arm is checked first because it is the reason this function was
        // not a `*provctx = NULL` assignment any more.
        //
        // The table is a real, terminated one rather than NULL: the init's **first** statement is
        // the seeding walk (`ossl_prov_seeding_from_dispatch`), and a NULL there is a dereference
        // the authority would also make. The walk needs a table; the refusal needs one without
        // `CORE_GET_LIBCTX`.
        static CORE_IN_NO_LIBCTX: [OsslDispatch; 1] = [OsslDispatch {
            function_id: OSSL_DISPATCH_END,
            function: ptr::null_mut(),
        }];
        // SAFETY: both slots are this frame's and writable; the table above is `'static`.
        let refused = unsafe {
            ossl_default_provider_init(
                ptr::null(),
                CORE_IN_NO_LIBCTX.as_ptr(),
                &mut out,
                &mut provctx,
            )
        };
        assert_eq!(refused, 0, "a core with no CORE_GET_LIBCTX is refused");

        // Now a core that does offer it. The two callbacks are this test's own, so the assertion
        // is about the *plumbing* rather than about the registry: what the init must do is call
        // `CORE_GET_LIBCTX` and store its answer.
        static MARKER: u8 = 0;
        /// The core's `OSSL_FUNC_core_get_libctx_fn`, returning a known address.
        ///
        /// # Safety
        /// The handle is unused; the answer is a `'static` address.
        unsafe extern "C" fn test_get_libctx(_handle: *const c_void) -> *mut c_void {
            ptr::addr_of!(MARKER).cast_mut().cast::<c_void>()
        }
        /// The core's `OSSL_FUNC_core_get_params_fn`, which this half never calls.
        ///
        /// # Safety
        /// Both arguments are unused.
        unsafe extern "C" fn test_get_params(
            _handle: *const c_void,
            _params: *mut OsslParam,
        ) -> c_int {
            1
        }
        static CORE_IN: [OsslDispatch; 3] = [
            OsslDispatch {
                function_id: crate::provider::core_dispatch::FUNC_CORE_GET_LIBCTX,
                function: test_get_libctx as *mut c_void,
            },
            OsslDispatch {
                function_id: crate::provider::core_dispatch::FUNC_CORE_GET_PARAMS,
                function: test_get_params as *mut c_void,
            },
            OsslDispatch {
                function_id: OSSL_DISPATCH_END,
                function: ptr::null_mut(),
            },
        ];

        let mut out: *const OsslDispatch = ptr::null();
        let mut provctx: *mut c_void = ptr::null_mut();
        // SAFETY: both slots are this frame's and writable; `CORE_IN` is `'static`; the handle is
        // ignored by both test callbacks.
        let ok = unsafe {
            ossl_default_provider_init(ptr::null(), CORE_IN.as_ptr(), &mut out, &mut provctx)
        };
        assert_eq!(ok, 1);
        assert!(!provctx.is_null(), "the context is published, not NULL");
        // The context carries whatever `CORE_GET_LIBCTX` answered, which is the whole point.
        // SAFETY: `provctx` is the `PROV_CTX` the call just published, and `MARKER` is `'static`.
        unsafe {
            assert_eq!(
                crate::provider::ctx::prov_libctx_of(provctx),
                test_get_libctx(ptr::null())
            );
            assert_eq!(
                crate::provider::ctx::ossl_prov_ctx_get0_core_get_params(provctx.cast()),
                test_get_params as *mut c_void
            );
            // The published context is freed the way the teardown entry would.
            crate::provider::ctx::ossl_prov_ctx_free(provctx.cast());
        }
        // SAFETY: `out` is the published `'static` table; query, then teardown, then the end.
        unsafe {
            assert_eq!((*out).function_id, FUNC_PROVIDER_QUERY_OPERATION);
            assert_eq!(
                (*out.add(1)).function_id,
                crate::provider::init::FUNC_PROVIDER_TEARDOWN
            );
            assert_eq!((*out.add(2)).function_id, OSSL_DISPATCH_END);
        }
    }

    #[test]
    fn sha256_provider_reports_the_size_and_blocksize_it_has() {
        let mut size: usize = 0;
        let mut block: usize = 0;
        let mut params: [OsslParam; 3] = [END; 3];
        // SAFETY: `size` is this frame's own slot and the constructor only records its address.
        params[0] = unsafe {
            crate::params::OSSL_PARAM_construct_size_t(OSSL_DIGEST_PARAM_SIZE, &mut size)
        };
        // SAFETY: `block` is this frame's own slot and the constructor only records its address.
        params[1] = unsafe {
            crate::params::OSSL_PARAM_construct_size_t(OSSL_DIGEST_PARAM_BLOCK_SIZE, &mut block)
        };
        // SAFETY: the array is terminated and its buffers are this frame's.
        let ok = unsafe { ossl_digest_default_get_params(params.as_mut_ptr(), 64, 32, 2) };
        assert_eq!(ok, 1);
        assert_eq!((size, block), (32, 64));
    }

    /// A `GET_PARAMS` stand-in that answers 0, so a row missing the callback fails the
    /// assertion below rather than the test panicking (which the crate's lints forbid).
    unsafe extern "C" fn no_get_params(_params: *mut OsslParam) -> c_int {
        0
    }

    /// The rows 8.1's second half adds must carry `prov/names.h`'s alias list verbatim and
    /// report the sizes the header constants give them. This reads `DEFLT_DIGESTS` directly
    /// rather than fetching, because a fetch sweeps every activated provider in the default
    /// context and a unit test that does so depends on which sibling test ran before it.
    #[test]
    fn the_added_rows_publish_the_names_and_sizes() {
        // (full algorithm_names string, blocksize, size)
        let want: [(&str, usize, usize); 27] = [
            ("SHA1:SHA-1:SSL3-SHA1:1.3.14.3.2.26", 64, 20),
            ("SHA2-224:SHA-224:SHA224:2.16.840.1.101.3.4.2.4", 64, 28),
            ("SHA2-256:SHA-256:SHA256:2.16.840.1.101.3.4.2.1", 64, 32),
            ("SHA2-256/192:SHA-256/192:SHA256-192", 64, 24),
            ("SHA2-384:SHA-384:SHA384:2.16.840.1.101.3.4.2.2", 128, 48),
            ("SHA2-512:SHA-512:SHA512:2.16.840.1.101.3.4.2.3", 128, 64),
            (
                "SHA2-512/224:SHA-512/224:SHA512-224:2.16.840.1.101.3.4.2.5",
                128,
                28,
            ),
            (
                "SHA2-512/256:SHA-512/256:SHA512-256:2.16.840.1.101.3.4.2.6",
                128,
                32,
            ),
            ("SHA3-224:2.16.840.1.101.3.4.2.7", 144, 28),
            ("SHA3-256:2.16.840.1.101.3.4.2.8", 136, 32),
            ("SHA3-384:2.16.840.1.101.3.4.2.9", 104, 48),
            ("SHA3-512:2.16.840.1.101.3.4.2.10", 72, 64),
            ("KECCAK-224", 144, 28),
            ("KECCAK-256", 136, 32),
            ("KECCAK-384", 104, 48),
            ("KECCAK-512", 72, 64),
            ("KECCAK-KMAC-128:KECCAK-KMAC128", 168, 32),
            ("KECCAK-KMAC-256:KECCAK-KMAC256", 136, 64),
            ("SHAKE-128:SHAKE128:2.16.840.1.101.3.4.2.11", 168, 0),
            ("SHAKE-256:SHAKE256:2.16.840.1.101.3.4.2.12", 136, 0),
            ("BLAKE2S-256:BLAKE2s256:1.3.6.1.4.1.1722.12.2.2.8", 64, 32),
            ("BLAKE2B-512:BLAKE2b512:1.3.6.1.4.1.1722.12.2.1.16", 128, 64),
            ("SM3:1.2.156.10197.1.401", 64, 32),
            ("MD5:SSL3-MD5:1.2.840.113549.2.5", 64, 16),
            ("MD5-SHA1", 64, 36),
            ("RIPEMD-160:RIPEMD160:RIPEMD:RMD160:1.3.36.3.2.1", 64, 20),
            ("NULL", 0, 0),
        ];
        for (i, (names, block, size)) in want.iter().enumerate() {
            let row = &DEFLT_DIGESTS[i];
            // SAFETY: every row's `algorithm_names` is a NUL-terminated literal and the loop runs
            // over the eleven rows the terminator does not end.
            let got = unsafe { core::ffi::CStr::from_ptr(row.algorithm_names) };
            assert_eq!(got.to_str(), Ok(*names), "row {i}");

            // Locate `OSSL_FUNC_DIGEST_GET_PARAMS` in the row's dispatch table and call it.
            let mut disp = row.implementation.cast::<OsslDispatch>();
            let mut get_params: Option<unsafe extern "C" fn(*mut OsslParam) -> c_int> = None;
            // SAFETY: the table is terminated; every entry before the terminator is readable.
            unsafe {
                while (*disp).function_id != OSSL_DISPATCH_END {
                    if (*disp).function_id == OSSL_FUNC_DIGEST_GET_PARAMS {
                        get_params = Some(core::mem::transmute::<
                            *mut c_void,
                            unsafe extern "C" fn(*mut OsslParam) -> c_int,
                        >((*disp).function));
                    }
                    disp = disp.add(1);
                }
            }
            let mut got_size: usize = 0;
            let mut got_block: usize = 0;
            let mut params: [OsslParam; 3] = [END; 3];
            // SAFETY: both slots are this frame's and the constructor records their addresses.
            unsafe {
                params[0] = crate::params::OSSL_PARAM_construct_size_t(
                    OSSL_DIGEST_PARAM_SIZE,
                    &mut got_size,
                );
                params[1] = crate::params::OSSL_PARAM_construct_size_t(
                    OSSL_DIGEST_PARAM_BLOCK_SIZE,
                    &mut got_block,
                );
            }
            let f = get_params.unwrap_or(no_get_params);
            // SAFETY: the callback's contract is `ossl_digest_default_get_params`'s, and the
            // params array is terminated with this frame's buffers.
            assert_eq!(unsafe { f(params.as_mut_ptr()) }, 1, "row {i} GET_PARAMS");
            assert_eq!((got_block, got_size), (*block, *size), "row {i} sizes");
        }
    }
}
