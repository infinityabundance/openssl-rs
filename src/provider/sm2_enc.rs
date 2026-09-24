//! Phase 8 — `providers/implementations/asymciphers/sm2_enc.c`: the `SM2`
//! `OSSL_OP_ASYM_CIPHER` row.
//!
//! Two hundred and forty template lines, one dispatch table, and the encryption face of the `SM2`
//! key object the `EC`/`SM2` key management row `src/provider/ec_kmgmt.rs` publishes (D389). The
//! context holds an `EC_KEY` borrow, the library context, and a `PROV_DIGEST` — the digest
//! parameter is a *name* the row fetches in its own library context, and it defaults to `SM3` when
//! unset.
//!
//! ## It is a thin face over `crypto/sm2/sm2_crypt.c`
//!
//! Every operation is one call: `sm2_asym_encrypt` is `ossl_sm2_ciphertext_size` on the size query
//! and `ossl_sm2_encrypt` otherwise, `sm2_asym_decrypt` is `ossl_sm2_plaintext_size` then
//! `ossl_sm2_decrypt`. The size-query arms are the ones that raise: `ossl_sm2_ciphertext_size`
//! answering 0 becomes the `PROV_R_INVALID_KEY` refusal at `sm2_enc.c:98`; the decrypt size query
//! returns `ossl_sm2_plaintext_size`'s own answer (and its `SM2_R_INVALID_ENCODING`) unchanged.
//!
//! ## The two decoders are the crate's repeated-key scan
//!
//! `util/perl/OpenSSL/paramnames.pm` emits a `switch` trie over each parameter's key whose whole
//! observable content is the repeated-key refusal at the parameter's own coordinate. The two
//! decoders here are the scan plus the located pointer, the shape `src/provider/rsa_enc.rs` uses,
//! with the coordinates read back from the generated tree (`PROV_SM2_ENC_188`, `:259`, `:270`,
//! `:281`). The settable list omits `engine` — it is the generated `'hidden'` key.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_char, c_int, c_void, CStr};
use core::ptr;

use crate::context::dispatch::{OsslDispatch, OSSL_DISPATCH_END};
use crate::ec::key::{EC_KEY_free, EC_KEY_up_ref};
use crate::ec::EcKey;
use crate::evp::asymcipher::{
    OSSL_FUNC_ASYM_CIPHER_DECRYPT, OSSL_FUNC_ASYM_CIPHER_DECRYPT_INIT,
    OSSL_FUNC_ASYM_CIPHER_DUPCTX, OSSL_FUNC_ASYM_CIPHER_ENCRYPT,
    OSSL_FUNC_ASYM_CIPHER_ENCRYPT_INIT, OSSL_FUNC_ASYM_CIPHER_FREECTX,
    OSSL_FUNC_ASYM_CIPHER_GETTABLE_CTX_PARAMS, OSSL_FUNC_ASYM_CIPHER_GET_CTX_PARAMS,
    OSSL_FUNC_ASYM_CIPHER_NEWCTX, OSSL_FUNC_ASYM_CIPHER_SETTABLE_CTX_PARAMS,
    OSSL_FUNC_ASYM_CIPHER_SET_CTX_PARAMS,
};
use crate::evp::digest::EVP_MD_get0_name;
use crate::params::{OSSL_PARAM_set_utf8_string, OsslParam, END};
use crate::provider::cipher::param_utf8_string;
use crate::provider::ctx::prov_libctx_of;
use crate::provider::util::prov_digest::{
    ossl_prov_digest_copy, ossl_prov_digest_fetch, ossl_prov_digest_load, ossl_prov_digest_md,
    ossl_prov_digest_reset, ProvDigest,
};
use crate::runtime::err::{err_sites, raise_site};
use crate::runtime::mem::{CRYPTO_free, CRYPTO_zalloc};
use crate::sm2::crypt::{
    ossl_sm2_ciphertext_size, ossl_sm2_decrypt, ossl_sm2_encrypt, ossl_sm2_plaintext_size,
};

/// The unit's own `__FILE__`. `sm2_enc.c` is `.c.in`-generated, so the build compiles it from the
/// build tree and the compiler records the bare path (D235's finding).
const FILE: *const c_char = c"providers/implementations/asymciphers/sm2_enc.c".as_ptr();

/// `OSSL_ASYM_CIPHER_PARAM_DIGEST` — `core_names.h`.
const OSSL_ASYM_CIPHER_PARAM_DIGEST: *const c_char = c"digest".as_ptr();

/// `OSSL_ASYM_CIPHER_PARAM_PROPERTIES` — `core_names.h`.
const OSSL_ASYM_CIPHER_PARAM_PROPERTIES: *const c_char = c"properties".as_ptr();

/// `OSSL_ASYM_CIPHER_PARAM_ENGINE` is the generated `'hidden'` key; the decoder matches its name
/// by bytes, so no constant is needed for it.
/// `PROV_SM2_CTX` — `sm2_enc.c:49-53`.
#[repr(C)]
struct ProvSm2Ctx {
    /// `OSSL_LIB_CTX *libctx`.
    libctx: *mut c_void,
    /// `EC_KEY *key` — a borrow carrying a reference.
    key: *mut EcKey,
    /// `PROV_DIGEST md`.
    md: ProvDigest,
}

/// `static void *sm2_newctx(void *provctx)` — `sm2_enc.c:55-64`.
///
/// # Safety
/// The asym_cipher `newctx` dispatch contract.
unsafe extern "C" fn sm2_newctx(provctx: *mut c_void) -> *mut c_void {
    // SAFETY: a fresh zeroed allocation of this call's own context.
    let ctx = CRYPTO_zalloc(core::mem::size_of::<ProvSm2Ctx>(), FILE, 57).cast::<ProvSm2Ctx>();
    if ctx.is_null() {
        return ptr::null_mut();
    }

    // SAFETY: `ctx` is this call's own allocation.
    unsafe {
        (*ctx).libctx = prov_libctx_of(provctx);
    }

    ctx.cast()
}

/// `static int sm2_init(void *vpsm2ctx, void *vkey, const OSSL_PARAM params[])` —
/// `sm2_enc.c:66-76`. One body for both the encrypt and decrypt inits.
///
/// # Safety
/// The asym_cipher init dispatch contract.
unsafe extern "C" fn sm2_init(
    vpsm2ctx: *mut c_void,
    vkey: *mut c_void,
    params: *const OsslParam,
) -> c_int {
    let psm2ctx = vpsm2ctx.cast::<ProvSm2Ctx>();

    // SAFETY: `psm2ctx` is NULL or the caller's context; `vkey` is NULL or the caller's key.
    unsafe {
        if psm2ctx.is_null() {
            return 0;
        }
        if vkey.is_null() || EC_KEY_up_ref(vkey.cast::<EcKey>()) == 0 {
            return 0;
        }
        EC_KEY_free((*psm2ctx).key);
        (*psm2ctx).key = vkey.cast::<EcKey>();

        sm2_set_ctx_params(vpsm2ctx, params)
    }
}

/// `static const EVP_MD *sm2_get_md(PROV_SM2_CTX *psm2ctx)` — `sm2_enc.c:78-86`. The digest
/// defaults to `SM3` and is fetched, not looked up, in the row's own library context.
///
/// # Safety
/// `psm2ctx` is live.
unsafe fn sm2_get_md(psm2ctx: *mut ProvSm2Ctx) -> *const crate::evp::digest::EvpMd {
    // SAFETY: the caller's contract.
    unsafe {
        let mut md = ossl_prov_digest_md(ptr::addr_of!((*psm2ctx).md));
        if md.is_null() {
            md = ossl_prov_digest_fetch(
                ptr::addr_of_mut!((*psm2ctx).md),
                (*psm2ctx).libctx,
                c"SM3".as_ptr(),
                ptr::null(),
            );
        }
        md
    }
}

/// `static int sm2_asym_encrypt(...)` — `sm2_enc.c:88-107`.
///
/// # Safety
/// The asym_cipher `encrypt` dispatch contract.
unsafe extern "C" fn sm2_asym_encrypt(
    vpsm2ctx: *mut c_void,
    out: *mut u8,
    outlen: *mut usize,
    _outsize: usize,
    in_: *const u8,
    inlen: usize,
) -> c_int {
    let psm2ctx = vpsm2ctx.cast::<ProvSm2Ctx>();

    // SAFETY: the dispatch contract; the unit's own context is live.
    unsafe {
        let md = sm2_get_md(psm2ctx);
        if md.is_null() {
            return 0;
        }

        if out.is_null() {
            if ossl_sm2_ciphertext_size((*psm2ctx).key, md, inlen, outlen) == 0 {
                raise_site(&err_sites::PROV_SM2_ENC_98);
                return 0;
            }
            return 1;
        }

        ossl_sm2_encrypt((*psm2ctx).key, md, in_, inlen, out, outlen)
    }
}

/// `static int sm2_asym_decrypt(...)` — `sm2_enc.c:109-126`.
///
/// # Safety
/// The asym_cipher `decrypt` dispatch contract.
unsafe extern "C" fn sm2_asym_decrypt(
    vpsm2ctx: *mut c_void,
    out: *mut u8,
    outlen: *mut usize,
    _outsize: usize,
    in_: *const u8,
    inlen: usize,
) -> c_int {
    let psm2ctx = vpsm2ctx.cast::<ProvSm2Ctx>();

    // SAFETY: the dispatch contract; the unit's own context is live.
    unsafe {
        let md = sm2_get_md(psm2ctx);
        if md.is_null() {
            return 0;
        }

        if out.is_null() {
            if ossl_sm2_plaintext_size(in_, inlen, outlen) == 0 {
                return 0;
            }
            return 1;
        }

        ossl_sm2_decrypt((*psm2ctx).key, md, in_, inlen, out, outlen)
    }
}

/// `static void sm2_freectx(void *vpsm2ctx)` — `sm2_enc.c:128-136`.
///
/// # Safety
/// The asym_cipher `freectx` dispatch contract.
unsafe extern "C" fn sm2_freectx(vpsm2ctx: *mut c_void) {
    let psm2ctx = vpsm2ctx.cast::<ProvSm2Ctx>();

    // SAFETY: `psm2ctx` is the caller's context.
    unsafe {
        EC_KEY_free((*psm2ctx).key);
        ossl_prov_digest_reset(ptr::addr_of_mut!((*psm2ctx).md));

        CRYPTO_free(psm2ctx.cast(), FILE, 135);
    }
}

/// `static void *sm2_dupctx(void *vpsm2ctx)` — `sm2_enc.c:138-161`.
///
/// # Safety
/// The asym_cipher `dupctx` dispatch contract.
unsafe extern "C" fn sm2_dupctx(vpsm2ctx: *mut c_void) -> *mut c_void {
    let srcctx = vpsm2ctx.cast::<ProvSm2Ctx>();

    // SAFETY: `srcctx` is the caller's context.
    unsafe {
        let dstctx =
            CRYPTO_zalloc(core::mem::size_of::<ProvSm2Ctx>(), FILE, 143).cast::<ProvSm2Ctx>();
        if dstctx.is_null() {
            return ptr::null_mut();
        }

        ptr::copy_nonoverlapping(srcctx, dstctx, 1);
        (*dstctx).md = ProvDigest {
            md: ptr::null(),
            alloc_md: ptr::null_mut(),
            engine: ptr::null_mut(),
        };

        if !(*dstctx).key.is_null() && EC_KEY_up_ref((*dstctx).key) == 0 {
            CRYPTO_free(dstctx.cast(), FILE, 152);
            return ptr::null_mut();
        }

        if ossl_prov_digest_copy(ptr::addr_of_mut!((*dstctx).md), ptr::addr_of!((*srcctx).md)) == 0
        {
            sm2_freectx(dstctx.cast());
            return ptr::null_mut();
        }

        dstctx.cast()
    }
}

/// `struct sm2_get_ctx_params_st` — the `produce_param_decoder` expansion at `sm2_enc.c:170-174`.
#[derive(Clone, Copy)]
struct GetCtxParams {
    digest: *const OsslParam,
}

/// `sm2_get_ctx_params_decoder` — the generated get decoder (`sm2_enc.c:176-196`).
///
/// # Safety
/// `params` is NULL or a key-terminated array.
unsafe fn sm2_get_ctx_params_decoder(params: *const OsslParam) -> Option<GetCtxParams> {
    let mut r = GetCtxParams {
        digest: ptr::null(),
    };

    if params.is_null() {
        return Some(r);
    }

    // SAFETY: the walk stops at the NULL key.
    unsafe {
        let mut p = params;
        while !(*p).key.is_null() {
            let s = CStr::from_ptr((*p).key).to_bytes();
            if s == b"digest" {
                if !r.digest.is_null() {
                    raise_site(&err_sites::PROV_SM2_ENC_188);
                    return None;
                }
                r.digest = p;
            }
            p = p.add(1);
        }
    }

    Some(r)
}

/// `static const OSSL_PARAM sm2_get_ctx_params_list[]` — `sm2_enc.c:163-168`.
static SM2_GET_CTX_PARAMS_LIST: [OsslParam; 2] =
    [param_utf8_string(OSSL_ASYM_CIPHER_PARAM_DIGEST), END];

/// `static int sm2_get_ctx_params(void *vpsm2ctx, OSSL_PARAM *params)` — `sm2_enc.c:200-217`.
///
/// # Safety
/// The asym_cipher `get_ctx_params` dispatch contract.
unsafe extern "C" fn sm2_get_ctx_params(vpsm2ctx: *mut c_void, params: *mut OsslParam) -> c_int {
    let psm2ctx = vpsm2ctx.cast::<ProvSm2Ctx>();

    // SAFETY: `psm2ctx` is NULL or the caller's context; `params` is a terminated array.
    unsafe {
        if psm2ctx.is_null() {
            return 0;
        }
        let Some(p) = sm2_get_ctx_params_decoder(params) else {
            return 0;
        };

        if !p.digest.is_null() {
            let md = ossl_prov_digest_md(ptr::addr_of!((*psm2ctx).md));
            let name = if md.is_null() {
                c"".as_ptr()
            } else {
                EVP_MD_get0_name(md)
            };
            if OSSL_PARAM_set_utf8_string(p.digest.cast_mut(), name) == 0 {
                return 0;
            }
        }

        1
    }
}

/// `static const OSSL_PARAM *sm2_gettable_ctx_params(void *vpsm2ctx, void *provctx)` —
/// `sm2_enc.c:219-223`.
///
/// # Safety
/// The asym_cipher `gettable_ctx_params` dispatch contract.
unsafe extern "C" fn sm2_gettable_ctx_params(
    _vpsm2ctx: *mut c_void,
    _provctx: *mut c_void,
) -> *const OsslParam {
    SM2_GET_CTX_PARAMS_LIST.as_ptr()
}

/// `struct sm2_set_ctx_params_st` — the `produce_param_decoder` expansion at `sm2_enc.c:235-241`.
#[derive(Clone, Copy)]
struct SetCtxParams {
    digest: *const OsslParam,
    engine: *const OsslParam,
    propq: *const OsslParam,
}

/// `sm2_set_ctx_params_decoder` — the generated set decoder (`sm2_enc.c:243-290`). The `switch` the
/// generator emits is over the key's first byte; it is written here as the three full-name tests it
/// is equivalent to, and the repeated-key refusal at each name's own coordinate is preserved.
///
/// # Safety
/// `params` is NULL or a key-terminated array.
unsafe fn sm2_set_ctx_params_decoder(params: *const OsslParam) -> Option<SetCtxParams> {
    let mut r = SetCtxParams {
        digest: ptr::null(),
        engine: ptr::null(),
        propq: ptr::null(),
    };

    if params.is_null() {
        return Some(r);
    }

    // SAFETY: the walk stops at the NULL key.
    unsafe {
        let mut p = params;
        while !(*p).key.is_null() {
            let s = CStr::from_ptr((*p).key).to_bytes();
            match s {
                b"digest" => {
                    if !r.digest.is_null() {
                        raise_site(&err_sites::PROV_SM2_ENC_259);
                        return None;
                    }
                    r.digest = p;
                }
                b"engine" => {
                    if !r.engine.is_null() {
                        raise_site(&err_sites::PROV_SM2_ENC_270);
                        return None;
                    }
                    r.engine = p;
                }
                b"properties" => {
                    if !r.propq.is_null() {
                        raise_site(&err_sites::PROV_SM2_ENC_281);
                        return None;
                    }
                    r.propq = p;
                }
                _ => {}
            }
            p = p.add(1);
        }
    }

    Some(r)
}

/// `static const OSSL_PARAM sm2_set_ctx_params_list[]` — `sm2_enc.c:227-232`, without the generated
/// `'hidden'` `engine` key.
static SM2_SET_CTX_PARAMS_LIST: [OsslParam; 3] = [
    param_utf8_string(OSSL_ASYM_CIPHER_PARAM_DIGEST),
    param_utf8_string(OSSL_ASYM_CIPHER_PARAM_PROPERTIES),
    END,
];

/// `static int sm2_set_ctx_params(void *vpsm2ctx, const OSSL_PARAM params[])` —
/// `sm2_enc.c:294-311`.
///
/// # Safety
/// The asym_cipher `set_ctx_params` dispatch contract.
unsafe extern "C" fn sm2_set_ctx_params(vpsm2ctx: *mut c_void, params: *const OsslParam) -> c_int {
    let psm2ctx = vpsm2ctx.cast::<ProvSm2Ctx>();

    // SAFETY: `psm2ctx` is NULL or the caller's context; `params` is a terminated array.
    unsafe {
        if psm2ctx.is_null() {
            return 0;
        }
        let Some(p) = sm2_set_ctx_params_decoder(params) else {
            return 0;
        };

        if ossl_prov_digest_load(
            ptr::addr_of_mut!((*psm2ctx).md),
            p.digest,
            p.propq,
            p.engine,
            (*psm2ctx).libctx,
        ) == 0
        {
            return 0;
        }

        1
    }
}

/// `static const OSSL_PARAM *sm2_settable_ctx_params(void *vpsm2ctx, void *provctx)` —
/// `sm2_enc.c:313-319`.
///
/// # Safety
/// The asym_cipher `settable_ctx_params` dispatch contract.
unsafe extern "C" fn sm2_settable_ctx_params(
    _vpsm2ctx: *mut c_void,
    _provctx: *mut c_void,
) -> *const OsslParam {
    SM2_SET_CTX_PARAMS_LIST.as_ptr()
}

/// `const OSSL_DISPATCH ossl_sm2_asym_cipher_functions[]` — `sm2_enc.c:223-240`.
pub(crate) static SM2_ASYM_CIPHER_FUNCTIONS: [OsslDispatch; 12] = [
    OsslDispatch {
        function_id: OSSL_FUNC_ASYM_CIPHER_NEWCTX,
        function: sm2_newctx as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_ASYM_CIPHER_ENCRYPT_INIT,
        function: sm2_init as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_ASYM_CIPHER_ENCRYPT,
        function: sm2_asym_encrypt as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_ASYM_CIPHER_DECRYPT_INIT,
        function: sm2_init as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_ASYM_CIPHER_DECRYPT,
        function: sm2_asym_decrypt as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_ASYM_CIPHER_FREECTX,
        function: sm2_freectx as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_ASYM_CIPHER_DUPCTX,
        function: sm2_dupctx as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_ASYM_CIPHER_GET_CTX_PARAMS,
        function: sm2_get_ctx_params as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_ASYM_CIPHER_GETTABLE_CTX_PARAMS,
        function: sm2_gettable_ctx_params as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_ASYM_CIPHER_SET_CTX_PARAMS,
        function: sm2_set_ctx_params as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_ASYM_CIPHER_SETTABLE_CTX_PARAMS,
        function: sm2_settable_ctx_params as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_DISPATCH_END,
        function: ptr::null_mut(),
    },
];
