//! Phase 8 — `providers/implementations/signature/slh_dsa_sig.c`: the twelve SLH-DSA signature
//! rows.
//!
//! Three hundred and ninety-three source lines and one macro that expands twelve times, publishing
//! the twelve `SLH-DSA-*` rows of `deflt_signature[]`. Every row's table is the same fifteen slots;
//! only `NEWCTX` differs, because it carries its own algorithm name into `slh_dsa_newctx`.
//!
//! ## The context holds the key, the hash context and the AlgorithmIdentifier
//!
//! `PROV_SLH_DSA_CTX` (`slh_dsa_sig.c.in:47-62`) borrows the key (ref counted by `EVP_PKEY`), owns
//! a `SLH_DSA_HASH_CTX` derived from it, and caches the encoded AlgorithmIdentifier plus the
//! optional context string and additional randomness a caller supplies. `slh_dsa_dupctx` is
//! `OPENSSL_memdup` of the whole struct with the three owned pointers replaced — so the two
//! `size_t` lengths and both byte arrays are copied by value, which is why the structure's field
//! order is the authority's.
//!
//! ## Signing has three randomness modes, and the middle one is the provider's own
//!
//! `slh_dsa_sign` (`:204-235`) chooses `opt_rand` in this order: the caller's `test-entropy` if it
//! was set, otherwise freshly drawn private bytes when `deterministic` is 0, otherwise NULL — which
//! the core turns into `PK_SEED` (`slh_dsa.c:92-93`). The temporary it draws is the only buffer
//! this unit cleanses on its own, and only when it was the one drawn.
//!
//! ## The AlgorithmIdentifier is built even when no key could produce one
//!
//! `slh_dsa_set_alg_id_buffer` (`:125-149`) ignores DER-writing errors, because an absent
//! AlgorithmIdentifier still leaves sign and verify valid; `aid_len` stays 0 and `get_ctx_params`
//! answers an empty octet string. That is the authority's shape and it is transcribed.
//!
//! SPDX-License-Identifier: Apache-2.0

#![allow(unreachable_pub)]
// The one shared body expands twelve times; the clippy threshold is the authority's shape.
#![allow(clippy::too_many_arguments)]

use core::ffi::{c_char, c_int, c_void};
use core::ptr;

use crate::context::dispatch::{OsslDispatch, OSSL_DISPATCH_END};
use crate::evp::pkey_ctx::{EVP_PKEY_OP_SIGN, EVP_PKEY_OP_VERIFY};
use crate::evp::signature::{
    OSSL_FUNC_SIGNATURE_DIGEST_SIGN, OSSL_FUNC_SIGNATURE_DIGEST_SIGN_INIT,
    OSSL_FUNC_SIGNATURE_DIGEST_VERIFY, OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_INIT,
    OSSL_FUNC_SIGNATURE_DUPCTX, OSSL_FUNC_SIGNATURE_FREECTX,
    OSSL_FUNC_SIGNATURE_GETTABLE_CTX_PARAMS, OSSL_FUNC_SIGNATURE_GET_CTX_PARAMS,
    OSSL_FUNC_SIGNATURE_NEWCTX, OSSL_FUNC_SIGNATURE_SETTABLE_CTX_PARAMS,
    OSSL_FUNC_SIGNATURE_SET_CTX_PARAMS, OSSL_FUNC_SIGNATURE_SIGN,
    OSSL_FUNC_SIGNATURE_SIGN_MESSAGE_INIT, OSSL_FUNC_SIGNATURE_VERIFY,
    OSSL_FUNC_SIGNATURE_VERIFY_MESSAGE_INIT,
};
use crate::packet::{
    WPACKET_cleanup, WPACKET_finish, WPACKET_get_curr, WPACKET_get_total_written, WPACKET_init_der,
    Wpacket,
};
use crate::params::{
    OSSL_PARAM_get_int, OSSL_PARAM_get_octet_string, OSSL_PARAM_locate_const,
    OSSL_PARAM_set_octet_string, OsslParam, END,
};
use crate::provider::cipher::{param_int, param_octet_string};
use crate::provider::ctx::prov_libctx_of;
use crate::provider::der_slh_dsa_key::ossl_DER_w_algorithmIdentifier_SLH_DSA;
use crate::rand::rand_lib::RAND_priv_bytes_ex;
use crate::runtime::err::{err_sites, raise_site, raise_site_data};
use crate::runtime::mem::{
    CRYPTO_free, CRYPTO_memdup, CRYPTO_strdup, CRYPTO_zalloc, OPENSSL_cleanse,
};
use crate::slh_dsa::dsa::{ossl_slh_dsa_sign, ossl_slh_dsa_verify};
use crate::slh_dsa::hash_ctx::{
    ossl_slh_dsa_hash_ctx_dup, ossl_slh_dsa_hash_ctx_free, ossl_slh_dsa_hash_ctx_new,
};
use crate::slh_dsa::key::{ossl_slh_dsa_key_get_n, ossl_slh_dsa_key_type_matches};
use crate::slh_dsa::{SlhDsaHashCtx, SlhDsaKey, SLH_DSA_MAX_CONTEXT_STRING_LEN};

/// `SLH_DSA_MAX_ADD_RANDOM_LEN` — `slh_dsa_sig.c.in:27`, the largest `n`.
const SLH_DSA_MAX_ADD_RANDOM_LEN: usize = 32;
/// `SLH_DSA_MESSAGE_ENCODE_RAW` — `slh_dsa_sig.c.in:29`.
const SLH_DSA_MESSAGE_ENCODE_RAW: c_int = 0;
/// `SLH_DSA_MESSAGE_ENCODE_PURE` — `slh_dsa_sig.c.in:30`.
const SLH_DSA_MESSAGE_ENCODE_PURE: c_int = 1;
/// `OSSL_MAX_ALGORITHM_ID_SIZE` — `include/internal/sizes.h:20`.
const OSSL_MAX_ALGORITHM_ID_SIZE: usize = 256;

/// `OSSL_SIGNATURE_PARAM_CONTEXT_STRING` — `core_names.h:548`.
const OSSL_SIGNATURE_PARAM_CONTEXT_STRING: *const c_char = c"context-string".as_ptr();
/// `OSSL_SIGNATURE_PARAM_TEST_ENTROPY` — `core_names.h:570`.
const OSSL_SIGNATURE_PARAM_TEST_ENTROPY: *const c_char = c"test-entropy".as_ptr();
/// `OSSL_SIGNATURE_PARAM_DETERMINISTIC` — `core_names.h:549`.
const OSSL_SIGNATURE_PARAM_DETERMINISTIC: *const c_char = c"deterministic".as_ptr();
/// `OSSL_SIGNATURE_PARAM_MESSAGE_ENCODING` — `core_names.h:561`.
const OSSL_SIGNATURE_PARAM_MESSAGE_ENCODING: *const c_char = c"message-encoding".as_ptr();
/// `OSSL_SIGNATURE_PARAM_ALGORITHM_ID` — `core_names.h:546`.
const OSSL_SIGNATURE_PARAM_ALGORITHM_ID: *const c_char = c"algorithm-id".as_ptr();

/// The unit's own `__FILE__`. `.c.in`-generated, so the bare build-relative path.
const FILE: *const c_char =
    c"../../src/openssl-3.6.4/providers/implementations/signature/slh_dsa_sig.c".as_ptr();
/// `slh_dsa_sig.c:81`, the `OPENSSL_zalloc(sizeof(PROV_SLH_DSA_CTX))` in `slh_dsa_newctx`.
const LINE_ZALLOC_CTX: c_int = 81;
/// `slh_dsa_sig.c:108`, the `OPENSSL_memdup(src, sizeof(*src))` in `slh_dsa_dupctx`.
const LINE_MEMDUP_CTX: c_int = 108;

/// `PROV_SLH_DSA_CTX` — `slh_dsa_sig.c.in:47-62`.
#[repr(C)]
struct ProvSlhDsaCtx {
    /// `SLH_DSA_KEY *key` — borrowed, not owned by this object.
    key: *mut SlhDsaKey,
    /// `SLH_DSA_HASH_CTX *hash_ctx`.
    hash_ctx: *mut SlhDsaHashCtx,
    /// `uint8_t context_string[SLH_DSA_MAX_CONTEXT_STRING_LEN]`.
    context_string: [u8; SLH_DSA_MAX_CONTEXT_STRING_LEN],
    /// `size_t context_string_len`.
    context_string_len: usize,
    /// `uint8_t add_random[SLH_DSA_MAX_ADD_RANDOM_LEN]`.
    add_random: [u8; SLH_DSA_MAX_ADD_RANDOM_LEN],
    /// `size_t add_random_len`.
    add_random_len: usize,
    /// `int msg_encode`.
    msg_encode: c_int,
    /// `int deterministic`.
    deterministic: c_int,
    /// `OSSL_LIB_CTX *libctx`.
    libctx: *mut c_void,
    /// `char *propq`.
    propq: *mut c_char,
    /// `const char *alg`.
    alg: *const c_char,
    /// `uint8_t aid_buf[OSSL_MAX_ALGORITHM_ID_SIZE]`.
    aid_buf: [u8; OSSL_MAX_ALGORITHM_ID_SIZE],
    /// `size_t aid_len`.
    aid_len: usize,
}

/// `ossl_prov_is_running()` — the literal 1 on this build.
#[inline]
fn is_running() -> c_int {
    1
}

/// `static void slh_dsa_freectx(void *vctx)` — `slh_dsa_sig.c:64-72`.
///
/// # Safety
/// The signature `freectx` dispatch contract.
unsafe extern "C" fn slh_dsa_freectx(vctx: *mut c_void) {
    let ctx = vctx.cast::<ProvSlhDsaCtx>();

    // SAFETY: `ctx` is the caller's context.
    unsafe {
        ossl_slh_dsa_hash_ctx_free((*ctx).hash_ctx);
        CRYPTO_free((*ctx).propq.cast(), FILE, LINE_FREE_PROPQ);
        OPENSSL_cleanse(
            (*ctx).add_random.as_mut_ptr().cast(),
            (*ctx).add_random.len(),
        );
        CRYPTO_free(ctx.cast(), FILE, LINE_FREE_CTX);
    }
}

/// `slh_dsa_sig.c:69`, the `OPENSSL_free(ctx->propq)` in `slh_dsa_freectx`.
const LINE_FREE_PROPQ: c_int = 69;
/// `slh_dsa_sig.c:71`, the `OPENSSL_free(ctx)` in `slh_dsa_freectx`.
const LINE_FREE_CTX: c_int = 71;

/// `static void *slh_dsa_newctx(void *provctx, const char *alg, const char *propq)` —
/// `slh_dsa_sig.c:74-94`.
///
/// # Safety
/// `provctx` is the caller's context; `alg` and `propq` are NUL-terminated or NULL.
unsafe fn slh_dsa_newctx(
    provctx: *mut c_void,
    alg: *const c_char,
    propq: *const c_char,
) -> *mut c_void {
    if is_running() == 0 {
        return ptr::null_mut();
    }

    // SAFETY: `CRYPTO_zalloc` answers a zeroed block or NULL.
    let ctx = CRYPTO_zalloc(core::mem::size_of::<ProvSlhDsaCtx>(), FILE, LINE_ZALLOC_CTX)
        .cast::<ProvSlhDsaCtx>();
    if ctx.is_null() {
        return ptr::null_mut();
    }

    // SAFETY: `ctx` is a fresh zeroed block this call owns.
    unsafe {
        (*ctx).libctx = prov_libctx_of(provctx);
        if !propq.is_null() {
            (*ctx).propq = CRYPTO_strdup(propq, FILE, LINE_STRDUP_PROPQ);
            if (*ctx).propq.is_null() {
                slh_dsa_freectx(ctx.cast());
                return ptr::null_mut();
            }
        }
        (*ctx).alg = alg;
        (*ctx).msg_encode = SLH_DSA_MESSAGE_ENCODE_PURE;
    }
    ctx.cast()
}

/// `slh_dsa_sig.c:86`, the `OPENSSL_strdup(propq)` in `slh_dsa_newctx`.
const LINE_STRDUP_PROPQ: c_int = 86;

/// `static void *slh_dsa_dupctx(void *vctx)` — `slh_dsa_sig.c:96-123`.
///
/// # Safety
/// The signature `dupctx` dispatch contract.
unsafe extern "C" fn slh_dsa_dupctx(vctx: *mut c_void) -> *mut c_void {
    let src = vctx.cast::<ProvSlhDsaCtx>();

    if is_running() == 0 {
        return ptr::null_mut();
    }

    /*
     * Note that the `SLH_DSA_KEY` is ref counted via `EVP_PKEY` so we can just copy the key here.
     */
    // SAFETY: `CRYPTO_memdup` copies `size` bytes from a readable source or answers NULL.
    let ret = unsafe {
        CRYPTO_memdup(
            src.cast(),
            core::mem::size_of::<ProvSlhDsaCtx>(),
            FILE,
            LINE_MEMDUP_CTX,
        )
    }
    .cast::<ProvSlhDsaCtx>();
    if ret.is_null() {
        return ptr::null_mut();
    }

    // SAFETY: `ret` is a fresh copy of `src`; the three owned pointers are replaced below.
    unsafe {
        (*ret).propq = ptr::null_mut();
        (*ret).hash_ctx = ptr::null_mut();
        if !(*src).propq.is_null() {
            (*ret).propq = CRYPTO_strdup((*src).propq, FILE, LINE_STRDUP_PROPQ);
            if (*ret).propq.is_null() {
                slh_dsa_freectx(ret.cast());
                return ptr::null_mut();
            }
        }
        (*ret).hash_ctx = ossl_slh_dsa_hash_ctx_dup((*src).hash_ctx);
        if (*ret).hash_ctx.is_null() {
            slh_dsa_freectx(ret.cast());
            return ptr::null_mut();
        }
    }
    ret.cast()
}

/// `static int slh_dsa_set_alg_id_buffer(PROV_SLH_DSA_CTX *ctx)` — `slh_dsa_sig.c:125-149`.
///
/// # Safety
/// `ctx` is live with `key` set.
unsafe fn slh_dsa_set_alg_id_buffer(ctx: *mut ProvSlhDsaCtx) -> c_int {
    /*
     * We do not care about DER writing errors. All it really means is that for some reason there is
     * no AlgorithmIdentifier to be had, but the operation itself is still valid.
     */
    // SAFETY: `ctx` is live per the contract.
    unsafe {
        (*ctx).aid_len = 0;
        let mut pkt = core::mem::MaybeUninit::<Wpacket>::uninit();
        let pkt = pkt.as_mut_ptr();
        let mut ret =
            WPACKET_init_der(pkt, (*ctx).aid_buf.as_mut_ptr(), OSSL_MAX_ALGORITHM_ID_SIZE);
        if ret != 0 {
            ret = ossl_DER_w_algorithmIdentifier_SLH_DSA(pkt, -1, (*ctx).key);
        }
        let mut aid: *mut u8 = ptr::null_mut();
        if ret != 0 && WPACKET_finish(pkt) != 0 {
            WPACKET_get_total_written(pkt, ptr::addr_of_mut!((*ctx).aid_len));
            aid = WPACKET_get_curr(pkt).cast::<u8>();
        }
        WPACKET_cleanup(pkt);
        if !aid.is_null() && (*ctx).aid_len != 0 {
            ptr::copy(aid, (*ctx).aid_buf.as_mut_ptr(), (*ctx).aid_len);
        }
    }
    1
}

/// `static int slh_dsa_signverify_msg_init(void *vctx, void *vkey, const OSSL_PARAM params[],`
/// `int operation, const char *desc)` — `slh_dsa_sig.c:151-180`.
///
/// `operation` and `desc` are unused by the authority.
///
/// # Safety
/// The signature init dispatch contract.
unsafe fn slh_dsa_signverify_msg_init(
    vctx: *mut c_void,
    vkey: *mut c_void,
    params: *const OsslParam,
    _operation: c_int,
    _desc: *const c_char,
) -> c_int {
    let ctx = vctx.cast::<ProvSlhDsaCtx>();
    let key = vkey.cast::<SlhDsaKey>();

    if is_running() == 0 || ctx.is_null() {
        return 0;
    }

    // SAFETY: `ctx`/`key` are the caller's.
    unsafe {
        if vkey.is_null() && (*ctx).key.is_null() {
            raise_site(&err_sites::PROV_SLH_DSA_SIG_161);
            return 0;
        }

        if !key.is_null() {
            if ossl_slh_dsa_key_type_matches(key, (*ctx).alg) == 0 {
                return 0;
            }
            (*ctx).hash_ctx = ossl_slh_dsa_hash_ctx_new(key);
            if (*ctx).hash_ctx.is_null() {
                return 0;
            }
            (*ctx).key = vkey.cast();
        }

        slh_dsa_set_alg_id_buffer(ctx);
        if slh_dsa_set_ctx_params(ctx.cast(), params) == 0 {
            return 0;
        }
    }
    1
}

/// `static int slh_dsa_sign_msg_init(void *vctx, void *vkey, const OSSL_PARAM params[])` —
/// `slh_dsa_sig.c:182-186`.
///
/// # Safety
/// The signature `sign_message_init` dispatch contract.
unsafe extern "C" fn slh_dsa_sign_msg_init(
    vctx: *mut c_void,
    vkey: *mut c_void,
    params: *const OsslParam,
) -> c_int {
    // SAFETY: the caller's contract, forwarded.
    unsafe {
        slh_dsa_signverify_msg_init(
            vctx,
            vkey,
            params,
            EVP_PKEY_OP_SIGN,
            c"SLH_DSA Sign Init".as_ptr(),
        )
    }
}

/// `static int slh_dsa_digest_signverify_init(void *vctx, const char *mdname, void *vkey,`
/// `const OSSL_PARAM params[])` — `slh_dsa_sig.c:188-204`.
///
/// # Safety
/// The signature digest-init dispatch contract.
unsafe extern "C" fn slh_dsa_digest_signverify_init(
    vctx: *mut c_void,
    mdname: *const c_char,
    vkey: *mut c_void,
    params: *const OsslParam,
) -> c_int {
    let ctx = vctx.cast::<ProvSlhDsaCtx>();

    // SAFETY: `mdname` is NULL or NUL-terminated; `ctx` is the caller's.
    unsafe {
        if !mdname.is_null() && *mdname != 0 {
            raise_site_data(
                &err_sites::PROV_SLH_DSA_SIG_192,
                c"Explicit digest not supported for SLH-DSA operations".as_ptr(),
            );
            return 0;
        }

        if vkey.is_null() && !(*ctx).key.is_null() {
            return slh_dsa_set_ctx_params(vctx, params);
        }

        slh_dsa_signverify_msg_init(
            vctx,
            vkey,
            params,
            EVP_PKEY_OP_SIGN,
            c"SLH_DSA Sign Init".as_ptr(),
        )
    }
}

/// `static int slh_dsa_sign(void *vctx, unsigned char *sig, size_t *siglen, size_t sigsize,`
/// `const unsigned char *msg, size_t msg_len)` — `slh_dsa_sig.c:206-235`.
///
/// # Safety
/// The signature `sign` dispatch contract.
unsafe extern "C" fn slh_dsa_sign(
    vctx: *mut c_void,
    sig: *mut u8,
    siglen: *mut usize,
    sigsize: usize,
    msg: *const u8,
    msg_len: usize,
) -> c_int {
    let ctx = vctx.cast::<ProvSlhDsaCtx>();
    let mut add_rand = [0u8; SLH_DSA_MAX_ADD_RANDOM_LEN];
    let mut opt_rand: *const u8 = ptr::null();

    if is_running() == 0 {
        return 0;
    }

    // SAFETY: `ctx` is the caller's context.
    unsafe {
        if !sig.is_null() {
            if (*ctx).add_random_len != 0 {
                opt_rand = (*ctx).add_random.as_ptr();
            } else if (*ctx).deterministic == 0 {
                let n = ossl_slh_dsa_key_get_n((*ctx).key);
                if RAND_priv_bytes_ex((*ctx).libctx, add_rand.as_mut_ptr(), n, 0) <= 0 {
                    return 0;
                }
                opt_rand = add_rand.as_ptr();
            }
        }
        let ret = ossl_slh_dsa_sign(
            (*ctx).hash_ctx,
            msg,
            msg_len,
            (*ctx).context_string.as_ptr(),
            (*ctx).context_string_len,
            opt_rand,
            (*ctx).msg_encode,
            sig,
            siglen,
            sigsize,
        );
        /* Only cleanse the temporary buffer generated for this signature. */
        if opt_rand == add_rand.as_ptr() {
            OPENSSL_cleanse(add_rand.as_mut_ptr().cast(), add_rand.len());
        }
        ret
    }
}

/// `static int slh_dsa_digest_sign(void *vctx, uint8_t *sig, size_t *siglen, size_t sigsize,`
/// `const uint8_t *tbs, size_t tbslen)` — `slh_dsa_sig.c:237-241`.
///
/// # Safety
/// The signature `digest_sign` dispatch contract.
unsafe extern "C" fn slh_dsa_digest_sign(
    vctx: *mut c_void,
    sig: *mut u8,
    siglen: *mut usize,
    sigsize: usize,
    tbs: *const u8,
    tbslen: usize,
) -> c_int {
    // SAFETY: the caller's contract, forwarded verbatim.
    unsafe { slh_dsa_sign(vctx, sig, siglen, sigsize, tbs, tbslen) }
}

/// `static int slh_dsa_verify_msg_init(void *vctx, void *vkey, const OSSL_PARAM params[])` —
/// `slh_dsa_sig.c:243-247`.
///
/// # Safety
/// The signature `verify_message_init` dispatch contract.
unsafe extern "C" fn slh_dsa_verify_msg_init(
    vctx: *mut c_void,
    vkey: *mut c_void,
    params: *const OsslParam,
) -> c_int {
    // SAFETY: the caller's contract, forwarded.
    unsafe {
        slh_dsa_signverify_msg_init(
            vctx,
            vkey,
            params,
            EVP_PKEY_OP_VERIFY,
            c"SLH_DSA Verify Init".as_ptr(),
        )
    }
}

/// `static int slh_dsa_verify(void *vctx, const uint8_t *sig, size_t siglen, const uint8_t *msg,`
/// `size_t msg_len)` — `slh_dsa_sig.c:249-259`.
///
/// # Safety
/// The signature `verify` dispatch contract.
unsafe extern "C" fn slh_dsa_verify(
    vctx: *mut c_void,
    sig: *const u8,
    siglen: usize,
    msg: *const u8,
    msg_len: usize,
) -> c_int {
    let ctx = vctx.cast::<ProvSlhDsaCtx>();

    if is_running() == 0 {
        return 0;
    }
    // SAFETY: `ctx` is the caller's context.
    unsafe {
        ossl_slh_dsa_verify(
            (*ctx).hash_ctx,
            msg,
            msg_len,
            (*ctx).context_string.as_ptr(),
            (*ctx).context_string_len,
            (*ctx).msg_encode,
            sig,
            siglen,
        )
    }
}

/// `static int slh_dsa_digest_verify(void *vctx, const uint8_t *sig, size_t siglen,`
/// `const uint8_t *tbs, size_t tbslen)` — `slh_dsa_sig.c:260-264`.
///
/// # Safety
/// The signature `digest_verify` dispatch contract.
unsafe extern "C" fn slh_dsa_digest_verify(
    vctx: *mut c_void,
    sig: *const u8,
    siglen: usize,
    tbs: *const u8,
    tbslen: usize,
) -> c_int {
    // SAFETY: the caller's contract, forwarded verbatim.
    unsafe { slh_dsa_verify(vctx, sig, siglen, tbs, tbslen) }
}

/// `static const OSSL_PARAM slh_dsa_set_ctx_params_list[]` — generated
/// `slh_dsa_sig.c:267-273`.
static SLH_DSA_SET_CTX_PARAMS_LIST: [OsslParam; 5] = [
    param_octet_string(OSSL_SIGNATURE_PARAM_CONTEXT_STRING),
    param_octet_string(OSSL_SIGNATURE_PARAM_TEST_ENTROPY),
    param_int(OSSL_SIGNATURE_PARAM_DETERMINISTIC),
    param_int(OSSL_SIGNATURE_PARAM_MESSAGE_ENCODING),
    END,
];

/// `struct slh_dsa_set_ctx_params_st` — generated `slh_dsa_sig.c:276-281`.
struct SlhDsaSetCtxParams {
    context: *mut OsslParam,
    det: *mut OsslParam,
    entropy: *mut OsslParam,
    msgenc: *mut OsslParam,
}

/// The set-ctx-params decoder's repeated-key coordinates — generated
/// `slh_dsa_sig.c:301/312/323/334`.
const SLH_DSA_SET_CTX_PARAMS_DECODER_KEYS: [(&err_sites::ErrSite, *const c_char); 4] = [
    (
        &err_sites::PROV_SLH_DSA_SIG_301,
        OSSL_SIGNATURE_PARAM_CONTEXT_STRING,
    ),
    (
        &err_sites::PROV_SLH_DSA_SIG_312,
        OSSL_SIGNATURE_PARAM_DETERMINISTIC,
    ),
    (
        &err_sites::PROV_SLH_DSA_SIG_323,
        OSSL_SIGNATURE_PARAM_MESSAGE_ENCODING,
    ),
    (
        &err_sites::PROV_SLH_DSA_SIG_334,
        OSSL_SIGNATURE_PARAM_TEST_ENTROPY,
    ),
];

/// `slh_dsa_set_ctx_params_decoder` — generated `slh_dsa_sig.c:286-345`.
///
/// # Safety
/// `params` is NULL or key-terminated; `r` is writable.
unsafe fn slh_dsa_set_ctx_params_decoder(
    params: *const OsslParam,
    r: &mut SlhDsaSetCtxParams,
) -> c_int {
    // SAFETY: the arguments are per the contract.
    unsafe {
        if !params.is_null() {
            let mut seen: u32 = 0;
            let mut p = params;
            while !(*p).key.is_null() {
                let k = core::ffi::CStr::from_ptr((*p).key).to_bytes();
                for (i, (site, name)) in SLH_DSA_SET_CTX_PARAMS_DECODER_KEYS.iter().enumerate() {
                    if core::ffi::CStr::from_ptr(*name).to_bytes() == k {
                        let bit = 1u32 << i;
                        if seen & bit != 0 {
                            raise_site(site);
                            return 0;
                        }
                        seen |= bit;
                        break;
                    }
                }
                p = p.add(1);
            }
        }
        r.context = OSSL_PARAM_locate_const(params, OSSL_SIGNATURE_PARAM_CONTEXT_STRING).cast_mut();
        r.det = OSSL_PARAM_locate_const(params, OSSL_SIGNATURE_PARAM_DETERMINISTIC).cast_mut();
        r.msgenc =
            OSSL_PARAM_locate_const(params, OSSL_SIGNATURE_PARAM_MESSAGE_ENCODING).cast_mut();
        r.entropy = OSSL_PARAM_locate_const(params, OSSL_SIGNATURE_PARAM_TEST_ENTROPY).cast_mut();
    }
    1
}

/// `static int slh_dsa_set_ctx_params(void *vctx, const OSSL_PARAM params[])` —
/// `slh_dsa_sig.c:347-383`.
///
/// # Safety
/// The signature `set_ctx_params` dispatch contract.
unsafe extern "C" fn slh_dsa_set_ctx_params(vctx: *mut c_void, params: *const OsslParam) -> c_int {
    let pctx = vctx.cast::<ProvSlhDsaCtx>();
    let mut p = SlhDsaSetCtxParams {
        context: ptr::null_mut(),
        det: ptr::null_mut(),
        entropy: ptr::null_mut(),
        msgenc: ptr::null_mut(),
    };

    // SAFETY: `pctx`/`params` are the caller's; `p` is this call's own decoder result.
    unsafe {
        if pctx.is_null() || slh_dsa_set_ctx_params_decoder(params, &mut p) == 0 {
            return 0;
        }

        if !p.context.is_null() {
            let mut vp: *mut c_void = (*pctx).context_string.as_mut_ptr().cast();
            if OSSL_PARAM_get_octet_string(
                p.context,
                &mut vp,
                (*pctx).context_string.len(),
                &mut (*pctx).context_string_len,
            ) == 0
            {
                (*pctx).context_string_len = 0;
                return 0;
            }
        }

        if !p.entropy.is_null() {
            let mut vp: *mut c_void = (*pctx).add_random.as_mut_ptr().cast();
            let n = ossl_slh_dsa_key_get_n((*pctx).key);
            if OSSL_PARAM_get_octet_string(p.entropy, &mut vp, n, &mut (*pctx).add_random_len) == 0
                || (*pctx).add_random_len != n
            {
                (*pctx).add_random_len = 0;
                return 0;
            }
        }

        if !p.det.is_null() && OSSL_PARAM_get_int(p.det, &mut (*pctx).deterministic) == 0 {
            return 0;
        }

        if !p.msgenc.is_null() && OSSL_PARAM_get_int(p.msgenc, &mut (*pctx).msg_encode) == 0 {
            return 0;
        }
    }
    1
}

/// `static const OSSL_PARAM *slh_dsa_settable_ctx_params(void *vctx, void *provctx)` —
/// `slh_dsa_sig.c:385-390`.
///
/// Both arguments are unused by the authority.
///
/// # Safety
/// Takes no live pointers it reads.
unsafe extern "C" fn slh_dsa_settable_ctx_params(
    _vctx: *mut c_void,
    _provctx: *mut c_void,
) -> *const OsslParam {
    SLH_DSA_SET_CTX_PARAMS_LIST.as_ptr()
}

/// `static const OSSL_PARAM slh_dsa_get_ctx_params_list[]` — generated
/// `slh_dsa_sig.c:394-398`.
static SLH_DSA_GET_CTX_PARAMS_LIST: [OsslParam; 2] =
    [param_octet_string(OSSL_SIGNATURE_PARAM_ALGORITHM_ID), END];

/// `struct slh_dsa_get_ctx_params_st` — generated `slh_dsa_sig.c:401-403`.
struct SlhDsaGetCtxParams {
    algid: *mut OsslParam,
}

/// `slh_dsa_get_ctx_params_decoder` — generated `slh_dsa_sig.c:407-426`.
///
/// # Safety
/// `params` is NULL or key-terminated; `r` is writable.
unsafe fn slh_dsa_get_ctx_params_decoder(
    params: *const OsslParam,
    r: &mut SlhDsaGetCtxParams,
) -> c_int {
    // SAFETY: the arguments are per the contract.
    unsafe {
        if !params.is_null() {
            let mut p = params;
            let mut seen = false;
            while !(*p).key.is_null() {
                let k = core::ffi::CStr::from_ptr((*p).key).to_bytes();
                if core::ffi::CStr::from_ptr(OSSL_SIGNATURE_PARAM_ALGORITHM_ID).to_bytes() == k {
                    if seen {
                        raise_site(&err_sites::PROV_SLH_DSA_SIG_418);
                        return 0;
                    }
                    seen = true;
                }
                p = p.add(1);
            }
        }
        r.algid = OSSL_PARAM_locate_const(params, OSSL_SIGNATURE_PARAM_ALGORITHM_ID).cast_mut();
    }
    1
}

/// `static const OSSL_PARAM *slh_dsa_gettable_ctx_params(void *vctx, void *provctx)` —
/// `slh_dsa_sig.c:430-434`.
///
/// Both arguments are unused by the authority.
///
/// # Safety
/// Takes no live pointers it reads.
unsafe extern "C" fn slh_dsa_gettable_ctx_params(
    _vctx: *mut c_void,
    _provctx: *mut c_void,
) -> *const OsslParam {
    SLH_DSA_GET_CTX_PARAMS_LIST.as_ptr()
}

/// `static int slh_dsa_get_ctx_params(void *vctx, OSSL_PARAM *params)` —
/// `slh_dsa_sig.c:436-451`.
///
/// # Safety
/// The signature `get_ctx_params` dispatch contract.
unsafe extern "C" fn slh_dsa_get_ctx_params(vctx: *mut c_void, params: *mut OsslParam) -> c_int {
    let ctx = vctx.cast::<ProvSlhDsaCtx>();
    let mut p = SlhDsaGetCtxParams {
        algid: ptr::null_mut(),
    };

    // SAFETY: `ctx`/`params` are the caller's; `p` is this call's own decoder result.
    unsafe {
        if ctx.is_null() || slh_dsa_get_ctx_params_decoder(params, &mut p) == 0 {
            return 0;
        }

        if !p.algid.is_null() {
            let aid = if (*ctx).aid_len == 0 {
                ptr::null()
            } else {
                (*ctx).aid_buf.as_ptr().cast()
            };
            if OSSL_PARAM_set_octet_string(p.algid, aid, (*ctx).aid_len) == 0 {
                return 0;
            }
        }
    }
    1
}

/// `MAKE_SIGNATURE_FUNCTIONS(alg, fn)` — `slh_dsa_sig.c:348-380`, once per parameter set.
///
/// Each expansion differs in the algorithm name and in the one per-algorithm callback
/// (`slh_dsa_<fn>_newctx`); every other slot is one of the shared functions above.
///
/// **The name is passed as a NUL-terminated C string, not as a Rust `&str`** — the same trap
/// `slh_dsa_kmgmt.rs`'s `make_keymgmt_functions!` documents and `RT-KEYMGMT` caught: `$alg.as_ptr()`
/// points into a `str` literal with no terminator, and the lookup on the other side is a
/// `strcmp`-style compare, so the name would never match.
macro_rules! make_signature_functions {
    ($table:ident, $alg:literal, $fn_newctx:ident) => {
        /// `static void *slh_dsa_<fn>_newctx(void *provctx, const char *propq)` — one expansion's
        /// new context.
        ///
        /// # Safety
        /// The signature `newctx` dispatch contract.
        unsafe extern "C" fn $fn_newctx(provctx: *mut c_void, propq: *const c_char) -> *mut c_void {
            // SAFETY: the caller's contract, forwarded with this expansion's algorithm name,
            // which `concat!` has already given its terminator.
            unsafe {
                slh_dsa_newctx(
                    provctx,
                    concat!($alg, "\0").as_ptr().cast::<c_char>(),
                    propq,
                )
            }
        }

        /// `const OSSL_DISPATCH ossl_slh_dsa_<fn>_signature_functions[]` — one expansion's table.
        pub(crate) static $table: [OsslDispatch; 16] = [
            OsslDispatch {
                function_id: OSSL_FUNC_SIGNATURE_NEWCTX,
                function: $fn_newctx as *mut c_void,
            },
            OsslDispatch {
                function_id: OSSL_FUNC_SIGNATURE_SIGN_MESSAGE_INIT,
                function: slh_dsa_sign_msg_init as *mut c_void,
            },
            OsslDispatch {
                function_id: OSSL_FUNC_SIGNATURE_SIGN,
                function: slh_dsa_sign as *mut c_void,
            },
            OsslDispatch {
                function_id: OSSL_FUNC_SIGNATURE_VERIFY_MESSAGE_INIT,
                function: slh_dsa_verify_msg_init as *mut c_void,
            },
            OsslDispatch {
                function_id: OSSL_FUNC_SIGNATURE_VERIFY,
                function: slh_dsa_verify as *mut c_void,
            },
            OsslDispatch {
                function_id: OSSL_FUNC_SIGNATURE_DIGEST_SIGN_INIT,
                function: slh_dsa_digest_signverify_init as *mut c_void,
            },
            OsslDispatch {
                function_id: OSSL_FUNC_SIGNATURE_DIGEST_SIGN,
                function: slh_dsa_digest_sign as *mut c_void,
            },
            OsslDispatch {
                function_id: OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_INIT,
                function: slh_dsa_digest_signverify_init as *mut c_void,
            },
            OsslDispatch {
                function_id: OSSL_FUNC_SIGNATURE_DIGEST_VERIFY,
                function: slh_dsa_digest_verify as *mut c_void,
            },
            OsslDispatch {
                function_id: OSSL_FUNC_SIGNATURE_FREECTX,
                function: slh_dsa_freectx as *mut c_void,
            },
            OsslDispatch {
                function_id: OSSL_FUNC_SIGNATURE_DUPCTX,
                function: slh_dsa_dupctx as *mut c_void,
            },
            OsslDispatch {
                function_id: OSSL_FUNC_SIGNATURE_SET_CTX_PARAMS,
                function: slh_dsa_set_ctx_params as *mut c_void,
            },
            OsslDispatch {
                function_id: OSSL_FUNC_SIGNATURE_SETTABLE_CTX_PARAMS,
                function: slh_dsa_settable_ctx_params as *mut c_void,
            },
            OsslDispatch {
                function_id: OSSL_FUNC_SIGNATURE_GET_CTX_PARAMS,
                function: slh_dsa_get_ctx_params as *mut c_void,
            },
            OsslDispatch {
                function_id: OSSL_FUNC_SIGNATURE_GETTABLE_CTX_PARAMS,
                function: slh_dsa_gettable_ctx_params as *mut c_void,
            },
            OsslDispatch {
                function_id: OSSL_DISPATCH_END,
                function: ptr::null_mut(),
            },
        ];
    };
}

make_signature_functions!(
    SLH_DSA_SHA2_128S_SIGNATURE_FUNCTIONS,
    "SLH-DSA-SHA2-128s",
    slh_dsa_sha2_128s_newctx
);
make_signature_functions!(
    SLH_DSA_SHA2_128F_SIGNATURE_FUNCTIONS,
    "SLH-DSA-SHA2-128f",
    slh_dsa_sha2_128f_newctx
);
make_signature_functions!(
    SLH_DSA_SHA2_192S_SIGNATURE_FUNCTIONS,
    "SLH-DSA-SHA2-192s",
    slh_dsa_sha2_192s_newctx
);
make_signature_functions!(
    SLH_DSA_SHA2_192F_SIGNATURE_FUNCTIONS,
    "SLH-DSA-SHA2-192f",
    slh_dsa_sha2_192f_newctx
);
make_signature_functions!(
    SLH_DSA_SHA2_256S_SIGNATURE_FUNCTIONS,
    "SLH-DSA-SHA2-256s",
    slh_dsa_sha2_256s_newctx
);
make_signature_functions!(
    SLH_DSA_SHA2_256F_SIGNATURE_FUNCTIONS,
    "SLH-DSA-SHA2-256f",
    slh_dsa_sha2_256f_newctx
);
make_signature_functions!(
    SLH_DSA_SHAKE_128S_SIGNATURE_FUNCTIONS,
    "SLH-DSA-SHAKE-128s",
    slh_dsa_shake_128s_newctx
);
make_signature_functions!(
    SLH_DSA_SHAKE_128F_SIGNATURE_FUNCTIONS,
    "SLH-DSA-SHAKE-128f",
    slh_dsa_shake_128f_newctx
);
make_signature_functions!(
    SLH_DSA_SHAKE_192S_SIGNATURE_FUNCTIONS,
    "SLH-DSA-SHAKE-192s",
    slh_dsa_shake_192s_newctx
);
make_signature_functions!(
    SLH_DSA_SHAKE_192F_SIGNATURE_FUNCTIONS,
    "SLH-DSA-SHAKE-192f",
    slh_dsa_shake_192f_newctx
);
make_signature_functions!(
    SLH_DSA_SHAKE_256S_SIGNATURE_FUNCTIONS,
    "SLH-DSA-SHAKE-256s",
    slh_dsa_shake_256s_newctx
);
make_signature_functions!(
    SLH_DSA_SHAKE_256F_SIGNATURE_FUNCTIONS,
    "SLH-DSA-SHAKE-256f",
    slh_dsa_shake_256f_newctx
);

/// `SLH_DSA_MESSAGE_ENCODE_RAW` is the value `set_ctx_params` writes for a raw message; named here
/// so a reader sees both encodings the unit carries.
const _: c_int = SLH_DSA_MESSAGE_ENCODE_RAW;
