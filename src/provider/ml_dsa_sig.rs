//! Phase 9 — `providers/implementations/signature/ml_dsa_sig.c`: the three ML-DSA signature rows.
//!
//! Five hundred and thirty-seven source lines and one macro that expands three times, publishing
//! the three `ML-DSA-*` rows of `deflt_signature[]`. Unlike the sibling SLH-DSA unit, this one
//! supports the message-oriented `sign_message_init`/`update`/`final` interface *and* the
//! digest-oriented one, so each table is twenty slots — the extra four being
//! `SIGN_MESSAGE_UPDATE`/`FINAL` and `VERIFY_MESSAGE_UPDATE`/`FINAL`. The three tables are
//! identical except for the per-algorithm `newctx`, which carries its own `EVP_PKEY_ML_DSA_*` type
//! into `ml_dsa_newctx`.
//!
//! ## The context holds the key, the message digest context and the AlgorithmIdentifier
//!
//! `PROV_ML_DSA_CTX` (`ml_dsa_sig.c.in:53-72`) borrows the key (ref counted by `EVP_PKEY`), owns an
//! `EVP_MD_CTX` raised by `ossl_ml_dsa_mu_init` for the `msg_init`/`update`/`final` path, and caches
//! the encoded AlgorithmIdentifier plus the optional context string and test entropy a caller
//! supplies. `ml_dsa_dupctx` is `OPENSSL_memdup` of the whole struct with its two owned pointers
//! (`sig`, `md_ctx`) replaced — so both `size_t` lengths and both byte arrays are copied by value,
//! which is why the structure's field order is the authority's.
//!
//! ## Signing has three randomness modes, and the middle one is the provider's own
//!
//! `ml_dsa_sign` (`:288-318`) chooses `rnd` in this order: the caller's `test-entropy` if it was
//! set, otherwise a zeroed buffer when `deterministic` is 1, otherwise freshly drawn private bytes.
//! The temporary it draws is cleansed only when it was the one drawn; `ml_dsa_sign_msg_final` does
//! the same for the `mu` representative it squeezes.
//!
//! ## The AlgorithmIdentifier is built even when no key could produce one
//!
//! `set_alg_id_buffer` (`:139-163`) ignores DER-writing errors, because an absent
//! AlgorithmIdentifier still leaves sign and verify valid; `aid_len` stays 0 and `get_ctx_params`
//! answers an empty octet string. That is the authority's shape and it is transcribed.
//!
//! ## The generated decoder and its aliased twin
//!
//! `ml_dsa_sig.c.in:375-376` aliases both the sign-case structure and its decoder onto the
//! verifymsg ones, so the compiled unit has one shared decoder over all six names; the generated
//! sign decoder the raise table still records is retained below, as the expanded text carries it.
//!
//! SPDX-License-Identifier: Apache-2.0

#![allow(unreachable_pub)]
// The three shared bodies expand with the authority's argument counts.
#![allow(clippy::too_many_arguments)]

use core::ffi::{c_char, c_int, c_void};
use core::mem::size_of;
use core::ptr;

use crate::context::dispatch::{OsslDispatch, OSSL_DISPATCH_END};
use crate::evp::digest::{EVP_MD_CTX_dup, EVP_MD_CTX_free, EvpMdCtx};
use crate::evp::pkey_ctx::{EVP_PKEY_OP_SIGN, EVP_PKEY_OP_SIGNMSG, EVP_PKEY_OP_VERIFYMSG};
use crate::evp::signature::{
    OSSL_FUNC_SIGNATURE_DIGEST_SIGN, OSSL_FUNC_SIGNATURE_DIGEST_SIGN_INIT,
    OSSL_FUNC_SIGNATURE_DIGEST_VERIFY, OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_INIT,
    OSSL_FUNC_SIGNATURE_DUPCTX, OSSL_FUNC_SIGNATURE_FREECTX,
    OSSL_FUNC_SIGNATURE_GETTABLE_CTX_PARAMS, OSSL_FUNC_SIGNATURE_GET_CTX_PARAMS,
    OSSL_FUNC_SIGNATURE_NEWCTX, OSSL_FUNC_SIGNATURE_SETTABLE_CTX_PARAMS,
    OSSL_FUNC_SIGNATURE_SET_CTX_PARAMS, OSSL_FUNC_SIGNATURE_SIGN,
    OSSL_FUNC_SIGNATURE_SIGN_MESSAGE_FINAL, OSSL_FUNC_SIGNATURE_SIGN_MESSAGE_INIT,
    OSSL_FUNC_SIGNATURE_SIGN_MESSAGE_UPDATE, OSSL_FUNC_SIGNATURE_VERIFY,
    OSSL_FUNC_SIGNATURE_VERIFY_MESSAGE_FINAL, OSSL_FUNC_SIGNATURE_VERIFY_MESSAGE_INIT,
    OSSL_FUNC_SIGNATURE_VERIFY_MESSAGE_UPDATE,
};
use crate::ml_dsa::key::ossl_ml_dsa_key_matches;
use crate::ml_dsa::sign::{
    ossl_ml_dsa_mu_finalize, ossl_ml_dsa_mu_init, ossl_ml_dsa_mu_update, ossl_ml_dsa_sign,
    ossl_ml_dsa_verify,
};
use crate::ml_dsa::{
    MlDsaKey, EVP_PKEY_ML_DSA_44, EVP_PKEY_ML_DSA_65, EVP_PKEY_ML_DSA_87, ML_DSA_ENTROPY_LEN,
    ML_DSA_MAX_CONTEXT_STRING_LEN, ML_DSA_MU_BYTES,
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
use crate::provider::der_ml_dsa_key::ossl_DER_w_algorithmIdentifier_ML_DSA;
use crate::rand::rand_lib::RAND_priv_bytes_ex;
use crate::runtime::err::{err_sites, raise_site, raise_site_data};
use crate::runtime::mem::{CRYPTO_free, CRYPTO_memdup, CRYPTO_zalloc, OPENSSL_cleanse};

/// `ML_DSA_MESSAGE_ENCODE_RAW` — `ml_dsa_sig.c.in:32`.
const ML_DSA_MESSAGE_ENCODE_RAW: c_int = 0;
/// `ML_DSA_MESSAGE_ENCODE_PURE` — `ml_dsa_sig.c.in:33`.
const ML_DSA_MESSAGE_ENCODE_PURE: c_int = 1;
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
/// `OSSL_SIGNATURE_PARAM_MU` — `core_names.h:564`.
const OSSL_SIGNATURE_PARAM_MU: *const c_char = c"mu".as_ptr();
/// `OSSL_SIGNATURE_PARAM_SIGNATURE` — `core_names.h:569`.
const OSSL_SIGNATURE_PARAM_SIGNATURE: *const c_char = c"signature".as_ptr();
/// `OSSL_SIGNATURE_PARAM_ALGORITHM_ID` — `core_names.h:546`.
const OSSL_SIGNATURE_PARAM_ALGORITHM_ID: *const c_char = c"algorithm-id".as_ptr();

/// The unit's own `__FILE__`. `.c.in`-generated, so the bare build-relative path.
const FILE: *const c_char =
    c"../../src/openssl-3.6.4/providers/implementations/signature/ml_dsa_sig.c".as_ptr();
/// `ml_dsa_sig.c:78`, the `OPENSSL_free(ctx->sig)` in `ml_dsa_freectx`.
const LINE_FREE_SIG: c_int = 78;
/// `ml_dsa_sig.c:79`, the `OPENSSL_free(ctx)` in `ml_dsa_freectx`.
const LINE_FREE_CTX: c_int = 79;
/// `ml_dsa_sig.c:89`, the `OPENSSL_zalloc(sizeof(PROV_ML_DSA_CTX))` in `ml_dsa_newctx`.
const LINE_ZALLOC_CTX: c_int = 89;
/// `ml_dsa_sig.c:111`, the `OPENSSL_memdup(src, sizeof(*src))` in `ml_dsa_dupctx`.
const LINE_MEMDUP_CTX: c_int = 111;
/// `ml_dsa_sig.c:117`, the `OPENSSL_memdup(srcctx->sig, srcctx->siglen)` in `ml_dsa_dupctx`.
const LINE_MEMDUP_SIG: c_int = 117;
/// `ml_dsa_sig.c:123`, the `OPENSSL_free(dstctx)` in `ml_dsa_dupctx`.
const LINE_FREE_DSTCTX: c_int = 123;
/// `ml_dsa_sig.c:637`, the `OPENSSL_free(pctx->sig)` in `ml_dsa_set_ctx_params`.
const LINE_FREE_SET_SIG: c_int = 637;

/// `PROV_ML_DSA_CTX` — `ml_dsa_sig.c.in:53-72`.
#[repr(C)]
struct ProvMlDsaCtx {
    /// `ML_DSA_KEY *key` — borrowed, not owned by this object.
    key: *mut MlDsaKey,
    /// `OSSL_LIB_CTX *libctx`.
    libctx: *mut c_void,
    /// `uint8_t context_string[ML_DSA_MAX_CONTEXT_STRING_LEN]`.
    context_string: [u8; ML_DSA_MAX_CONTEXT_STRING_LEN],
    /// `size_t context_string_len`.
    context_string_len: usize,
    /// `uint8_t test_entropy[ML_DSA_ENTROPY_LEN]`.
    test_entropy: [u8; ML_DSA_ENTROPY_LEN],
    /// `size_t test_entropy_len`.
    test_entropy_len: usize,
    /// `int msg_encode`.
    msg_encode: c_int,
    /// `int deterministic`.
    deterministic: c_int,
    /// `int evp_type`.
    evp_type: c_int,
    /// `uint8_t aid_buf[OSSL_MAX_ALGORITHM_ID_SIZE]`.
    aid_buf: [u8; OSSL_MAX_ALGORITHM_ID_SIZE],
    /// `size_t aid_len`.
    aid_len: usize,
    /// `int mu` — flag indicating we begin from `\mu`, not the message.
    mu: c_int,
    /// `int operation`.
    operation: c_int,
    /// `EVP_MD_CTX *md_ctx` — the `msg_init`/`update`/`final` interface's context.
    md_ctx: *mut EvpMdCtx,
    /// `unsigned char *sig` — the signature, for verification.
    sig: *mut u8,
    /// `size_t siglen`.
    siglen: usize,
}

/// `ossl_prov_is_running()` — the literal 1 on this build.
#[inline]
fn is_running() -> c_int {
    1
}

/// `static void ml_dsa_freectx(void *vctx)` — `ml_dsa_sig.c:72-80`.
///
/// # Safety
/// The signature `freectx` dispatch contract.
unsafe extern "C" fn ml_dsa_freectx(vctx: *mut c_void) {
    let ctx = vctx.cast::<ProvMlDsaCtx>();

    // SAFETY: `ctx` is the caller's context.
    unsafe {
        EVP_MD_CTX_free((*ctx).md_ctx);
        OPENSSL_cleanse(
            (*ctx).test_entropy.as_mut_ptr().cast(),
            (*ctx).test_entropy_len,
        );
        CRYPTO_free((*ctx).sig.cast(), FILE, LINE_FREE_SIG);
        CRYPTO_free(ctx.cast(), FILE, LINE_FREE_CTX);
    }
}

/// `static void *ml_dsa_newctx(void *provctx, int evp_type, const char *propq)` —
/// `ml_dsa_sig.c:82-97`.
///
/// # Safety
/// `provctx` is the caller's context; `propq` is unused by the authority.
unsafe fn ml_dsa_newctx(
    provctx: *mut c_void,
    evp_type: c_int,
    _propq: *const c_char,
) -> *mut c_void {
    if is_running() == 0 {
        return ptr::null_mut();
    }

    // SAFETY: `CRYPTO_zalloc` answers a zeroed block or NULL.
    let ctx =
        CRYPTO_zalloc(size_of::<ProvMlDsaCtx>(), FILE, LINE_ZALLOC_CTX).cast::<ProvMlDsaCtx>();
    if ctx.is_null() {
        return ptr::null_mut();
    }

    // SAFETY: `ctx` is a fresh zeroed block this call owns.
    unsafe {
        (*ctx).libctx = prov_libctx_of(provctx);
        (*ctx).msg_encode = ML_DSA_MESSAGE_ENCODE_PURE;
        (*ctx).evp_type = evp_type;
    }
    ctx.cast()
}

/// `static void *ml_dsa_dupctx(void *vctx)` — `ml_dsa_sig.c:99-137`.
///
/// # Safety
/// The signature `dupctx` dispatch contract.
unsafe extern "C" fn ml_dsa_dupctx(vctx: *mut c_void) -> *mut c_void {
    let srcctx = vctx.cast::<ProvMlDsaCtx>();

    if is_running() == 0 {
        return ptr::null_mut();
    }

    /*
     * Note that the `ML_DSA_KEY` is ref counted via `EVP_PKEY` so we can just copy the key here.
     */
    // SAFETY: `CRYPTO_memdup` copies `size` bytes from a readable source or answers NULL.
    let dstctx = unsafe {
        CRYPTO_memdup(
            srcctx.cast(),
            size_of::<ProvMlDsaCtx>(),
            FILE,
            LINE_MEMDUP_CTX,
        )
    }
    .cast::<ProvMlDsaCtx>();
    if dstctx.is_null() {
        return ptr::null_mut();
    }

    // SAFETY: `dstctx` is a fresh copy of `srcctx`; the two owned pointers are replaced below.
    unsafe {
        if !(*srcctx).sig.is_null() {
            (*dstctx).sig = CRYPTO_memdup(
                (*srcctx).sig.cast(),
                (*srcctx).siglen,
                FILE,
                LINE_MEMDUP_SIG,
            )
            .cast::<u8>();
            if (*dstctx).sig.is_null() {
                /*
                 * Can't call `ml_dsa_freectx()` here, as it would free `md_ctx`, which has not
                 * been duplicated yet.
                 */
                CRYPTO_free(dstctx.cast(), FILE, LINE_FREE_DSTCTX);
                return ptr::null_mut();
            }
        }

        if !(*srcctx).md_ctx.is_null() {
            (*dstctx).md_ctx = EVP_MD_CTX_dup((*srcctx).md_ctx);
            if (*dstctx).md_ctx.is_null() {
                ml_dsa_freectx(dstctx.cast());
                return ptr::null_mut();
            }
        }
    }
    dstctx.cast()
}

/// `static int set_alg_id_buffer(PROV_ML_DSA_CTX *ctx)` — `ml_dsa_sig.c:139-163`.
///
/// # Safety
/// `ctx` is live with `key` set.
unsafe fn set_alg_id_buffer(ctx: *mut ProvMlDsaCtx) -> c_int {
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
            ret = ossl_DER_w_algorithmIdentifier_ML_DSA(pkt, -1, (*ctx).key);
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

/// `static int ml_dsa_signverify_msg_init(void *vctx, void *vkey, const OSSL_PARAM params[],`
/// `int operation, const char *desc)` — `ml_dsa_sig.c:165-191`.
///
/// `desc` is unused by the authority.
///
/// # Safety
/// The signature init dispatch contract.
unsafe fn ml_dsa_signverify_msg_init(
    vctx: *mut c_void,
    vkey: *mut c_void,
    params: *const OsslParam,
    operation: c_int,
    _desc: *const c_char,
) -> c_int {
    let ctx = vctx.cast::<ProvMlDsaCtx>();
    let key = vkey.cast::<MlDsaKey>();

    if is_running() == 0 || ctx.is_null() {
        return 0;
    }

    // SAFETY: `ctx`/`key` are the caller's.
    unsafe {
        if vkey.is_null() && (*ctx).key.is_null() {
            raise_site(&err_sites::PROV_ML_DSA_SIG_177);
            return 0;
        }

        if !key.is_null() {
            (*ctx).key = vkey.cast();
        }
        if ossl_ml_dsa_key_matches((*ctx).key, (*ctx).evp_type) == 0 {
            return 0;
        }

        set_alg_id_buffer(ctx);
        (*ctx).mu = 0;
        (*ctx).operation = operation;

        ml_dsa_set_ctx_params(ctx.cast(), params)
    }
}

/// `static int ml_dsa_sign_msg_init(void *vctx, void *vkey, const OSSL_PARAM params[])` —
/// `ml_dsa_sig.c:193-197`.
///
/// # Safety
/// The signature `sign_message_init` dispatch contract.
unsafe extern "C" fn ml_dsa_sign_msg_init(
    vctx: *mut c_void,
    vkey: *mut c_void,
    params: *const OsslParam,
) -> c_int {
    // SAFETY: the caller's contract, forwarded.
    unsafe {
        ml_dsa_signverify_msg_init(
            vctx,
            vkey,
            params,
            EVP_PKEY_OP_SIGNMSG,
            c"ML_DSA Sign Init".as_ptr(),
        )
    }
}

/// `static int ml_dsa_digest_signverify_init(void *vctx, const char *mdname, void *vkey,`
/// `const OSSL_PARAM params[])` — `ml_dsa_sig.c:199-217`.
///
/// # Safety
/// The signature digest-init dispatch contract.
unsafe extern "C" fn ml_dsa_digest_signverify_init(
    vctx: *mut c_void,
    mdname: *const c_char,
    vkey: *mut c_void,
    params: *const OsslParam,
) -> c_int {
    let ctx = vctx.cast::<ProvMlDsaCtx>();

    // SAFETY: `mdname` is NULL or NUL-terminated; `ctx` is the caller's.
    unsafe {
        if !mdname.is_null() && *mdname != 0 {
            raise_site_data(
                &err_sites::PROV_ML_DSA_SIG_205,
                c"Explicit digest not supported for ML-DSA operations".as_ptr(),
            );
            return 0;
        }

        (*ctx).mu = 0;

        if vkey.is_null() && !(*ctx).key.is_null() {
            return ml_dsa_set_ctx_params(vctx, params);
        }

        ml_dsa_signverify_msg_init(
            vctx,
            vkey,
            params,
            EVP_PKEY_OP_SIGN,
            c"ML_DSA Sign Init".as_ptr(),
        )
    }
}

/// `static int ml_dsa_signverify_msg_update(void *vctx, const unsigned char *data,`
/// `size_t datalen)` — `ml_dsa_sig.c:219-243`.
///
/// # Safety
/// The signature `sign_message_update`/`verify_message_update` dispatch contract.
unsafe extern "C" fn ml_dsa_signverify_msg_update(
    vctx: *mut c_void,
    data: *const u8,
    datalen: usize,
) -> c_int {
    let ctx = vctx.cast::<ProvMlDsaCtx>();

    if ctx.is_null() {
        return 0;
    }

    if is_running() == 0 {
        return 0;
    }

    // SAFETY: `ctx` is the caller's context; `data` is readable for `datalen` bytes.
    unsafe {
        if (*ctx).mu != 0 {
            return 0;
        }

        if (*ctx).md_ctx.is_null() {
            (*ctx).md_ctx = ossl_ml_dsa_mu_init(
                (*ctx).key,
                (*ctx).msg_encode,
                (*ctx).context_string.as_ptr(),
                (*ctx).context_string_len,
            );
            if (*ctx).md_ctx.is_null() {
                return 0;
            }
        }

        ossl_ml_dsa_mu_update((*ctx).md_ctx, data, datalen)
    }
}

/// `static int ml_dsa_sign_msg_final(void *vctx, unsigned char *sig, size_t *siglen,`
/// `size_t sigsize)` — `ml_dsa_sig.c:245-286`.
///
/// # Safety
/// The signature `sign_message_final` dispatch contract.
unsafe extern "C" fn ml_dsa_sign_msg_final(
    vctx: *mut c_void,
    sig: *mut u8,
    siglen: *mut usize,
    sigsize: usize,
) -> c_int {
    let ctx = vctx.cast::<ProvMlDsaCtx>();
    let mut rand_tmp = [0u8; ML_DSA_ENTROPY_LEN];
    let mut rnd: *const u8 = ptr::null();
    let mut mu = [0u8; ML_DSA_MU_BYTES];
    // `int ret = 0;` — every path that reaches the tail assigns it, so the initialiser is dead in
    // Rust the way it is in the C; a `let ret;` binding is the same answer.
    let ret;

    if ctx.is_null() {
        return 0;
    }

    if is_running() == 0 {
        return 0;
    }

    // SAFETY: `ctx`/`sig`/`siglen` are the caller's; `mu`/`rand_tmp` are this call's own.
    unsafe {
        if (*ctx).md_ctx.is_null() {
            return 0;
        }

        if !sig.is_null() {
            if (*ctx).test_entropy_len != 0 {
                rnd = (*ctx).test_entropy.as_ptr();
            } else {
                if (*ctx).deterministic == 1 {
                    rand_tmp = [0u8; ML_DSA_ENTROPY_LEN];
                } else if RAND_priv_bytes_ex(
                    (*ctx).libctx,
                    rand_tmp.as_mut_ptr(),
                    rand_tmp.len(),
                    0,
                ) <= 0
                {
                    return 0;
                }
                rnd = rand_tmp.as_ptr();
            }

            if ossl_ml_dsa_mu_finalize((*ctx).md_ctx, mu.as_mut_ptr(), mu.len()) == 0 {
                OPENSSL_cleanse(mu.as_mut_ptr().cast(), mu.len());
                return 0;
            }
        }

        ret = ossl_ml_dsa_sign(
            (*ctx).key,
            1,
            mu.as_ptr(),
            mu.len(),
            ptr::null(),
            0,
            rnd,
            rand_tmp.len(),
            0,
            sig,
            siglen,
            sigsize,
        );
        if rnd != (*ctx).test_entropy.as_ptr() {
            OPENSSL_cleanse(rand_tmp.as_mut_ptr().cast(), rand_tmp.len());
        }
        OPENSSL_cleanse(mu.as_mut_ptr().cast(), mu.len());
    }
    ret
}

/// `static int ml_dsa_sign(void *vctx, uint8_t *sig, size_t *siglen, size_t sigsize,`
/// `const uint8_t *msg, size_t msg_len)` — `ml_dsa_sig.c:288-318`.
///
/// # Safety
/// The signature `sign` dispatch contract.
unsafe extern "C" fn ml_dsa_sign(
    vctx: *mut c_void,
    sig: *mut u8,
    siglen: *mut usize,
    sigsize: usize,
    msg: *const u8,
    msg_len: usize,
) -> c_int {
    let ret;
    let ctx = vctx.cast::<ProvMlDsaCtx>();
    let mut rand_tmp = [0u8; ML_DSA_ENTROPY_LEN];
    let mut rnd: *const u8 = ptr::null();

    if is_running() == 0 {
        return 0;
    }

    // SAFETY: `ctx`/`sig`/`siglen`/`msg` are the caller's; `rand_tmp` is this call's own.
    unsafe {
        if !sig.is_null() {
            if (*ctx).test_entropy_len != 0 {
                rnd = (*ctx).test_entropy.as_ptr();
            } else {
                if (*ctx).deterministic == 1 {
                    rand_tmp = [0u8; ML_DSA_ENTROPY_LEN];
                } else if RAND_priv_bytes_ex(
                    (*ctx).libctx,
                    rand_tmp.as_mut_ptr(),
                    rand_tmp.len(),
                    0,
                ) <= 0
                {
                    return 0;
                }
                rnd = rand_tmp.as_ptr();
            }
        }
        ret = ossl_ml_dsa_sign(
            (*ctx).key,
            (*ctx).mu,
            msg,
            msg_len,
            (*ctx).context_string.as_ptr(),
            (*ctx).context_string_len,
            rnd,
            rand_tmp.len(),
            (*ctx).msg_encode,
            sig,
            siglen,
            sigsize,
        );
        /* Only cleanse the temporary buffer generated for this signature. */
        if rnd != (*ctx).test_entropy.as_ptr() {
            OPENSSL_cleanse(rand_tmp.as_mut_ptr().cast(), rand_tmp.len());
        }
    }
    ret
}

/// `static int ml_dsa_digest_sign(void *vctx, uint8_t *sig, size_t *siglen, size_t sigsize,`
/// `const uint8_t *tbs, size_t tbslen)` — `ml_dsa_sig.c:319-323`.
///
/// # Safety
/// The signature `digest_sign` dispatch contract.
unsafe extern "C" fn ml_dsa_digest_sign(
    vctx: *mut c_void,
    sig: *mut u8,
    siglen: *mut usize,
    sigsize: usize,
    tbs: *const u8,
    tbslen: usize,
) -> c_int {
    // SAFETY: the caller's contract, forwarded verbatim.
    unsafe { ml_dsa_sign(vctx, sig, siglen, sigsize, tbs, tbslen) }
}

/// `static int ml_dsa_verify_msg_init(void *vctx, void *vkey, const OSSL_PARAM params[])` —
/// `ml_dsa_sig.c:325-329`.
///
/// # Safety
/// The signature `verify_message_init` dispatch contract.
unsafe extern "C" fn ml_dsa_verify_msg_init(
    vctx: *mut c_void,
    vkey: *mut c_void,
    params: *const OsslParam,
) -> c_int {
    // SAFETY: the caller's contract, forwarded.
    unsafe {
        ml_dsa_signverify_msg_init(
            vctx,
            vkey,
            params,
            EVP_PKEY_OP_VERIFYMSG,
            c"ML_DSA Verify Init".as_ptr(),
        )
    }
}

/// `static int ml_dsa_verify_msg_final(void *vctx)` — `ml_dsa_sig.c:331-349`.
///
/// # Safety
/// The signature `verify_message_final` dispatch contract.
unsafe extern "C" fn ml_dsa_verify_msg_final(vctx: *mut c_void) -> c_int {
    let ctx = vctx.cast::<ProvMlDsaCtx>();
    let mut mu = [0u8; ML_DSA_MU_BYTES];
    let mut ret = 0;

    if is_running() == 0 {
        return 0;
    }

    // SAFETY: `ctx` is the caller's context; `mu` is this call's own.
    unsafe {
        if (*ctx).md_ctx.is_null() {
            return 0;
        }

        if ossl_ml_dsa_mu_finalize((*ctx).md_ctx, mu.as_mut_ptr(), mu.len()) != 0 {
            ret = ossl_ml_dsa_verify(
                (*ctx).key,
                1,
                mu.as_ptr(),
                mu.len(),
                ptr::null(),
                0,
                0,
                (*ctx).sig,
                (*ctx).siglen,
            );
        }

        OPENSSL_cleanse(mu.as_mut_ptr().cast(), mu.len());
    }
    ret
}

/// `static int ml_dsa_verify(void *vctx, const uint8_t *sig, size_t siglen, const uint8_t *msg,`
/// `size_t msg_len)` — `ml_dsa_sig.c:351-361`.
///
/// # Safety
/// The signature `verify` dispatch contract.
unsafe extern "C" fn ml_dsa_verify(
    vctx: *mut c_void,
    sig: *const u8,
    siglen: usize,
    msg: *const u8,
    msg_len: usize,
) -> c_int {
    let ctx = vctx.cast::<ProvMlDsaCtx>();

    if is_running() == 0 {
        return 0;
    }
    // SAFETY: `ctx`/`sig`/`msg` are the caller's context and buffers.
    unsafe {
        ossl_ml_dsa_verify(
            (*ctx).key,
            (*ctx).mu,
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

/// `static int ml_dsa_digest_verify(void *vctx, const uint8_t *sig, size_t siglen,`
/// `const uint8_t *tbs, size_t tbslen)` — `ml_dsa_sig.c:362-368`.
///
/// # Safety
/// The signature `digest_verify` dispatch contract.
unsafe extern "C" fn ml_dsa_digest_verify(
    vctx: *mut c_void,
    sig: *const u8,
    siglen: usize,
    tbs: *const u8,
    tbslen: usize,
) -> c_int {
    // SAFETY: the caller's contract, forwarded verbatim.
    unsafe { ml_dsa_verify(vctx, sig, siglen, tbs, tbslen) }
}

/// `static const OSSL_PARAM ml_dsa_set_ctx_params_list[]` — generated `ml_dsa_sig.c:379-387`.
///
/// The signing case's list: the six-name decoder recognizes `signature` too, but the sign list
/// does not advertise it.
static ML_DSA_SET_CTX_PARAMS_LIST: [OsslParam; 6] = [
    param_octet_string(OSSL_SIGNATURE_PARAM_CONTEXT_STRING),
    param_octet_string(OSSL_SIGNATURE_PARAM_TEST_ENTROPY),
    param_int(OSSL_SIGNATURE_PARAM_DETERMINISTIC),
    param_int(OSSL_SIGNATURE_PARAM_MESSAGE_ENCODING),
    param_int(OSSL_SIGNATURE_PARAM_MU),
    END,
];

/// `struct ml_dsa_verifymsg_set_ctx_params_st` — generated `ml_dsa_sig.c:494-501`.
///
/// The sign-case structure (`ml_dsa_sig.c.in:375`) is `#define`d onto this one, so its five fields
/// are the first five here and the two decoders share this type.
struct MlDsaVerifymsgSetCtxParams {
    ctx: *mut OsslParam,
    det: *mut OsslParam,
    ent: *mut OsslParam,
    msgenc: *mut OsslParam,
    mu: *mut OsslParam,
    sig: *mut OsslParam,
}

/// The sign decoder's repeated-key coordinates — generated
/// `ml_dsa_sig.c:415/426/441/454/466`, in the generated switch's alphabetical key order.
///
/// The C preprocessor aliases `ml_dsa_set_ctx_params_decoder` onto the verifymsg decoder, so this
/// array is retained only to carry the five raise sites the generated text records.
#[allow(dead_code)] // the authority's `#define` inlines the sign decoder onto the verifymsg one
const ML_DSA_SET_CTX_PARAMS_DECODER_KEYS: [(&err_sites::ErrSite, *const c_char); 5] = [
    (
        &err_sites::PROV_ML_DSA_SIG_415,
        OSSL_SIGNATURE_PARAM_CONTEXT_STRING,
    ),
    (
        &err_sites::PROV_ML_DSA_SIG_426,
        OSSL_SIGNATURE_PARAM_DETERMINISTIC,
    ),
    (
        &err_sites::PROV_ML_DSA_SIG_441,
        OSSL_SIGNATURE_PARAM_MESSAGE_ENCODING,
    ),
    (&err_sites::PROV_ML_DSA_SIG_454, OSSL_SIGNATURE_PARAM_MU),
    (
        &err_sites::PROV_ML_DSA_SIG_466,
        OSSL_SIGNATURE_PARAM_TEST_ENTROPY,
    ),
];

/// The verifymsg decoder's repeated-key coordinates — generated
/// `ml_dsa_sig.c:520/531/546/559/571/582`, in the generated switch's alphabetical key order.
const ML_DSA_VERIFYMSG_SET_CTX_PARAMS_DECODER_KEYS: [(&err_sites::ErrSite, *const c_char); 6] = [
    (
        &err_sites::PROV_ML_DSA_SIG_520,
        OSSL_SIGNATURE_PARAM_CONTEXT_STRING,
    ),
    (
        &err_sites::PROV_ML_DSA_SIG_531,
        OSSL_SIGNATURE_PARAM_DETERMINISTIC,
    ),
    (
        &err_sites::PROV_ML_DSA_SIG_546,
        OSSL_SIGNATURE_PARAM_MESSAGE_ENCODING,
    ),
    (&err_sites::PROV_ML_DSA_SIG_559, OSSL_SIGNATURE_PARAM_MU),
    (
        &err_sites::PROV_ML_DSA_SIG_571,
        OSSL_SIGNATURE_PARAM_SIGNATURE,
    ),
    (
        &err_sites::PROV_ML_DSA_SIG_582,
        OSSL_SIGNATURE_PARAM_TEST_ENTROPY,
    ),
];

/// `ml_dsa_set_ctx_params_decoder` — generated `ml_dsa_sig.c:400-475`.
///
/// # Safety
/// `params` is NULL or key-terminated; `r` is writable.
#[allow(dead_code)] // the authority's `#define` inlines this decoder onto the verifymsg one
unsafe fn ml_dsa_set_ctx_params_decoder(
    params: *const OsslParam,
    r: &mut MlDsaVerifymsgSetCtxParams,
) -> c_int {
    // SAFETY: the arguments are per the contract.
    unsafe {
        if !params.is_null() {
            let mut seen: u32 = 0;
            let mut p = params;
            while !(*p).key.is_null() {
                let k = core::ffi::CStr::from_ptr((*p).key).to_bytes();
                for (i, (site, name)) in ML_DSA_SET_CTX_PARAMS_DECODER_KEYS.iter().enumerate() {
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
        r.ctx = OSSL_PARAM_locate_const(params, OSSL_SIGNATURE_PARAM_CONTEXT_STRING).cast_mut();
        r.det = OSSL_PARAM_locate_const(params, OSSL_SIGNATURE_PARAM_DETERMINISTIC).cast_mut();
        r.ent = OSSL_PARAM_locate_const(params, OSSL_SIGNATURE_PARAM_TEST_ENTROPY).cast_mut();
        r.msgenc =
            OSSL_PARAM_locate_const(params, OSSL_SIGNATURE_PARAM_MESSAGE_ENCODING).cast_mut();
        r.mu = OSSL_PARAM_locate_const(params, OSSL_SIGNATURE_PARAM_MU).cast_mut();
    }
    1
}

/// `ml_dsa_verifymsg_set_ctx_params_decoder` — generated `ml_dsa_sig.c:505-590`.
///
/// # Safety
/// `params` is NULL or key-terminated; `r` is writable.
unsafe fn ml_dsa_verifymsg_set_ctx_params_decoder(
    params: *const OsslParam,
    r: &mut MlDsaVerifymsgSetCtxParams,
) -> c_int {
    // SAFETY: the arguments are per the contract.
    unsafe {
        if !params.is_null() {
            let mut seen: u32 = 0;
            let mut p = params;
            while !(*p).key.is_null() {
                let k = core::ffi::CStr::from_ptr((*p).key).to_bytes();
                for (i, (site, name)) in ML_DSA_VERIFYMSG_SET_CTX_PARAMS_DECODER_KEYS
                    .iter()
                    .enumerate()
                {
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
        r.ctx = OSSL_PARAM_locate_const(params, OSSL_SIGNATURE_PARAM_CONTEXT_STRING).cast_mut();
        r.det = OSSL_PARAM_locate_const(params, OSSL_SIGNATURE_PARAM_DETERMINISTIC).cast_mut();
        r.ent = OSSL_PARAM_locate_const(params, OSSL_SIGNATURE_PARAM_TEST_ENTROPY).cast_mut();
        r.msgenc =
            OSSL_PARAM_locate_const(params, OSSL_SIGNATURE_PARAM_MESSAGE_ENCODING).cast_mut();
        r.mu = OSSL_PARAM_locate_const(params, OSSL_SIGNATURE_PARAM_MU).cast_mut();
        r.sig = OSSL_PARAM_locate_const(params, OSSL_SIGNATURE_PARAM_SIGNATURE).cast_mut();
    }
    1
}

/// `static int ml_dsa_set_ctx_params(void *vctx, const OSSL_PARAM params[])` —
/// `ml_dsa_sig.c:595-645`.
///
/// # Safety
/// The signature `set_ctx_params` dispatch contract.
unsafe extern "C" fn ml_dsa_set_ctx_params(vctx: *mut c_void, params: *const OsslParam) -> c_int {
    let pctx = vctx.cast::<ProvMlDsaCtx>();
    let mut p = MlDsaVerifymsgSetCtxParams {
        ctx: ptr::null_mut(),
        det: ptr::null_mut(),
        ent: ptr::null_mut(),
        msgenc: ptr::null_mut(),
        mu: ptr::null_mut(),
        sig: ptr::null_mut(),
    };

    // SAFETY: `pctx`/`params` are the caller's; `p` is this call's own decoder result.
    unsafe {
        if pctx.is_null() || ml_dsa_verifymsg_set_ctx_params_decoder(params, &mut p) == 0 {
            return 0;
        }

        if !p.ctx.is_null() {
            let mut vp: *mut c_void = (*pctx).context_string.as_mut_ptr().cast();
            if OSSL_PARAM_get_octet_string(
                p.ctx,
                &mut vp,
                (*pctx).context_string.len(),
                &mut (*pctx).context_string_len,
            ) == 0
            {
                (*pctx).context_string_len = 0;
                return 0;
            }
        }

        if !p.ent.is_null() {
            let mut vp: *mut c_void = (*pctx).test_entropy.as_mut_ptr().cast();
            (*pctx).test_entropy_len = 0;
            if OSSL_PARAM_get_octet_string(
                p.ent,
                &mut vp,
                (*pctx).test_entropy.len(),
                &mut (*pctx).test_entropy_len,
            ) == 0
            {
                return 0;
            }
            if (*pctx).test_entropy_len != (*pctx).test_entropy.len() {
                (*pctx).test_entropy_len = 0;
                raise_site(&err_sites::PROV_ML_DSA_SIG_622);
                return 0;
            }
        }

        if !p.det.is_null() && OSSL_PARAM_get_int(p.det, &mut (*pctx).deterministic) == 0 {
            return 0;
        }

        if !p.msgenc.is_null() && OSSL_PARAM_get_int(p.msgenc, &mut (*pctx).msg_encode) == 0 {
            return 0;
        }

        if !p.mu.is_null() && OSSL_PARAM_get_int(p.mu, &mut (*pctx).mu) == 0 {
            return 0;
        }

        if !p.sig.is_null() && (*pctx).operation == EVP_PKEY_OP_VERIFYMSG {
            CRYPTO_free((*pctx).sig.cast(), FILE, LINE_FREE_SET_SIG);
            (*pctx).sig = ptr::null_mut();
            (*pctx).siglen = 0;
            if OSSL_PARAM_get_octet_string(
                p.sig,
                ptr::addr_of_mut!((*pctx).sig).cast::<*mut c_void>(),
                0,
                &mut (*pctx).siglen,
            ) == 0
            {
                return 0;
            }
        }
    }
    1
}

/// `static const OSSL_PARAM *ml_dsa_settable_ctx_params(void *vctx, void *provctx)` —
/// `ml_dsa_sig.c:648-657`.
///
/// `provctx` is unused by the authority.
///
/// # Safety
/// The signature `settable_ctx_params` dispatch contract.
unsafe extern "C" fn ml_dsa_settable_ctx_params(
    vctx: *mut c_void,
    _provctx: *mut c_void,
) -> *const OsslParam {
    let pctx = vctx.cast::<ProvMlDsaCtx>();

    // SAFETY: `pctx` is the caller's context or NULL, which is checked.
    unsafe {
        if !pctx.is_null() && (*pctx).operation == EVP_PKEY_OP_VERIFYMSG {
            ML_DSA_VERIFYMSG_SET_CTX_PARAMS_LIST.as_ptr()
        } else {
            ML_DSA_SET_CTX_PARAMS_LIST.as_ptr()
        }
    }
}

/// `static const OSSL_PARAM ml_dsa_verifymsg_set_ctx_params_list[]` — generated
/// `ml_dsa_sig.c:482-491`.
static ML_DSA_VERIFYMSG_SET_CTX_PARAMS_LIST: [OsslParam; 7] = [
    param_octet_string(OSSL_SIGNATURE_PARAM_CONTEXT_STRING),
    param_octet_string(OSSL_SIGNATURE_PARAM_TEST_ENTROPY),
    param_int(OSSL_SIGNATURE_PARAM_DETERMINISTIC),
    param_int(OSSL_SIGNATURE_PARAM_MESSAGE_ENCODING),
    param_int(OSSL_SIGNATURE_PARAM_MU),
    param_octet_string(OSSL_SIGNATURE_PARAM_SIGNATURE),
    END,
];

/// `static const OSSL_PARAM ml_dsa_get_ctx_params_list[]` — generated `ml_dsa_sig.c:662-666`.
static ML_DSA_GET_CTX_PARAMS_LIST: [OsslParam; 2] =
    [param_octet_string(OSSL_SIGNATURE_PARAM_ALGORITHM_ID), END];

/// `struct ml_dsa_get_ctx_params_st` — generated `ml_dsa_sig.c:669-671`.
struct MlDsaGetCtxParams {
    algid: *mut OsslParam,
}

/// `ml_dsa_get_ctx_params_decoder` — generated `ml_dsa_sig.c:675-694`.
///
/// # Safety
/// `params` is NULL or key-terminated; `r` is writable.
unsafe fn ml_dsa_get_ctx_params_decoder(
    params: *const OsslParam,
    r: &mut MlDsaGetCtxParams,
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
                        raise_site(&err_sites::PROV_ML_DSA_SIG_686);
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

/// `static const OSSL_PARAM *ml_dsa_gettable_ctx_params(void *vctx, void *provctx)` —
/// `ml_dsa_sig.c:698-702`.
///
/// Both arguments are unused by the authority.
///
/// # Safety
/// Takes no live pointers it reads.
unsafe extern "C" fn ml_dsa_gettable_ctx_params(
    _vctx: *mut c_void,
    _provctx: *mut c_void,
) -> *const OsslParam {
    ML_DSA_GET_CTX_PARAMS_LIST.as_ptr()
}

/// `static int ml_dsa_get_ctx_params(void *vctx, OSSL_PARAM *params)` —
/// `ml_dsa_sig.c:704-720`.
///
/// # Safety
/// The signature `get_ctx_params` dispatch contract.
unsafe extern "C" fn ml_dsa_get_ctx_params(vctx: *mut c_void, params: *mut OsslParam) -> c_int {
    let ctx = vctx.cast::<ProvMlDsaCtx>();
    let mut p = MlDsaGetCtxParams {
        algid: ptr::null_mut(),
    };

    // SAFETY: `ctx`/`params` are the caller's; `p` is this call's own decoder result.
    unsafe {
        if ctx.is_null() || ml_dsa_get_ctx_params_decoder(params, &mut p) == 0 {
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

/// `MAKE_SIGNATURE_FUNCTIONS(alg)` — `ml_dsa_sig.c:722-764`, once per parameter set.
///
/// Each expansion differs in the algorithm's `EVP_PKEY_ML_DSA_*` type and in the one per-algorithm
/// callback (`ml_dsa_<n>_newctx`); every other slot is one of the shared functions above.
macro_rules! make_ml_dsa_signature_functions {
    ($table:ident, $evp_type:expr, $fn_newctx:ident) => {
        /// `static void *ml_dsa_<n>_newctx(void *provctx, const char *propq)` — one expansion's
        /// new context.
        ///
        /// # Safety
        /// The signature `newctx` dispatch contract.
        unsafe extern "C" fn $fn_newctx(provctx: *mut c_void, propq: *const c_char) -> *mut c_void {
            // SAFETY: the caller's contract, forwarded with this expansion's `EVP_PKEY` type.
            unsafe { ml_dsa_newctx(provctx, $evp_type, propq) }
        }

        /// `const OSSL_DISPATCH ossl_ml_dsa_<n>_signature_functions[]` — one expansion's table.
        pub(crate) static $table: [OsslDispatch; 20] = [
            OsslDispatch {
                function_id: OSSL_FUNC_SIGNATURE_NEWCTX,
                function: $fn_newctx as *mut c_void,
            },
            OsslDispatch {
                function_id: OSSL_FUNC_SIGNATURE_SIGN_MESSAGE_INIT,
                function: ml_dsa_sign_msg_init as *mut c_void,
            },
            OsslDispatch {
                function_id: OSSL_FUNC_SIGNATURE_SIGN_MESSAGE_UPDATE,
                function: ml_dsa_signverify_msg_update as *mut c_void,
            },
            OsslDispatch {
                function_id: OSSL_FUNC_SIGNATURE_SIGN_MESSAGE_FINAL,
                function: ml_dsa_sign_msg_final as *mut c_void,
            },
            OsslDispatch {
                function_id: OSSL_FUNC_SIGNATURE_SIGN,
                function: ml_dsa_sign as *mut c_void,
            },
            OsslDispatch {
                function_id: OSSL_FUNC_SIGNATURE_VERIFY_MESSAGE_INIT,
                function: ml_dsa_verify_msg_init as *mut c_void,
            },
            OsslDispatch {
                function_id: OSSL_FUNC_SIGNATURE_VERIFY_MESSAGE_UPDATE,
                function: ml_dsa_signverify_msg_update as *mut c_void,
            },
            OsslDispatch {
                function_id: OSSL_FUNC_SIGNATURE_VERIFY_MESSAGE_FINAL,
                function: ml_dsa_verify_msg_final as *mut c_void,
            },
            OsslDispatch {
                function_id: OSSL_FUNC_SIGNATURE_VERIFY,
                function: ml_dsa_verify as *mut c_void,
            },
            OsslDispatch {
                function_id: OSSL_FUNC_SIGNATURE_DIGEST_SIGN_INIT,
                function: ml_dsa_digest_signverify_init as *mut c_void,
            },
            OsslDispatch {
                function_id: OSSL_FUNC_SIGNATURE_DIGEST_SIGN,
                function: ml_dsa_digest_sign as *mut c_void,
            },
            OsslDispatch {
                function_id: OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_INIT,
                function: ml_dsa_digest_signverify_init as *mut c_void,
            },
            OsslDispatch {
                function_id: OSSL_FUNC_SIGNATURE_DIGEST_VERIFY,
                function: ml_dsa_digest_verify as *mut c_void,
            },
            OsslDispatch {
                function_id: OSSL_FUNC_SIGNATURE_FREECTX,
                function: ml_dsa_freectx as *mut c_void,
            },
            OsslDispatch {
                function_id: OSSL_FUNC_SIGNATURE_SET_CTX_PARAMS,
                function: ml_dsa_set_ctx_params as *mut c_void,
            },
            OsslDispatch {
                function_id: OSSL_FUNC_SIGNATURE_SETTABLE_CTX_PARAMS,
                function: ml_dsa_settable_ctx_params as *mut c_void,
            },
            OsslDispatch {
                function_id: OSSL_FUNC_SIGNATURE_GET_CTX_PARAMS,
                function: ml_dsa_get_ctx_params as *mut c_void,
            },
            OsslDispatch {
                function_id: OSSL_FUNC_SIGNATURE_GETTABLE_CTX_PARAMS,
                function: ml_dsa_gettable_ctx_params as *mut c_void,
            },
            OsslDispatch {
                function_id: OSSL_FUNC_SIGNATURE_DUPCTX,
                function: ml_dsa_dupctx as *mut c_void,
            },
            OsslDispatch {
                function_id: OSSL_DISPATCH_END,
                function: ptr::null_mut(),
            },
        ];
    };
}

make_ml_dsa_signature_functions!(
    ML_DSA_44_SIGNATURE_FUNCTIONS,
    EVP_PKEY_ML_DSA_44,
    ml_dsa_44_newctx
);
make_ml_dsa_signature_functions!(
    ML_DSA_65_SIGNATURE_FUNCTIONS,
    EVP_PKEY_ML_DSA_65,
    ml_dsa_65_newctx
);
make_ml_dsa_signature_functions!(
    ML_DSA_87_SIGNATURE_FUNCTIONS,
    EVP_PKEY_ML_DSA_87,
    ml_dsa_87_newctx
);

/// `ML_DSA_MESSAGE_ENCODE_RAW` is the value `set_ctx_params` writes for a raw message; named here
/// so a reader sees both encodings the unit carries.
const _: c_int = ML_DSA_MESSAGE_ENCODE_RAW;
