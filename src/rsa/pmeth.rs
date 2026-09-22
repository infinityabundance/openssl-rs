//! `crypto/rsa/rsa_pmeth.c` — the `RSA` and `RSA-PSS` `EVP_PKEY_METHOD` objects and their callbacks.
//!
//! Transcribed whole. The unit defines **two** objects over one set of callbacks — `rsa_pkey_meth`
//! (`EVP_PKEY_RSA`, `:816`) and `rsa_pss_pkey_meth` (`EVP_PKEY_RSA_PSS`, `:908`) — and the pair is
//! the reason `pkey_ctx_is_pss` exists: `(ctx->pmeth->pkey_id == EVP_PKEY_RSA_PSS)`
//! (`crypto/rsa/rsa_local.h:151`) is read by `pkey_rsa_init` to choose the default padding, by
//! `pkey_rsa_ctrl`'s padding arm to forbid `PKCS1` on a PSS context, by the six CMS/PKCS7 arms, and
//! by `rsa_set_pss_param` and `pkey_pss_init`. That read is why `EvpPkeyCtx` grew a `pmeth` member
//! in this slice.
//!
//! ## The padding mode is a mode, and the digest is not
//!
//! `pkey_rsa_init` picks `RSA_PKCS1_PSS_PADDING` or `RSA_PKCS1_PADDING` from the **method**, not from
//! the key, so a context built from `EVP_PKEY_meth_find(EVP_PKEY_RSA_PSS)` defaults to PSS before any
//! key is seen. `min_saltlen` starts at -1 ("no restriction") and is the flag `rsa_pss_restricted`
//! reads; `pkey_pss_init` lowers it from the key's own `rsa->pss` parameters and *also* installs
//! them as the context's defaults, which is what then blocks an invalid `saltlen` in
//! `pkey_rsa_ctrl`.
//!
//! ## Two arms are constant-time by construction, and one of them is easy to get wrong
//!
//! `pkey_rsa_decrypt`'s tail is `constant_time_select_s(constant_time_msb_s(ret), *outlen, ret)`
//! then `constant_time_select_int(constant_time_msb(ret), ret, 1)` — the *length* and the *return*
//! are selected on the sign of `ret` rather than branched on, so a caller cannot tell a padding
//! failure from a short plaintext by timing. The first takes the `size_t` helpers and the second the
//! `unsigned int` ones, which is why the crate has four of them.
//!
//! ## What this module does not do
//!
//! `ossl_rsa_pkey_method` and `ossl_rsa_pss_pkey_method` are published as statics and named by
//! `src/evp/pkey_ctx.rs`'s `PMETH_STANDARD_METHODS`, so `EVP_PKEY_meth_find` answers them. No caller
//! builds an `EVP_PKEY_CTX` from either yet: that is `int_ctx_new`'s `pmeth` arm, still recorded as
//! absent.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_char, c_int, c_long, c_uint, c_void, CStr};
use core::ptr;

use crate::bn::bignum::{
    BN_asc2bn, BN_dup, BN_free, BN_is_odd, BN_is_one, BN_new, BN_set_word, BigNum,
};
use crate::bn::ctx::{BN_GENCB_free, BN_GENCB_new};
use crate::evp::digest::{EVP_MD_get_size, EVP_MD_get_type, EvpMd};
use crate::evp::legacy_sha::EVP_sha1;
use crate::evp::p_legacy_assign::EVP_PKEY_get0_RSA;
use crate::evp::pkey::{EVP_PKEY_assign, EvpPkey};
use crate::evp::pkey_ctx::{
    EvpPkeyCtx, EvpPkeyMethod, EVP_PKEY_CTRL_CMS_DECRYPT, EVP_PKEY_CTRL_CMS_ENCRYPT,
    EVP_PKEY_CTRL_CMS_SIGN, EVP_PKEY_CTRL_DIGESTINIT, EVP_PKEY_CTRL_GET_MD,
    EVP_PKEY_CTRL_GET_RSA_MGF1_MD, EVP_PKEY_CTRL_GET_RSA_OAEP_LABEL, EVP_PKEY_CTRL_GET_RSA_OAEP_MD,
    EVP_PKEY_CTRL_GET_RSA_PADDING, EVP_PKEY_CTRL_GET_RSA_PSS_SALTLEN, EVP_PKEY_CTRL_MD,
    EVP_PKEY_CTRL_PEER_KEY, EVP_PKEY_CTRL_PKCS7_DECRYPT, EVP_PKEY_CTRL_PKCS7_ENCRYPT,
    EVP_PKEY_CTRL_PKCS7_SIGN, EVP_PKEY_CTRL_RSA_IMPLICIT_REJECTION, EVP_PKEY_CTRL_RSA_KEYGEN_BITS,
    EVP_PKEY_CTRL_RSA_KEYGEN_PRIMES, EVP_PKEY_CTRL_RSA_KEYGEN_PUBEXP, EVP_PKEY_CTRL_RSA_MGF1_MD,
    EVP_PKEY_CTRL_RSA_OAEP_LABEL, EVP_PKEY_CTRL_RSA_OAEP_MD, EVP_PKEY_CTRL_RSA_PADDING,
    EVP_PKEY_CTRL_RSA_PSS_SALTLEN, EVP_PKEY_FLAG_AUTOARGLEN, EVP_PKEY_OP_KEYGEN, EVP_PKEY_OP_SIGN,
    EVP_PKEY_OP_TYPE_CRYPT, EVP_PKEY_OP_TYPE_SIG, EVP_PKEY_OP_VERIFY, EVP_PKEY_RSA,
    EVP_PKEY_RSA_PSS, RSA_NO_PADDING, RSA_PKCS1_OAEP_PADDING, RSA_PKCS1_PADDING,
    RSA_PKCS1_PSS_PADDING, RSA_PSS_SALTLEN_AUTO, RSA_PSS_SALTLEN_DIGEST, RSA_PSS_SALTLEN_MAX,
    RSA_X931_PADDING,
};
use crate::evp::pmeth_gn::evp_pkey_set_cb_translate;
use crate::rand::sys::atoi;
use crate::rsa::ameth::{ossl_rsa_pss_get_param, ossl_rsa_pss_params_create};
use crate::rsa::ctrl::{
    EVP_PKEY_CTX_set0_rsa_oaep_label, EVP_PKEY_CTX_set1_rsa_keygen_pubexp,
    EVP_PKEY_CTX_set_rsa_keygen_bits, EVP_PKEY_CTX_set_rsa_keygen_primes,
    EVP_PKEY_CTX_set_rsa_padding, EVP_PKEY_CTX_set_rsa_pss_keygen_saltlen,
    EVP_PKEY_CTX_set_rsa_pss_saltlen,
};
use crate::rsa::gen::{RSA_generate_multi_prime_key, RSA_DEFAULT_PRIME_NUM, RSA_MIN_MODULUS_BITS};
use crate::rsa::mp::RSA_MAX_PRIME_NUM;
use crate::rsa::object::{
    RSA_bits, RSA_free, RSA_new, RSA_private_decrypt, RSA_private_encrypt, RSA_public_decrypt,
    RSA_public_encrypt, RSA_size,
};
use crate::rsa::ossl::RSA_PKCS1_NO_IMPLICIT_REJECT_PADDING;
use crate::rsa::pss::{RSA_padding_add_PKCS1_PSS_mgf1, RSA_verify_PKCS1_PSS_mgf1};
use crate::rsa::sign::{ossl_rsa_verify, RSA_sign, RSA_sign_ASN1_OCTET_STRING, RSA_verify};
use crate::rsa::Rsa;
use crate::runtime::constant_time::{
    constant_time_msb_s, constant_time_msb_u32, constant_time_select, constant_time_select_int,
};
use crate::runtime::err::{err_sites, raise_site};
use crate::runtime::mem::{CRYPTO_free, CRYPTO_malloc, CRYPTO_memdup, CRYPTO_zalloc};
use crate::runtime::obj::{
    NID_md2, NID_md4, NID_md5, NID_md5_sha1, NID_mdc2, NID_ripemd160, NID_sha1, NID_sha224,
    NID_sha256, NID_sha384, NID_sha3_224, NID_sha3_256, NID_sha3_384, NID_sha3_512, NID_sha512,
    NID_sha512_224, NID_sha512_256,
};
use crate::runtime::str::OPENSSL_hexstr2buf;

/// `crypto/rsa/rsa_pmeth.c` — the translation unit every allocation and error below is attributed to.
const FILE: *const c_char = c"../../src/openssl-3.6.4/crypto/rsa/rsa_pmeth.c".as_ptr();

/// `pkey_rsa_init`'s `OPENSSL_zalloc(sizeof(*rctx))` (`:64`).
const LINE_ZALLOC_RCTX: c_int = 64;
/// `pkey_rsa_copy`'s `OPENSSL_free(dctx->oaep_label)` before the duplicate (`:105`).
const LINE_FREE_OAEP_LABEL_COPY: c_int = 105;
/// `pkey_rsa_copy`'s `OPENSSL_memdup(sctx->oaep_label, sctx->oaep_labellen)` (`:106`).
const LINE_MEMDUP_OAEP_LABEL: c_int = 106;
/// `setup_tbuf`'s `OPENSSL_malloc(RSA_size(...))` (`:118`).
const LINE_MALLOC_TBUF: c_int = 118;
/// `pkey_rsa_cleanup`'s `OPENSSL_free(rctx->tbuf)` (`:128`).
const LINE_FREE_TBUF: c_int = 128;
/// `pkey_rsa_cleanup`'s `OPENSSL_free(rctx->oaep_label)` (`:129`).
const LINE_FREE_OAEP_LABEL: c_int = 129;
/// `pkey_rsa_cleanup`'s `OPENSSL_free(rctx)` (`:130`).
const LINE_FREE_RCTX: c_int = 130;
/// `pkey_rsa_ctrl`'s `OPENSSL_free(rctx->oaep_label)` on replacement (`:594`).
const LINE_FREE_OAEP_LABEL_CTRL: c_int = 594;
/// `pkey_rsa_ctrl_str`'s `OPENSSL_free(lab)` on a refused `set0` (`:751`).
const LINE_FREE_LAB: c_int = 751;

/// `RSA_F4` — `include/openssl/rsa.h:43`: the exponent `pkey_rsa_keygen` defaults to.
const RSA_F4: u64 = 0x1_0001;

/// `#define rsa_pss_restricted(rctx) (rctx->min_saltlen != -1)` — `crypto/rsa/rsa_pmeth.c:60`.
///
/// # Safety
/// `rctx` must be live.
unsafe fn rsa_pss_restricted(rctx: *const RsaPkeyCtx) -> bool {
    // SAFETY: `rctx` is live per the contract.
    unsafe { (*rctx).min_saltlen != -1 }
}

/// `#define pkey_ctx_is_pss(ctx) (ctx->pmeth->pkey_id == EVP_PKEY_RSA_PSS)` —
/// `crypto/rsa/rsa_local.h:151`.
///
/// Six call sites, and it is the reason `EvpPkeyCtx` carries `pmeth`. The authority dereferences
/// unconditionally, so a context with no method is a fault there and here.
///
/// # Safety
/// `ctx` must be live and its `pmeth` non-NULL.
unsafe fn pkey_ctx_is_pss(ctx: *const EvpPkeyCtx) -> bool {
    // SAFETY: `ctx` is live and `pmeth` is the method the context was built from.
    unsafe { (*(*ctx).pmeth).pkey_id == EVP_PKEY_RSA_PSS }
}

/// `RSA_PKEY_CTX` — `crypto/rsa/rsa_pmeth.c:33-57`.
///
/// Fourteen members. `tbuf` is the scratch the sign/verify/encrypt/decrypt arms share — allocated
/// lazily by `setup_tbuf` and freed by `pkey_rsa_cleanup` — and `oaep_label` is an owned buffer
/// whose length is `oaep_labellen`.
#[repr(C)]
struct RsaPkeyCtx {
    /// `int nbits` — the key size for generation (default 2048).
    nbits: c_int,
    /// `BIGNUM *pub_exp` — the public exponent, owned.
    pub_exp: *mut BigNum,
    /// `int primes` — the number of primes (default `RSA_DEFAULT_PRIME_NUM`).
    primes: c_int,
    /// `int gentmp[2]` — the keygen callback's scratch, published as `ctx->keygen_info`.
    gentmp: [c_int; 2],
    /// `int pad_mode` — the `RSA_*_PADDING` mode.
    pad_mode: c_int,
    /// `const EVP_MD *md` — the digest, borrowed.
    md: *const EvpMd,
    /// `const EVP_MD *mgf1md` — the MGF1 digest, borrowed.
    mgf1md: *const EvpMd,
    /// `int saltlen` — the PSS salt length, or one of the `RSA_PSS_SALTLEN_*` sentinels.
    saltlen: c_int,
    /// `int min_saltlen` — the PSS restriction, or -1 when unrestricted.
    min_saltlen: c_int,
    /// `unsigned char *tbuf` — the shared scratch, owned.
    tbuf: *mut u8,
    /// `unsigned char *oaep_label` — the OAEP label, owned.
    oaep_label: *mut u8,
    /// `size_t oaep_labellen`.
    oaep_labellen: usize,
    /// `int implicit_rejection` — whether PKCS#1 v1.5 decryption uses implicit rejection.
    implicit_rejection: c_int,
}

/// `strcmp(s, lit) == 0` in the crate's `CStr` idiom.
///
/// # Safety
/// `s` must be NUL-terminated.
unsafe fn cstr_is(s: *const c_char, lit: &[u8]) -> bool {
    // SAFETY: `s` is NUL-terminated per the contract.
    unsafe { CStr::from_ptr(s) }.to_bytes() == lit
}

/// `static int pkey_rsa_init(EVP_PKEY_CTX *ctx)` — `:62`.
///
/// # Safety
/// `ctx` must be live.
unsafe extern "C" fn pkey_rsa_init(ctx: *mut EvpPkeyCtx) -> c_int {
    /* `CRYPTO_zalloc` is a safe entry point of this crate. */
    let rctx = CRYPTO_zalloc(core::mem::size_of::<RsaPkeyCtx>(), FILE, LINE_ZALLOC_RCTX)
        .cast::<RsaPkeyCtx>();
    if rctx.is_null() {
        return 0;
    }
    // SAFETY: `ctx` is live per the contract.
    let is_pss = unsafe { pkey_ctx_is_pss(ctx) };
    // SAFETY: `rctx` is this call's own allocation and `ctx` is live per the contract.
    unsafe {
        (*rctx).nbits = 2048;
        (*rctx).primes = RSA_DEFAULT_PRIME_NUM;
        (*rctx).pad_mode = if is_pss {
            RSA_PKCS1_PSS_PADDING
        } else {
            RSA_PKCS1_PADDING
        };
        /* Maximum for sign, auto for verify. */
        (*rctx).saltlen = RSA_PSS_SALTLEN_AUTO;
        (*rctx).min_saltlen = -1;
        (*rctx).implicit_rejection = 1;

        (*ctx).data = rctx.cast::<c_void>();
        (*ctx).keygen_info = ptr::addr_of_mut!((*rctx).gentmp).cast::<c_int>();
        (*ctx).keygen_info_count = 2;
    }
    1
}

/// `static int pkey_rsa_copy(EVP_PKEY_CTX *dst, const EVP_PKEY_CTX *src)` — `:85`.
///
/// # Safety
/// `dst` and `src` must be live.
unsafe extern "C" fn pkey_rsa_copy(dst: *mut EvpPkeyCtx, src: *const EvpPkeyCtx) -> c_int {
    // SAFETY: `dst` is live per the contract.
    if unsafe { pkey_rsa_init(dst) } == 0 {
        return 0;
    }
    // SAFETY: both contexts are live and `init` installed `dst`'s own context.
    let (sctx, dctx) = unsafe {
        (
            (*src).data.cast::<RsaPkeyCtx>(),
            (*dst).data.cast::<RsaPkeyCtx>(),
        )
    };
    // SAFETY: both contexts are live.
    unsafe { (*dctx).nbits = (*sctx).nbits };
    // SAFETY: `sctx` is live.
    if !unsafe { (*sctx).pub_exp }.is_null() {
        // SAFETY: the exponent is this source context's own live object.
        let dup = unsafe { BN_dup((*sctx).pub_exp) };
        // SAFETY: `dctx` is live.
        unsafe { (*dctx).pub_exp = dup };
        if dup.is_null() {
            return 0;
        }
    }
    // SAFETY: both contexts are live.
    unsafe {
        (*dctx).pad_mode = (*sctx).pad_mode;
        (*dctx).md = (*sctx).md;
        (*dctx).mgf1md = (*sctx).mgf1md;
        (*dctx).saltlen = (*sctx).saltlen;
        (*dctx).implicit_rejection = (*sctx).implicit_rejection;
    }
    // SAFETY: `sctx` is live.
    if !unsafe { (*sctx).oaep_label }.is_null() {
        // SAFETY: the label is this source context's own allocation or NULL.
        unsafe {
            CRYPTO_free(
                (*dctx).oaep_label.cast::<c_void>(),
                FILE,
                LINE_FREE_OAEP_LABEL_COPY,
            );
        }
        // SAFETY: the source buffer is readable for its recorded length.
        let dup = unsafe {
            CRYPTO_memdup(
                (*sctx).oaep_label.cast::<c_void>(),
                (*sctx).oaep_labellen,
                FILE,
                LINE_MEMDUP_OAEP_LABEL,
            )
        };
        // SAFETY: `dctx` is live.
        unsafe { (*dctx).oaep_label = dup.cast::<u8>() };
        if dup.is_null() {
            return 0;
        }
        // SAFETY: `dctx` is live.
        unsafe { (*dctx).oaep_labellen = (*sctx).oaep_labellen };
    }
    1
}

/// `static int setup_tbuf(RSA_PKEY_CTX *ctx, EVP_PKEY_CTX *pk)` — `:114`.
///
/// # Safety
/// `ctx` and `pk` must be live.
unsafe fn setup_tbuf(ctx: *mut RsaPkeyCtx, pk: *mut EvpPkeyCtx) -> c_int {
    // SAFETY: `ctx` is live.
    if !unsafe { (*ctx).tbuf }.is_null() {
        return 1;
    }
    /* `CRYPTO_malloc` is a safe entry point of this crate. */
    // SAFETY: `pk` is live.
    let size = unsafe { RSA_size(EVP_PKEY_get0_RSA((*pk).pkey)) };
    let tbuf = CRYPTO_malloc(size as usize, FILE, LINE_MALLOC_TBUF).cast::<u8>();
    // SAFETY: `ctx` is live.
    unsafe { (*ctx).tbuf = tbuf };
    if tbuf.is_null() {
        return 0;
    }
    1
}

/// `static void pkey_rsa_cleanup(EVP_PKEY_CTX *ctx)` — `:123`.
///
/// # Safety
/// `ctx` must be live.
unsafe extern "C" fn pkey_rsa_cleanup(ctx: *mut EvpPkeyCtx) {
    // SAFETY: `ctx` is live per the contract.
    let rctx = unsafe { (*ctx).data }.cast::<RsaPkeyCtx>();
    if rctx.is_null() {
        return;
    }
    // SAFETY: each field is NULL or this context's own allocation, and every free accepts NULL.
    unsafe {
        BN_free((*rctx).pub_exp);
        CRYPTO_free((*rctx).tbuf.cast::<c_void>(), FILE, LINE_FREE_TBUF);
        CRYPTO_free(
            (*rctx).oaep_label.cast::<c_void>(),
            FILE,
            LINE_FREE_OAEP_LABEL,
        );
        CRYPTO_free(rctx.cast::<c_void>(), FILE, LINE_FREE_RCTX);
    }
}

/// `static int pkey_rsa_sign(EVP_PKEY_CTX *ctx, unsigned char *sig, size_t *siglen, const unsigned
/// char *tbs, size_t tbslen)` — `:134`.
///
/// # Safety
/// As [`crate::evp::pkey_ctx::PkeyMethSignFn`].
unsafe extern "C" fn pkey_rsa_sign(
    ctx: *mut EvpPkeyCtx,
    sig: *mut u8,
    siglen: *mut usize,
    tbs: *const u8,
    tbslen: usize,
) -> c_int {
    // SAFETY: `ctx` is live and `data` is this method's own context.
    let rctx = unsafe { (*ctx).data }.cast::<RsaPkeyCtx>();
    /* Discard the const: the key may be a cached copy and these calls do not modify it. */
    // SAFETY: `ctx` is live.
    let rsa = unsafe { EVP_PKEY_get0_RSA((*ctx).pkey) } as *mut Rsa;

    // SAFETY: `rctx` is live.
    if !unsafe { (*rctx).md }.is_null() {
        // SAFETY: the field is a live digest on this arm.
        let md_size = unsafe { EVP_MD_get_size((*rctx).md) };
        if md_size <= 0 {
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&err_sites::RSA_PMETH_151) };
            return -1;
        }
        if tbslen != md_size as usize {
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&err_sites::RSA_PMETH_156) };
            return -1;
        }

        // SAFETY: the field is a live digest on this arm.
        let md_type = unsafe { EVP_MD_get_type((*rctx).md) };
        let ret: c_int = if md_type == NID_mdc2 {
            let mut sltmp: c_uint = 0;
            // SAFETY: `rctx` is live.
            if unsafe { (*rctx).pad_mode } != RSA_PKCS1_PADDING {
                return -1;
            }
            // SAFETY: the caller's buffers and the live key, per the contract.
            let r = unsafe {
                RSA_sign_ASN1_OCTET_STRING(0, tbs, tbslen as c_uint, sig, &mut sltmp, rsa)
            };
            if r <= 0 {
                return r;
            }
            sltmp as c_int
        // SAFETY: `rctx` is live.
        } else if unsafe { (*rctx).pad_mode } == RSA_X931_PADDING {
            // SAFETY: `rsa` is live.
            if unsafe { RSA_size(rsa) } as usize <= tbslen {
                // SAFETY: a compile-time-constant site.
                unsafe { raise_site(&err_sites::RSA_PMETH_171) };
                return -1;
            }
            // SAFETY: `rctx` and `ctx` are live.
            if unsafe { setup_tbuf(rctx, ctx) } == 0 {
                // SAFETY: a compile-time-constant site.
                unsafe { raise_site(&err_sites::RSA_PMETH_175) };
                return -1;
            }
            // SAFETY: `tbuf` is this context's own buffer of at least `tbslen + 1` bytes on this arm
            // and `tbs` is readable for `tbslen`.
            unsafe {
                ptr::copy_nonoverlapping(tbs, (*rctx).tbuf, tbslen);
                *(*rctx).tbuf.add(tbslen) =
                    crate::rsa::RSA_X931_hash_id(EVP_MD_get_type((*rctx).md)) as u8;
            }
            // SAFETY: `tbuf` is live and holds `tbslen + 1` encoded bytes; the caller's `sig`.
            unsafe {
                RSA_private_encrypt(
                    (tbslen + 1) as c_int,
                    (*rctx).tbuf,
                    sig,
                    rsa,
                    RSA_X931_PADDING,
                )
            }
        // SAFETY: `rctx` is live.
        } else if unsafe { (*rctx).pad_mode } == RSA_PKCS1_PADDING {
            let mut sltmp: c_uint = 0;
            // SAFETY: the caller's buffers and the live key, per the contract.
            let r = unsafe { RSA_sign(md_type, tbs, tbslen as c_uint, sig, &mut sltmp, rsa) };
            if r <= 0 {
                return r;
            }
            sltmp as c_int
        // SAFETY: `rctx` is live.
        } else if unsafe { (*rctx).pad_mode } == RSA_PKCS1_PSS_PADDING {
            // SAFETY: `rctx` and `ctx` are live.
            if unsafe { setup_tbuf(rctx, ctx) } == 0 {
                return -1;
            }
            // SAFETY: `rsa`, `tbuf` and the digests are live on this arm.
            if unsafe {
                RSA_padding_add_PKCS1_PSS_mgf1(
                    rsa,
                    (*rctx).tbuf,
                    tbs,
                    (*rctx).md,
                    (*rctx).mgf1md,
                    (*rctx).saltlen,
                )
            } == 0
            {
                return -1;
            }
            // SAFETY: `rsa` is live.
            let rsa_sz = unsafe { RSA_size(rsa) };
            // SAFETY: `tbuf` holds the encoded message and the caller's `sig` is writable.
            unsafe { RSA_private_encrypt(rsa_sz, (*rctx).tbuf, sig, rsa, RSA_NO_PADDING) }
        } else {
            return -1;
        };
        if ret < 0 {
            return ret;
        }
        // SAFETY: `siglen` is writable per the contract.
        unsafe { *siglen = ret as usize };
        return 1;
    }
    // SAFETY: `rctx` is live.
    let ret = unsafe { RSA_private_encrypt(tbslen as c_int, tbs, sig, rsa, (*rctx).pad_mode) };
    if ret < 0 {
        return ret;
    }
    // SAFETY: `siglen` is writable per the contract.
    unsafe { *siglen = ret as usize };
    1
}

/// `static int pkey_rsa_verifyrecover(EVP_PKEY_CTX *ctx, unsigned char *rout, size_t *routlen, const
/// unsigned char *sig, size_t siglen)` — `:211`.
///
/// # Safety
/// As [`crate::evp::pkey_ctx::PkeyMethVerifyRecoverFn`].
unsafe extern "C" fn pkey_rsa_verifyrecover(
    ctx: *mut EvpPkeyCtx,
    rout: *mut u8,
    routlen: *mut usize,
    sig: *const u8,
    siglen: usize,
) -> c_int {
    // SAFETY: `ctx` is live and `data` is this method's own context.
    let rctx = unsafe { (*ctx).data }.cast::<RsaPkeyCtx>();
    // SAFETY: `ctx` is live.
    let rsa = unsafe { EVP_PKEY_get0_RSA((*ctx).pkey) } as *mut Rsa;

    let mut ret: c_int;
    // SAFETY: `rctx` is live.
    if !unsafe { (*rctx).md }.is_null() {
        // SAFETY: `rctx` is live.
        if unsafe { (*rctx).pad_mode } == RSA_X931_PADDING {
            // SAFETY: `rctx` and `ctx` are live.
            if unsafe { setup_tbuf(rctx, ctx) } == 0 {
                return -1;
            }
            // SAFETY: `tbuf` is the context's own buffer and the caller's `sig` is readable.
            ret = unsafe {
                RSA_public_decrypt(siglen as c_int, sig, (*rctx).tbuf, rsa, RSA_X931_PADDING)
            };
            if ret <= 0 {
                return 0;
            }
            ret -= 1;
            // SAFETY: the field is a live digest on this arm and `tbuf` is live.
            let expected = unsafe { crate::rsa::RSA_X931_hash_id(EVP_MD_get_type((*rctx).md)) };
            // SAFETY: `ret` is an index inside the buffer just filled.
            if unsafe { *(*rctx).tbuf.offset(ret as isize) } as c_int != expected {
                // SAFETY: a compile-time-constant site.
                unsafe { raise_site(&err_sites::RSA_PMETH_234) };
                return 0;
            }
            // SAFETY: the field is a live digest on this arm.
            if ret != unsafe { EVP_MD_get_size((*rctx).md) } {
                // SAFETY: a compile-time-constant site.
                unsafe { raise_site(&err_sites::RSA_PMETH_238) };
                return 0;
            }
            if !rout.is_null() {
                // SAFETY: `rout` is writable for `ret` bytes and `tbuf` is readable for that many.
                unsafe { ptr::copy_nonoverlapping((*rctx).tbuf, rout, ret as usize) };
            }
        // SAFETY: `rctx` is live.
        } else if unsafe { (*rctx).pad_mode } == RSA_PKCS1_PADDING {
            let mut sltmp: usize = 0;
            // SAFETY: the caller's buffers and the live key, per the contract.
            ret = unsafe {
                ossl_rsa_verify(
                    EVP_MD_get_type((*rctx).md),
                    ptr::null(),
                    0,
                    rout,
                    &mut sltmp,
                    sig,
                    siglen,
                    rsa,
                )
            };
            if ret <= 0 {
                return 0;
            }
            ret = sltmp as c_int;
        } else {
            return -1;
        }
    } else {
        // SAFETY: `rctx` is live.
        ret = unsafe { RSA_public_decrypt(siglen as c_int, sig, rout, rsa, (*rctx).pad_mode) };
    }
    if ret <= 0 {
        return ret;
    }
    // SAFETY: `routlen` is writable per the contract.
    unsafe { *routlen = ret as usize };
    1
}

/// `static int pkey_rsa_verify(EVP_PKEY_CTX *ctx, const unsigned char *sig, size_t siglen, const
/// unsigned char *tbs, size_t tbslen)` — `:263`.
///
/// # Safety
/// As [`crate::evp::pkey_ctx::PkeyMethVerifyFn`].
unsafe extern "C" fn pkey_rsa_verify(
    ctx: *mut EvpPkeyCtx,
    sig: *const u8,
    siglen: usize,
    tbs: *const u8,
    tbslen: usize,
) -> c_int {
    // SAFETY: `ctx` is live and `data` is this method's own context.
    let rctx = unsafe { (*ctx).data }.cast::<RsaPkeyCtx>();
    // SAFETY: `ctx` is live.
    let rsa = unsafe { EVP_PKEY_get0_RSA((*ctx).pkey) } as *mut Rsa;
    let mut rslen: usize = 0;

    // SAFETY: `rctx` is live.
    if !unsafe { (*rctx).md }.is_null() {
        // SAFETY: `rctx` is live.
        if unsafe { (*rctx).pad_mode } == RSA_PKCS1_PADDING {
            // SAFETY: the caller's buffers and the live key, per the contract.
            return unsafe {
                RSA_verify(
                    EVP_MD_get_type((*rctx).md),
                    tbs,
                    tbslen as c_uint,
                    sig,
                    siglen as c_uint,
                    rsa,
                )
            };
        }
        // SAFETY: the field is a live digest on this arm.
        let md_size = unsafe { EVP_MD_get_size((*rctx).md) };
        if md_size <= 0 {
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&err_sites::RSA_PMETH_283) };
            return -1;
        }
        if tbslen != md_size as usize {
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&err_sites::RSA_PMETH_287) };
            return -1;
        }
        // SAFETY: `rctx` and `ctx` are live.
        if unsafe { (*rctx).pad_mode } == RSA_X931_PADDING {
            // SAFETY: `ctx` and the caller's buffers are live.
            if unsafe { pkey_rsa_verifyrecover(ctx, ptr::null_mut(), &mut rslen, sig, siglen) } <= 0
            {
                return 0;
            }
        // SAFETY: `rctx` is live.
        } else if unsafe { (*rctx).pad_mode } == RSA_PKCS1_PSS_PADDING {
            // SAFETY: `rctx` and `ctx` are live.
            if unsafe { setup_tbuf(rctx, ctx) } == 0 {
                return -1;
            }
            // SAFETY: `tbuf` is the context's own buffer and the caller's `sig` is readable.
            let ret = unsafe {
                RSA_public_decrypt(siglen as c_int, sig, (*rctx).tbuf, rsa, RSA_NO_PADDING)
            };
            if ret <= 0 {
                return 0;
            }
            // SAFETY: `rsa`, `tbuf` and the digests are live on this arm.
            let ret = unsafe {
                RSA_verify_PKCS1_PSS_mgf1(
                    rsa,
                    tbs,
                    (*rctx).md,
                    (*rctx).mgf1md,
                    (*rctx).tbuf,
                    (*rctx).saltlen,
                )
            };
            if ret <= 0 {
                return 0;
            }
            return 1;
        } else {
            return -1;
        }
    } else {
        // SAFETY: `rctx` and `ctx` are live.
        if unsafe { setup_tbuf(rctx, ctx) } == 0 {
            return -1;
        }
        // SAFETY: `tbuf` is the context's own buffer and the caller's `sig` is readable.
        let ret = unsafe {
            RSA_public_decrypt(siglen as c_int, sig, (*rctx).tbuf, rsa, (*rctx).pad_mode)
        };
        if ret <= 0 {
            return 0;
        }
        rslen = ret as usize;
    }

    // SAFETY: `rslen` counts the bytes just written to `tbuf`, which `tbs` is compared against.
    if rslen != tbslen || unsafe { libc_memcmp(tbs, (*rctx).tbuf, rslen) } != 0 {
        return 0;
    }
    1
}

/// `memcmp(a, b, n)` — the authority's call, not a crate symbol.
///
/// # Safety
/// Both pointers must be readable for `n` bytes.
unsafe fn libc_memcmp(a: *const u8, b: *const u8, n: usize) -> c_int {
    // SAFETY: both pointers are readable for `n` bytes per the contract.
    let (a, b) = unsafe {
        (
            core::slice::from_raw_parts(a, n),
            core::slice::from_raw_parts(b, n),
        )
    };
    match a.cmp(b) {
        core::cmp::Ordering::Less => -1,
        core::cmp::Ordering::Equal => 0,
        core::cmp::Ordering::Greater => 1,
    }
}

/// `static int pkey_rsa_encrypt(EVP_PKEY_CTX *ctx, unsigned char *out, size_t *outlen, const unsigned
/// char *in, size_t inlen)` — `:325`.
///
/// # Safety
/// As [`crate::evp::pkey_ctx::PkeyMethCryptFn`].
unsafe extern "C" fn pkey_rsa_encrypt(
    ctx: *mut EvpPkeyCtx,
    out: *mut u8,
    outlen: *mut usize,
    input: *const u8,
    inlen: usize,
) -> c_int {
    // SAFETY: `ctx` is live and `data` is this method's own context.
    let rctx = unsafe { (*ctx).data }.cast::<RsaPkeyCtx>();
    // SAFETY: `ctx` is live.
    let rsa = unsafe { EVP_PKEY_get0_RSA((*ctx).pkey) } as *mut Rsa;

    // SAFETY: `rctx` is live.
    let ret = if unsafe { (*rctx).pad_mode } == RSA_PKCS1_OAEP_PADDING {
        // SAFETY: `rsa` is live.
        let klen = unsafe { RSA_size(rsa) };
        // SAFETY: `rctx` and `ctx` are live.
        if unsafe { setup_tbuf(rctx, ctx) } == 0 {
            return -1;
        }
        // SAFETY: `tbuf` is the context's own buffer of `klen` bytes and the digests are live.
        if unsafe {
            crate::rsa::RSA_padding_add_PKCS1_OAEP_mgf1(
                (*rctx).tbuf,
                klen,
                input,
                inlen as c_int,
                (*rctx).oaep_label,
                (*rctx).oaep_labellen as c_int,
                (*rctx).md,
                (*rctx).mgf1md,
            )
        } == 0
        {
            return -1;
        }
        // SAFETY: `tbuf` holds `klen` encoded bytes and the caller's `out` is writable.
        unsafe { RSA_public_encrypt(klen, (*rctx).tbuf, out, rsa, RSA_NO_PADDING) }
    } else {
        // SAFETY: the caller's buffers and the live key, per the contract.
        unsafe { RSA_public_encrypt(inlen as c_int, input, out, rsa, (*rctx).pad_mode) }
    };
    if ret < 0 {
        return ret;
    }
    // SAFETY: `outlen` is writable per the contract.
    unsafe { *outlen = ret as usize };
    1
}

/// `static int pkey_rsa_decrypt(EVP_PKEY_CTX *ctx, unsigned char *out, size_t *outlen, const unsigned
/// char *in, size_t inlen)` — `:358`.
///
/// # Safety
/// As [`crate::evp::pkey_ctx::PkeyMethCryptFn`].
unsafe extern "C" fn pkey_rsa_decrypt(
    ctx: *mut EvpPkeyCtx,
    out: *mut u8,
    outlen: *mut usize,
    input: *const u8,
    inlen: usize,
) -> c_int {
    // SAFETY: `ctx` is live and `data` is this method's own context.
    let rctx = unsafe { (*ctx).data }.cast::<RsaPkeyCtx>();
    // SAFETY: `ctx` is live.
    let rsa = unsafe { EVP_PKEY_get0_RSA((*ctx).pkey) } as *mut Rsa;

    // SAFETY: `rctx` is live.
    let mut ret = if unsafe { (*rctx).pad_mode } == RSA_PKCS1_OAEP_PADDING {
        // SAFETY: `rctx` and `ctx` are live.
        if unsafe { setup_tbuf(rctx, ctx) } == 0 {
            return -1;
        }
        // SAFETY: `tbuf` is the context's own buffer and the caller's `in` is readable.
        let ret = unsafe {
            RSA_private_decrypt(inlen as c_int, input, (*rctx).tbuf, rsa, RSA_NO_PADDING)
        };
        if ret <= 0 {
            return ret;
        }
        // SAFETY: `out` is writable and `tbuf` holds `ret` encoded bytes, per the authority's own
        // argument list.
        unsafe {
            crate::rsa::RSA_padding_check_PKCS1_OAEP_mgf1(
                out,
                ret,
                (*rctx).tbuf,
                ret,
                ret,
                (*rctx).oaep_label,
                (*rctx).oaep_labellen as c_int,
                (*rctx).md,
                (*rctx).mgf1md,
            )
        }
    } else {
        // SAFETY: `rctx` is live.
        let pad_mode = if unsafe { (*rctx).pad_mode } == RSA_PKCS1_PADDING
            && unsafe { (*rctx).implicit_rejection } == 0
        {
            RSA_PKCS1_NO_IMPLICIT_REJECT_PADDING
        } else {
            // SAFETY: `rctx` is live.
            unsafe { (*rctx).pad_mode }
        };
        // SAFETY: the caller's buffers and the live key, per the contract.
        unsafe { RSA_private_decrypt(inlen as c_int, input, out, rsa, pad_mode) }
    };
    /* The length and the return are selected on the sign of `ret` rather than branched on, so a
     * padding failure is indistinguishable from a short plaintext by timing. */
    // SAFETY: `outlen` is readable and writable per the contract.
    unsafe {
        *outlen = constant_time_select(constant_time_msb_s(ret as usize), *outlen, ret as usize);
    }
    ret = constant_time_select_int(constant_time_msb_u32(ret as u32), ret, 1);
    ret
}

/// `static int check_padding_md(const EVP_MD *md, int padding)` — `:395`.
///
/// # Safety
/// `md` NULL or live.
unsafe fn check_padding_md(md: *const EvpMd, padding: c_int) -> c_int {
    if md.is_null() {
        return 1;
    }
    // SAFETY: `md` is live per the contract.
    let mdnid = unsafe { EVP_MD_get_type(md) };

    if padding == RSA_NO_PADDING {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::RSA_PMETH_405) };
        return 0;
    }

    if padding == RSA_X931_PADDING {
        // SAFETY: `RSA_X931_hash_id` is a safe entry point of this crate over the NID it is handed.
        if crate::rsa::RSA_X931_hash_id(mdnid) == -1 {
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&err_sites::RSA_PMETH_411) };
            return 0;
        }
    } else {
        /* List of all supported RSA digests. */
        if mdnid == NID_sha1
            || mdnid == NID_sha224
            || mdnid == NID_sha256
            || mdnid == NID_sha384
            || mdnid == NID_sha512
            || mdnid == NID_sha512_224
            || mdnid == NID_sha512_256
            || mdnid == NID_md5
            || mdnid == NID_md5_sha1
            || mdnid == NID_md2
            || mdnid == NID_md4
            || mdnid == NID_mdc2
            || mdnid == NID_ripemd160
            || mdnid == NID_sha3_224
            || mdnid == NID_sha3_256
            || mdnid == NID_sha3_384
            || mdnid == NID_sha3_512
        {
            return 1;
        }
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::RSA_PMETH_437) };
        return 0;
    }
    1
}

/// `static int pkey_rsa_ctrl(EVP_PKEY_CTX *ctx, int type, int p1, void *p2)` — `:445`.
///
/// # Safety
/// As [`crate::evp::pkey_ctx::PkeyMethCtrlFn`].
unsafe extern "C" fn pkey_rsa_ctrl(
    ctx: *mut EvpPkeyCtx,
    type_: c_int,
    p1: c_int,
    p2: *mut c_void,
) -> c_int {
    // SAFETY: `ctx` is live and `data` is this method's own context.
    let rctx = unsafe { (*ctx).data }.cast::<RsaPkeyCtx>();

    match type_ {
        EVP_PKEY_CTRL_RSA_PADDING => {
            if (RSA_PKCS1_PADDING..=RSA_PKCS1_PSS_PADDING).contains(&p1) {
                // SAFETY: `rctx` is live.
                if unsafe { check_padding_md((*rctx).md, p1) } == 0 {
                    return 0;
                }
                if p1 == RSA_PKCS1_PSS_PADDING {
                    // SAFETY: `ctx` is live.
                    if unsafe { (*ctx).operation } & (EVP_PKEY_OP_SIGN | EVP_PKEY_OP_VERIFY) == 0 {
                        /* `goto bad_pad`. */
                        // SAFETY: a compile-time-constant site.
                        unsafe { raise_site(&err_sites::RSA_PMETH_473) };
                        return -2;
                    }
                    // SAFETY: `rctx` is live.
                    if unsafe { (*rctx).md }.is_null() {
                        // SAFETY: `EVP_sha1` is a safe entry point of this crate.
                        unsafe { (*rctx).md = EVP_sha1() };
                    }
                // SAFETY: `ctx` is live.
                } else if unsafe { pkey_ctx_is_pss(ctx) } {
                    /* `goto bad_pad`. */
                    // SAFETY: a compile-time-constant site.
                    unsafe { raise_site(&err_sites::RSA_PMETH_473) };
                    return -2;
                }
                if p1 == RSA_PKCS1_OAEP_PADDING {
                    // SAFETY: `ctx` is live.
                    if unsafe { (*ctx).operation } & EVP_PKEY_OP_TYPE_CRYPT == 0 {
                        // SAFETY: a compile-time-constant site.
                        unsafe { raise_site(&err_sites::RSA_PMETH_473) };
                        return -2;
                    }
                    // SAFETY: `rctx` is live.
                    if unsafe { (*rctx).md }.is_null() {
                        // SAFETY: `EVP_sha1` is a safe entry point of this crate.
                        unsafe { (*rctx).md = EVP_sha1() };
                    }
                }
                // SAFETY: `rctx` is live.
                unsafe { (*rctx).pad_mode = p1 };
                return 1;
            }
            /* `fall through` to `bad_pad`. */
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&err_sites::RSA_PMETH_473) };
            -2
        }
        EVP_PKEY_CTRL_GET_RSA_PADDING => {
            // SAFETY: `p2` is writable and `rctx` is live.
            unsafe { *p2.cast::<c_int>() = (*rctx).pad_mode };
            1
        }
        EVP_PKEY_CTRL_RSA_PSS_SALTLEN | EVP_PKEY_CTRL_GET_RSA_PSS_SALTLEN => {
            // SAFETY: `rctx` is live.
            if unsafe { (*rctx).pad_mode } != RSA_PKCS1_PSS_PADDING {
                // SAFETY: a compile-time-constant site.
                unsafe { raise_site(&err_sites::RSA_PMETH_483) };
                return -2;
            }
            if type_ == EVP_PKEY_CTRL_GET_RSA_PSS_SALTLEN {
                // SAFETY: `p2` is writable and `rctx` is live.
                unsafe { *p2.cast::<c_int>() = (*rctx).saltlen };
            } else {
                if p1 < RSA_PSS_SALTLEN_MAX {
                    return -2;
                }
                // SAFETY: `rctx` is live.
                if unsafe { rsa_pss_restricted(rctx) } {
                    // SAFETY: `ctx` and `rctx` are live.
                    if p1 == RSA_PSS_SALTLEN_AUTO
                        // SAFETY: `ctx` is live.
                        && unsafe { (*ctx).operation } == EVP_PKEY_OP_VERIFY
                    {
                        // SAFETY: a compile-time-constant site.
                        unsafe { raise_site(&err_sites::RSA_PMETH_494) };
                        return -2;
                    }
                    // SAFETY: `rctx` is live.
                    let md_size = unsafe { EVP_MD_get_size((*rctx).md) };
                    if md_size <= 0 {
                        // SAFETY: a compile-time-constant site.
                        unsafe { raise_site(&err_sites::RSA_PMETH_499) };
                        return -2;
                    }
                    // SAFETY: `rctx` is live.
                    if (p1 == RSA_PSS_SALTLEN_DIGEST && unsafe { (*rctx).min_saltlen } > md_size)
                        // SAFETY: `rctx` is live.
                        || (p1 >= 0 && p1 < unsafe { (*rctx).min_saltlen })
                    {
                        // SAFETY: a compile-time-constant site.
                        unsafe { raise_site(&err_sites::RSA_PMETH_505) };
                        return 0;
                    }
                }
                // SAFETY: `rctx` is live.
                unsafe { (*rctx).saltlen = p1 };
            }
            1
        }
        EVP_PKEY_CTRL_RSA_KEYGEN_BITS => {
            if p1 < RSA_MIN_MODULUS_BITS {
                // SAFETY: a compile-time-constant site.
                unsafe { raise_site(&err_sites::RSA_PMETH_515) };
                return -2;
            }
            // SAFETY: `rctx` is live.
            unsafe { (*rctx).nbits = p1 };
            1
        }
        EVP_PKEY_CTRL_RSA_KEYGEN_PUBEXP => {
            if p2.is_null() {
                // SAFETY: a compile-time-constant site.
                unsafe { raise_site(&err_sites::RSA_PMETH_523) };
                return -2;
            }
            // SAFETY: `p2` is a live exponent on this arm.
            let e = p2.cast::<BigNum>();
            // SAFETY: `e` is live.
            if unsafe { BN_is_odd(e) } == 0 || unsafe { BN_is_one(e) } != 0 {
                // SAFETY: a compile-time-constant site.
                unsafe { raise_site(&err_sites::RSA_PMETH_523) };
                return -2;
            }
            // SAFETY: the field is this context's own exponent or NULL.
            unsafe {
                BN_free((*rctx).pub_exp);
                (*rctx).pub_exp = e;
            }
            1
        }
        EVP_PKEY_CTRL_RSA_KEYGEN_PRIMES => {
            if !(RSA_DEFAULT_PRIME_NUM..=RSA_MAX_PRIME_NUM).contains(&p1) {
                // SAFETY: a compile-time-constant site.
                unsafe { raise_site(&err_sites::RSA_PMETH_532) };
                return -2;
            }
            // SAFETY: `rctx` is live.
            unsafe { (*rctx).primes = p1 };
            1
        }
        EVP_PKEY_CTRL_RSA_OAEP_MD | EVP_PKEY_CTRL_GET_RSA_OAEP_MD => {
            // SAFETY: `rctx` is live.
            if unsafe { (*rctx).pad_mode } != RSA_PKCS1_OAEP_PADDING {
                // SAFETY: a compile-time-constant site.
                unsafe { raise_site(&err_sites::RSA_PMETH_541) };
                return -2;
            }
            if type_ == EVP_PKEY_CTRL_GET_RSA_OAEP_MD {
                // SAFETY: `p2` is writable and `rctx` is live.
                unsafe { *p2.cast::<*const EvpMd>() = (*rctx).md };
            } else {
                // SAFETY: `rctx` is live.
                unsafe { (*rctx).md = p2.cast::<EvpMd>() };
            }
            1
        }
        EVP_PKEY_CTRL_MD => {
            // SAFETY: `rctx` is live and `p2` is a live digest on this arm.
            if unsafe { check_padding_md(p2.cast::<EvpMd>(), (*rctx).pad_mode) } == 0 {
                return 0;
            }
            // SAFETY: `rctx` is live.
            if unsafe { rsa_pss_restricted(rctx) } {
                // SAFETY: the field is a live digest and `p2` is a live digest on this arm.
                if unsafe { EVP_MD_get_type((*rctx).md) }
                    // SAFETY: `p2` is a live digest on this arm.
                    == unsafe { EVP_MD_get_type(p2.cast::<EvpMd>()) }
                {
                    return 1;
                }
                // SAFETY: a compile-time-constant site.
                unsafe { raise_site(&err_sites::RSA_PMETH_556) };
                return 0;
            }
            // SAFETY: `rctx` is live.
            unsafe { (*rctx).md = p2.cast::<EvpMd>() };
            1
        }
        EVP_PKEY_CTRL_GET_MD => {
            // SAFETY: `p2` is writable and `rctx` is live.
            unsafe { *p2.cast::<*const EvpMd>() = (*rctx).md };
            1
        }
        EVP_PKEY_CTRL_RSA_MGF1_MD | EVP_PKEY_CTRL_GET_RSA_MGF1_MD => {
            // SAFETY: `rctx` is live.
            if unsafe { (*rctx).pad_mode } != RSA_PKCS1_PSS_PADDING
                // SAFETY: `rctx` is live.
                && unsafe { (*rctx).pad_mode } != RSA_PKCS1_OAEP_PADDING
            {
                // SAFETY: a compile-time-constant site.
                unsafe { raise_site(&err_sites::RSA_PMETH_570) };
                return -2;
            }
            if type_ == EVP_PKEY_CTRL_GET_RSA_MGF1_MD {
                // SAFETY: `rctx` is live.
                let answer = if unsafe { (*rctx).mgf1md }.is_null() {
                    // SAFETY: `rctx` is live.
                    unsafe { (*rctx).md }
                } else {
                    // SAFETY: `rctx` is live.
                    unsafe { (*rctx).mgf1md }
                };
                // SAFETY: `p2` is writable per the contract.
                unsafe { *p2.cast::<*const EvpMd>() = answer };
            } else {
                // SAFETY: `rctx` is live.
                if unsafe { rsa_pss_restricted(rctx) } {
                    // SAFETY: the field is a live digest and `p2` is a live digest on this arm.
                    if unsafe { EVP_MD_get_type((*rctx).mgf1md) }
                        // SAFETY: `p2` is a live digest on this arm.
                        == unsafe { EVP_MD_get_type(p2.cast::<EvpMd>()) }
                    {
                        return 1;
                    }
                    // SAFETY: a compile-time-constant site.
                    unsafe { raise_site(&err_sites::RSA_PMETH_582) };
                    return 0;
                }
                // SAFETY: `rctx` is live.
                unsafe { (*rctx).mgf1md = p2.cast::<EvpMd>() };
            }
            1
        }
        EVP_PKEY_CTRL_RSA_OAEP_LABEL => {
            // SAFETY: `rctx` is live.
            if unsafe { (*rctx).pad_mode } != RSA_PKCS1_OAEP_PADDING {
                // SAFETY: a compile-time-constant site.
                unsafe { raise_site(&err_sites::RSA_PMETH_591) };
                return -2;
            }
            // SAFETY: the field is this context's own allocation or NULL.
            unsafe {
                CRYPTO_free(
                    (*rctx).oaep_label.cast::<c_void>(),
                    FILE,
                    LINE_FREE_OAEP_LABEL_CTRL,
                );
                if !p2.is_null() && p1 > 0 {
                    (*rctx).oaep_label = p2.cast::<u8>();
                    (*rctx).oaep_labellen = p1 as usize;
                } else {
                    (*rctx).oaep_label = ptr::null_mut();
                    (*rctx).oaep_labellen = 0;
                }
            }
            1
        }
        EVP_PKEY_CTRL_GET_RSA_OAEP_LABEL => {
            // SAFETY: `rctx` is live.
            if unsafe { (*rctx).pad_mode } != RSA_PKCS1_OAEP_PADDING {
                // SAFETY: a compile-time-constant site.
                unsafe { raise_site(&err_sites::RSA_PMETH_606) };
                return -2;
            }
            if p2.is_null() {
                // SAFETY: a compile-time-constant site.
                unsafe { raise_site(&err_sites::RSA_PMETH_610) };
                return 0;
            }
            // SAFETY: `p2` is writable and `rctx` is live.
            unsafe {
                *p2.cast::<*mut u8>() = (*rctx).oaep_label;
                (*rctx).oaep_labellen as c_int
            }
        }
        EVP_PKEY_CTRL_RSA_IMPLICIT_REJECTION => {
            // SAFETY: `rctx` is live.
            if unsafe { (*rctx).pad_mode } != RSA_PKCS1_PADDING {
                // SAFETY: a compile-time-constant site.
                unsafe { raise_site(&err_sites::RSA_PMETH_618) };
                return -2;
            }
            // SAFETY: `rctx` is live.
            unsafe { (*rctx).implicit_rejection = p1 };
            1
        }
        EVP_PKEY_CTRL_DIGESTINIT | EVP_PKEY_CTRL_PKCS7_SIGN | EVP_PKEY_CTRL_CMS_SIGN => 1,
        EVP_PKEY_CTRL_PKCS7_ENCRYPT
        | EVP_PKEY_CTRL_PKCS7_DECRYPT
        | EVP_PKEY_CTRL_CMS_DECRYPT
        | EVP_PKEY_CTRL_CMS_ENCRYPT => {
            // SAFETY: `ctx` is live.
            if !unsafe { pkey_ctx_is_pss(ctx) } {
                return 1;
            }
            /* `fall through` to `PEER_KEY`. */
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&err_sites::RSA_PMETH_641) };
            -2
        }
        EVP_PKEY_CTRL_PEER_KEY => {
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&err_sites::RSA_PMETH_641) };
            -2
        }
        _ => -2,
    }
}

/// `static int pkey_rsa_ctrl_str(EVP_PKEY_CTX *ctx, const char *type, const char *value)` — `:649`.
///
/// # Safety
/// As [`crate::evp::pkey_ctx::PkeyMethCtrlStrFn`].
unsafe extern "C" fn pkey_rsa_ctrl_str(
    ctx: *mut EvpPkeyCtx,
    type_: *const c_char,
    value: *const c_char,
) -> c_int {
    if value.is_null() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::RSA_PMETH_653) };
        return 0;
    }
    // SAFETY: `type_` is NUL-terminated per the contract.
    if unsafe { cstr_is(type_, b"rsa_padding_mode") } {
        // SAFETY: `value` is NUL-terminated per the contract.
        let pm = if unsafe { cstr_is(value, b"pkcs1") } {
            RSA_PKCS1_PADDING
        } else if unsafe { cstr_is(value, b"none") } {
            RSA_NO_PADDING
        } else if unsafe { cstr_is(value, b"oeap") } {
            /* The authority's own typo, reproduced because it is reachable: `oeap` is answered and
             * `oaep` is not. */
            RSA_PKCS1_OAEP_PADDING
        } else if unsafe { cstr_is(value, b"oaep") } {
            RSA_PKCS1_OAEP_PADDING
        } else if unsafe { cstr_is(value, b"x931") } {
            RSA_X931_PADDING
        } else if unsafe { cstr_is(value, b"pss") } {
            RSA_PKCS1_PSS_PADDING
        } else {
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&err_sites::RSA_PMETH_672) };
            return -2;
        };
        // SAFETY: `ctx` is live.
        return unsafe { EVP_PKEY_CTX_set_rsa_padding(ctx, pm) };
    }

    // SAFETY: `type_` is NUL-terminated per the contract.
    if unsafe { cstr_is(type_, b"rsa_pss_saltlen") } {
        // SAFETY: `value` is NUL-terminated per the contract.
        let saltlen = if unsafe { cstr_is(value, b"digest") } {
            RSA_PSS_SALTLEN_DIGEST
        // SAFETY: `value` is NUL-terminated per the contract.
        } else if unsafe { cstr_is(value, b"max") } {
            RSA_PSS_SALTLEN_MAX
        // SAFETY: `value` is NUL-terminated per the contract.
        } else if unsafe { cstr_is(value, b"auto") } {
            RSA_PSS_SALTLEN_AUTO
        } else {
            atoi(value)
        };
        // SAFETY: `ctx` is live.
        return unsafe { EVP_PKEY_CTX_set_rsa_pss_saltlen(ctx, saltlen) };
    }

    // SAFETY: `type_` is NUL-terminated per the contract.
    if unsafe { cstr_is(type_, b"rsa_keygen_bits") } {
        // SAFETY: `value` is NUL-terminated and `ctx` is live.
        return unsafe { EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, atoi(value)) };
    }

    // SAFETY: `type_` is NUL-terminated per the contract.
    if unsafe { cstr_is(type_, b"rsa_keygen_pubexp") } {
        let mut pubexp: *mut BigNum = ptr::null_mut();
        /* `BN_asc2bn` is an unsafe entry point of this crate. */
        // SAFETY: `value` is NUL-terminated and `pubexp` is this frame's own slot.
        if unsafe { BN_asc2bn(&mut pubexp, value) } == 0 {
            return 0;
        }
        // SAFETY: `ctx` is live.
        let ret = unsafe { EVP_PKEY_CTX_set1_rsa_keygen_pubexp(ctx, pubexp) };
        // SAFETY: `pubexp` is this call's own allocation.
        unsafe { BN_free(pubexp) };
        return ret;
    }

    // SAFETY: `type_` is NUL-terminated per the contract.
    if unsafe { cstr_is(type_, b"rsa_keygen_primes") } {
        // SAFETY: `value` is NUL-terminated and `ctx` is live.
        return unsafe { EVP_PKEY_CTX_set_rsa_keygen_primes(ctx, atoi(value)) };
    }

    // SAFETY: `type_` is NUL-terminated per the contract.
    if unsafe { cstr_is(type_, b"rsa_mgf1_md") } {
        // SAFETY: `ctx` and `value` are live.
        return unsafe {
            crate::evp::pkey_ctx::EVP_PKEY_CTX_md(
                ctx,
                EVP_PKEY_OP_TYPE_SIG | EVP_PKEY_OP_TYPE_CRYPT,
                EVP_PKEY_CTRL_RSA_MGF1_MD,
                value,
            )
        };
    }

    // SAFETY: `ctx` is live.
    if unsafe { pkey_ctx_is_pss(ctx) } {
        // SAFETY: `type_` is NUL-terminated per the contract.
        if unsafe { cstr_is(type_, b"rsa_pss_keygen_mgf1_md") } {
            // SAFETY: `ctx` and `value` are live.
            return unsafe {
                crate::evp::pkey_ctx::EVP_PKEY_CTX_md(
                    ctx,
                    EVP_PKEY_OP_KEYGEN,
                    EVP_PKEY_CTRL_RSA_MGF1_MD,
                    value,
                )
            };
        }
        // SAFETY: `type_` is NUL-terminated per the contract.
        if unsafe { cstr_is(type_, b"rsa_pss_keygen_md") } {
            // SAFETY: `ctx` and `value` are live.
            return unsafe {
                crate::evp::pkey_ctx::EVP_PKEY_CTX_md(
                    ctx,
                    EVP_PKEY_OP_KEYGEN,
                    EVP_PKEY_CTRL_MD,
                    value,
                )
            };
        }
        // SAFETY: `type_` is NUL-terminated per the contract.
        if unsafe { cstr_is(type_, b"rsa_pss_keygen_saltlen") } {
            // SAFETY: `value` is NUL-terminated and `ctx` is live.
            return unsafe { EVP_PKEY_CTX_set_rsa_pss_keygen_saltlen(ctx, atoi(value)) };
        }
    }

    // SAFETY: `type_` is NUL-terminated per the contract.
    if unsafe { cstr_is(type_, b"rsa_oaep_md") } {
        // SAFETY: `ctx` and `value` are live.
        return unsafe {
            crate::evp::pkey_ctx::EVP_PKEY_CTX_md(
                ctx,
                EVP_PKEY_OP_TYPE_CRYPT,
                EVP_PKEY_CTRL_RSA_OAEP_MD,
                value,
            )
        };
    }

    // SAFETY: `type_` is NUL-terminated per the contract.
    if unsafe { cstr_is(type_, b"rsa_oaep_label") } {
        let mut lablen: c_long = 0;
        // SAFETY: `value` is NUL-terminated per the contract.
        let lab = unsafe { OPENSSL_hexstr2buf(value, &mut lablen) };
        if lab.is_null() {
            return 0;
        }
        // SAFETY: `ctx` is live, `lab` is this call's own buffer and `lablen` its length.
        let ret =
            unsafe { EVP_PKEY_CTX_set0_rsa_oaep_label(ctx, lab.cast::<c_void>(), lablen as c_int) };
        if ret <= 0 {
            // SAFETY: `lab` is this call's own buffer, refused by the setter.
            unsafe { CRYPTO_free(lab.cast::<c_void>(), FILE, LINE_FREE_LAB) };
        }
        return ret;
    }
    -2
}

/// `static int rsa_set_pss_param(RSA *rsa, EVP_PKEY_CTX *ctx)` — `:759`.
///
/// # Safety
/// `rsa` and `ctx` must be live.
unsafe fn rsa_set_pss_param(rsa: *mut Rsa, ctx: *mut EvpPkeyCtx) -> c_int {
    // SAFETY: `ctx` is live and `data` is this method's own context.
    let rctx = unsafe { (*ctx).data }.cast::<RsaPkeyCtx>();

    // SAFETY: `ctx` is live.
    if !unsafe { pkey_ctx_is_pss(ctx) } {
        return 1;
    }
    /* If all parameters are default values, do not set PSS. */
    // SAFETY: `rctx` is live.
    if unsafe { (*rctx).md }.is_null()
        // SAFETY: `rctx` is live.
        && unsafe { (*rctx).mgf1md }.is_null()
        // SAFETY: `rctx` is live.
        && unsafe { (*rctx).saltlen } == -2
    {
        return 1;
    }
    // SAFETY: `rctx` is live.
    let saltlen = if unsafe { (*rctx).saltlen } == -2 {
        0
    } else {
        // SAFETY: `rctx` is live.
        unsafe { (*rctx).saltlen }
    };
    // SAFETY: the digests are NULL or live and `saltlen` is the value just computed.
    let pss = unsafe { ossl_rsa_pss_params_create((*rctx).md, (*rctx).mgf1md, saltlen) };
    // SAFETY: `rsa` is live.
    unsafe { (*rsa).pss = pss };
    if pss.is_null() {
        return 0;
    }
    1
}

/// `static int pkey_rsa_keygen(EVP_PKEY_CTX *ctx, EVP_PKEY *pkey)` — `:777`.
///
/// # Safety
/// As [`crate::evp::pkey_ctx::PkeyMethParamgenFn`].
unsafe extern "C" fn pkey_rsa_keygen(ctx: *mut EvpPkeyCtx, pkey: *mut EvpPkey) -> c_int {
    // SAFETY: `ctx` is live and `data` is this method's own context.
    let rctx = unsafe { (*ctx).data }.cast::<RsaPkeyCtx>();

    // SAFETY: `rctx` is live.
    if unsafe { (*rctx).pub_exp }.is_null() {
        // SAFETY: `BN_new` is an unsafe entry point of this crate.
        let e = unsafe { BN_new() };
        // SAFETY: `rctx` is live.
        unsafe { (*rctx).pub_exp = e };
        // SAFETY: `e` is live on this arm.
        if e.is_null() || unsafe { BN_set_word(e, RSA_F4) } == 0 {
            return 0;
        }
    }
    // SAFETY: `RSA_new` is an unsafe entry point of this crate.
    let rsa = unsafe { RSA_new() };
    if rsa.is_null() {
        return 0;
    }
    // SAFETY: `ctx` is live.
    let pcb = if unsafe { (*ctx).pkey_gencb }.is_some() {
        // SAFETY: no preconditions.
        let cb = unsafe { BN_GENCB_new() };
        if cb.is_null() {
            // SAFETY: `rsa` is this call's own object.
            unsafe { RSA_free(rsa) };
            return 0;
        }
        // SAFETY: `cb` is live and `ctx` is the caller's.
        unsafe { evp_pkey_set_cb_translate(cb, ctx) };
        cb
    } else {
        ptr::null_mut()
    };
    // SAFETY: `rsa` is live, `rctx`'s exponent is live and `pcb` is NULL or live.
    let ret = unsafe {
        RSA_generate_multi_prime_key(rsa, (*rctx).nbits, (*rctx).primes, (*rctx).pub_exp, pcb)
    };
    // SAFETY: `pcb` is NULL or this call's own object.
    unsafe { BN_GENCB_free(pcb) };
    // SAFETY: `rsa` and `ctx` are live.
    if ret > 0 && unsafe { rsa_set_pss_param(rsa, ctx) } == 0 {
        // SAFETY: `rsa` is this call's own object on this arm.
        unsafe { RSA_free(rsa) };
        return 0;
    }
    if ret > 0 {
        // SAFETY: `ctx` is live and `pkey` and `rsa` are live.
        unsafe { EVP_PKEY_assign(pkey, (*(*ctx).pmeth).pkey_id, rsa.cast::<c_void>()) };
    } else {
        // SAFETY: `rsa` is this call's own object on this arm.
        unsafe { RSA_free(rsa) };
    }
    ret
}

/// `static const EVP_PKEY_METHOD rsa_pkey_meth` — `crypto/rsa/rsa_pmeth.c:816-849`.
pub(crate) static RSA_PKEY_METH: EvpPkeyMethod = EvpPkeyMethod {
    pkey_id: EVP_PKEY_RSA,
    flags: EVP_PKEY_FLAG_AUTOARGLEN,
    init: Some(pkey_rsa_init),
    copy: Some(pkey_rsa_copy),
    cleanup: Some(pkey_rsa_cleanup),
    paramgen_init: None,
    paramgen: None,
    keygen_init: None,
    keygen: Some(pkey_rsa_keygen),
    sign_init: None,
    sign: Some(pkey_rsa_sign),
    verify_init: None,
    verify: Some(pkey_rsa_verify),
    verify_recover_init: None,
    verify_recover: Some(pkey_rsa_verifyrecover),
    signctx_init: None,
    signctx: None,
    verifyctx_init: None,
    verifyctx: None,
    encrypt_init: None,
    encrypt: Some(pkey_rsa_encrypt),
    decrypt_init: None,
    decrypt: Some(pkey_rsa_decrypt),
    derive_init: None,
    derive: None,
    ctrl: Some(pkey_rsa_ctrl),
    ctrl_str: Some(pkey_rsa_ctrl_str),
    digestsign: None,
    digestverify: None,
    check: None,
    public_check: None,
    param_check: None,
    digest_custom: None,
};

/// `static int pkey_pss_init(EVP_PKEY_CTX *ctx)` — `:861`.
///
/// Called for PSS sign or verify initialisation: it checks the PSS parameter sanity and sets the
/// restrictions on key usage that `pkey_rsa_ctrl` then enforces.
///
/// # Safety
/// `ctx` must be live.
unsafe extern "C" fn pkey_pss_init(ctx: *mut EvpPkeyCtx) -> c_int {
    // SAFETY: `ctx` is live and `data` is this method's own context.
    let rctx = unsafe { (*ctx).data }.cast::<RsaPkeyCtx>();

    /* Should never happen. */
    // SAFETY: `ctx` is live.
    if !unsafe { pkey_ctx_is_pss(ctx) } {
        return 0;
    }
    // SAFETY: `ctx` is live.
    let rsa = unsafe { EVP_PKEY_get0_RSA((*ctx).pkey) };
    /* If no restrictions, just return. */
    // SAFETY: `rsa` is live.
    if unsafe { (*rsa).pss }.is_null() {
        return 1;
    }
    /* Get and check the parameters. */
    let mut md: *const EvpMd = ptr::null();
    let mut mgf1md: *const EvpMd = ptr::null();
    let mut min_saltlen: c_int = 0;
    // SAFETY: the key's `pss` is live on this arm and the three slots are this frame's own.
    if unsafe { ossl_rsa_pss_get_param((*rsa).pss, &mut md, &mut mgf1md, &mut min_saltlen) } == 0 {
        return 0;
    }

    /* See if the minimum salt length exceeds the maximum possible. */
    // SAFETY: `md` is a live digest on this arm.
    let md_size = unsafe { EVP_MD_get_size(md) };
    if md_size <= 0 {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::RSA_PMETH_883) };
        return 0;
    }
    // SAFETY: `rsa` is live.
    let mut max_saltlen = unsafe { RSA_size(rsa) } - md_size;
    // SAFETY: `rsa` is live.
    if unsafe { RSA_bits(rsa) } & 0x7 == 1 {
        max_saltlen -= 1;
    }
    if min_saltlen > max_saltlen {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::RSA_PMETH_890) };
        return 0;
    }

    /* The restrictions become the context's defaults, so `pkey_rsa_ctrl` can then block any attempt
     * to use an invalid value. */
    // SAFETY: `rctx` is live.
    unsafe {
        (*rctx).min_saltlen = min_saltlen;
        (*rctx).md = md;
        (*rctx).mgf1md = mgf1md;
        (*rctx).saltlen = min_saltlen;
    }
    1
}

/// `static const EVP_PKEY_METHOD rsa_pss_pkey_meth` — `crypto/rsa/rsa_pmeth.c:908-930`.
///
/// The same callbacks as `rsa_pkey_meth` except that `sign_init` and `verify_init` are
/// [`pkey_pss_init`] rather than NULL — which is what makes PSS parameters observable at all.
pub(crate) static RSA_PSS_PKEY_METH: EvpPkeyMethod = EvpPkeyMethod {
    pkey_id: EVP_PKEY_RSA_PSS,
    flags: EVP_PKEY_FLAG_AUTOARGLEN,
    init: Some(pkey_rsa_init),
    copy: Some(pkey_rsa_copy),
    cleanup: Some(pkey_rsa_cleanup),
    paramgen_init: None,
    paramgen: None,
    keygen_init: None,
    keygen: Some(pkey_rsa_keygen),
    sign_init: Some(pkey_pss_init),
    sign: Some(pkey_rsa_sign),
    verify_init: Some(pkey_pss_init),
    verify: Some(pkey_rsa_verify),
    verify_recover_init: None,
    verify_recover: None,
    signctx_init: None,
    signctx: None,
    verifyctx_init: None,
    verifyctx: None,
    encrypt_init: None,
    encrypt: None,
    decrypt_init: None,
    decrypt: None,
    derive_init: None,
    derive: None,
    ctrl: Some(pkey_rsa_ctrl),
    ctrl_str: Some(pkey_rsa_ctrl_str),
    digestsign: None,
    digestverify: None,
    check: None,
    public_check: None,
    param_check: None,
    digest_custom: None,
};

/// `const EVP_PKEY_METHOD *ossl_rsa_pkey_method(void)` — `crypto/rsa/rsa_pmeth.c:851`.
///
/// # Safety
/// Nothing: the answer is a `static` of this module.
#[allow(dead_code)] // its only reader today is `PMETH_STANDARD_METHODS` in `src/evp/pkey_ctx.rs`
pub(crate) unsafe extern "C" fn ossl_rsa_pkey_method() -> *const EvpPkeyMethod {
    ptr::addr_of!(RSA_PKEY_METH)
}

/// `const EVP_PKEY_METHOD *ossl_rsa_pss_pkey_method(void)` — `crypto/rsa/rsa_pmeth.c:932`.
///
/// # Safety
/// Nothing: the answer is a `static` of this module.
#[allow(dead_code)] // its only reader today is `PMETH_STANDARD_METHODS` in `src/evp/pkey_ctx.rs`
pub(crate) unsafe extern "C" fn ossl_rsa_pss_pkey_method() -> *const EvpPkeyMethod {
    ptr::addr_of!(RSA_PSS_PKEY_METH)
}
