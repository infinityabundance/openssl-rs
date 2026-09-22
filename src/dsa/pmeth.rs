//! `crypto/dsa/dsa_pmeth.c` — the `DSA` `EVP_PKEY_METHOD` object and its nine callbacks.
//!
//! Transcribed whole. The unit defines one object (`dsa_pkey_meth`, published by
//! `ossl_dsa_pkey_method`, `:291`) and the context structure `DSA_PKEY_CTX` the callbacks hang off
//! `ctx->data`; there is no second object here, unlike `crypto/dh/dh_pmeth.c`'s DH/DHX pair or
//! `crypto/rsa/rsa_pmeth.c`'s RSA/RSA-PSS pair, because DSA has one type.
//!
//! ## The context is the callback's own allocation, and `keygen_info` points into it
//!
//! `pkey_dsa_init` mallocs a `DSA_PKEY_CTX` and stores it in `ctx->data`; `ctx->keygen_info` is set
//! to the address of the structure's **own** `gentmp` array (`:50`), which is why the transcription
//! takes `addr_of_mut!` of the field rather than allocating a second array. `pkey_dsa_cleanup`
//! frees it with no NULL test — `OPENSSL_free(NULL)` is a no-op and the authority relies on that.
//!
//! ## Three refusals are `-2`, which is the "unsupported" answer rather than a failure
//!
//! `pkey_dsa_ctrl`'s `EVP_PKEY_CTRL_DSA_PARAMGEN_BITS` and `_Q_BITS` arms answer **-2** for an
//! out-of-range value, where the two digest arms raise and answer **0** — and `EVP_PKEY_CTRL_PEER_KEY`
//! raises `EVP_R_OPERATION_NOT_SUPPORTED_FOR_THIS_KEYTYPE` and answers -2 as well. The distinction is
//! the caller's: `EVP_PKEY_CTX_ctrl` treats -2 as "not handled" and 0 as "handled and refused", so a
//! transcription that returned 0 for the range refusals would make an unsupported control look like a
//! rejected one.
//!
//! ## What this module does not do
//!
//! The object is published as a `static` and named by `src/evp/pkey_ctx.rs`'s
//! `PMETH_STANDARD_METHODS`, so `EVP_PKEY_meth_find(EVP_PKEY_DSA)` answers it. **No caller in this
//! crate builds an `EVP_PKEY_CTX` from it yet**: that is `int_ctx_new`'s `pmeth` arm, which is
//! 7.4c's and still recorded as absent, so the callbacks are reachable through the table and not yet
//! through a context.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_char, c_int, c_uint, c_void, CStr};
use core::ptr;

use crate::bn::ctx::{BN_GENCB_free, BN_GENCB_new};
use crate::dsa::ctrl::{
    EVP_PKEY_CTX_set_dsa_paramgen_bits, EVP_PKEY_CTX_set_dsa_paramgen_md,
    EVP_PKEY_CTX_set_dsa_paramgen_q_bits,
};
use crate::dsa::key::DSA_generate_key;
use crate::dsa::object::{DSA_free, DSA_new};
use crate::dsa::sign::{DSA_sign, DSA_verify};
use crate::dsa::Dsa;
use crate::evp::digest::{EVP_MD_get0_name, EVP_MD_get_size, EVP_MD_get_type, EvpMd};
use crate::evp::legacy_evp::EVP_get_digestbyname;
use crate::evp::pkey::{EVP_PKEY_assign, EVP_PKEY_copy_parameters, EVP_PKEY_get0_DSA, EvpPkey};
use crate::evp::pkey_ctx::{
    EvpPkeyCtx, EvpPkeyMethod, EVP_PKEY_CTRL_CMS_SIGN, EVP_PKEY_CTRL_DIGESTINIT,
    EVP_PKEY_CTRL_DSA_PARAMGEN_BITS, EVP_PKEY_CTRL_DSA_PARAMGEN_MD,
    EVP_PKEY_CTRL_DSA_PARAMGEN_Q_BITS, EVP_PKEY_CTRL_GET_MD, EVP_PKEY_CTRL_MD,
    EVP_PKEY_CTRL_PEER_KEY, EVP_PKEY_CTRL_PKCS7_SIGN, EVP_PKEY_DSA, EVP_PKEY_FLAG_AUTOARGLEN,
};
use crate::evp::pmeth_gn::evp_pkey_set_cb_translate;
use crate::ffc::params::ossl_ffc_set_digest;
use crate::ffc::params_generate::ossl_ffc_params_FIPS186_4_generate;
use crate::ffc::FFC_PARAM_TYPE_DSA;
use crate::rand::sys::atoi;
use crate::runtime::err::{err_sites, raise_site};
use crate::runtime::mem::{CRYPTO_free, CRYPTO_malloc};
use crate::runtime::obj::{
    NID_dsa, NID_dsaWithSHA, NID_sha1, NID_sha224, NID_sha256, NID_sha384, NID_sha3_224,
    NID_sha3_256, NID_sha3_384, NID_sha3_512, NID_sha512,
};

/// `crypto/dsa/dsa_pmeth.c` — the translation unit every allocation and error below is attributed
/// to. The build-relative prefix is the one the compiler recorded for this profile.
const FILE: *const c_char = c"../../src/openssl-3.6.4/crypto/dsa/dsa_pmeth.c".as_ptr();

/// `pkey_dsa_init`'s `OPENSSL_malloc(sizeof(*dctx))` (`:40`).
const LINE_MALLOC_DCTX: c_int = 40;
/// `pkey_dsa_cleanup`'s `OPENSSL_free(dctx)` (`:74`).
const LINE_FREE_DCTX: c_int = 74;

/// `DSA_PKEY_CTX` — `crypto/dsa/dsa_pmeth.c:27-36`.
///
/// Five members, and the layout is the authority's: `ctx->keygen_info` is the address of `gentmp`,
/// so `gentmp`'s position inside the structure is part of what the callbacks publish.
#[repr(C)]
struct DsaPkeyCtx {
    /// `int nbits` — the size of `p` in bits (default 2048).
    nbits: c_int,
    /// `int qbits` — the size of `q` in bits (default 224).
    qbits: c_int,
    /// `const EVP_MD *pmd` — the digest for parameter generation.
    pmd: *const EvpMd,
    /// `int gentmp[2]` — the keygen callback's scratch, published as `ctx->keygen_info`.
    gentmp: [c_int; 2],
    /// `const EVP_MD *md` — the digest the signature is made over.
    md: *const EvpMd,
}

/// `strcmp(s, lit) == 0` in the crate's `CStr` idiom.
///
/// # Safety
/// `s` must be NUL-terminated.
unsafe fn cstr_is(s: *const c_char, lit: &[u8]) -> bool {
    // SAFETY: `s` is NUL-terminated per the contract.
    unsafe { CStr::from_ptr(s) }.to_bytes() == lit
}

/// `static int pkey_dsa_init(EVP_PKEY_CTX *ctx)` — `:38`.
///
/// # Safety
/// `ctx` must be live.
unsafe extern "C" fn pkey_dsa_init(ctx: *mut EvpPkeyCtx) -> c_int {
    /* `CRYPTO_malloc` is one of the safe entry points of this crate: it validates its own argument
     * and answers NULL rather than reading anything of the caller's. */
    let dctx = CRYPTO_malloc(core::mem::size_of::<DsaPkeyCtx>(), FILE, LINE_MALLOC_DCTX)
        .cast::<DsaPkeyCtx>();
    if dctx.is_null() {
        return 0;
    }
    // SAFETY: `dctx` is this call's own allocation and `ctx` is live per the contract.
    unsafe {
        (*dctx).nbits = 2048;
        (*dctx).qbits = 224;
        (*dctx).pmd = ptr::null();
        (*dctx).md = ptr::null();

        (*ctx).data = dctx.cast::<c_void>();
        /* `ctx->keygen_info = dctx->gentmp`: the address of the structure's own array. */
        (*ctx).keygen_info = ptr::addr_of_mut!((*dctx).gentmp).cast::<c_int>();
        (*ctx).keygen_info_count = 2;
    }
    1
}

/// `static int pkey_dsa_copy(EVP_PKEY_CTX *dst, const EVP_PKEY_CTX *src)` — `:56`.
///
/// The authority's order matters: `pkey_dsa_init(dst)` runs **first**, so a failure leaves `dst`'s
/// `data` a fresh context rather than the caller's.
///
/// # Safety
/// `dst` and `src` must be live.
unsafe extern "C" fn pkey_dsa_copy(dst: *mut EvpPkeyCtx, src: *const EvpPkeyCtx) -> c_int {
    // SAFETY: `dst` is live per the contract.
    if unsafe { pkey_dsa_init(dst) } == 0 {
        return 0;
    }
    // SAFETY: both contexts are live and `init` installed `dst`'s own context.
    let (sctx, dctx) = unsafe {
        (
            (*src).data.cast::<DsaPkeyCtx>(),
            (*dst).data.cast::<DsaPkeyCtx>(),
        )
    };
    // SAFETY: both contexts are this method's own live allocations.
    unsafe {
        (*dctx).nbits = (*sctx).nbits;
        (*dctx).qbits = (*sctx).qbits;
        (*dctx).pmd = (*sctx).pmd;
        (*dctx).md = (*sctx).md;
    }
    1
}

/// `static void pkey_dsa_cleanup(EVP_PKEY_CTX *ctx)` — `:71`.
///
/// # Safety
/// `ctx` must be live.
unsafe extern "C" fn pkey_dsa_cleanup(ctx: *mut EvpPkeyCtx) {
    // SAFETY: `ctx` is live per the contract.
    let dctx = unsafe { (*ctx).data };
    // SAFETY: `dctx` is NULL or this method's own allocation, and `CRYPTO_free` accepts NULL.
    unsafe { CRYPTO_free(dctx, FILE, LINE_FREE_DCTX) };
}

/// `static int pkey_dsa_sign(EVP_PKEY_CTX *ctx, unsigned char *sig, size_t *siglen, const unsigned
/// char *tbs, size_t tbslen)` — `:77`.
///
/// # Safety
/// As [`crate::evp::pkey_ctx::PkeyMethSignFn`].
unsafe extern "C" fn pkey_dsa_sign(
    ctx: *mut EvpPkeyCtx,
    sig: *mut u8,
    siglen: *mut usize,
    tbs: *const u8,
    tbslen: usize,
) -> c_int {
    // SAFETY: `ctx` is live and `data` is this method's own context.
    let dctx = unsafe { (*ctx).data }.cast::<DsaPkeyCtx>();
    /* The authority discards the const on `EVP_PKEY_get0_DSA`'s answer because the key may be a
     * cached copy; these calls do not modify it. */
    // SAFETY: `ctx` is live.
    let dsa = unsafe { EVP_PKEY_get0_DSA((*ctx).pkey) } as *mut Dsa;

    // SAFETY: `dctx` is live.
    if !unsafe { (*dctx).md }.is_null() {
        // SAFETY: the field is a live digest on this arm.
        let md_size = unsafe { EVP_MD_get_size((*dctx).md) };
        if md_size <= 0 {
            return 0;
        }
        if tbslen != md_size as usize {
            return 0;
        }
    }

    let mut sltmp: c_uint = 0;
    // SAFETY: the caller's buffers, the live key and the method's own context, per the contract.
    let ret = unsafe { DSA_sign(0, tbs, tbslen as c_int, sig, &mut sltmp, dsa) };
    if ret <= 0 {
        return ret;
    }
    // SAFETY: `siglen` is writable per the contract.
    unsafe { *siglen = sltmp as usize };
    1
}

/// `static int pkey_dsa_verify(EVP_PKEY_CTX *ctx, const unsigned char *sig, size_t siglen, const
/// unsigned char *tbs, size_t tbslen)` — `:107`.
///
/// # Safety
/// As [`crate::evp::pkey_ctx::PkeyMethVerifyFn`].
unsafe extern "C" fn pkey_dsa_verify(
    ctx: *mut EvpPkeyCtx,
    sig: *const u8,
    siglen: usize,
    tbs: *const u8,
    tbslen: usize,
) -> c_int {
    // SAFETY: `ctx` is live and `data` is this method's own context.
    let dctx = unsafe { (*ctx).data }.cast::<DsaPkeyCtx>();
    // SAFETY: `ctx` is live.
    let dsa = unsafe { EVP_PKEY_get0_DSA((*ctx).pkey) } as *mut Dsa;

    // SAFETY: `dctx` is live.
    if !unsafe { (*dctx).md }.is_null() {
        // SAFETY: the field is a live digest on this arm.
        let md_size = unsafe { EVP_MD_get_size((*dctx).md) };
        if md_size <= 0 {
            return 0;
        }
        if tbslen != md_size as usize {
            return 0;
        }
    }

    // SAFETY: the caller's buffers and the live key, per the contract.
    unsafe { DSA_verify(0, tbs, tbslen as c_int, sig, siglen as c_int, dsa) }
}

/// `EVP_MD_get_type((const EVP_MD *)p2)`, which is how both digest arms of `pkey_dsa_ctrl` read
/// their `p2`.
///
/// # Safety
/// `p2` must be a live `EVP_MD`.
unsafe fn md_type_of(p2: *const c_void) -> c_int {
    // SAFETY: `p2` is a live digest per the contract.
    unsafe { EVP_MD_get_type(p2.cast::<EvpMd>()) }
}

/// `static int pkey_dsa_ctrl(EVP_PKEY_CTX *ctx, int type, int p1, void *p2)` — `:133`.
///
/// # Safety
/// As [`crate::evp::pkey_ctx::PkeyMethCtrlFn`].
unsafe extern "C" fn pkey_dsa_ctrl(
    ctx: *mut EvpPkeyCtx,
    type_: c_int,
    p1: c_int,
    p2: *mut c_void,
) -> c_int {
    // SAFETY: `ctx` is live and `data` is this method's own context.
    let dctx = unsafe { (*ctx).data }.cast::<DsaPkeyCtx>();

    match type_ {
        EVP_PKEY_CTRL_DSA_PARAMGEN_BITS => {
            if p1 < 256 {
                return -2;
            }
            // SAFETY: `dctx` is live.
            unsafe { (*dctx).nbits = p1 };
            1
        }
        EVP_PKEY_CTRL_DSA_PARAMGEN_Q_BITS => {
            if p1 != 160 && p1 != 224 && p1 != 0 && p1 != 256 {
                return -2;
            }
            // SAFETY: `dctx` is live.
            unsafe { (*dctx).qbits = p1 };
            1
        }
        EVP_PKEY_CTRL_DSA_PARAMGEN_MD => {
            // SAFETY: `p2` is a live digest on this arm per the authority's contract.
            let t = unsafe { md_type_of(p2) };
            if t != NID_sha1 && t != NID_sha224 && t != NID_sha256 {
                // SAFETY: a compile-time-constant site.
                unsafe { raise_site(&err_sites::DSA_PMETH_152) };
                return 0;
            }
            // SAFETY: `dctx` is live.
            unsafe { (*dctx).pmd = p2.cast::<EvpMd>() };
            1
        }
        EVP_PKEY_CTRL_MD => {
            // SAFETY: `p2` is a live digest on this arm per the authority's contract.
            let t = unsafe { md_type_of(p2) };
            if t != NID_sha1
                && t != NID_dsa
                && t != NID_dsaWithSHA
                && t != NID_sha224
                && t != NID_sha256
                && t != NID_sha384
                && t != NID_sha512
                && t != NID_sha3_224
                && t != NID_sha3_256
                && t != NID_sha3_384
                && t != NID_sha3_512
            {
                // SAFETY: a compile-time-constant site.
                unsafe { raise_site(&err_sites::DSA_PMETH_160) };
                return 0;
            }
            // SAFETY: `dctx` is live.
            unsafe { (*dctx).md = p2.cast::<EvpMd>() };
            1
        }
        EVP_PKEY_CTRL_GET_MD => {
            // SAFETY: `p2` is a writable `const EVP_MD *` slot and `dctx` is live.
            unsafe { *p2.cast::<*const EvpMd>() = (*dctx).md };
            1
        }
        EVP_PKEY_CTRL_DIGESTINIT | EVP_PKEY_CTRL_PKCS7_SIGN | EVP_PKEY_CTRL_CMS_SIGN => 1,
        EVP_PKEY_CTRL_PEER_KEY => {
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&err_sites::DSA_PMETH_176) };
            -2
        }
        _ => -2,
    }
}

/// `static int pkey_dsa_ctrl_str(EVP_PKEY_CTX *ctx, const char *type, const char *value)` — `:183`.
///
/// # Safety
/// As [`crate::evp::pkey_ctx::PkeyMethCtrlStrFn`].
unsafe extern "C" fn pkey_dsa_ctrl_str(
    ctx: *mut EvpPkeyCtx,
    type_: *const c_char,
    value: *const c_char,
) -> c_int {
    // SAFETY: `type_` is NUL-terminated per the contract.
    if unsafe { cstr_is(type_, b"dsa_paramgen_bits") } {
        // SAFETY: `value` is NUL-terminated per the contract and `ctx` is live.
        return unsafe { EVP_PKEY_CTX_set_dsa_paramgen_bits(ctx, atoi(value)) };
    }
    // SAFETY: `type_` is NUL-terminated per the contract.
    if unsafe { cstr_is(type_, b"dsa_paramgen_q_bits") } {
        // SAFETY: `value` is NUL-terminated per the contract and `ctx` is live.
        return unsafe { EVP_PKEY_CTX_set_dsa_paramgen_q_bits(ctx, atoi(value)) };
    }
    // SAFETY: `type_` is NUL-terminated per the contract.
    if unsafe { cstr_is(type_, b"dsa_paramgen_md") } {
        // SAFETY: `value` is NUL-terminated per the contract.
        let md = unsafe { EVP_get_digestbyname(value) };
        if md.is_null() {
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&err_sites::DSA_PMETH_199) };
            return 0;
        }
        // SAFETY: `ctx` is live.
        return unsafe { EVP_PKEY_CTX_set_dsa_paramgen_md(ctx, md) };
    }
    -2
}

/// `static int pkey_dsa_paramgen(EVP_PKEY_CTX *ctx, EVP_PKEY *pkey)` — `:207`.
///
/// # Safety
/// As [`crate::evp::pkey_ctx::PkeyMethParamgenFn`].
unsafe extern "C" fn pkey_dsa_paramgen(ctx: *mut EvpPkeyCtx, pkey: *mut EvpPkey) -> c_int {
    // SAFETY: `ctx` is live and `data` is this method's own context.
    let dctx = unsafe { (*ctx).data }.cast::<DsaPkeyCtx>();
    // SAFETY: `ctx` is live.
    let pcb = if unsafe { (*ctx).pkey_gencb }.is_some() {
        // SAFETY: no preconditions.
        let cb = unsafe { BN_GENCB_new() };
        if cb.is_null() {
            return 0;
        }
        // SAFETY: `cb` is live and `ctx` is the caller's.
        unsafe { evp_pkey_set_cb_translate(cb, ctx) };
        cb
    } else {
        ptr::null_mut()
    };
    // SAFETY: no preconditions.
    let dsa = unsafe { DSA_new() };
    if dsa.is_null() {
        // SAFETY: `pcb` is NULL or this call's own object.
        unsafe { BN_GENCB_free(pcb) };
        return 0;
    }
    // SAFETY: `dctx` is live.
    if !unsafe { (*dctx).md }.is_null() {
        // SAFETY: `dsa` is live and the digest is a live one on this arm.
        unsafe {
            ossl_ffc_set_digest(
                ptr::addr_of_mut!((*dsa).params),
                EVP_MD_get0_name((*dctx).md),
                ptr::null(),
            )
        };
    }

    let mut res: c_int = 0;
    // SAFETY: `dsa` is live, the context's parameters are this call's to write, and `pcb` is NULL or
    // live.
    let ret = unsafe {
        ossl_ffc_params_FIPS186_4_generate(
            ptr::null_mut(),
            ptr::addr_of_mut!((*dsa).params),
            FFC_PARAM_TYPE_DSA,
            (*dctx).nbits as usize,
            (*dctx).qbits as usize,
            &mut res,
            pcb,
        )
    };
    // SAFETY: `pcb` is NULL or this call's own object.
    unsafe { BN_GENCB_free(pcb) };
    if ret > 0 {
        // SAFETY: `pkey` and `dsa` are live; the assignment takes the object on success.
        unsafe { EVP_PKEY_assign(pkey, EVP_PKEY_DSA, dsa.cast::<c_void>()) };
    } else {
        // SAFETY: `dsa` is this call's own object on this arm.
        unsafe { DSA_free(dsa) };
    }
    ret
}

/// `static int pkey_dsa_keygen(EVP_PKEY_CTX *ctx, EVP_PKEY *pkey)` — `:240`.
///
/// # Safety
/// As [`crate::evp::pkey_ctx::PkeyMethParamgenFn`].
unsafe extern "C" fn pkey_dsa_keygen(ctx: *mut EvpPkeyCtx, pkey: *mut EvpPkey) -> c_int {
    // SAFETY: `ctx` is live.
    if unsafe { (*ctx).pkey }.is_null() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::DSA_PMETH_245) };
        return 0;
    }
    // SAFETY: no preconditions.
    let dsa = unsafe { DSA_new() };
    if dsa.is_null() {
        return 0;
    }
    // SAFETY: `pkey` and `dsa` are live.
    unsafe { EVP_PKEY_assign(pkey, EVP_PKEY_DSA, dsa.cast::<c_void>()) };
    /* Note: if the copy fails, `pkey` is freed by the caller's own cleanup. */
    // SAFETY: both keys are live per the contract.
    if unsafe { EVP_PKEY_copy_parameters(pkey, (*ctx).pkey) } == 0 {
        return 0;
    }
    // SAFETY: `pkey` is live and holds the key just assigned.
    unsafe { DSA_generate_key(EVP_PKEY_get0_DSA(pkey) as *mut Dsa) }
}

/// `static const EVP_PKEY_METHOD dsa_pkey_meth` — `crypto/dsa/dsa_pmeth.c:258-289`.
///
/// Nine of the twenty-seven callbacks are set: `init`, `copy`, `cleanup`, `paramgen`, `keygen`,
/// `sign`, `verify`, `ctrl` and `ctrl_str`. The rest are NULL, which is what leaves
/// `EVP_PKEY_meth_get0_info`'s flags word as `EVP_PKEY_FLAG_AUTOARGLEN` alone.
pub(crate) static DSA_PKEY_METH: EvpPkeyMethod = EvpPkeyMethod {
    pkey_id: EVP_PKEY_DSA,
    flags: EVP_PKEY_FLAG_AUTOARGLEN,
    init: Some(pkey_dsa_init),
    copy: Some(pkey_dsa_copy),
    cleanup: Some(pkey_dsa_cleanup),
    paramgen_init: None,
    paramgen: Some(pkey_dsa_paramgen),
    keygen_init: None,
    keygen: Some(pkey_dsa_keygen),
    sign_init: None,
    sign: Some(pkey_dsa_sign),
    verify_init: None,
    verify: Some(pkey_dsa_verify),
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
    ctrl: Some(pkey_dsa_ctrl),
    ctrl_str: Some(pkey_dsa_ctrl_str),
    digestsign: None,
    digestverify: None,
    check: None,
    public_check: None,
    param_check: None,
    digest_custom: None,
};

/// `const EVP_PKEY_METHOD *ossl_dsa_pkey_method(void)` — `crypto/dsa/dsa_pmeth.c:291`.
///
/// A row of `crypto/evp/pmeth_lib.c`'s `standard_methods[]`, which `EVP_PKEY_meth_find` walks.
///
/// # Safety
/// Nothing: the answer is a `static` of this module.
#[allow(dead_code)] // its only reader today is `PMETH_STANDARD_METHODS` in `src/evp/pkey_ctx.rs`
pub(crate) unsafe extern "C" fn ossl_dsa_pkey_method() -> *const EvpPkeyMethod {
    ptr::addr_of!(DSA_PKEY_METH)
}
