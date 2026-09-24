//! `crypto/ec/ec_pmeth.c` — the `EC` `EVP_PKEY_METHOD` object and its callbacks.
//!
//! Transcribed whole. The unit defines one object (`ec_pkey_meth`, published by
//! `ossl_ec_pkey_method`, `:501`) over the `EC_PKEY_CTX` structure its callbacks hang off
//! `ctx->data`, and it is the only one of the four `*_pmeth.c` units that reads a **struct field of a
//! key** directly rather than through an accessor: `pkey_ec_ctrl`'s cofactor arm tests
//! `ec_key->group->cofactor` with `BN_is_one` and duplicates the key when the mode is turned on
//! (`:296-306`). That read is why `EcKey`'s and `EcGroup`'s `group`/`cofactor` fields had to be the
//! authority's, which D335 measured.
//!
//! ## The cofactor mode is a tri-state, and `-1` is "unset"
//!
//! `cofactor_mode` starts at **-1** in `pkey_ec_init` and `EVP_PKEY_CTRL_EC_ECDH_COFACTOR`'s read arm
//! answers the key's own `EC_FLAG_COFACTOR_ECDH` bit only while it is still -1 (`:272-278`). Once set
//! to 0 or 1, the private `co_key` copy carries the flag and the read answers the cached mode — so a
//! transcription that defaulted the field to 0 would answer "off" for a key whose flag is on.
//!
//! ## Two callbacks are shared with the signature path, and one of them is conditional
//!
//! `pkey_ec_sign`/`pkey_ec_verify` dispatch to `ECDSA_sign`/`ECDSA_verify` with the digest's NID, or
//! `NID_sha1` when none was set. `pkey_ec_derive`, `pkey_ec_kdf_derive` and the cofactor arm are
//! inside `#ifndef OPENSSL_NO_EC`, which is compiled **in** on this profile, so they are present
//! rather than reduced.
//!
//! ## What this module does not do
//!
//! `ossl_ec_pkey_method` is published as a static and named by `src/evp/pkey_ctx.rs`'s
//! `PMETH_STANDARD_METHODS`, so `EVP_PKEY_meth_find(EVP_PKEY_EC)` answers it. No caller builds an
//! `EVP_PKEY_CTX` from it yet: that is `int_ctx_new`'s `pmeth` arm, still recorded as absent.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_char, c_int, c_uint, c_void, CStr};
use core::ptr;

use crate::bn::bignum::BN_is_one;
use crate::ec::ctrl::{
    EVP_PKEY_CTX_set_ec_param_enc, EVP_PKEY_CTX_set_ec_paramgen_curve_nid,
    EVP_PKEY_CTX_set_ecdh_cofactor_mode, EVP_PKEY_CTX_set_ecdh_kdf_md,
};
use crate::ec::curve::{EC_GROUP_new_by_curve_name, EC_curve_nist2nid};
use crate::ec::ecdsa::{ECDSA_sign, ECDSA_verify};
use crate::ec::kdf::ossl_ecdh_kdf_X9_63;
use crate::ec::key::{
    EC_KEY_clear_flags, EC_KEY_dup, EC_KEY_free, EC_KEY_generate_key, EC_KEY_get0_group,
    EC_KEY_get0_public_key, EC_KEY_get_flags, EC_KEY_new, EC_KEY_set_flags, EC_KEY_set_group,
    EC_FLAG_COFACTOR_ECDH,
};
use crate::ec::kmeth::ECDH_compute_key;
use crate::ec::lib::{EC_GROUP_dup, EC_GROUP_free, EC_GROUP_get_degree, EC_GROUP_set_asn1_flag};
use crate::ec::{EcGroup, EcKey};
use crate::evp::digest::{EVP_MD_get_type, EvpMd};
use crate::evp::legacy_evp::EVP_get_digestbyname;
use crate::evp::p_legacy_assign::EVP_PKEY_get0_EC_KEY;
use crate::evp::pkey::{evp_pkey_is_provided, EVP_PKEY_assign, EVP_PKEY_copy_parameters, EvpPkey};
use crate::evp::pkey_ctx::{
    EvpPkeyCtx, EvpPkeyMethod, EVP_PKEY_CTRL_CMS_SIGN, EVP_PKEY_CTRL_DIGESTINIT,
    EVP_PKEY_CTRL_EC_ECDH_COFACTOR, EVP_PKEY_CTRL_EC_KDF_MD, EVP_PKEY_CTRL_EC_KDF_OUTLEN,
    EVP_PKEY_CTRL_EC_KDF_TYPE, EVP_PKEY_CTRL_EC_KDF_UKM, EVP_PKEY_CTRL_EC_PARAMGEN_CURVE_NID,
    EVP_PKEY_CTRL_EC_PARAM_ENC, EVP_PKEY_CTRL_GET_EC_KDF_MD, EVP_PKEY_CTRL_GET_EC_KDF_OUTLEN,
    EVP_PKEY_CTRL_GET_EC_KDF_UKM, EVP_PKEY_CTRL_GET_MD, EVP_PKEY_CTRL_MD, EVP_PKEY_CTRL_PEER_KEY,
    EVP_PKEY_CTRL_PKCS7_SIGN, EVP_PKEY_EC, EVP_PKEY_ECDH_KDF_NONE, EVP_PKEY_ECDH_KDF_X9_63,
    OPENSSL_EC_NAMED_CURVE,
};
use crate::rand::sys::atoi;
use crate::runtime::err::{err_sites, raise_site};
use crate::runtime::mem::{
    CRYPTO_clear_free, CRYPTO_free, CRYPTO_malloc, CRYPTO_memdup, CRYPTO_zalloc,
};
use crate::runtime::obj::{
    NID_ecdsa_with_SHA1, NID_sha1, NID_sha224, NID_sha256, NID_sha384, NID_sha3_224, NID_sha3_256,
    NID_sha3_384, NID_sha3_512, NID_sha512, NID_sm3, NID_undef, OBJ_ln2nid, OBJ_sn2nid,
};

/// `crypto/ec/ec_pmeth.c` — the translation unit every allocation and error below is attributed to.
const FILE: *const c_char = c"../../src/openssl-3.6.4/crypto/ec/ec_pmeth.c".as_ptr();

/// `pkey_ec_init`'s `OPENSSL_zalloc(sizeof(*dctx))` (`:51`).
const LINE_ZALLOC_DCTX: c_int = 51;
/// `pkey_ec_copy`'s `OPENSSL_memdup(sctx->kdf_ukm, sctx->kdf_ukmlen)` (`:83`).
const LINE_MEMDUP_KDF_UKM: c_int = 83;
/// `pkey_ec_cleanup`'s `OPENSSL_free(dctx->kdf_ukm)` (`:98`).
const LINE_FREE_KDF_UKM: c_int = 98;
/// `pkey_ec_cleanup`'s `OPENSSL_free(dctx)` (`:99`).
const LINE_FREE_DCTX: c_int = 99;
/// `pkey_ec_kdf_derive`'s `OPENSSL_malloc(ktmplen)` (`:230`).
const LINE_MALLOC_KTMP: c_int = 230;
/// `pkey_ec_kdf_derive`'s `OPENSSL_clear_free(ktmp, ktmplen)` (`:242`).
const LINE_CLEAR_FREE_KTMP: c_int = 242;
/// `pkey_ec_ctrl`'s `OPENSSL_free(dctx->kdf_ukm)` on replacement (`:341`).
const LINE_FREE_KDF_UKM_CTRL: c_int = 341;

/// The authority's `ossl_assert` under `-DNDEBUG`, which this profile's Makefile sets: a plain check
/// that returns its argument, **not** the `OPENSSL_die` form. `crate::mac::ssl3_cbc` carries the same
/// helper for the same reason.
#[inline]
fn ossl_assert(expr: bool) -> c_int {
    c_int::from(expr)
}

/// `EC_PKEY_CTX` — `crypto/ec/ec_pmeth.c:27-45`.
///
/// Nine members. `cofactor_mode` is `signed char` and `kdf_type` is `char`, so both are [`c_char`];
/// `kdf_ukm` is a borrowed buffer this context frees on replacement and cleanup, exactly as
/// `DH_PKEY_CTX`'s is.
#[repr(C)]
struct EcPkeyCtx {
    /// `EC_GROUP *gen_group` — the key/paramgen group, owned.
    gen_group: *mut EcGroup,
    /// `const EVP_MD *md` — the digest the signature is made over.
    md: *const EvpMd,
    /// `EC_KEY *co_key` — the duplicated key when a custom cofactor is needed, owned.
    co_key: *mut EcKey,
    /// `signed char cofactor_mode` — -1 unset, 0 off, 1 on.
    cofactor_mode: c_char,
    /// `char kdf_type` — `EVP_PKEY_ECDH_KDF_NONE` or `_X9_63`.
    kdf_type: c_char,
    /// `const EVP_MD *kdf_md` — borrowed.
    kdf_md: *const EvpMd,
    /// `unsigned char *kdf_ukm` — borrowed, freed by this context on replacement and cleanup.
    kdf_ukm: *mut u8,
    /// `size_t kdf_ukmlen`.
    kdf_ukmlen: usize,
    /// `size_t kdf_outlen`.
    kdf_outlen: usize,
}

/// `strcmp(s, lit) == 0` in the crate's `CStr` idiom.
///
/// # Safety
/// `s` must be NUL-terminated.
unsafe fn cstr_is(s: *const c_char, lit: &[u8]) -> bool {
    // SAFETY: `s` is NUL-terminated per the contract.
    unsafe { CStr::from_ptr(s) }.to_bytes() == lit
}

/// `static int pkey_ec_init(EVP_PKEY_CTX *ctx)` — `:47`.
///
/// # Safety
/// `ctx` must be live.
unsafe extern "C" fn pkey_ec_init(ctx: *mut EvpPkeyCtx) -> c_int {
    /* `CRYPTO_zalloc` is a safe entry point of this crate. */
    let dctx = CRYPTO_zalloc(core::mem::size_of::<EcPkeyCtx>(), FILE, LINE_ZALLOC_DCTX)
        .cast::<EcPkeyCtx>();
    if dctx.is_null() {
        return 0;
    }
    // SAFETY: `dctx` is this call's own allocation and `ctx` is live per the contract.
    unsafe {
        (*dctx).cofactor_mode = -1;
        (*dctx).kdf_type = EVP_PKEY_ECDH_KDF_NONE as c_char;
        (*ctx).data = dctx.cast::<c_void>();
    }
    1
}

/// `static int pkey_ec_copy(EVP_PKEY_CTX *dst, const EVP_PKEY_CTX *src)` — `:60`.
///
/// # Safety
/// `dst` and `src` must be live.
unsafe extern "C" fn pkey_ec_copy(dst: *mut EvpPkeyCtx, src: *const EvpPkeyCtx) -> c_int {
    // SAFETY: `dst` is live per the contract.
    if unsafe { pkey_ec_init(dst) } == 0 {
        return 0;
    }
    // SAFETY: both contexts are live and `init` installed `dst`'s own context.
    let (sctx, dctx) = unsafe {
        (
            (*src).data.cast::<EcPkeyCtx>(),
            (*dst).data.cast::<EcPkeyCtx>(),
        )
    };

    // SAFETY: `sctx` is live.
    if !unsafe { (*sctx).gen_group }.is_null() {
        // SAFETY: the group is this source context's own live object.
        let dup = unsafe { EC_GROUP_dup((*sctx).gen_group) };
        // SAFETY: `dctx` is live.
        unsafe { (*dctx).gen_group = dup };
        if dup.is_null() {
            return 0;
        }
    }
    // SAFETY: both contexts are live.
    unsafe { (*dctx).md = (*sctx).md };

    // SAFETY: `sctx` is live.
    if !unsafe { (*sctx).co_key }.is_null() {
        // SAFETY: the key is this source context's own live object.
        let dup = unsafe { EC_KEY_dup((*sctx).co_key) };
        // SAFETY: `dctx` is live.
        unsafe { (*dctx).co_key = dup };
        if dup.is_null() {
            return 0;
        }
    }
    // SAFETY: both contexts are live.
    unsafe {
        (*dctx).kdf_type = (*sctx).kdf_type;
        (*dctx).kdf_md = (*sctx).kdf_md;
        (*dctx).kdf_outlen = (*sctx).kdf_outlen;
    }
    // SAFETY: `sctx` is live.
    if !unsafe { (*sctx).kdf_ukm }.is_null() {
        // SAFETY: the source buffer is readable for its recorded length.
        let ukm = unsafe {
            CRYPTO_memdup(
                (*sctx).kdf_ukm.cast::<c_void>(),
                (*sctx).kdf_ukmlen,
                FILE,
                LINE_MEMDUP_KDF_UKM,
            )
        };
        // SAFETY: `dctx` is live.
        unsafe { (*dctx).kdf_ukm = ukm.cast::<u8>() };
        if ukm.is_null() {
            return 0;
        }
    } else {
        // SAFETY: `dctx` is live.
        unsafe { (*dctx).kdf_ukm = ptr::null_mut() };
    }
    // SAFETY: both contexts are live.
    unsafe { (*dctx).kdf_ukmlen = (*sctx).kdf_ukmlen };
    1
}

/// `static void pkey_ec_cleanup(EVP_PKEY_CTX *ctx)` — `:92`.
///
/// # Safety
/// `ctx` must be live.
unsafe extern "C" fn pkey_ec_cleanup(ctx: *mut EvpPkeyCtx) {
    // SAFETY: `ctx` is live per the contract.
    let dctx = unsafe { (*ctx).data }.cast::<EcPkeyCtx>();
    if dctx.is_null() {
        return;
    }
    // SAFETY: the three fields are NULL or this context's own allocations, and both frees accept
    // NULL.
    unsafe {
        EC_GROUP_free((*dctx).gen_group);
        EC_KEY_free((*dctx).co_key);
        CRYPTO_free((*dctx).kdf_ukm.cast::<c_void>(), FILE, LINE_FREE_KDF_UKM);
        CRYPTO_free(dctx.cast::<c_void>(), FILE, LINE_FREE_DCTX);
        (*ctx).data = ptr::null_mut();
    }
}

/// `static int pkey_ec_sign(EVP_PKEY_CTX *ctx, unsigned char *sig, size_t *siglen, const unsigned
/// char *tbs, size_t tbslen)` — `:104`.
///
/// # Safety
/// As [`crate::evp::pkey_ctx::PkeyMethSignFn`].
unsafe extern "C" fn pkey_ec_sign(
    ctx: *mut EvpPkeyCtx,
    sig: *mut u8,
    siglen: *mut usize,
    tbs: *const u8,
    tbslen: usize,
) -> c_int {
    // SAFETY: `ctx` is live and `data` is this method's own context.
    let dctx = unsafe { (*ctx).data }.cast::<EcPkeyCtx>();
    /* The authority discards the const on `EVP_PKEY_get0_EC_KEY`'s answer because the key may be a
     * cached copy; these calls do not modify it. */
    // SAFETY: `ctx` is live.
    let ec = unsafe { EVP_PKEY_get0_EC_KEY((*ctx).pkey) } as *mut EcKey;
    // SAFETY: `ec` is live.
    let sig_sz = unsafe { crate::ec::asn1::ECDSA_size(ec) };

    /* `ossl_assert(sig_sz > 0)`: `sig_sz` is reused as a `size_t`, so a non-positive answer is
     * refused rather than cast. */
    if ossl_assert(sig_sz > 0) == 0 {
        return 0;
    }

    if sig.is_null() {
        // SAFETY: `siglen` is writable per the contract.
        unsafe { *siglen = sig_sz as usize };
        return 1;
    }

    // SAFETY: `siglen` is readable per the contract.
    if unsafe { *siglen } < sig_sz as usize {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::EC_PMETH_128) };
        return 0;
    }

    // SAFETY: `dctx` is live.
    let type_ = if unsafe { (*dctx).md }.is_null() {
        NID_sha1
    } else {
        // SAFETY: the field is a live digest on this arm.
        unsafe { EVP_MD_get_type((*dctx).md) }
    };

    let mut sltmp: c_uint = 0;
    // SAFETY: the caller's buffers and the live key, per the contract.
    let ret = unsafe { ECDSA_sign(type_, tbs, tbslen as c_int, sig, &mut sltmp, ec) };
    if ret <= 0 {
        return ret;
    }
    // SAFETY: `siglen` is writable per the contract.
    unsafe { *siglen = sltmp as usize };
    1
}

/// `static int pkey_ec_verify(EVP_PKEY_CTX *ctx, const unsigned char *sig, size_t siglen, const
/// unsigned char *tbs, size_t tbslen)` — `:142`.
///
/// # Safety
/// As [`crate::evp::pkey_ctx::PkeyMethVerifyFn`].
unsafe extern "C" fn pkey_ec_verify(
    ctx: *mut EvpPkeyCtx,
    sig: *const u8,
    siglen: usize,
    tbs: *const u8,
    tbslen: usize,
) -> c_int {
    // SAFETY: `ctx` is live and `data` is this method's own context.
    let dctx = unsafe { (*ctx).data }.cast::<EcPkeyCtx>();
    // SAFETY: `ctx` is live.
    let ec = unsafe { EVP_PKEY_get0_EC_KEY((*ctx).pkey) } as *mut EcKey;

    // SAFETY: `dctx` is live.
    let type_ = if unsafe { (*dctx).md }.is_null() {
        NID_sha1
    } else {
        // SAFETY: the field is a live digest on this arm.
        unsafe { EVP_MD_get_type((*dctx).md) }
    };

    // SAFETY: the caller's buffers and the live key, per the contract.
    unsafe { ECDSA_verify(type_, tbs, tbslen as c_int, sig, siglen as c_int, ec) }
}

/// `static int pkey_ec_derive(EVP_PKEY_CTX *ctx, unsigned char *key, size_t *keylen)` — `:166`.
///
/// # Safety
/// As [`crate::evp::pkey_ctx::PkeyMethDeriveFn`].
unsafe extern "C" fn pkey_ec_derive(
    ctx: *mut EvpPkeyCtx,
    key: *mut u8,
    keylen: *mut usize,
) -> c_int {
    // SAFETY: `ctx` is live and `data` is this method's own context.
    let dctx = unsafe { (*ctx).data }.cast::<EcPkeyCtx>();

    // SAFETY: `ctx` is live.
    if unsafe { (*ctx).pkey }.is_null() || unsafe { (*ctx).peerkey }.is_null() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::EC_PMETH_176) };
        return 0;
    }
    // SAFETY: the peer key is live.
    let eckeypub = unsafe { EVP_PKEY_get0_EC_KEY((*ctx).peerkey) };
    if eckeypub.is_null() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::EC_PMETH_181) };
        return 0;
    }

    // SAFETY: `dctx` is live.
    let eckey = if !unsafe { (*dctx).co_key }.is_null() {
        // SAFETY: the field is this context's own live key on this arm.
        unsafe { (*dctx).co_key }
    } else {
        // SAFETY: `ctx` is live and holds the key this method was built for.
        (unsafe { EVP_PKEY_get0_EC_KEY((*ctx).pkey) }) as *mut EcKey
    };

    if key.is_null() {
        // SAFETY: `eckey` is live.
        let group = unsafe { EC_KEY_get0_group(eckey) };
        if group.is_null() {
            return 0;
        }
        // SAFETY: `group` is live.
        let degree = unsafe { EC_GROUP_get_degree(group) };
        // SAFETY: `keylen` is writable per the contract.
        unsafe { *keylen = ((degree + 7) / 8) as usize };
        return 1;
    }
    // SAFETY: `eckeypub` is live.
    let pubkey = unsafe { EC_KEY_get0_public_key(eckeypub) };

    /* NB: unlike PKCS#3 DH, an `*outlen` below the maximum is not an error — the result is
     * truncated. */
    // SAFETY: `keylen` is readable per the contract.
    let outlen = unsafe { *keylen };

    // SAFETY: the caller's buffer, the peer point and the live key, per the contract.
    let ret = unsafe { ECDH_compute_key(key.cast::<c_void>(), outlen, pubkey, eckey, None) };
    if ret <= 0 {
        return 0;
    }
    // SAFETY: `keylen` is writable per the contract.
    unsafe { *keylen = ret as usize };
    1
}

/// `static int pkey_ec_kdf_derive(EVP_PKEY_CTX *ctx, unsigned char *key, size_t *keylen)` — `:213`.
///
/// # Safety
/// As [`crate::evp::pkey_ctx::PkeyMethDeriveFn`].
unsafe extern "C" fn pkey_ec_kdf_derive(
    ctx: *mut EvpPkeyCtx,
    key: *mut u8,
    keylen: *mut usize,
) -> c_int {
    // SAFETY: `ctx` is live and `data` is this method's own context.
    let dctx = unsafe { (*ctx).data }.cast::<EcPkeyCtx>();

    // SAFETY: `dctx` is live.
    if unsafe { (*dctx).kdf_type } as c_int == EVP_PKEY_ECDH_KDF_NONE {
        // SAFETY: `ctx` is live and the caller's slots are forwarded.
        return unsafe { pkey_ec_derive(ctx, key, keylen) };
    }
    if key.is_null() {
        // SAFETY: `keylen` is writable per the contract and `dctx` is live.
        unsafe { *keylen = (*dctx).kdf_outlen };
        return 1;
    }
    // SAFETY: `keylen` and `dctx` are readable per the contract.
    if unsafe { *keylen } != unsafe { (*dctx).kdf_outlen } {
        return 0;
    }
    let mut ktmplen: usize = 0;
    // SAFETY: `ctx` is live and `ktmplen` is this frame's own slot.
    if unsafe { pkey_ec_derive(ctx, ptr::null_mut(), &mut ktmplen) } == 0 {
        return 0;
    }
    /* `CRYPTO_malloc` is a safe entry point of this crate. */
    let ktmp = CRYPTO_malloc(ktmplen, FILE, LINE_MALLOC_KTMP).cast::<u8>();
    if ktmp.is_null() {
        return 0;
    }
    // SAFETY: `ktmp` is this call's own buffer of `ktmplen` bytes and `ctx` is live.
    if unsafe { pkey_ec_derive(ctx, ktmp, &mut ktmplen) } == 0 {
        // SAFETY: `ktmp` is this call's own buffer.
        unsafe { CRYPTO_clear_free(ktmp.cast::<c_void>(), ktmplen, FILE, LINE_CLEAR_FREE_KTMP) };
        return 0;
    }
    /* The KDF's nine arguments are the caller's buffer, this call's buffer and the context's own
     * fields; `*keylen` is the requested output length. */
    // SAFETY: as above, plus `ossl_ecdh_kdf_X9_63`'s own contract.
    let ok = unsafe {
        ossl_ecdh_kdf_X9_63(
            key,
            *keylen,
            ktmp,
            ktmplen,
            (*dctx).kdf_ukm,
            (*dctx).kdf_ukmlen,
            (*dctx).kdf_md,
            (*ctx).libctx,
            (*ctx).propquery,
        )
    };
    let rv = if ok != 0 { 1 } else { 0 };
    // SAFETY: `ktmp` is this call's own buffer.
    unsafe { CRYPTO_clear_free(ktmp.cast::<c_void>(), ktmplen, FILE, LINE_CLEAR_FREE_KTMP) };
    rv
}

/// `EVP_MD_get_type((const EVP_MD *)p2)`, which is how `pkey_ec_ctrl`'s digest arm reads its `p2`.
///
/// # Safety
/// `p2` must be a live `EVP_MD`.
unsafe fn md_type_of(p2: *const c_void) -> c_int {
    // SAFETY: `p2` is a live digest per the contract.
    unsafe { EVP_MD_get_type(p2.cast::<EvpMd>()) }
}

/// `static int pkey_ec_ctrl(EVP_PKEY_CTX *ctx, int type, int p1, void *p2)` — `:247`.
///
/// # Safety
/// As [`crate::evp::pkey_ctx::PkeyMethCtrlFn`].
unsafe extern "C" fn pkey_ec_ctrl(
    ctx: *mut EvpPkeyCtx,
    type_: c_int,
    p1: c_int,
    p2: *mut c_void,
) -> c_int {
    // SAFETY: `ctx` is live and `data` is this method's own context.
    let dctx = unsafe { (*ctx).data }.cast::<EcPkeyCtx>();

    match type_ {
        EVP_PKEY_CTRL_EC_PARAMGEN_CURVE_NID => {
            let group = EC_GROUP_new_by_curve_name(p1);
            if group.is_null() {
                // SAFETY: a compile-time-constant site.
                unsafe { raise_site(&err_sites::EC_PMETH_255) };
                return 0;
            }
            // SAFETY: `dctx`'s field is this context's own group or NULL.
            unsafe {
                EC_GROUP_free((*dctx).gen_group);
                (*dctx).gen_group = group;
            }
            1
        }
        EVP_PKEY_CTRL_EC_PARAM_ENC => {
            // SAFETY: `dctx` is live.
            if unsafe { (*dctx).gen_group }.is_null() {
                // SAFETY: a compile-time-constant site.
                unsafe { raise_site(&err_sites::EC_PMETH_264) };
                return 0;
            }
            // SAFETY: the group is this context's own live object.
            unsafe { EC_GROUP_set_asn1_flag((*dctx).gen_group, p1) };
            1
        }
        EVP_PKEY_CTRL_EC_ECDH_COFACTOR => {
            if p1 == -2 {
                // SAFETY: `dctx` is live.
                if unsafe { (*dctx).cofactor_mode } as c_int != -1 {
                    // SAFETY: `dctx` is live.
                    return unsafe { (*dctx).cofactor_mode } as c_int;
                } else {
                    // SAFETY: `ctx` is live.
                    let ec_key = unsafe { EVP_PKEY_get0_EC_KEY((*ctx).pkey) };
                    // SAFETY: `ec_key` is live and its flags are readable.
                    let flags = unsafe { EC_KEY_get_flags(ec_key) };
                    return if flags & EC_FLAG_COFACTOR_ECDH != 0 {
                        1
                    } else {
                        0
                    };
                }
            } else if !(-1..=1).contains(&p1) {
                return -2;
            }
            // SAFETY: `dctx` is live.
            unsafe { (*dctx).cofactor_mode = p1 as c_char };
            if p1 != -1 {
                /* Discard the const, as the authority does: this only works for a "real" legacy key
                 * and not for a cached copy of a provided one. */
                // SAFETY: `ctx` is live.
                let ec_key = unsafe { EVP_PKEY_get0_EC_KEY((*ctx).pkey) } as *mut EcKey;

                // SAFETY: `ctx` is live.
                if unsafe { evp_pkey_is_provided((*ctx).pkey) } != 0 {
                    // SAFETY: a compile-time-constant site.
                    unsafe { raise_site(&err_sites::EC_PMETH_290) };
                    return 0;
                }
                // SAFETY: `ec_key` is live.
                if unsafe { (*ec_key).group }.is_null() {
                    return -2;
                }
                /* If the cofactor is 1 the mode does nothing. */
                // SAFETY: the group is live on this arm.
                if unsafe { BN_is_one((*(*ec_key).group).cofactor) } != 0 {
                    return 1;
                }
                // SAFETY: `dctx` is live.
                if unsafe { (*dctx).co_key }.is_null() {
                    // SAFETY: `ec_key` is a live key.
                    let dup = unsafe { EC_KEY_dup(ec_key) };
                    // SAFETY: `dctx` is live.
                    unsafe { (*dctx).co_key = dup };
                    if dup.is_null() {
                        return 0;
                    }
                }
                // SAFETY: `dctx`'s copy is live on this arm.
                if p1 != 0 {
                    // SAFETY: the copy is live.
                    unsafe { EC_KEY_set_flags((*dctx).co_key, EC_FLAG_COFACTOR_ECDH) };
                } else {
                    // SAFETY: the copy is live.
                    unsafe { EC_KEY_clear_flags((*dctx).co_key, EC_FLAG_COFACTOR_ECDH) };
                }
            } else {
                // SAFETY: the field is this context's own key or NULL.
                unsafe {
                    EC_KEY_free((*dctx).co_key);
                    (*dctx).co_key = ptr::null_mut();
                }
            }
            1
        }
        EVP_PKEY_CTRL_EC_KDF_TYPE => {
            if p1 == -2 {
                // SAFETY: `dctx` is live.
                return unsafe { (*dctx).kdf_type } as c_int;
            }
            if p1 != EVP_PKEY_ECDH_KDF_NONE && p1 != EVP_PKEY_ECDH_KDF_X9_63 {
                return -2;
            }
            // SAFETY: `dctx` is live.
            unsafe { (*dctx).kdf_type = p1 as c_char };
            1
        }
        EVP_PKEY_CTRL_EC_KDF_MD => {
            // SAFETY: `dctx` is live.
            unsafe { (*dctx).kdf_md = p2.cast::<EvpMd>() };
            1
        }
        EVP_PKEY_CTRL_GET_EC_KDF_MD => {
            // SAFETY: `p2` is writable and `dctx` is live.
            unsafe { *p2.cast::<*const EvpMd>() = (*dctx).kdf_md };
            1
        }
        EVP_PKEY_CTRL_EC_KDF_OUTLEN => {
            if p1 <= 0 {
                return -2;
            }
            // SAFETY: `dctx` is live.
            unsafe { (*dctx).kdf_outlen = p1 as usize };
            1
        }
        EVP_PKEY_CTRL_GET_EC_KDF_OUTLEN => {
            // SAFETY: `p2` is writable and `dctx` is live.
            unsafe { *p2.cast::<c_int>() = (*dctx).kdf_outlen as c_int };
            1
        }
        EVP_PKEY_CTRL_EC_KDF_UKM => {
            // SAFETY: `dctx`'s field is this context's own or NULL, and `CRYPTO_free` accepts NULL.
            unsafe {
                CRYPTO_free(
                    (*dctx).kdf_ukm.cast::<c_void>(),
                    FILE,
                    LINE_FREE_KDF_UKM_CTRL,
                );
                (*dctx).kdf_ukm = p2.cast::<u8>();
                if !p2.is_null() {
                    (*dctx).kdf_ukmlen = p1 as usize;
                } else {
                    (*dctx).kdf_ukmlen = 0;
                }
            }
            1
        }
        EVP_PKEY_CTRL_GET_EC_KDF_UKM => {
            // SAFETY: `p2` is writable and `dctx` is live.
            unsafe { *p2.cast::<*mut u8>() = (*dctx).kdf_ukm };
            // SAFETY: `dctx` is live.
            unsafe { (*dctx).kdf_ukmlen as c_int }
        }
        EVP_PKEY_CTRL_MD => {
            // SAFETY: `p2` is a live digest on this arm per the authority's contract.
            let t = unsafe { md_type_of(p2) };
            if t != NID_sha1
                && t != NID_ecdsa_with_SHA1
                && t != NID_sha224
                && t != NID_sha256
                && t != NID_sha384
                && t != NID_sha512
                && t != NID_sha3_224
                && t != NID_sha3_256
                && t != NID_sha3_384
                && t != NID_sha3_512
                && t != NID_sm3
            {
                // SAFETY: a compile-time-constant site.
                unsafe { raise_site(&err_sites::EC_PMETH_355) };
                return 0;
            }
            // SAFETY: `dctx` is live.
            unsafe { (*dctx).md = p2.cast::<EvpMd>() };
            1
        }
        EVP_PKEY_CTRL_GET_MD => {
            // SAFETY: `p2` is writable and `dctx` is live.
            unsafe { *p2.cast::<*const EvpMd>() = (*dctx).md };
            1
        }
        EVP_PKEY_CTRL_PEER_KEY
        | EVP_PKEY_CTRL_DIGESTINIT
        | EVP_PKEY_CTRL_PKCS7_SIGN
        | EVP_PKEY_CTRL_CMS_SIGN => 1,
        _ => -2,
    }
}

/// `static int pkey_ec_ctrl_str(EVP_PKEY_CTX *ctx, const char *type, const char *value)` — `:377`.
///
/// # Safety
/// As [`crate::evp::pkey_ctx::PkeyMethCtrlStrFn`].
unsafe extern "C" fn pkey_ec_ctrl_str(
    ctx: *mut EvpPkeyCtx,
    type_: *const c_char,
    value: *const c_char,
) -> c_int {
    // SAFETY: `type_` is NUL-terminated per the contract.
    if unsafe { cstr_is(type_, b"ec_paramgen_curve") } {
        // SAFETY: `value` is NUL-terminated per the contract.
        let mut nid = unsafe { EC_curve_nist2nid(value) };
        if nid == NID_undef {
            // SAFETY: `value` is NUL-terminated per the contract.
            nid = unsafe { OBJ_sn2nid(value) };
        }
        if nid == NID_undef {
            // SAFETY: `value` is NUL-terminated per the contract.
            nid = unsafe { OBJ_ln2nid(value) };
        }
        if nid == NID_undef {
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&err_sites::EC_PMETH_388) };
            return 0;
        }
        // SAFETY: `ctx` is live.
        return unsafe { EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx, nid) };
    }
    // SAFETY: `type_` is NUL-terminated per the contract.
    if unsafe { cstr_is(type_, b"ec_param_enc") } {
        // SAFETY: `value` is NUL-terminated per the contract.
        let param_enc = if unsafe { cstr_is(value, b"explicit") } {
            0
        } else if unsafe { cstr_is(value, b"named_curve") } {
            OPENSSL_EC_NAMED_CURVE
        } else {
            return -2;
        };
        // SAFETY: `ctx` is live.
        return unsafe { EVP_PKEY_CTX_set_ec_param_enc(ctx, param_enc) };
    }
    // SAFETY: `type_` is NUL-terminated per the contract.
    if unsafe { cstr_is(type_, b"ecdh_kdf_md") } {
        // SAFETY: `value` is NUL-terminated per the contract.
        let md = unsafe { EVP_get_digestbyname(value) };
        if md.is_null() {
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&err_sites::EC_PMETH_404) };
            return 0;
        }
        // SAFETY: `ctx` is live.
        return unsafe { EVP_PKEY_CTX_set_ecdh_kdf_md(ctx, md) };
    }
    // SAFETY: `type_` is NUL-terminated per the contract.
    if unsafe { cstr_is(type_, b"ecdh_cofactor_mode") } {
        // SAFETY: `value` is NUL-terminated and `ctx` is live.
        return unsafe { EVP_PKEY_CTX_set_ecdh_cofactor_mode(ctx, atoi(value)) };
    }
    -2
}

/// `static int pkey_ec_paramgen(EVP_PKEY_CTX *ctx, EVP_PKEY *pkey)` — `:417`.
///
/// # Safety
/// As [`crate::evp::pkey_ctx::PkeyMethParamgenFn`].
unsafe extern "C" fn pkey_ec_paramgen(ctx: *mut EvpPkeyCtx, pkey: *mut EvpPkey) -> c_int {
    // SAFETY: `ctx` is live and `data` is this method's own context.
    let dctx = unsafe { (*ctx).data }.cast::<EcPkeyCtx>();

    // SAFETY: `dctx` is live.
    if unsafe { (*dctx).gen_group }.is_null() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::EC_PMETH_424) };
        return 0;
    }
    // SAFETY: no preconditions.
    let ec = unsafe { EC_KEY_new() };
    if ec.is_null() {
        return 0;
    }
    /* `!(ret = EC_KEY_set_group(...)) || !ossl_assert(ret = EVP_PKEY_assign_EC_KEY(pkey, ec))`: the
     * assignment runs only when the group was set, and either failure frees the key. */
    // SAFETY: `ec` and the context's group are live.
    let mut ret = unsafe { EC_KEY_set_group(ec, (*dctx).gen_group) };
    if ret == 0 {
        // SAFETY: `ec` is this call's own object.
        unsafe { EC_KEY_free(ec) };
        return ret;
    }
    // SAFETY: `pkey` and `ec` are live.
    ret = unsafe { EVP_PKEY_assign(pkey, EVP_PKEY_EC, ec.cast::<c_void>()) };
    if ossl_assert(ret != 0) == 0 {
        // SAFETY: `ec` is this call's own object, not taken by the failed assignment.
        unsafe { EC_KEY_free(ec) };
    }
    ret
}

/// `static int pkey_ec_keygen(EVP_PKEY_CTX *ctx, EVP_PKEY *pkey)` — `:436`.
///
/// # Safety
/// As [`crate::evp::pkey_ctx::PkeyMethParamgenFn`].
unsafe extern "C" fn pkey_ec_keygen(ctx: *mut EvpPkeyCtx, pkey: *mut EvpPkey) -> c_int {
    // SAFETY: `ctx` is live and `data` is this method's own context.
    let dctx = unsafe { (*ctx).data }.cast::<EcPkeyCtx>();

    // SAFETY: `ctx` and `dctx` are live.
    if unsafe { (*ctx).pkey }.is_null() && unsafe { (*dctx).gen_group }.is_null() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::EC_PMETH_443) };
        return 0;
    }
    // SAFETY: no preconditions.
    let ec = unsafe { EC_KEY_new() };
    if ec.is_null() {
        return 0;
    }
    // SAFETY: `pkey` and `ec` are live.
    if ossl_assert(unsafe { EVP_PKEY_assign(pkey, EVP_PKEY_EC, ec.cast::<c_void>()) } != 0) == 0 {
        // SAFETY: `ec` is this call's own object, not taken by the failed assignment.
        unsafe { EC_KEY_free(ec) };
        return 0;
    }
    // SAFETY: `ctx` is live.
    let ret = if !unsafe { (*ctx).pkey }.is_null() {
        // SAFETY: both keys are live per the contract.
        unsafe { EVP_PKEY_copy_parameters(pkey, (*ctx).pkey) }
    } else {
        // SAFETY: `ec` is live and the context's group is this method's own.
        unsafe { EC_KEY_set_group(ec, (*dctx).gen_group) }
    };

    if ret != 0 {
        // SAFETY: `ec` is live and holds the parameters just installed.
        unsafe { EC_KEY_generate_key(ec) }
    } else {
        0
    }
}

/// `static const EVP_PKEY_METHOD ec_pkey_meth` — `crypto/ec/ec_pmeth.c:462-499`.
///
/// Flags are **0**, and the derive column is `pkey_ec_kdf_derive` (the KDF wrapper, not
/// `pkey_ec_derive`), which is what makes `EVP_PKEY_CTRL_EC_KDF_TYPE` observable.
pub(crate) static EC_PKEY_METH: EvpPkeyMethod = EvpPkeyMethod {
    pkey_id: EVP_PKEY_EC,
    flags: 0,
    init: Some(pkey_ec_init),
    copy: Some(pkey_ec_copy),
    cleanup: Some(pkey_ec_cleanup),
    paramgen_init: None,
    paramgen: Some(pkey_ec_paramgen),
    keygen_init: None,
    keygen: Some(pkey_ec_keygen),
    sign_init: None,
    sign: Some(pkey_ec_sign),
    verify_init: None,
    verify: Some(pkey_ec_verify),
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
    derive: Some(pkey_ec_kdf_derive),
    ctrl: Some(pkey_ec_ctrl),
    ctrl_str: Some(pkey_ec_ctrl_str),
    digestsign: None,
    digestverify: None,
    check: None,
    public_check: None,
    param_check: None,
    digest_custom: None,
};

/// `const EVP_PKEY_METHOD *ossl_ec_pkey_method(void)` — `crypto/ec/ec_pmeth.c:501`.
///
/// # Safety
/// Nothing: the answer is a `static` of this module.
#[allow(dead_code)] // its only reader today is `PMETH_STANDARD_METHODS` in `src/evp/pkey_ctx.rs`
pub(crate) unsafe extern "C" fn ossl_ec_pkey_method() -> *const EvpPkeyMethod {
    ptr::addr_of!(EC_PKEY_METH)
}
