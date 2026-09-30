//! Phase 10.10 — `crypto/asn1/a_sign.c`: the ASN.1 signing layer, whole.
//!
//! The unit publishes four functions, and all four land here: the deprecated `ASN1_sign`
//! (`:27-109`), the `_ex`/non-`_ex` pair `ASN1_item_sign_ex`/`ASN1_item_sign` (`:113-144`) and
//! `ASN1_item_sign_ctx` (`:146-288`), which the pair delegates to. Nothing in the unit's
//! closure is unlanded: `evp_md_ctx_new_ex` is landed with this subphase in
//! `src/evp/digest.rs`, `EVP_DigestSignInit`/`EVP_DigestSign`/`EVP_SignFinal`/`EVP_MD_CTX_*`
//! are Phase 7's, `d2i_X509_ALGOR`/`X509_ALGOR_set0` are 8.8's, the `EVP_PKEY_ASN1_METHOD`
//! `item_sign` slot and the `ameth` pointer are landed, and the two string helpers
//! (`ASN1_STRING_set0`, `ossl_asn1_string_set_bits_left`) are `asn1_lib.c`'s.
//!
//! ## The three algorithm-identifier arms are the point of the unit
//!
//! `ASN1_item_sign_ctx` chooses how the `AlgorithmIdentifier` is filled by asking what the key
//! is, and the three arms are genuinely different:
//!
//! * a key with **no** `ameth` (`pkey->ameth == NULL`) is a provider-only key, and its
//!   algorithm identifier is the octet string the provider answers for
//!   `OSSL_SIGNATURE_PARAM_ALGORITHM_ID`, decoded with `d2i_X509_ALGOR` and handed back
//!   (`rv = 3`, "the method sets the identifiers, just sign");
//! * a key whose method supplies `item_sign` hands the whole operation to it, and the meaning
//!   of its return value is the authority's own comment: `<=0` error, `1` method does
//!   everything, `2` carry on, `3` identifiers set;
//! * every other key (`rv = 2`) matches its digest and pkey nids to a signature OID with
//!   `OBJ_find_sigid_by_algs`, and whether the parameters are an explicit `NULL` or absent is
//!   `pkey_flags & ASN1_PKEY_SIGPARAM_NULL`.
//!
//! ## The bit-string compatibility tail
//!
//! Both signing paths end with `ossl_asn1_string_set_bits_left(signature, 0)`: the authority's
//! comment is explicit that this is for compatibility, so a signature bit string this unit
//! produced never claims unused bits. It is transcribed at both sites (`:103`, `:283`).
//!
//! ## The engine engine's absence, and the one call that stands in for it
//!
//! `#ifndef OPENSSL_NO_SM2` selects `EVP_PKEY_get_id(pkey) == NID_sm2 ? NID_sm2 : pkey->ameth->pkey_id`.
//! The profile builds SM2, so the test is live. The engine block the authority carries elsewhere
//! is not on this path at all.
//!
//! ## The raise sites
//!
//! Eighteen `ERR_raise*` sites in the unit; every one this transcription reaches is the
//! generated constant `A_SIGN_*` in [`crate::runtime::err::err_sites`], because
//! `crypto/asn1/a_sign.c` joins `gen_err_raise_sites.py`'s covered set with this subphase.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_char, c_int, c_long, c_uchar, c_uint, c_void, CStr};
use core::ptr;

use crate::asn1::a_type::{ASN1_TYPE_free, ASN1_TYPE_new};
use crate::asn1::bitstr::set_bits_left;
use crate::asn1::i2d::ASN1_item_i2d;
use crate::asn1::layout::{Asn1Item, Asn1String, I2dOfVoid, V_ASN1_NULL, V_ASN1_UNDEF};
use crate::asn1::prim::ASN1_OBJECT_free;
use crate::asn1::string::ASN1_STRING_set0;
use crate::asn1::x_algor::{d2i_X509_ALGOR, X509Algor, X509_ALGOR_set0};
use crate::evp::digest::{
    evp_md_ctx_new_ex, EVP_DigestInit_ex, EVP_DigestSign, EVP_DigestSignInit, EVP_DigestUpdate,
    EVP_MD_CTX_free, EVP_MD_CTX_get0_md, EVP_MD_CTX_get_pkey_ctx, EVP_MD_CTX_new, EVP_MD_get_type,
    EvpMd, EvpMdCtx,
};
use crate::evp::p_legacy::EVP_SignFinal;
use crate::evp::pkey::{EVP_PKEY_get_id, EVP_PKEY_get_size, EvpPkey, ASN1_PKEY_SIGPARAM_NULL};
use crate::evp::pkey_asn1::Asn1BitString;
use crate::evp::pkey_ctx::{
    EVP_PKEY_CTX_free, EVP_PKEY_CTX_get0_pkey, EVP_PKEY_CTX_get_params, EVP_PKEY_OP_TYPE_SIG,
};
use crate::ffi::guard_ffi;
use crate::params::{OSSL_PARAM_construct_end, OSSL_PARAM_construct_octet_string};
use crate::runtime::err::err_sites;
use crate::runtime::err::raise_site;
use crate::runtime::mem::{CRYPTO_clear_free, CRYPTO_malloc};
use crate::runtime::obj::{NID_dsaWithSHA1, NID_sm2, OBJ_find_sigid_by_algs, OBJ_nid2obj};

/// The authority translation unit for this file's `OPENSSL_malloc`/`OPENSSL_clear_free`
/// expansions.
const FILE: &CStr = c"crypto/asn1/a_sign.c";
/// `ASN1_sign`'s `OPENSSL_malloc(inll)` (`:79`).
const LINE_MALLOC_IN: c_int = 79;
/// `ASN1_sign`'s `OPENSSL_malloc(outll)` (`:81`).
const LINE_MALLOC_OUT: c_int = 81;
/// `ASN1_sign`'s `OPENSSL_clear_free(buf_in, inll)` (`:106`).
const LINE_CLEAR_IN: c_int = 106;
/// `ASN1_sign`'s `OPENSSL_clear_free(buf_out, outll)` (`:107`).
const LINE_CLEAR_OUT: c_int = 107;
/// `ASN1_item_sign_ctx`'s `OPENSSL_malloc(outll)` (`:266`).
const LINE_MALLOC_SIGN: c_int = 266;
/// `ASN1_item_sign_ctx`'s `OPENSSL_clear_free(buf_in, inl)` (`:285`).
const LINE_CLEAR_SIGN_IN: c_int = 285;
/// `ASN1_item_sign_ctx`'s `OPENSSL_clear_free(buf_out, outll)` (`:286`).
const LINE_CLEAR_SIGN_OUT: c_int = 286;

/// `OSSL_SIGNATURE_PARAM_ALGORITHM_ID` — `include/openssl/core_names.h`, the key a signature
/// provider answers the `AlgorithmIdentifier` DER under.
const OSSL_SIGNATURE_PARAM_ALGORITHM_ID: *const c_char = c"algorithm-id".as_ptr();

/// `int ASN1_sign(i2d_of_void *i2d, X509_ALGOR *algor1, X509_ALGOR *algor2,
/// ASN1_BIT_STRING *signature, char *data, EVP_PKEY *pkey, const EVP_MD *type)` —
/// `crypto/asn1/a_sign.c:27-109`.
///
/// The deprecated spelling. It fills both `AlgorithmIdentifier`s from `type->pkey_type` (with
/// the RFC 3370 special case that `id-dsa-with-sha1` omits its parameters), signs the DER of
/// `data` with the legacy `EVP_SignInit_ex`/`EVP_SignUpdate`/`EVP_SignFinal` chain, and hands
/// the signature to `ASN1_STRING_set0`. The answer is the signature length, or 0 on any
/// failure.
///
/// # Safety
///
/// `i2d` must be a live encoder matching `data`; `algor1`/`algor2` NULL or live;
/// `signature` live and uniquely owned; `pkey` a live key; `type` a live method.
#[no_mangle]
pub unsafe extern "C" fn ASN1_sign(
    i2d: I2dOfVoid,
    algor1: *mut X509Algor,
    algor2: *mut X509Algor,
    signature: *mut Asn1String,
    data: *mut c_char,
    pkey: *mut EvpPkey,
    type_: *const EvpMd,
) -> c_int {
    guard_ffi(0, || {
        let ctx = EVP_MD_CTX_new();
        if ctx.is_null() {
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&err_sites::A_SIGN_38) };
            return 0;
        }
        let mut outl: c_int;

        for i in 0..2 {
            let a = if i == 0 { algor1 } else { algor2 };
            if a.is_null() {
                continue;
            }
            // SAFETY: `type_` is a live method and `a` is live.
            if unsafe { (*type_).pkey_type } == NID_dsaWithSHA1 {
                // SAFETY: `a` is live and its parameter slot is either NULL or owned.
                unsafe {
                    ASN1_TYPE_free((*a).parameter);
                    (*a).parameter = ptr::null_mut();
                }
            } else {
                // SAFETY: `a` is live.
                let need_null =
                    unsafe { (*a).parameter.is_null() || (*(*a).parameter).type_ != V_ASN1_NULL };
                if need_null {
                    // SAFETY: `a` is live and its parameter slot is either NULL or owned.
                    unsafe { ASN1_TYPE_free((*a).parameter) };
                    let fresh = ASN1_TYPE_new();
                    if fresh.is_null() {
                        // SAFETY: `ctx` is this call's own context.
                        unsafe { EVP_MD_CTX_free(ctx) };
                        return 0;
                    }
                    // SAFETY: `a` is live; `fresh` is this call's own object.
                    unsafe {
                        (*a).parameter = fresh;
                        (*fresh).type_ = V_ASN1_NULL;
                    }
                }
            }
            // SAFETY: `a` is live and its algorithm slot is either NULL or owned; `type_` is
            // a live method.
            unsafe {
                ASN1_OBJECT_free((*a).algorithm);
                (*a).algorithm = OBJ_nid2obj((*type_).pkey_type);
            }
            // SAFETY: `a` is live.
            let alg = unsafe { (*a).algorithm };
            if alg.is_null() {
                // SAFETY: a compile-time-constant site.
                unsafe { raise_site(&err_sites::A_SIGN_64) };
                // SAFETY: `ctx` is this call's own context.
                unsafe { EVP_MD_CTX_free(ctx) };
                return 0;
            }
            // SAFETY: `alg` is live.
            if unsafe { (*alg).length } == 0 {
                // SAFETY: a compile-time-constant site.
                unsafe { raise_site(&err_sites::A_SIGN_68) };
                // SAFETY: `ctx` is this call's own context.
                unsafe { EVP_MD_CTX_free(ctx) };
                return 0;
            }
        }

        // SAFETY: `i2d` is the caller's live encoder, and a null destination sizes.
        let inl = unsafe { i2d(data.cast::<c_void>(), ptr::null_mut()) };
        if inl <= 0 {
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&err_sites::A_SIGN_75) };
            // SAFETY: `ctx` is this call's own context.
            unsafe { EVP_MD_CTX_free(ctx) };
            return 0;
        }
        let inll = inl as usize;
        // SAFETY: the allocator's contract; `FILE`/`LINE_MALLOC_IN` are the authority's.
        let buf_in = CRYPTO_malloc(inll, FILE.as_ptr(), LINE_MALLOC_IN).cast::<c_uchar>();
        // SAFETY: `pkey` is a live key.
        outl = unsafe { EVP_PKEY_get_size(pkey) };
        let outll = outl as usize;
        // SAFETY: the allocator's contract; `FILE`/`LINE_MALLOC_OUT` are the authority's.
        let buf_out = CRYPTO_malloc(outll, FILE.as_ptr(), LINE_MALLOC_OUT).cast::<c_uchar>();
        if buf_in.is_null() || buf_out.is_null() {
            // SAFETY: both buffers are NULL or this call's own allocations.
            unsafe {
                CRYPTO_clear_free(buf_in.cast::<c_void>(), inll, FILE.as_ptr(), LINE_CLEAR_IN);
                CRYPTO_clear_free(
                    buf_out.cast::<c_void>(),
                    outll,
                    FILE.as_ptr(),
                    LINE_CLEAR_OUT,
                );
                EVP_MD_CTX_free(ctx);
            }
            return 0;
        }
        let mut p = buf_in;
        // SAFETY: `p` has room for the encoded length `inl`.
        unsafe { i2d(data.cast::<c_void>(), &mut p) };

        let mut outl_u: c_uint = outl as c_uint;
        // SAFETY: `EVP_SignInit_ex`/`EVP_SignUpdate` are macros over `EVP_DigestInit_ex`/
        // `EVP_DigestUpdate`; `type_` is live; the buffers hold the lengths given them.
        let ok = unsafe {
            EVP_DigestInit_ex(ctx, type_, ptr::null_mut()) != 0
                && EVP_DigestUpdate(ctx, buf_in.cast::<c_void>(), inl as usize) != 0
                && EVP_SignFinal(ctx, buf_out, &mut outl_u, pkey) != 0
        };
        if !ok {
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&err_sites::A_SIGN_94) };
            // SAFETY: both buffers are this call's own.
            unsafe {
                CRYPTO_clear_free(buf_in.cast::<c_void>(), inll, FILE.as_ptr(), LINE_CLEAR_IN);
                CRYPTO_clear_free(
                    buf_out.cast::<c_void>(),
                    outll,
                    FILE.as_ptr(),
                    LINE_CLEAR_OUT,
                );
                EVP_MD_CTX_free(ctx);
            }
            return 0;
        }
        outl = outl_u as c_int;
        // SAFETY: `signature` is live and uniquely owned; `buf_out` is handed over and nulled.
        unsafe {
            ASN1_STRING_set0(signature, buf_out.cast::<c_void>(), outl);
            set_bits_left(signature, 0);
            CRYPTO_clear_free(buf_in.cast::<c_void>(), inll, FILE.as_ptr(), LINE_CLEAR_IN);
            EVP_MD_CTX_free(ctx);
        }
        outl
    })
}

/// `int ASN1_item_sign(const ASN1_ITEM *it, X509_ALGOR *algor1, X509_ALGOR *algor2,
/// ASN1_BIT_STRING *signature, const void *data, EVP_PKEY *pkey, const EVP_MD *md)` —
/// `crypto/asn1/a_sign.c:113-119`.
///
/// The `_ex`-less spelling: no separate id, default context and no property query.
///
/// # Safety
///
/// The same contract as [`ASN1_item_sign_ex`] with `id = NULL`, `libctx = NULL`, `propq = NULL`.
#[no_mangle]
pub unsafe extern "C" fn ASN1_item_sign(
    it: *const Asn1Item,
    algor1: *mut X509Algor,
    algor2: *mut X509Algor,
    signature: *mut Asn1String,
    data: *const c_void,
    pkey: *mut EvpPkey,
    md: *const EvpMd,
) -> c_int {
    // SAFETY: forwarded under this function's contract.
    unsafe {
        ASN1_item_sign_ex(
            it,
            algor1,
            algor2,
            signature,
            data,
            ptr::null(),
            pkey,
            md,
            ptr::null_mut(),
            ptr::null(),
        )
    }
}

/// `int ASN1_item_sign_ex(const ASN1_ITEM *it, X509_ALGOR *algor1, X509_ALGOR *algor2,
/// ASN1_BIT_STRING *signature, const void *data, const ASN1_OCTET_STRING *id, EVP_PKEY *pkey,
/// const EVP_MD *md, OSSL_LIB_CTX *libctx, const char *propq)` — `crypto/asn1/a_sign.c:121-144`.
///
/// Builds the digest context with [`evp_md_ctx_new_ex`] — which is where the `id` and the
/// library context/property query are bound to the key — initialises it for signing, and hands
/// it to [`ASN1_item_sign_ctx`]. The context's `EVP_PKEY_CTX` is released before the context
/// itself, exactly as the authority's `err:` tail does.
///
/// # Safety
///
/// `it` live; `algor1`/`algor2` NULL or live; `signature` live; `data` live; `id` NULL or
/// live; `pkey` a live key; `md` a live or NULL method; `libctx`/`propq` NULL or the
/// context's own.
#[no_mangle]
pub unsafe extern "C" fn ASN1_item_sign_ex(
    it: *const Asn1Item,
    algor1: *mut X509Algor,
    algor2: *mut X509Algor,
    signature: *mut Asn1String,
    data: *const c_void,
    id: *const Asn1String,
    pkey: *mut EvpPkey,
    md: *const EvpMd,
    libctx: *mut c_void,
    propq: *const c_char,
) -> c_int {
    guard_ffi(0, || {
        // SAFETY: the arguments are the caller's, forwarded under this function's contract.
        let ctx = unsafe { evp_md_ctx_new_ex(pkey, id, libctx, propq) };
        if ctx.is_null() {
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&err_sites::A_SIGN_131) };
            return 0;
        }
        // Designated initialiser, per the authority: the non-`_ex` init, because the key is
        // already bound into the context.
        // SAFETY: `ctx` is live; `md` and `pkey` are the caller's.
        if unsafe { EVP_DigestSignInit(ctx, ptr::null_mut(), md, ptr::null_mut(), pkey) } == 0 {
            // SAFETY: `ctx` is live.
            unsafe {
                EVP_PKEY_CTX_free(EVP_MD_CTX_get_pkey_ctx(ctx));
                EVP_MD_CTX_free(ctx);
            }
            return 0;
        }
        // SAFETY: `ctx` is live and the remaining arguments are the caller's.
        let rv = unsafe { ASN1_item_sign_ctx(it, algor1, algor2, signature, data, ctx) };
        // SAFETY: `ctx` is live.
        unsafe {
            EVP_PKEY_CTX_free(EVP_MD_CTX_get_pkey_ctx(ctx));
            EVP_MD_CTX_free(ctx);
        }
        rv
    })
}

/// `int ASN1_item_sign_ctx(const ASN1_ITEM *it, X509_ALGOR *algor1, X509_ALGOR *algor2,
/// ASN1_BIT_STRING *signature, const void *data, EVP_MD_CTX *ctx)` —
/// `crypto/asn1/a_sign.c:146-288`.
///
/// The core: it resolves the key out of the context and takes one of the three
/// algorithm-identifier arms described in the module documentation, then signs the DER of
/// `data`. The answer is the signature length, or a value `<= 0` on failure.
///
/// # Safety
///
/// `it` live; `algor1`/`algor2` NULL or live; `signature` live and uniquely owned; `data` live;
/// `ctx` a live initialised signing context.
#[no_mangle]
pub unsafe extern "C" fn ASN1_item_sign_ctx(
    it: *const Asn1Item,
    mut algor1: *mut X509Algor,
    mut algor2: *mut X509Algor,
    signature: *mut Asn1String,
    data: *const c_void,
    ctx: *mut EvpMdCtx,
) -> c_int {
    guard_ffi(0, || {
        // SAFETY: `ctx` is live and initialised.
        let (md, pkey) = unsafe {
            (
                EVP_MD_CTX_get0_md(ctx),
                EVP_PKEY_CTX_get0_pkey(EVP_MD_CTX_get_pkey_ctx(ctx)),
            )
        };

        if pkey.is_null() {
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&err_sites::A_SIGN_161) };
            return 0;
        }

        // SAFETY: `pkey` is live per the check above.
        let ameth = unsafe { (*pkey).ameth };
        let mut outl: usize = 0;
        let mut outll: usize = 0;
        let rv: c_int;

        if ameth.is_null() {
            // SAFETY: `ctx` is live.
            let pctx = unsafe { EVP_MD_CTX_get_pkey_ctx(ctx) };
            let mut aid = [0u8; 128];
            // SAFETY: `ctx` is live; `pctx` is read for its operation bits.
            let is_sig =
                !pctx.is_null() && (unsafe { (*pctx).operation } & EVP_PKEY_OP_TYPE_SIG) != 0;
            if !is_sig {
                // SAFETY: a compile-time-constant site.
                unsafe { raise_site(&err_sites::A_SIGN_173) };
                return 0;
            }
            let mut params = [
                // SAFETY: `aid` is a 128-byte writable buffer and the key is a static literal.
                unsafe {
                    OSSL_PARAM_construct_octet_string(
                        OSSL_SIGNATURE_PARAM_ALGORITHM_ID,
                        aid.as_mut_ptr().cast::<c_void>(),
                        aid.len(),
                    )
                },
                OSSL_PARAM_construct_end(),
            ];
            // SAFETY: `pctx` is a live signature context and `params` is a two-entry array.
            if unsafe { EVP_PKEY_CTX_get_params(pctx, params.as_mut_ptr()) } <= 0 {
                return 0;
            }
            if params[0].return_size == 0 {
                // SAFETY: a compile-time-constant site.
                unsafe { raise_site(&err_sites::A_SIGN_185) };
                return 0;
            }
            let aid_len = params[0].return_size;
            if !algor1.is_null() {
                let mut pp: *const c_uchar = aid.as_ptr();
                // SAFETY: `pp` points into `aid` and `aid_len` is its valid length.
                if unsafe { d2i_X509_ALGOR(&mut algor1, &mut pp, aid_len as c_long) }.is_null() {
                    // SAFETY: a compile-time-constant site.
                    unsafe { raise_site(&err_sites::A_SIGN_193) };
                    return 0;
                }
            }
            if !algor2.is_null() {
                let mut pp: *const c_uchar = aid.as_ptr();
                // SAFETY: `pp` points into `aid` and `aid_len` is its valid length.
                if unsafe { d2i_X509_ALGOR(&mut algor2, &mut pp, aid_len as c_long) }.is_null() {
                    // SAFETY: a compile-time-constant site.
                    unsafe { raise_site(&err_sites::A_SIGN_202) };
                    return 0;
                }
            }
            rv = 3;
        } else {
            // SAFETY: `ameth` is live per the check above.
            let item_sign = unsafe { (*ameth).item_sign };
            match item_sign {
                Some(f) => {
                    // SAFETY: `f` is the caller's method callback with the authority's signature,
                    // and `signature` is a bit string aliasing an `ASN1_STRING`.
                    rv = unsafe {
                        f(
                            ctx,
                            it,
                            data,
                            algor1,
                            algor2,
                            signature.cast::<Asn1BitString>(),
                        )
                    };
                    if rv == 1 {
                        // SAFETY: `signature` is live.
                        outl = unsafe { (*signature).length } as usize;
                    }
                    // Return-value meanings: <=0 error; 1 method did everything; 2 carry on;
                    // 3 identifiers set.
                    if rv <= 0 {
                        // SAFETY: a compile-time-constant site.
                        unsafe { raise_site(&err_sites::A_SIGN_220) };
                    }
                    if rv <= 1 {
                        return outl as c_int;
                    }
                }
                None => {
                    rv = 2;
                }
            }
        }

        if rv == 2 {
            if md.is_null() {
                // SAFETY: a compile-time-constant site.
                unsafe { raise_site(&err_sites::A_SIGN_229) };
                return 0;
            }
            // SAFETY: `pkey` is live; the SM2 test reads its type and the method its id.
            let pkey_id = unsafe {
                if EVP_PKEY_get_id(pkey) == NID_sm2 {
                    NID_sm2
                } else {
                    (*ameth).pkey_id
                }
            };
            let mut signid: c_int = 0;
            // SAFETY: `md` is live (`EVP_MD_get_type` is `EVP_MD_nid`); `signid` is a writable slot.
            if unsafe { OBJ_find_sigid_by_algs(&mut signid, EVP_MD_get_type(md), pkey_id) } == 0 {
                // SAFETY: a compile-time-constant site.
                unsafe { raise_site(&err_sites::A_SIGN_240) };
                return 0;
            }
            // SAFETY: `ameth` is live.
            let paramtype = if (unsafe { (*ameth).pkey_flags } & ASN1_PKEY_SIGPARAM_NULL) != 0 {
                V_ASN1_NULL
            } else {
                V_ASN1_UNDEF
            };
            if !algor1.is_null() {
                // SAFETY: `algor1` is live; `OBJ_nid2obj` returns a static object or NULL.
                let ok = unsafe {
                    X509_ALGOR_set0(algor1, OBJ_nid2obj(signid), paramtype, ptr::null_mut())
                };
                if ok == 0 {
                    return 0;
                }
            }
            if !algor2.is_null() {
                // SAFETY: `algor2` is live.
                let ok = unsafe {
                    X509_ALGOR_set0(algor2, OBJ_nid2obj(signid), paramtype, ptr::null_mut())
                };
                if ok == 0 {
                    return 0;
                }
            }
        }

        let mut buf_in: *mut c_uchar = ptr::null_mut();
        // SAFETY: `data` is a live value of `it`'s type; `buf_in` is a null slot.
        let buf_len = unsafe { ASN1_item_i2d(data, &mut buf_in, it) };
        if buf_len <= 0 {
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&err_sites::A_SIGN_256) };
            return 0;
        }
        let inl = buf_len as usize;

        // SAFETY: `ctx` is live; a null signature buffer asks for the length.
        if unsafe { EVP_DigestSign(ctx, ptr::null_mut(), &mut outll, buf_in, inl) } == 0 {
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&err_sites::A_SIGN_262) };
            // SAFETY: `buf_in` is this call's own allocation.
            unsafe {
                CRYPTO_clear_free(
                    buf_in.cast::<c_void>(),
                    inl,
                    FILE.as_ptr(),
                    LINE_CLEAR_SIGN_IN,
                )
            };
            return 0;
        }
        outl = outll;
        // SAFETY: the allocator's contract; `FILE`/`LINE_MALLOC_SIGN` are the authority's.
        let buf_out = CRYPTO_malloc(outll, FILE.as_ptr(), LINE_MALLOC_SIGN).cast::<c_uchar>();
        if buf_in.is_null() || buf_out.is_null() {
            // SAFETY: both buffers are NULL or this call's own allocations.
            unsafe {
                CRYPTO_clear_free(
                    buf_in.cast::<c_void>(),
                    inl,
                    FILE.as_ptr(),
                    LINE_CLEAR_SIGN_IN,
                );
                CRYPTO_clear_free(
                    buf_out.cast::<c_void>(),
                    outll,
                    FILE.as_ptr(),
                    LINE_CLEAR_SIGN_OUT,
                );
            }
            return 0;
        }

        // SAFETY: `ctx` is live, `buf_out` is writable for `outl` bytes, and `buf_in` holds `inl`.
        if unsafe { EVP_DigestSign(ctx, buf_out, &mut outl, buf_in, inl) } == 0 {
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&err_sites::A_SIGN_274) };
            // SAFETY: both buffers are this call's own.
            unsafe {
                CRYPTO_clear_free(
                    buf_in.cast::<c_void>(),
                    inl,
                    FILE.as_ptr(),
                    LINE_CLEAR_SIGN_IN,
                );
                CRYPTO_clear_free(
                    buf_out.cast::<c_void>(),
                    outll,
                    FILE.as_ptr(),
                    LINE_CLEAR_SIGN_OUT,
                );
            }
            return 0;
        }
        // SAFETY: `signature` is live and uniquely owned; `buf_out` is handed over and not freed
        // on the success path (the authority sets it to NULL).
        unsafe {
            ASN1_STRING_set0(signature, buf_out.cast::<c_void>(), outl as c_int);
            set_bits_left(signature, 0);
            CRYPTO_clear_free(
                buf_in.cast::<c_void>(),
                inl,
                FILE.as_ptr(),
                LINE_CLEAR_SIGN_IN,
            );
        }
        outl as c_int
    })
}
