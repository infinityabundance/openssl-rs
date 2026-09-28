//! Phase 10.11 — `crypto/asn1/a_verify.c`: the ASN.1 verification layer, whole.
//!
//! The unit publishes four functions and all four land here: the deprecated `ASN1_verify`
//! (`:27-84`, under `#ifndef OPENSSL_NO_DEPRECATED_3_0`), the `_ex`/non-`_ex` pair
//! `ASN1_item_verify_ex`/`ASN1_item_verify` (`:88-109`) and `ASN1_item_verify_ctx`
//! (`:111-226`), which the pair delegates to. Nothing in the unit's closure is unlanded:
//! `evp_md_ctx_new_ex` landed with 10.10 in `src/evp/digest.rs`, `EVP_DigestVerifyInit`/
//! `EVP_DigestVerify`/`EVP_MD_CTX_*` are Phase 7's, `EVP_VerifyFinal` is `p_legacy.rs`'s,
//! `evp_pkey_is_legacy`/`EVP_PKEY_is_a` are `pkey.rs`'s, `ossl_rsa_pss_to_ctx` is 8.8's, and the
//! `EVP_PKEY_ASN1_METHOD` `item_verify` slot is landed.
//!
//! ## This is the subphase's Phase-7 hand-off
//!
//! `ASN1_item_verify_ex` had a **single** blocker after 10.10: `ASN1_item_verify_ctx`, declared in
//! `x509.h` and defined here at `:111`. Landing it closes Phase 7's last blocked row, and
//! `forensics/tools/phase7_obligations.py`'s `BLOCKED_HANDOFFS` entry is **retired** with this
//! change rather than left covering a built symbol.
//!
//! ## The four arms of `ASN1_item_verify_ctx`
//!
//! The signing twin's mirror image, and the same algorithm-identifier question asked in reverse:
//!
//! * a **legacy** key (`evp_pkey_is_legacy`) whose signature OID carries no digest NID
//!   (`mdnid == NID_undef`) hands the whole operation to the method's `item_verify`, whose return
//!   value is the authority's own contract (`<=0` error, `1` done, `2` the method has called
//!   `EVP_DigestVerifyInit`);
//! * a key whose signature OID is RSA-PSS but whose digest NID is absent goes through
//!   `ossl_rsa_pss_to_ctx`, which also starts the digest-verify;
//! * every other key matches its type against `OBJ_nid2sn(pknid)` with `EVP_PKEY_is_a` and
//!   initialises the digest-verify with the digest the OID names (or NULL, which Ed25519/Ed448
//!   allow);
//! * the data is then DER-encoded and verified against the signature bits.
//!
//! The `signature->flags & 0x7` test is the bit-string **unused-bits** check and is shared with
//! `ASN1_verify`; it is raised before any work in both.
//!
//! ## The raise sites
//!
//! Nineteen `ERR_raise*` sites in the unit; every one this transcription reaches is the generated
//! constant `A_VERIFY_*` in [`crate::runtime::err::err_sites`], because
//! `crypto/asn1/a_verify.c` joins `gen_err_raise_sites.py`'s covered set with this subphase
//! (it was on the "deliberately not covered" list as Phase 11 surface until now). They are
//! `ERR_LIB_ASN1` with the generic `ERR_R_*` codes and the `ASN1_R_*` reasons
//! (`UNKNOWN_MESSAGE_DIGEST_ALGORITHM`, `INVALID_BIT_STRING_BITS_LEFT`,
//! `UNKNOWN_SIGNATURE_ALGORITHM`, `WRONG_PUBLIC_KEY_TYPE`).
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_char, c_int, c_uchar, c_uint, c_void, CStr};
use core::ptr;

use crate::asn1::i2d::ASN1_item_i2d;
use crate::asn1::layout::{Asn1Item, Asn1String, I2dOfVoid, V_ASN1_BIT_STRING};
use crate::evp::digest::{
    evp_md_ctx_new_ex, EVP_DigestInit_ex, EVP_DigestUpdate, EVP_DigestVerify, EVP_DigestVerifyInit,
    EVP_MD_CTX_free, EVP_MD_CTX_get_pkey_ctx, EVP_MD_CTX_new, EvpMdCtx,
};
use crate::evp::legacy_evp::EVP_get_digestbyname;
use crate::evp::p_legacy::EVP_VerifyFinal;
use crate::evp::pkey::{evp_pkey_is_legacy, EVP_PKEY_is_a, EvpPkey};
use crate::evp::pkey_asn1::Asn1BitString;
use crate::evp::pkey_ctx::{EVP_PKEY_CTX_free, EVP_PKEY_CTX_get0_pkey, EVP_PKEY_RSA_PSS};
use crate::ffi::guard_ffi;
use crate::rsa::ameth::ossl_rsa_pss_to_ctx;
use crate::runtime::err::{err_sites, raise_site, raise_site_data};
use crate::runtime::mem::{CRYPTO_clear_free, CRYPTO_malloc};
use crate::runtime::obj::{NID_undef, OBJ_find_sigid_algs, OBJ_nid2sn, OBJ_obj2nid};

/// The authority translation unit for this file's `OPENSSL_malloc`/`OPENSSL_clear_free`
/// expansions.
const FILE: &CStr = c"crypto/asn1/a_verify.c";
/// `ASN1_verify`'s `OPENSSL_malloc(inl)` (`:56`).
const LINE_MALLOC_IN: c_int = 56;
/// `ASN1_verify`'s `OPENSSL_clear_free(buf_in, inl)` (`:65`).
const LINE_CLEAR_IN: c_int = 65;

/// `int ASN1_verify(i2d_of_void *i2d, X509_ALGOR *a, ASN1_BIT_STRING *signature, char *data,
/// EVP_PKEY *pkey)` — `crypto/asn1/a_verify.c:27-84`.
///
/// The deprecated spelling: it looks the digest up from the algorithm's short name, rejects a
/// bit string that claims unused bits, DER-encodes `data`, and runs the legacy
/// `EVP_VerifyInit_ex`/`EVP_VerifyUpdate`/`EVP_VerifyFinal` chain. `-1` means "did not get far
/// enough to say", `0` a completed refusal, `1` a verified signature.
///
/// # Safety
///
/// `i2d` must be a live encoder matching `data`; `a` a live algorithm; `signature` a live bit
/// string; `data` readable by `i2d`; `pkey` a live key.
#[no_mangle]
pub unsafe extern "C" fn ASN1_verify(
    i2d: I2dOfVoid,
    a: *mut crate::asn1::x_algor::X509Algor,
    signature: *mut Asn1String,
    data: *mut c_char,
    pkey: *mut EvpPkey,
) -> c_int {
    guard_ffi(-1, || {
        let ctx = EVP_MD_CTX_new();
        let mut ret: c_int = -1;

        if ctx.is_null() {
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&err_sites::A_VERIFY_36) };
            return ret;
        }

        // SAFETY: `a` is live.
        let i = unsafe { OBJ_obj2nid((*a).algorithm) };
        // SAFETY: `OBJ_nid2sn` answers a short name or NULL, which `EVP_get_digestbyname`
        // treats as "unknown".
        let type_ = unsafe { EVP_get_digestbyname(OBJ_nid2sn(i)) };
        if type_.is_null() {
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&err_sites::A_VERIFY_42) };
            // SAFETY: `ctx` is this call's own.
            unsafe { EVP_MD_CTX_free(ctx) };
            return ret;
        }

        // SAFETY: `signature` is live.
        if unsafe { (*signature).type_ } == V_ASN1_BIT_STRING
            // SAFETY: `signature` is live.
            && unsafe { (*signature).flags } & 0x7 != 0
        {
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&err_sites::A_VERIFY_47) };
            // SAFETY: `ctx` is this call's own.
            unsafe { EVP_MD_CTX_free(ctx) };
            return ret;
        }

        // SAFETY: `i2d` is the caller's live encoder; a null destination sizes.
        let inl = unsafe { i2d(data.cast::<c_void>(), ptr::null_mut()) };
        if inl <= 0 {
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&err_sites::A_VERIFY_53) };
            // SAFETY: `ctx` is this call's own.
            unsafe { EVP_MD_CTX_free(ctx) };
            return ret;
        }
        // SAFETY: the allocator's contract; `FILE`/`LINE_MALLOC_IN` are the authority's.
        let buf_in = CRYPTO_malloc(inl as usize, FILE.as_ptr(), LINE_MALLOC_IN).cast::<c_uchar>();
        if buf_in.is_null() {
            // SAFETY: `ctx` is this call's own.
            unsafe { EVP_MD_CTX_free(ctx) };
            return ret;
        }
        let mut p = buf_in;

        // SAFETY: `p` has room for the encoded length `inl`.
        unsafe { i2d(data.cast::<c_void>(), &mut p) };
        // SAFETY: `EVP_VerifyInit_ex`/`EVP_VerifyUpdate` are macros over `EVP_DigestInit_ex`/
        // `EVP_DigestUpdate`; `type_` is live; the buffer holds `inl` bytes.
        ret = c_int::from(
            unsafe { EVP_DigestInit_ex(ctx, type_, ptr::null_mut()) } != 0
                && unsafe { EVP_DigestUpdate(ctx, buf_in.cast::<c_void>(), inl as usize) } != 0,
        );

        // SAFETY: `buf_in` is this call's own allocation of `inl` bytes.
        unsafe {
            CRYPTO_clear_free(
                buf_in.cast::<c_void>(),
                inl as usize,
                FILE.as_ptr(),
                LINE_CLEAR_IN,
            )
        };

        if ret == 0 {
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&err_sites::A_VERIFY_68) };
            // SAFETY: `ctx` is this call's own.
            unsafe { EVP_MD_CTX_free(ctx) };
            return -1;
        }

        // SAFETY: `signature`/`pkey` are live.
        if unsafe { EVP_VerifyFinal(ctx, (*signature).data, (*signature).length as c_uint, pkey) }
            <= 0
        {
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&err_sites::A_VERIFY_76) };
            ret = 0;
            // SAFETY: `ctx` is this call's own.
            unsafe { EVP_MD_CTX_free(ctx) };
            return ret;
        }
        ret = 1;
        // SAFETY: `ctx` is this call's own.
        unsafe { EVP_MD_CTX_free(ctx) };
        ret
    })
}

/// `int ASN1_item_verify(const ASN1_ITEM *it, const X509_ALGOR *alg, const ASN1_BIT_STRING
/// *signature, const void *data, EVP_PKEY *pkey)` — `crypto/asn1/a_verify.c:88-93`.
///
/// The `_ex`-less spelling: no separate id, default context and no property query.
///
/// # Safety
///
/// The same contract as [`ASN1_item_verify_ex`] with `id = NULL`, `libctx = NULL`,
/// `propq = NULL`.
#[no_mangle]
pub unsafe extern "C" fn ASN1_item_verify(
    it: *const Asn1Item,
    alg: *const crate::asn1::x_algor::X509Algor,
    signature: *const Asn1String,
    data: *const c_void,
    pkey: *mut EvpPkey,
) -> c_int {
    // SAFETY: forwarded under this function's contract.
    unsafe {
        ASN1_item_verify_ex(
            it,
            alg,
            signature,
            data,
            ptr::null(),
            pkey,
            ptr::null_mut(),
            ptr::null(),
        )
    }
}

/// `int ASN1_item_verify_ex(const ASN1_ITEM *it, const X509_ALGOR *alg, const ASN1_BIT_STRING
/// *signature, const void *data, const ASN1_OCTET_STRING *id, EVP_PKEY *pkey, OSSL_LIB_CTX
/// *libctx, const char *propq)` — `crypto/asn1/a_verify.c:95-109`.
///
/// Builds the digest context with [`evp_md_ctx_new_ex`] -- which is where the `id` and the
/// library context/property query are bound to the key -- hands it to
/// [`ASN1_item_verify_ctx`], and releases the context's `EVP_PKEY_CTX` before the context itself,
/// exactly as the authority does. **This is the form 10.11 un-blocks**: it was Phase 7's last
/// blocked hand-off, with `ASN1_item_verify_ctx` as its single blocker.
///
/// # Safety
///
/// `it` live; `alg`/`signature` live; `data` live; `id` NULL or live; `pkey` a live key;
/// `libctx`/`propq` NULL or the context's own.
#[no_mangle]
pub unsafe extern "C" fn ASN1_item_verify_ex(
    it: *const Asn1Item,
    alg: *const crate::asn1::x_algor::X509Algor,
    signature: *const Asn1String,
    data: *const c_void,
    id: *const Asn1String,
    pkey: *mut EvpPkey,
    libctx: *mut c_void,
    propq: *const c_char,
) -> c_int {
    guard_ffi(-1, || {
        let mut rv: c_int = -1;
        // SAFETY: the arguments are the caller's, forwarded under this function's contract.
        let ctx = unsafe { evp_md_ctx_new_ex(pkey, id, libctx, propq) };
        if !ctx.is_null() {
            // SAFETY: `ctx` is live and the remaining arguments are the caller's.
            rv = unsafe { ASN1_item_verify_ctx(it, alg, signature, data, ctx) };
            // SAFETY: `ctx` is live.
            unsafe {
                EVP_PKEY_CTX_free(EVP_MD_CTX_get_pkey_ctx(ctx));
                EVP_MD_CTX_free(ctx);
            }
        }
        rv
    })
}

/// `int ASN1_item_verify_ctx(const ASN1_ITEM *it, const X509_ALGOR *alg, const ASN1_BIT_STRING
/// *signature, const void *data, EVP_MD_CTX *ctx)` — `crypto/asn1/a_verify.c:111-226`.
///
/// The core: it resolves the key out of the context, takes one of the four arms described in the
/// module documentation, DER-encodes `data` and verifies the signature over it. The answer is `1`
/// for a verified signature, `-1` for "could not complete" and `0` for a completed refusal.
///
/// # Safety
///
/// `it` live; `alg`/`signature` live; `data` live; `ctx` a live verification context.
#[no_mangle]
pub unsafe extern "C" fn ASN1_item_verify_ctx(
    it: *const Asn1Item,
    alg: *const crate::asn1::x_algor::X509Algor,
    signature: *const Asn1String,
    data: *const c_void,
    ctx: *mut EvpMdCtx,
) -> c_int {
    guard_ffi(-1, || {
        let mut ret: c_int = -1;
        let mut buf_in: *mut c_uchar = ptr::null_mut();

        // SAFETY: `ctx` is live and initialised.
        let pkey = unsafe { EVP_PKEY_CTX_get0_pkey(EVP_MD_CTX_get_pkey_ctx(ctx)) };

        if pkey.is_null() {
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&err_sites::A_VERIFY_124) };
            return -1;
        }

        // SAFETY: `signature` is live.
        if unsafe { (*signature).type_ } == V_ASN1_BIT_STRING
            // SAFETY: `signature` is live.
            && unsafe { (*signature).flags } & 0x7 != 0
        {
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&err_sites::A_VERIFY_129) };
            return -1;
        }

        // Convert the signature OID into digest and public key OIDs.
        let mut mdnid: c_int = 0;
        let mut pknid: c_int = 0;
        // SAFETY: `alg` is live; `mdnid`/`pknid` are this frame's out-parameters.
        if unsafe { OBJ_find_sigid_algs(OBJ_obj2nid((*alg).algorithm), &mut mdnid, &mut pknid) }
            == 0
        {
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&err_sites::A_VERIFY_135) };
            return ret;
        }

        // SAFETY: `pkey` is live per the check above.
        if mdnid == NID_undef && unsafe { evp_pkey_is_legacy(pkey) } != 0 {
            // SAFETY: `pkey` is live.
            let ameth = unsafe { (*pkey).ameth };
            let item_verify = if ameth.is_null() {
                None
            } else {
                // SAFETY: `ameth` is the key's own method table.
                unsafe { (*ameth).item_verify }
            };
            let Some(item_verify) = item_verify else {
                // SAFETY: a compile-time-constant site.
                unsafe { raise_site(&err_sites::A_VERIFY_141) };
                return ret;
            };
            // SAFETY: the callback was read from the live key and every pointer is the caller's.
            ret =
                unsafe { item_verify(ctx, it, data, alg, signature.cast::<Asn1BitString>(), pkey) };
            // Return values meaning: <=0 error; 1 method does everything; 2 carry on as normal
            // (the method has called EVP_DigestVerifyInit).
            if ret <= 0 {
                // SAFETY: a compile-time-constant site.
                unsafe { raise_site(&err_sites::A_VERIFY_152) };
            }
            if ret <= 1 {
                return ret;
            }
        } else {
            let mut type_: *const crate::evp::digest::EvpMd = ptr::null();

            // We do not yet have the ability for providers to handle X509_ALGOR style
            // parameters; RSA-PSS is special-cased.
            if mdnid == NID_undef && pknid == EVP_PKEY_RSA_PSS {
                // SAFETY: `pkey` is live; the two names are NUL-terminated literals.
                if unsafe { EVP_PKEY_is_a(pkey, c"RSA".as_ptr()) } == 0
                    // SAFETY: as above.
                    && unsafe { EVP_PKEY_is_a(pkey, c"RSA-PSS".as_ptr()) } == 0
                {
                    // SAFETY: a compile-time-constant site.
                    unsafe { raise_site(&err_sites::A_VERIFY_166) };
                    return ret;
                }
                // SAFETY: `ctx`/`alg`/`pkey` are live. This function also calls
                // `EVP_DigestVerifyInit`.
                if unsafe { ossl_rsa_pss_to_ctx(ctx, ptr::null_mut(), alg, pkey) } <= 0 {
                    // SAFETY: a compile-time-constant site.
                    unsafe { raise_site(&err_sites::A_VERIFY_171) };
                    return ret;
                }
            } else {
                // Check the public key OID matches the public key type.
                // SAFETY: `pkey` is live and the short name is the authority's.
                if unsafe { EVP_PKEY_is_a(pkey, OBJ_nid2sn(pknid)) } == 0 {
                    // SAFETY: a compile-time-constant site.
                    unsafe { raise_site(&err_sites::A_VERIFY_177) };
                    return ret;
                }

                if mdnid != NID_undef {
                    // SAFETY: `EVP_get_digestbynid` is the macro `EVP_get_digestbyname(
                    // OBJ_nid2sn(nid))`.
                    type_ = unsafe { EVP_get_digestbyname(OBJ_nid2sn(mdnid)) };
                    if type_.is_null() {
                        let mut msg = [0 as c_char; 64];
                        // SAFETY: `msg` is a live buffer and the format/argument are the
                        // authority's (`"nid=0x%x"`).
                        unsafe {
                            crate::runtime::bio::print::BIO_snprintf(
                                msg.as_mut_ptr(),
                                msg.len(),
                                c"nid=0x%x".as_ptr(),
                                mdnid,
                            )
                        };
                        // SAFETY: a compile-time-constant site; `msg` is NUL-terminated.
                        unsafe { raise_site_data(&err_sites::A_VERIFY_184, msg.as_ptr()) };
                        return ret;
                    }
                }

                // Some algorithms (notably Ed25519 and Ed448) may allow a NULL digest.
                // SAFETY: `ctx`/`pkey` are live; `type_` is NULL or live.
                if unsafe {
                    EVP_DigestVerifyInit(ctx, ptr::null_mut(), type_, ptr::null_mut(), pkey)
                } == 0
                {
                    // SAFETY: a compile-time-constant site.
                    unsafe { raise_site(&err_sites::A_VERIFY_196) };
                    ret = 0;
                    return ret;
                }
            }
        }

        // SAFETY: `data` is live; `buf_in` is this frame's out-parameter; `it` is the item.
        let inl = unsafe { ASN1_item_i2d(data, &mut buf_in, it) };
        if inl <= 0 {
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&err_sites::A_VERIFY_205) };
            return -1;
        }
        if buf_in.is_null() {
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&err_sites::A_VERIFY_210) };
            return -1;
        }
        let inll = inl as usize;

        // SAFETY: `ctx` is live; `signature` is live; `buf_in` is readable for `inl` bytes.
        ret = unsafe {
            EVP_DigestVerify(
                ctx,
                (*signature).data,
                (*signature).length as usize,
                buf_in,
                inl as usize,
            )
        };
        if ret <= 0 {
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&err_sites::A_VERIFY_219) };
            // SAFETY: `buf_in` is this frame's allocation of `inll` bytes.
            unsafe {
                CRYPTO_clear_free(buf_in.cast::<c_void>(), inll, FILE.as_ptr(), LINE_CLEAR_IN)
            };
            return ret;
        }
        ret = 1;
        // SAFETY: `buf_in` is this frame's allocation of `inll` bytes.
        unsafe { CRYPTO_clear_free(buf_in.cast::<c_void>(), inll, FILE.as_ptr(), LINE_CLEAR_IN) };
        ret
    })
}
