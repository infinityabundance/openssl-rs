//! Phase 10.10 — `crypto/asn1/a_digest.c`: "digest an ASN.1 value", in the two spellings the
//! unit publishes.
//!
//! This is the unit `X509_digest` reaches first: `crypto/x509/x_all.c:498` is one call to
//! `ossl_asn1_item_digest_ex` (`crypto/asn1/a_digest.c:54`), and the engine functional
//! reference that call asks for — `ENGINE_get_digest_engine(EVP_MD_get_type(md))` (`:68`) —
//! is what subphase 10.9 (D452) landed. Nothing else on the path was waiting: `ASN1_item_i2d`,
//! `EVP_MD_get0_provider`, `EVP_MD_fetch`, `EVP_MD_free` and `EVP_Digest` are all landed, so
//! **the unit is transcribed whole and nothing is withheld.**
//!
//! ## The engine arm is landed, not skipped
//!
//! `md`'s provider is what decides the arm. A method a caller fetched from a provider has one,
//! and `ossl_asn1_item_digest_ex` digests through it directly. A method with **no** provider --
//! the legacy `EVP_sha256()` statics are the ones a caller actually passes -- takes the
//! `#if !defined(OPENSSL_NO_ENGINE)` arm: `ENGINE_get_digest_engine` is asked whether a
//! functional reference is reserved for this nid, and if one is, it is **released immediately**
//! (`ENGINE_finish`) because the authority only wants the side effect of the lookup; otherwise
//! the method is fetched from `libctx` by name. The profile has `OPENSSL_NO_ENGINE` undefined
//! and 10.9 landed the registry, so the arm is reachable and is transcribed rather than
//! elided — a candidate that fetched a digest where the authority consulted the engine table
//! would diverge on every call with an engine registered.
//!
//! ## What a caller can observe
//!
//! The digest bytes, and the allocation/free balance. `ASN1_digest` encodes through the
//! caller's `i2d` callback into a buffer it owns; `ossl_asn1_item_digest_ex` encodes through
//! `ASN1_item_i2d` and **frees the buffer on every path**, including the two early returns
//! after the encode, which is why a failed fetch (`fetched_md == NULL`) still frees `str`.
//!
//! ## The raise sites
//!
//! `ASN1_digest`'s `i2d`-failed arm raises `ERR_LIB_ASN1`/`ERR_R_INTERNAL_ERROR`
//! (`:36`). `ossl_asn1_item_digest_ex` raises nothing of its own — the fetch it may perform
//! records its own error — so this unit contributes one coordinate, `A_DIGEST_36`, generated
//! by `gen_err_raise_sites.py` once `crypto/asn1/a_digest.c` joined its covered set.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_char, c_int, c_uchar, c_uint, c_void, CStr};
use core::ptr;

use crate::asn1::i2d::ASN1_item_i2d;
use crate::asn1::layout::{Asn1Item, I2dOfVoid};
use crate::engine::eng_init::ENGINE_finish;
use crate::engine::tb_digest::ENGINE_get_digest_engine;
use crate::evp::digest::{
    EVP_Digest, EVP_MD_fetch, EVP_MD_free, EVP_MD_get0_name, EVP_MD_get0_provider, EVP_MD_get_type,
    EvpMd,
};
use crate::ffi::guard_ffi;
use crate::runtime::err::err_sites;
use crate::runtime::err::raise_site;
use crate::runtime::mem::{CRYPTO_free, CRYPTO_malloc};

/// The authority translation unit for this file's `OPENSSL_malloc`/`OPENSSL_free` expansions.
const FILE: &CStr = c"crypto/asn1/a_digest.c";
/// `ASN1_digest`'s `OPENSSL_malloc(inl)` (`:39`).
const LINE_MALLOC: c_int = 39;
/// `ASN1_digest`'s failure-path `OPENSSL_free(str)` (`:45`).
const LINE_FREE_FAIL: c_int = 45;
/// `ASN1_digest`'s success-path `OPENSSL_free(str)` (`:48`).
const LINE_FREE_OK: c_int = 48;
/// `ossl_asn1_item_digest_ex`'s single `OPENSSL_free(str)` (`:81`).
const LINE_FREE_ITEM: c_int = 81;

/// `int ASN1_digest(i2d_of_void *i2d, const EVP_MD *type, char *data, unsigned char *md,
/// unsigned int *len)` — `crypto/asn1/a_digest.c:28-50`.
///
/// The legacy spelling: the caller supplies both the value and its encoder, and the digest is
/// computed over the DER the encoder produces rather than over the in-memory structure. A
/// value whose `i2d` reports a non-positive length raises `A_DIGEST_36` and answers 0 without
/// calling the digest at all.
///
/// # Safety
///
/// `i2d` must be a live encoder matching `data`; `type` a live method; `data` a live value;
/// `md` writable for the digest size and `len` writable.
#[no_mangle]
pub unsafe extern "C" fn ASN1_digest(
    i2d: I2dOfVoid,
    type_: *const EvpMd,
    data: *mut c_char,
    md: *mut c_uchar,
    len: *mut c_uint,
) -> c_int {
    guard_ffi(0, || {
        // SAFETY: `i2d` is the caller's live encoder; a null destination is the sizing
        // convention it shares with `ASN1_item_i2d`.
        let inl = unsafe { i2d(data.cast::<c_void>(), ptr::null_mut()) };
        if inl <= 0 {
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&err_sites::A_DIGEST_36) };
            return 0;
        }
        // SAFETY: the allocator's contract; `FILE`/`LINE_MALLOC` are the authority's coordinate.
        let str_ = CRYPTO_malloc(inl as usize, FILE.as_ptr(), LINE_MALLOC).cast::<c_uchar>();
        if str_.is_null() {
            return 0;
        }
        let mut p = str_;
        // SAFETY: `p` has room for the length the sizing pass reported.
        unsafe { i2d(data.cast::<c_void>(), &mut p) };

        // SAFETY: `str_` holds `inl` encoded bytes and the remaining arguments are the caller's.
        let ok = unsafe {
            EVP_Digest(
                str_.cast::<c_void>(),
                inl as usize,
                md,
                len,
                type_,
                ptr::null_mut(),
            )
        };
        if ok == 0 {
            // SAFETY: `str_` came from this allocator and is not owned elsewhere.
            unsafe { CRYPTO_free(str_.cast::<c_void>(), FILE.as_ptr(), LINE_FREE_FAIL) };
            return 0;
        }
        // SAFETY: `str_` came from this allocator and is not owned elsewhere.
        unsafe { CRYPTO_free(str_.cast::<c_void>(), FILE.as_ptr(), LINE_FREE_OK) };
        1
    })
}

/// `int ossl_asn1_item_digest_ex(const ASN1_ITEM *it, const EVP_MD *md, void *asn,
/// unsigned char *data, unsigned int *len, OSSL_LIB_CTX *libctx, const char *propq)` —
/// `crypto/asn1/a_digest.c:54-85`.
///
/// The item-driven spelling, and the one `X509_digest` calls. The value is encoded with
/// [`ASN1_item_i2d`] and the digest is taken over that DER.
///
/// Two release paths matter and both are reproduced: the encode's buffer is freed on **every**
/// path, including the early return when the fetch left `fetched_md` NULL, and a method this
/// call fetched itself is released after the digest while the caller's own method is not
/// (`fetched_md != md`).
///
/// # Safety
///
/// `it` must be a live item; `asn` a live value of its type; `md` a live method; `data`
/// writable for the digest size and `len` writable; `libctx` and `propq` NULL or the
/// fetch's own arguments.
pub(crate) unsafe fn ossl_asn1_item_digest_ex(
    it: *const Asn1Item,
    md: *const EvpMd,
    asn: *mut c_void,
    data: *mut c_uchar,
    len: *mut c_uint,
    libctx: *mut c_void,
    propq: *const c_char,
) -> c_int {
    let mut str_: *mut c_uchar = ptr::null_mut();
    let mut fetched_md: *mut EvpMd = md.cast_mut();

    // SAFETY: `asn` is a live value of `it`'s type and `str_` is a null slot, which asks for
    // an allocation.
    let i = unsafe { ASN1_item_i2d(asn.cast::<c_void>(), &mut str_, it) };
    if i < 0 || str_.is_null() {
        return 0;
    }

    // SAFETY: `md` is live per the contract; a provider-less legacy method is the arm below.
    if unsafe { EVP_MD_get0_provider(md) }.is_null() {
        // SAFETY: `md` is live; `EVP_MD_get_type` reads its nid. The reference, if any, is
        // released at once -- the authority only wants the table side effect.
        let tmpeng = ENGINE_get_digest_engine(unsafe { EVP_MD_get_type(md) });
        if !tmpeng.is_null() {
            // SAFETY: `tmpeng` is a live functional reference this call owns.
            unsafe { ENGINE_finish(tmpeng) };
        } else {
            // SAFETY: `md` is live; `name`/`propq`/`libctx` are the caller's.
            fetched_md = unsafe { EVP_MD_fetch(libctx, EVP_MD_get0_name(md), propq) };
        }
    }

    let ret = if fetched_md.is_null() {
        0
    } else {
        // SAFETY: `str_` holds `i` encoded bytes, `fetched_md` is live, and the output
        // arguments are the caller's.
        unsafe {
            EVP_Digest(
                str_.cast::<c_void>(),
                i as usize,
                data,
                len,
                fetched_md,
                ptr::null_mut(),
            )
        }
    };

    // SAFETY: `str_` came from `ASN1_item_i2d`'s allocation and is not owned elsewhere.
    unsafe { CRYPTO_free(str_.cast::<c_void>(), FILE.as_ptr(), LINE_FREE_ITEM) };
    if fetched_md.cast_const() != md {
        // SAFETY: `fetched_md` is this call's own reference, distinct from the caller's `md`.
        unsafe { EVP_MD_free(fetched_md) };
    }
    ret
}

/// `int ASN1_item_digest(const ASN1_ITEM *it, const EVP_MD *md, void *asn, unsigned char *data,
/// unsigned int *len)` — `crypto/asn1/a_digest.c:87-91`.
///
/// The `_ex`-less spelling: the default library context and no property query.
///
/// # Safety
///
/// The same contract as [`ossl_asn1_item_digest_ex`] with a NULL `libctx`/`propq`.
#[no_mangle]
pub unsafe extern "C" fn ASN1_item_digest(
    it: *const Asn1Item,
    md: *const EvpMd,
    asn: *mut c_void,
    data: *mut c_uchar,
    len: *mut c_uint,
) -> c_int {
    // SAFETY: forwarded under this function's contract, with the NULL context and property
    // query the authority passes.
    unsafe { ossl_asn1_item_digest_ex(it, md, asn, data, len, ptr::null_mut(), ptr::null()) }
}
