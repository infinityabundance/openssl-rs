//! `crypto/asn1/d2i_pr.c`'s `ossl_d2i_PrivateKey_legacy` — the type-specific private-key
//! decoder with its PKCS#8 fallback. D368.
//!
//! One internal of the unit, landed because it is the third leg of
//! `pem_read_bio_key_legacy` (`crypto/pem/pem_pkey.c:181`): a `-----BEGIN <TYPE> PRIVATE
//! KEY-----` block is read by the method's `old_priv_decode`, and a block that is really a
//! `PrivateKeyInfo` is read by `evp_pkcs82pkey_legacy` instead. The unit's six exports —
//! `d2i_PrivateKey_decoder`, `d2i_PrivateKey_ex`, `d2i_PrivateKey`, `d2i_AutoPrivateKey_legacy`,
//! `d2i_AutoPrivateKey_ex`, `d2i_AutoPrivateKey` — are Phase 7's and are **not** landed here;
//! `forensics/prerequisites.json` records the stratum that still owes them. This module is a
//! partial transcription and names what it withholds.
//!
//! ## The three-way decode, and why the mark pair is part of it
//!
//! The authority wraps the whole decode in `ERR_set_mark()`/`ERR_pop_to_mark()` so the
//! type-specific refusal is not left on the queue when the fallback succeeds; every early exit
//! calls `ERR_clear_last_mark()` instead. The order matters: the PKCS#8 decode is attempted
//! **before** `ret` is released, so a caller who passed their own key is not left holding a
//! freed pointer when the fallback fails.
//!
//! ## The ENGINE pair collapses
//!
//! The authority's `else` branch finishes `ret->engine` and clears it under
//! `#ifndef OPENSSL_NO_ENGINE`. ENGINE is Phase 13's, the crate's keys never hold one, and the
//! same collapse is recorded for `EVP_PKEY_free`'s tail — so the pair is omitted with this
//! coordinate rather than written as a call to a name that does not exist.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_char, c_int, c_long, c_uchar, c_void};
use core::ptr;

use crate::asn1::p8_pkey::{d2i_PKCS8_PRIV_KEY_INFO, PKCS8_PRIV_KEY_INFO_free, Pkcs8PrivKeyInfo};
use crate::evp::evp_pkey::evp_pkcs82pkey_legacy;
use crate::evp::pkey::{
    EVP_PKEY_free, EVP_PKEY_get_base_id, EVP_PKEY_new, EVP_PKEY_set_type, EvpPkey,
};
use crate::evp::pkey_asn1::EVP_PKEY_type;
use crate::runtime::err::{
    err_sites, raise_site, ERR_clear_last_mark, ERR_pop_to_mark, ERR_set_mark,
};

/// `EVP_PKEY *ossl_d2i_PrivateKey_legacy(int keytype, EVP_PKEY **a, const unsigned char **pp,
/// long length, OSSL_LIB_CTX *libctx, const char *propq)` — `crypto/asn1/d2i_pr.c:101-164`.
///
/// # Safety
/// `a` must be NULL or point at a writable `EVP_PKEY *` slot; `pp` must point at a readable
/// cursor for `length` bytes; `libctx`/`propq` are the fallback's decode context.
#[no_mangle]
pub unsafe extern "C" fn ossl_d2i_PrivateKey_legacy(
    keytype: c_int,
    a: *mut *mut EvpPkey,
    pp: *mut *const c_uchar,
    length: c_long,
    libctx: *mut c_void,
    propq: *const c_char,
) -> *mut EvpPkey {
    // SAFETY: `pp` is the caller's readable cursor.
    let mut p: *const c_uchar = unsafe { *pp };
    // SAFETY: `a` is NULL or a live slot; the dereference is guarded by the short-circuit.
    let hold = !a.is_null() && !unsafe { *a }.is_null();

    let ret: *mut EvpPkey = if !hold {
        // SAFETY: no preconditions.
        let fresh = unsafe { EVP_PKEY_new() };
        if fresh.is_null() {
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&err_sites::D2I_PR_110) };
            return ptr::null_mut();
        }
        fresh
    } else {
        // SAFETY: `hold` is true, so `*a` is a live key.
        let existing = unsafe { *a };
        /* The authority finishes `existing->engine` and clears it under `!OPENSSL_NO_ENGINE`;
         * ENGINE is Phase 13's and the crate's keys never hold one, so the pair collapses. */
        existing
    };

    // SAFETY: `ret` is live.
    if unsafe { EVP_PKEY_set_type(ret, keytype) } == 0 {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::D2I_PR_122) };
        // SAFETY: `ret`, `a` are the caller's and this call's own.
        return unsafe { err_out(ret, a) };
    }

    ERR_set_mark();
    // SAFETY: `ret` is live and `EVP_PKEY_set_type` above succeeded, so its `ameth` is set.
    let ameth = unsafe { (*ret).ameth };
    // SAFETY: `ameth` is the key's own method table.
    let (old_priv_decode, priv_decode, priv_decode_ex) = unsafe {
        (
            (*ameth).old_priv_decode,
            (*ameth).priv_decode,
            (*ameth).priv_decode_ex,
        )
    };

    let decoded = match old_priv_decode {
        // SAFETY: the callback was read from the live key; `p` is this frame's cursor.
        Some(dec) => (unsafe { dec(ret, &raw mut p, length as c_int) }) != 0,
        None => false,
    };

    if decoded {
        ERR_clear_last_mark();
    } else if priv_decode.is_some() || priv_decode_ex.is_some() {
        // SAFETY: `p` is this frame's cursor and `length` describes the input.
        let p8: *mut Pkcs8PrivKeyInfo =
            unsafe { d2i_PKCS8_PRIV_KEY_INFO(ptr::null_mut(), &raw mut p, length) };
        if p8.is_null() {
            ERR_clear_last_mark();
            // SAFETY: `ret`, `a` are the caller's and this call's own.
            return unsafe { err_out(ret, a) };
        }
        // SAFETY: `p8` is live; the context arguments are the caller's.
        let tmp = unsafe { evp_pkcs82pkey_legacy(p8, libctx, propq) };
        // SAFETY: `p8` is this call's own.
        unsafe { PKCS8_PRIV_KEY_INFO_free(p8) };
        if tmp.is_null() {
            ERR_clear_last_mark();
            // SAFETY: `ret`, `a` are the caller's and this call's own.
            return unsafe { err_out(ret, a) };
        }
        // SAFETY: `ret` is live and this call owns it.
        unsafe { EVP_PKEY_free(ret) };
        let ret = tmp;
        ERR_pop_to_mark();
        // SAFETY: `keytype` is an integer and `ret` is live.
        if unsafe { EVP_PKEY_type(keytype) } != unsafe { EVP_PKEY_get_base_id(ret) } {
            // SAFETY: `ret` is this call's own; `a` must not be written.
            return unsafe { err_out(ret, a) };
        }
        // SAFETY: `pp` is the caller's writable cursor.
        unsafe { *pp = p };
        if !a.is_null() {
            // SAFETY: `a` is a live slot.
            unsafe { *a = ret };
        }
        return ret;
    } else {
        ERR_clear_last_mark();
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::D2I_PR_150) };
        // SAFETY: `ret`, `a` are the caller's and this call's own.
        return unsafe { err_out(ret, a) };
    }

    // SAFETY: `pp` is the caller's writable cursor.
    unsafe { *pp = p };
    if !a.is_null() {
        // SAFETY: `a` is a live slot.
        unsafe { *a = ret };
    }
    ret
}

/// The authority's `err:` label — `d2i_pr.c:160-163` — as one function.
///
/// `*a` is written only after the decode succeeds, so a caller who passed the key this call was
/// given does **not** have it freed under them: the test is pointer identity, not NULL.
///
/// # Safety
/// `ret` must be NULL or live; `a` must be NULL or a live `EVP_PKEY *` slot.
unsafe fn err_out(ret: *mut EvpPkey, a: *mut *mut EvpPkey) -> *mut EvpPkey {
    // SAFETY: `a` is NULL or live and `ret` is NULL or live.
    if a.is_null() || unsafe { *a } != ret {
        // SAFETY: `ret` is NULL or live.
        unsafe { EVP_PKEY_free(ret) };
    }
    ptr::null_mut()
}
