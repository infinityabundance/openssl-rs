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

use crate::asn1::a_type::ASN1_TYPE_free;
use crate::asn1::p8_pkey::{
    d2i_PKCS8_PRIV_KEY_INFO, PKCS8_PRIV_KEY_INFO_free, PKCS8_pkey_get0, Pkcs8PrivKeyInfo,
};
use crate::asn1::prim::ASN1_INTEGER_get_int64;
use crate::asn1::typ::d2i_ASN1_SEQUENCE_ANY;
use crate::decoder_lib::OSSL_DECODER_from_data;
use crate::decoder_meth::OSSL_DECODER_CTX_free;
use crate::decoder_pkey::OSSL_DECODER_CTX_new_for_pkey;
use crate::evp::evp_pkey::evp_pkcs82pkey_legacy;
use crate::evp::keymgmt_lib::evp_keymgmt_util_has;
use crate::evp::pkey::{
    evp_pkey_type2name, EVP_PKEY_free, EVP_PKEY_get_base_id, EVP_PKEY_new, EVP_PKEY_set_type,
    EvpPkey,
};
use crate::evp::pkey_asn1::EVP_PKEY_type;
use crate::runtime::err::{
    err_sites, raise_site, ERR_clear_last_mark, ERR_pop_to_mark, ERR_set_mark,
};
use crate::runtime::obj::{Asn1Object, OBJ_obj2txt};
use crate::runtime::stack::{OPENSSL_sk_num, OPENSSL_sk_pop_free, OpenSslStack};

/// `OSSL_KEYMGMT_SELECT_PRIVATE_KEY` — `include/openssl/core_dispatch.h:640`.
const OSSL_KEYMGMT_SELECT_PRIVATE_KEY: c_int = 0x01;
/// `EVP_PKEY_KEYPAIR` — `include/openssl/evp.h:112`, the selection the decoder is built with.
const EVP_PKEY_KEYPAIR: c_int = 0x87;
/// `EVP_PKEY_NONE` — `include/openssl/evp.h`, `NID_undef`.
const EVP_PKEY_NONE: c_int = crate::evp::pkey::EVP_PKEY_NONE;
/// `EVP_PKEY_DSA`/`EVP_PKEY_EC`/`EVP_PKEY_RSA` — the three ids `d2i_AutoPrivateKey_legacy`
/// discriminates by the ASN.1 element count.
const EVP_PKEY_DSA: c_int = 116;
const EVP_PKEY_EC: c_int = 408;
const EVP_PKEY_RSA: c_int = 6;
/// `OSSL_MAX_NAME_SIZE` — `include/internal/sizes.h`.
const OSSL_MAX_NAME_SIZE: usize = 50;

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

/// `static EVP_PKEY *d2i_PrivateKey_decoder(int keytype, EVP_PKEY **a, const unsigned char **pp,
/// long length, OSSL_LIB_CTX *libctx, const char *propq)` — `crypto/asn1/d2i_pr.c:28-99`.
///
/// The **provider** arm the four exports try first. It probes the input as a `PrivateKeyInfo`
/// (ignoring the probe's errors) to choose the decoder's `structure`, derives a key-type name
/// either from `keytype` or from the PKCS#8 algorithm OID, and runs the `OSSL_DECODER` framework.
/// `pp` is deliberately reset to the input start before the decode, and `*a` is restored to the
/// caller's key after the context is built so the framework's construct does not free it.
///
/// # Safety
/// `a` NULL or a live `EVP_PKEY *` slot; `pp` a readable cursor for `length` bytes; the two
/// context strings NULL or NUL-terminated.
unsafe fn d2i_private_key_decoder(
    keytype: c_int,
    a: *mut *mut EvpPkey,
    pp: *mut *const c_uchar,
    length: c_long,
    libctx: *mut c_void,
    propq: *const c_char,
) -> *mut EvpPkey {
    let mut len: usize = length as usize;
    let mut pkey: *mut EvpPkey = ptr::null_mut();
    let mut bak_a: *mut EvpPkey = ptr::null_mut();
    let mut ppkey: *mut *mut EvpPkey = &mut pkey;
    let mut keytypebuf = [0 as c_char; OSSL_MAX_NAME_SIZE];
    // SAFETY: `pp` is the caller's readable cursor.
    let p: *const c_uchar = unsafe { *pp };

    let mut key_name: *const c_char = ptr::null();
    if keytype != EVP_PKEY_NONE {
        key_name = evp_pkey_type2name(keytype);
        if key_name.is_null() {
            return ptr::null_mut();
        }
    }

    /* This is just a probe. It might fail, so we ignore errors. */
    ERR_set_mark();
    // SAFETY: `pp` is the caller's readable cursor and `length` describes it.
    let p8info = unsafe { d2i_PKCS8_PRIV_KEY_INFO(ptr::null_mut(), pp, length) };
    ERR_pop_to_mark();

    let structure: *const c_char;
    if !p8info.is_null() {
        let mut v: i64 = 0;
        // SAFETY: `p8info` is live and `v` is this frame's out-parameter.
        let got = unsafe { ASN1_INTEGER_get_int64(&raw mut v, (*p8info).version) };
        if got == 0 || (v != 0 && v != 1) {
            // SAFETY: `pp` is the caller's writable cursor.
            unsafe { *pp = p };
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&err_sites::D2I_PR_61) };
            // SAFETY: `p8info` is this call's own.
            unsafe { PKCS8_PRIV_KEY_INFO_free(p8info) };
            return ptr::null_mut();
        }
        let mut algoid: *const Asn1Object = ptr::null();
        // SAFETY: `p8info` is live; `algoid` is this frame's out-parameter.
        if key_name.is_null()
            // SAFETY: `p8info` is live; `algoid` is this frame's out-parameter.
            && unsafe {
                PKCS8_pkey_get0(
                    &raw mut algoid,
                    ptr::null_mut(),
                    ptr::null_mut(),
                    ptr::null_mut(),
                    p8info,
                )
            } != 0
            // SAFETY: `algoid` is live and `keytypebuf` is a live buffer of the size passed.
            && unsafe {
                OBJ_obj2txt(
                    keytypebuf.as_mut_ptr(),
                    OSSL_MAX_NAME_SIZE as c_int,
                    algoid,
                    0,
                )
            } != 0
        {
            key_name = keytypebuf.as_ptr();
        }
        structure = c"PrivateKeyInfo".as_ptr();
        // SAFETY: `p8info` is this call's own.
        unsafe { PKCS8_PRIV_KEY_INFO_free(p8info) };
    } else {
        structure = c"type-specific".as_ptr();
    }
    // SAFETY: `pp` is the caller's writable cursor.
    unsafe { *pp = p };

    // SAFETY: `a` is NULL or a live slot per the contract.
    if !a.is_null() && !unsafe { *a }.is_null() {
        // SAFETY: `a` is a live slot.
        bak_a = unsafe { *a };
        ppkey = a;
    }
    // SAFETY: `ppkey` is a live slot; the two strings are live per the contract.
    let dctx = unsafe {
        OSSL_DECODER_CTX_new_for_pkey(
            ppkey,
            c"DER".as_ptr(),
            structure,
            key_name,
            EVP_PKEY_KEYPAIR,
            libctx,
            propq,
        )
    };
    if !a.is_null() {
        // SAFETY: `a` is a live slot.
        unsafe { *a = bak_a };
    }
    if dctx.is_null() {
        // SAFETY: `ppkey`/`a` are the caller's and this call's own.
        return unsafe { decoder_err_out(ppkey, a) };
    }

    // SAFETY: `dctx` is live; `pp`/`len` are this frame's.
    let ret = unsafe { OSSL_DECODER_from_data(dctx, pp, &raw mut len) };
    // SAFETY: `dctx` is this frame's.
    unsafe { OSSL_DECODER_CTX_free(dctx) };
    if ret != 0
        // SAFETY: `ppkey` is a live slot.
        && !unsafe { *ppkey }.is_null()
        // SAFETY: `*ppkey` is live.
        && unsafe { evp_keymgmt_util_has(*ppkey, OSSL_KEYMGMT_SELECT_PRIVATE_KEY) } != 0
    {
        if !a.is_null() {
            // SAFETY: `a` is a live slot.
            unsafe { *a = *ppkey };
        }
        // SAFETY: `ppkey` is a live slot.
        return unsafe { *ppkey };
    }

    // SAFETY: `ppkey`/`a` are the caller's and this call's own.
    unsafe { decoder_err_out(ppkey, a) }
}

/// The authority's `err:` label of `d2i_PrivateKey_decoder` (`:95-98`) — releases the key only
/// when it is not the caller's own slot.
///
/// # Safety
/// `ppkey` must be a live slot; `a` NULL or the caller's slot.
unsafe fn decoder_err_out(ppkey: *mut *mut EvpPkey, a: *mut *mut EvpPkey) -> *mut EvpPkey {
    if ppkey != a {
        // SAFETY: `ppkey` is a live slot and its key is this call's own.
        unsafe { EVP_PKEY_free(*ppkey) };
    }
    ptr::null_mut()
}

/// `ASN1_TYPE_free` under the stack destructor's `void (*)(void *)` spelling — the authority
/// passes it to `sk_ASN1_TYPE_pop_free` directly, where the compiler casts it.
///
/// # Safety
/// `x` must be a live `ASN1_TYPE` or NULL.
unsafe extern "C" fn asn1_type_free_void(x: *mut c_void) {
    // SAFETY: the caller's contract, restated in the typed destructor's terms.
    unsafe { ASN1_TYPE_free(x.cast::<crate::asn1::layout::Asn1Type>()) }
}

/// `EVP_PKEY *d2i_PrivateKey_ex(int keytype, EVP_PKEY **a, const unsigned char **pp, long length,
/// OSSL_LIB_CTX *libctx, const char *propq)` — `d2i_pr.c:166-177`.
///
/// The provider decoder first, the legacy method as the fallback.
///
/// # Safety
/// As [`d2i_private_key_decoder`].
#[no_mangle]
pub unsafe extern "C" fn d2i_PrivateKey_ex(
    keytype: c_int,
    a: *mut *mut EvpPkey,
    pp: *mut *const c_uchar,
    length: c_long,
    libctx: *mut c_void,
    propq: *const c_char,
) -> *mut EvpPkey {
    // SAFETY: `a`/`pp` are the caller's and the context strings theirs.
    let mut ret = unsafe { d2i_private_key_decoder(keytype, a, pp, length, libctx, propq) };
    if ret.is_null() {
        // SAFETY: `a`/`pp` are the caller's and the context strings theirs.
        ret = unsafe { ossl_d2i_PrivateKey_legacy(keytype, a, pp, length, libctx, propq) };
    }
    ret
}

/// `EVP_PKEY *d2i_PrivateKey(int type, EVP_PKEY **a, const unsigned char **pp, long length)` —
/// `d2i_pr.c:179-183`.
///
/// # Safety
/// As [`d2i_private_key_decoder`], with a NULL context.
#[no_mangle]
pub unsafe extern "C" fn d2i_PrivateKey(
    type_: c_int,
    a: *mut *mut EvpPkey,
    pp: *mut *const c_uchar,
    length: c_long,
) -> *mut EvpPkey {
    // SAFETY: `a`/`pp` are the caller's; the context is NULL.
    unsafe { d2i_PrivateKey_ex(type_, a, pp, length, ptr::null_mut(), ptr::null()) }
}

/// `static EVP_PKEY *d2i_AutoPrivateKey_legacy(EVP_PKEY **a, const unsigned char **pp,
/// long length, OSSL_LIB_CTX *libctx, const char *propq)` — `d2i_pr.c:185-235`.
///
/// The element-count discrimination: six elements is a DSA key, four an EC key, three a
/// `PrivateKeyInfo`, anything else RSA. The `inkey` stack is released before the recursive call in
/// every arm.
///
/// # Safety
/// `a` NULL or a live slot; `pp` a readable cursor for `length` bytes.
unsafe fn d2i_auto_private_key_legacy(
    a: *mut *mut EvpPkey,
    pp: *mut *const c_uchar,
    length: c_long,
    libctx: *mut c_void,
    propq: *const c_char,
) -> *mut EvpPkey {
    // SAFETY: `pp` is the caller's readable cursor.
    let mut p: *const c_uchar = unsafe { *pp };
    // SAFETY: `p` is a readable cursor and `length` describes it; the out-slot starts NULL.
    let inkey: *mut OpenSslStack =
        unsafe { d2i_ASN1_SEQUENCE_ANY(ptr::null_mut(), &raw mut p, length) };
    // SAFETY: `pp` is the caller's readable cursor.
    p = unsafe { *pp };

    // SAFETY: `inkey` is NULL or a live stack; `OPENSSL_sk_num` answers -1 for NULL.
    let num = unsafe { OPENSSL_sk_num(inkey) };
    let mut keytype = EVP_PKEY_RSA;
    if num == 6 {
        keytype = EVP_PKEY_DSA;
    } else if num == 4 {
        keytype = EVP_PKEY_EC;
    } else if num == 3 {
        // SAFETY: `p` is a readable cursor and `length` describes it.
        let p8 = unsafe { d2i_PKCS8_PRIV_KEY_INFO(ptr::null_mut(), &raw mut p, length) };
        // SAFETY: `inkey` is live and `asn1_type_free_void` is the element destructor.
        unsafe { OPENSSL_sk_pop_free(inkey, Some(asn1_type_free_void)) };
        if p8.is_null() {
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&err_sites::D2I_PR_218) };
            return ptr::null_mut();
        }
        // SAFETY: `p8` is live and the context strings are the caller's.
        let ret = unsafe { evp_pkcs82pkey_legacy(p8, libctx, propq) };
        // SAFETY: `p8` is this call's own.
        unsafe { PKCS8_PRIV_KEY_INFO_free(p8) };
        if ret.is_null() {
            return ptr::null_mut();
        }
        // SAFETY: `pp` is the caller's writable cursor.
        unsafe { *pp = p };
        if !a.is_null() {
            // SAFETY: `a` is a live slot.
            unsafe { *a = ret };
        }
        return ret;
    }
    // SAFETY: `inkey` is live and `asn1_type_free_void` is the element destructor.
    unsafe { OPENSSL_sk_pop_free(inkey, Some(asn1_type_free_void)) };
    // SAFETY: `a`/`pp` are the caller's and the context strings theirs.
    unsafe { ossl_d2i_PrivateKey_legacy(keytype, a, pp, length, libctx, propq) }
}

/// `EVP_PKEY *d2i_AutoPrivateKey_ex(EVP_PKEY **a, const unsigned char **pp, long length,
/// OSSL_LIB_CTX *libctx, const char *propq)` — `d2i_pr.c:241-252`.
///
/// # Safety
/// `a` NULL or a live slot; `pp` a readable cursor for `length` bytes.
#[no_mangle]
pub unsafe extern "C" fn d2i_AutoPrivateKey_ex(
    a: *mut *mut EvpPkey,
    pp: *mut *const c_uchar,
    length: c_long,
    libctx: *mut c_void,
    propq: *const c_char,
) -> *mut EvpPkey {
    // SAFETY: the provider decoder's contract, with `EVP_PKEY_NONE`.
    let mut ret = unsafe { d2i_private_key_decoder(EVP_PKEY_NONE, a, pp, length, libctx, propq) };
    if ret.is_null() {
        // SAFETY: `a`/`pp` are the caller's and the context strings theirs.
        ret = unsafe { d2i_auto_private_key_legacy(a, pp, length, libctx, propq) };
    }
    ret
}

/// `EVP_PKEY *d2i_AutoPrivateKey(EVP_PKEY **a, const unsigned char **pp, long length)` —
/// `d2i_pr.c:254-258`.
///
/// # Safety
/// `a` NULL or a live slot; `pp` a readable cursor for `length` bytes.
#[no_mangle]
pub unsafe extern "C" fn d2i_AutoPrivateKey(
    a: *mut *mut EvpPkey,
    pp: *mut *const c_uchar,
    length: c_long,
) -> *mut EvpPkey {
    // SAFETY: `a`/`pp` are the caller's; the context is NULL.
    unsafe { d2i_AutoPrivateKey_ex(a, pp, length, ptr::null_mut(), ptr::null()) }
}
