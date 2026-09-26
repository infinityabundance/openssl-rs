//! `crypto/asn1/i2d_evp.c`'s five writers — the `i2d_*` half of the key-format hand-offs Phase 7
//! passed forward. Phase 10.6.
//!
//! The unit's identity is the bytes: `i2d_KeyParams`, `i2d_PrivateKey`, `i2d_PKCS8PrivateKey` and
//! `i2d_PublicKey` return the DER of a fixed key, and `i2d_KeyParams_bio` writes that DER. What
//! makes them interesting is the **two ways to produce it**:
//!
//!   * a **provided** key is encoded through the `OSSL_ENCODER` framework — `i2d_provided` opens an
//!     `OSSL_ENCODER_CTX` for the key and the requested output type/structure and calls
//!     `OSSL_ENCODER_to_data`, walking a small `{type, structure}` chain until one answers;
//!   * a **legacy** key is encoded by its own `EVP_PKEY_ASN1_METHOD` — `ameth->param_encode`,
//!     `ameth->old_priv_encode`, or `EVP_PKEY2PKCS8`'s `ameth->priv_encode` — or, for the public
//!     key, by `i2d_RSAPublicKey`/`i2d_DSAPublicKey`/`i2o_ECPublicKey` in a `switch` over the base
//!     id.
//!
//! `RT-KEYFORMAT` drives both arms. The provided arm's fixed keys are what a provider `EVP_PKEY`
//! reaches; the legacy arm's are built with `EVP_PKEY_set1_*`, which leaves `keymgmt` NULL so the
//! `switch` runs. This module transcribes the whole unit; a key whose arm needs an encoder row
//! `encode_key2any.c` has not published yet is named in the court's pending set rather than counted
//! as passing (`docs/PHASE-10-SUBPHASES.md` §3.5).
//!
//! ## Phase 11 owns three of the names it calls, and they are not defined here
//!
//! `EVP_PKEY2PKCS8` and `i2d_PKCS8_PRIV_KEY_INFO` sit in the authority unit but are declared in
//! `x509.h`, whose 548 exports `forensics/atlas/symbol-ownership.json` gives to Phase 11. The
//! first is transcribed **internally** (`ossl_evp_pkey2pkcs8`, `src/evp/evp_pkey.rs`) because the
//! legacy arm cannot be written without it; the second is already landed as a Phase 11 export and
//! is called by its own name. This is the `D-DECODER-ABSENT` class of boundary, recorded rather
//! than left for a reader to discover.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_char, c_int, c_uchar, c_void};
use core::ptr;

use crate::asn1::a_i2d_fp::ASN1_i2d_bio;
use crate::asn1::layout::I2dOfVoid;
use crate::asn1::p8_pkey::{i2d_PKCS8_PRIV_KEY_INFO, PKCS8_PRIV_KEY_INFO_free};
use crate::ec::asn1::i2o_ECPublicKey;
use crate::encoder_lib::OSSL_ENCODER_to_data;
use crate::encoder_meth::OSSL_ENCODER_CTX_free;
use crate::encoder_pkey::OSSL_ENCODER_CTX_new_for_pkey;
use crate::evp::evp_pkey::ossl_evp_pkey2pkcs8;
use crate::evp::p_legacy_assign::{EVP_PKEY_get0_EC_KEY, EVP_PKEY_get0_RSA};
use crate::evp::pkey::{evp_pkey_is_provided, EVP_PKEY_get0_DSA, EVP_PKEY_get_base_id, EvpPkey};
use crate::rsa::asn1::i2d_RSAPublicKey;
use crate::runtime::bio::Bio;
use crate::runtime::err::{err_sites, raise_site};

/// `EVP_PKEY_KEY_PARAMETERS` — `include/openssl/evp.h:106`. Same three-with-one spelling
/// `src/provider/encode_key2blob.rs` carries: `pkey.rs` keeps its copy module-private.
const EVP_PKEY_KEY_PARAMETERS: c_int = 0x04 | 0x80;
/// `EVP_PKEY_PUBLIC_KEY` — `:110`.
const EVP_PKEY_PUBLIC_KEY: c_int = EVP_PKEY_KEY_PARAMETERS | 0x02;
/// `EVP_PKEY_KEYPAIR` — `:112`.
const EVP_PKEY_KEYPAIR: c_int = EVP_PKEY_PUBLIC_KEY | 0x01;

/// One `{output_type, output_structure}` pair; the chain is terminated by a NULL `output_type`, as
/// the authority's `struct type_and_structure_st[]` is.
type TypeAndStructure = (*const c_char, *const c_char);

/// `EVP_PKEY_RSA`/`EVP_PKEY_DSA`/`EVP_PKEY_EC` — the three base ids `i2d_PublicKey`'s `switch`
/// names. Spelled here because only the ids are needed and `pkey.rs` does not export them.
const EVP_PKEY_RSA: c_int = 6;
const EVP_PKEY_DSA: c_int = 116;
const EVP_PKEY_EC: c_int = 408;

/// `static int i2d_provided(const EVP_PKEY *a, int selection,
/// const struct type_and_structure_st *output_info, unsigned char **pp)` — `i2d_evp.c:33-71`.
///
/// The chain walk: `ret` starts at -1 and each entry is tried while it stays there. A `NULL` `pp`
/// (or a `NULL` `*pp`) is a sizing pass, answered by the number of bytes written; a caller-provided
/// buffer is answered by `INT_MAX - bytes_left`, which is what `OSSL_ENCODER_to_data`'s decrement
/// leaves behind.
///
/// # Safety
/// `a` must be a live `EVP_PKEY`; `pp` NULL or pointing at a writable cursor; `output_info` a
/// NULL-terminated chain of the pair type.
unsafe fn i2d_provided(
    a: *const EvpPkey,
    selection: c_int,
    output_info: *const TypeAndStructure,
    pp: *mut *mut c_uchar,
) -> c_int {
    let mut ret: c_int = -1;
    let mut info = output_info;

    // SAFETY: `info` walks a NULL-terminated array of the pair type.
    while ret == -1 && !unsafe { (*info).0 }.is_null() {
        let mut len: usize = c_int::MAX as usize;
        // SAFETY: `pp` is NULL or points at a readable pointer per the contract.
        let pp_was_null = pp.is_null() || unsafe { (*pp).is_null() };

        // SAFETY: `a` is live; the two strings are this frame's chain entries.
        let ctx = unsafe {
            OSSL_ENCODER_CTX_new_for_pkey(a, selection, (*info).0, (*info).1, ptr::null())
        };
        if ctx.is_null() {
            return -1;
        }
        // SAFETY: `ctx` is live and `pp`/`len` are this frame's.
        if unsafe { OSSL_ENCODER_to_data(ctx, pp, &raw mut len) } != 0 {
            if pp_was_null {
                ret = len as c_int;
            } else {
                ret = c_int::MAX - (len as c_int);
            }
        }
        // SAFETY: `ctx` is live and this call owns it.
        unsafe { OSSL_ENCODER_CTX_free(ctx) };
        // SAFETY: `info` is still within the NULL-terminated chain; the loop condition checks it.
        info = unsafe { info.add(1) };
    }

    if ret == -1 {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::I2D_EVP_69) };
    }
    ret
}

/// `int i2d_KeyParams(const EVP_PKEY *a, unsigned char **pp)` — `i2d_evp.c:73-89`.
///
/// # Safety
/// `a` must be live; `pp` NULL or a writable cursor.
#[no_mangle]
pub unsafe extern "C" fn i2d_KeyParams(a: *const EvpPkey, pp: *mut *mut c_uchar) -> c_int {
    let output_info: [TypeAndStructure; 2] = [
        (c"DER".as_ptr(), c"type-specific".as_ptr()),
        (ptr::null(), ptr::null()),
    ];

    // SAFETY: `a` is live per the contract.
    if unsafe { evp_pkey_is_provided(a) } != 0 {
        // SAFETY: `a` is live and `output_info` is a NULL-terminated chain live for this call.
        return unsafe { i2d_provided(a, EVP_PKEY_KEY_PARAMETERS, output_info.as_ptr(), pp) };
    }
    // SAFETY: `a` is live per the contract.
    let ameth = unsafe { (*a).ameth };
    if !ameth.is_null() {
        // SAFETY: `ameth` is `a`'s own method table.
        if let Some(param_encode) = unsafe { (*ameth).param_encode } {
            // SAFETY: the callback is `a`'s own and `a` is live.
            return unsafe { param_encode(a, pp) };
        }
    }
    // SAFETY: a compile-time-constant site.
    unsafe { raise_site(&err_sites::I2D_EVP_87) };
    -1
}

/// `static int i2d_KeyParams_bio(BIO *bp, const EVP_PKEY *pkey)` — `i2d_evp.c:91-94`, the
/// `ASN1_i2d_bio_of(EVP_PKEY, i2d_KeyParams, …)` expansion.
///
/// # Safety
/// `bp` must be a live BIO; `pkey` a live `EVP_PKEY`.
#[no_mangle]
pub unsafe extern "C" fn i2d_KeyParams_bio(bp: *mut Bio, pkey: *const EvpPkey) -> c_int {
    // SAFETY: this wrapper restates `i2d_KeyParams`'s contract in `I2dOfVoid`'s terms.
    unsafe extern "C" fn i2d_void(x: *const c_void, out: *mut *mut c_uchar) -> c_int {
        // SAFETY: the caller's contract, restated in the typed encoder's terms.
        unsafe { i2d_KeyParams(x.cast::<EvpPkey>(), out) }
    }
    let i2d: I2dOfVoid = i2d_void;
    // SAFETY: `bp` is live, `i2d` is the encoder above, `pkey` is live.
    unsafe { ASN1_i2d_bio(i2d, bp, pkey.cast::<c_void>()) }
}

/// `static int i2d_PrivateKey_impl(const EVP_PKEY *a, unsigned char **pp, int traditional)` —
/// `i2d_evp.c:96-129`.
///
/// `traditional` selects the legacy method's `old_priv_encode` over `priv_encode`, and for a
/// provided key selects the `type-specific` output structure over `PrivateKeyInfo`.
///
/// # Safety
/// `a` must be live; `pp` NULL or a writable cursor.
unsafe fn i2d_private_key_impl(
    a: *const EvpPkey,
    pp: *mut *mut c_uchar,
    traditional: c_int,
) -> c_int {
    let trad_output_info: [TypeAndStructure; 3] = [
        (c"DER".as_ptr(), c"type-specific".as_ptr()),
        (c"DER".as_ptr(), c"PrivateKeyInfo".as_ptr()),
        (ptr::null(), ptr::null()),
    ];

    // SAFETY: `a` is live per the contract.
    if unsafe { evp_pkey_is_provided(a) } != 0 {
        // `oi` starts at the traditional entry and advances one when `!traditional`, exactly the
        // authority's `const struct … *oi = trad_output_info; if (!traditional) ++oi;`.
        let oi = if traditional != 0 {
            trad_output_info.as_ptr()
        } else {
            // SAFETY: indexing the two-live-entry chain one past its head is in bounds.
            unsafe { trad_output_info.as_ptr().add(1) }
        };
        // SAFETY: `a` is live and `oi` points into the chain live for this call.
        return unsafe { i2d_provided(a, EVP_PKEY_KEYPAIR, oi, pp) };
    }

    // SAFETY: `a` is live per the contract.
    let ameth = unsafe { (*a).ameth };
    if traditional != 0 && !ameth.is_null() {
        // SAFETY: `ameth` is `a`'s own method table.
        if let Some(old_priv_encode) = unsafe { (*ameth).old_priv_encode } {
            // SAFETY: the callback is `a`'s own and `a` is live.
            return unsafe { old_priv_encode(a, pp) };
        }
    }
    if !ameth.is_null() {
        // SAFETY: `ameth` is `a`'s own method table.
        if unsafe { (*ameth).priv_encode }.is_some() {
            // SAFETY: `a` is live and this is the authority's PKCS#8 conversion.
            let p8 = unsafe { ossl_evp_pkey2pkcs8(a) };
            let mut ret = 0;
            if !p8.is_null() {
                // SAFETY: `p8` is live and this call owns it after the encode.
                ret = unsafe { i2d_PKCS8_PRIV_KEY_INFO(p8, pp) };
                // SAFETY: `p8` is live and this call owns it.
                unsafe { PKCS8_PRIV_KEY_INFO_free(p8) };
            }
            return ret;
        }
    }
    // SAFETY: a compile-time-constant site.
    unsafe { raise_site(&err_sites::I2D_EVP_127) };
    -1
}

/// `int i2d_PrivateKey(const EVP_PKEY *a, unsigned char **pp)` — `i2d_evp.c:131-134`, the
/// traditional spelling.
///
/// # Safety
/// `a` must be live; `pp` NULL or a writable cursor.
#[no_mangle]
pub unsafe extern "C" fn i2d_PrivateKey(a: *const EvpPkey, pp: *mut *mut c_uchar) -> c_int {
    // SAFETY: `a` is live and `pp` is the caller's cursor.
    unsafe { i2d_private_key_impl(a, pp, 1) }
}

/// `int i2d_PKCS8PrivateKey(const EVP_PKEY *a, unsigned char **pp)` — `i2d_evp.c:136-139`.
///
/// # Safety
/// `a` must be live; `pp` NULL or a writable cursor.
#[no_mangle]
pub unsafe extern "C" fn i2d_PKCS8PrivateKey(a: *const EvpPkey, pp: *mut *mut c_uchar) -> c_int {
    // SAFETY: `a` is live and `pp` is the caller's cursor.
    unsafe { i2d_private_key_impl(a, pp, 0) }
}

/// `int i2d_PublicKey(const EVP_PKEY *a, unsigned char **pp)` — `i2d_evp.c:141-169`.
///
/// The provided arm's chain is `DER`/`type-specific` then `blob`/NULL (the EC point encoding);
/// the legacy arm is the `switch` over `EVP_PKEY_get_base_id`.
///
/// # Safety
/// `a` must be live; `pp` NULL or a writable cursor.
#[no_mangle]
pub unsafe extern "C" fn i2d_PublicKey(a: *const EvpPkey, pp: *mut *mut c_uchar) -> c_int {
    let output_info: [TypeAndStructure; 3] = [
        (c"DER".as_ptr(), c"type-specific".as_ptr()),
        (c"blob".as_ptr(), ptr::null()),
        (ptr::null(), ptr::null()),
    ];

    // SAFETY: `a` is live per the contract.
    if unsafe { evp_pkey_is_provided(a) } != 0 {
        // SAFETY: `a` is live and `output_info` is a NULL-terminated chain live for this call.
        return unsafe { i2d_provided(a, EVP_PKEY_PUBLIC_KEY, output_info.as_ptr(), pp) };
    }
    // SAFETY: `a` is live per the contract.
    match unsafe { EVP_PKEY_get_base_id(a) } {
        EVP_PKEY_RSA => {
            // SAFETY: `a` is live and `EVP_PKEY_get0_RSA` reads its own key.
            let rsa = unsafe { EVP_PKEY_get0_RSA(a) };
            // SAFETY: `rsa` is the key `a` holds.
            unsafe { i2d_RSAPublicKey(rsa, pp) }
        }
        EVP_PKEY_DSA => {
            // SAFETY: `a` is live and `EVP_PKEY_get0_DSA` reads its own key.
            let dsa = unsafe { EVP_PKEY_get0_DSA(a) };
            // SAFETY: `dsa` is the key `a` holds.
            unsafe { crate::dsa::asn1::i2d_DSAPublicKey(dsa, pp) }
        }
        EVP_PKEY_EC => {
            // SAFETY: `a` is live and `EVP_PKEY_get0_EC_KEY` reads its own key.
            let ec = unsafe { EVP_PKEY_get0_EC_KEY(a) };
            // SAFETY: `ec` is the key `a` holds.
            unsafe { i2o_ECPublicKey(ec, pp) }
        }
        _ => {
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&err_sites::I2D_EVP_166) };
            -1
        }
    }
}
