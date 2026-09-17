//! Phase 7.4c — `crypto/asn1/p5_scrypt.c`'s two `PKCS5_v2_scrypt_keyivgen` exports.
//!
//! The authority file is `crypto/asn1/p5_scrypt.c`, and it is one translation unit split across two
//! strata: its two keygen exports are declared in `evp.h` and are therefore **Phase 7's**
//! (`forensics/atlas/symbol-ownership.json`), while `PKCS5_pbe2_set_scrypt` and the
//! `SCRYPT_PARAMS_*`/`d2i_SCRYPT_PARAMS` accessors are declared in `x509.h` and are Phase 11's.
//! This module transcribes the Phase 7 half; the Phase 11 half stays in the ledger.
//!
//! It is a module of its own rather than a second half of `src/evp/pbe.rs` because the convention
//! this stratum follows is one crate file per authority unit, and `crypto/asn1/*` units already
//! land under `src/evp/` where that is where their owners are (`src/evp/pkey_asn1.rs` is
//! `crypto/asn1/ameth_lib.c`). The two `SCRYPT_PARAMS` *templates* are transcribed here as
//! file-local statics for the reason `src/asn1/evp_asn1.rs` records for its pair items: the item
//! is `static const` inside the authority's own accessor, nothing outside the unit can name it, and
//! the exported accessor is Phase 11's.
//!
//! ## Five ways to refuse, and one that is a *probe* rather than a derivation
//!
//! ```text
//! :252  no cipher on the context                     EVP_R_NO_CIPHER_SET
//! :261  the parameter does not decode                EVP_R_DECODE_ERROR
//! :267  the context's key length is negative         EVP_R_INVALID_KEY_LENGTH
//! :278  keyLength present and not the context's      EVP_R_UNSUPPORTED_KEYLENGTH
//! :289  N, r or p does not fit a uint64_t, or the
//!       scrypt parameters are rejected by scrypt      EVP_R_ILLEGAL_SCRYPT_PARAMETERS
//! ```
//!
//! `:289` is the interesting one and it is **not** a derivation: the function calls
//! `EVP_PBE_scrypt_ex(NULL, 0, NULL, 0, N, r, p, 0, NULL, 0, libctx, propq)` and throws the key
//! away, purely to ask the KDF whether the parameters are acceptable. A `key == NULL, keylen == 0`
//! derivation is what that is, so a probe's SCRYPT implementation sees **two** derivations per
//! successful call and one per `:289` refusal — which is exactly how the court distinguishes "the
//! parameter probe ran" from "the derivation ran".
//!
//! ## `passlen` is not normalised here
//!
//! Unlike `p5_crpt.c`, this body does not turn a `passlen` of `-1` into `strlen(pass)`: it forwards
//! the `int` into `EVP_PBE_scrypt_ex`'s `size_t`, so `-1` arrives as `SIZE_MAX`. That is the
//! authority's arithmetic and it is reproduced rather than tidied, because the two files'
//! disagreement about the same argument is exactly the kind of thing a "make these consistent" pass
//! removes. The court drives the `-1` spelling and both sides agree on it.
//!
//! ## `keylen` is not `key`'s bound
//!
//! `PKCS5_v2_scrypt_keyivgen_ex` reads the key length from the context and never checks it against
//! `key[EVP_MAX_KEY_LENGTH]` — unlike its `p5_crpt2.c` sibling, which asserts. With a cipher whose
//! provider reports a key length above 64 the authority writes past the buffer; this crate bounds
//! the copy and refuses, which is the disposition `D-RCU-3` records for the one other always-live
//! `OPENSSL_assert`-shaped abort in this stratum. The difference is a fault boundary, not a
//! comparable observation, and it is named in `RT-EVP-PBE`'s comment rather than driven.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_char, c_int, c_long, c_void};
use core::ptr;

use crate::asn1::asn_pack::ASN1_item_unpack;
use crate::asn1::fre::ASN1_item_free;
use crate::asn1::items::{ASN1_INTEGER_it, ASN1_OCTET_STRING_it};
use crate::asn1::layout::*;
use crate::asn1::prim::ASN1_INTEGER_get_uint64;
use crate::evp::cipher::EvpCipher;
use crate::evp::cipher_ctx::{
    EVP_CIPHER_CTX_get0_cipher, EVP_CIPHER_CTX_get_key_length, EVP_CipherInit_ex, EvpCipherCtx,
};
use crate::evp::digest::EvpMd;
use crate::evp::pbe::EVP_PBE_scrypt_ex;
use crate::runtime::err::{err_sites, raise_site};
use crate::runtime::mem::OPENSSL_cleanse;

/// `EVP_MAX_KEY_LENGTH` — `include/openssl/evp.h:35`.
const EVP_MAX_KEY_LENGTH: usize = 64;

/// `SCRYPT_PARAMS` — `crypto/asn1/p5_scrypt.c:21-27`.
///
/// `#[repr(C)]` because the template reaches the fields by *offset*: the offsets below are
/// asserted against this declaration rather than assumed from it.
#[repr(C)]
struct ScryptParams {
    /// `ASN1_SIMPLE(SCRYPT_PARAMS, salt, ASN1_OCTET_STRING)` — a pointer, at offset 0.
    salt: *mut Asn1String,
    /// `ASN1_SIMPLE(SCRYPT_PARAMS, costParameter, ASN1_INTEGER)` — at offset 8.
    cost_parameter: *mut Asn1String,
    /// `ASN1_SIMPLE(SCRYPT_PARAMS, blockSize, ASN1_INTEGER)` — at offset 16.
    block_size: *mut Asn1String,
    /// `ASN1_SIMPLE(SCRYPT_PARAMS, parallelizationParameter, ASN1_INTEGER)` — at offset 24.
    parallelization_parameter: *mut Asn1String,
    /// `ASN1_OPT(SCRYPT_PARAMS, keyLength, ASN1_INTEGER)` — at offset 32.
    key_length: *mut Asn1String,
}

// The offsets the template array below names.
const _: () = {
    assert!(core::mem::size_of::<ScryptParams>() == 40);
    assert!(core::mem::offset_of!(ScryptParams, salt) == 0);
    assert!(core::mem::offset_of!(ScryptParams, cost_parameter) == 8);
    assert!(core::mem::offset_of!(ScryptParams, block_size) == 16);
    assert!(core::mem::offset_of!(ScryptParams, parallelization_parameter) == 24);
    assert!(core::mem::offset_of!(ScryptParams, key_length) == 32);
};

/// `scrypt_params_seq_tt` — `crypto/asn1/p5_scrypt.c:21-27`'s five fields, the last optional.
static SCRYPT_PARAMS_TT: [Asn1Template; 5] = [
    Asn1Template {
        flags: 0,
        tag: 0,
        offset: 0,
        field_name: c"salt".as_ptr(),
        item: ASN1_OCTET_STRING_it as *mut c_void,
    },
    Asn1Template {
        flags: 0,
        tag: 0,
        offset: 8,
        field_name: c"costParameter".as_ptr(),
        item: ASN1_INTEGER_it as *mut c_void,
    },
    Asn1Template {
        flags: 0,
        tag: 0,
        offset: 16,
        field_name: c"blockSize".as_ptr(),
        item: ASN1_INTEGER_it as *mut c_void,
    },
    Asn1Template {
        flags: 0,
        tag: 0,
        offset: 24,
        field_name: c"parallelizationParameter".as_ptr(),
        item: ASN1_INTEGER_it as *mut c_void,
    },
    Asn1Template {
        flags: ASN1_TFLG_OPTIONAL,
        tag: 0,
        offset: 32,
        field_name: c"keyLength".as_ptr(),
        item: ASN1_INTEGER_it as *mut c_void,
    },
];

/// `SCRYPT_PARAMS_it`'s descriptor, private here because the accessor is Phase 11's.
static SCRYPT_PARAMS_ITEM: Asn1Item = Asn1Item {
    itype: ASN1_ITYPE_SEQUENCE,
    utype: V_ASN1_SEQUENCE as c_long,
    templates: SCRYPT_PARAMS_TT.as_ptr(),
    tcount: 5,
    funcs: ptr::null(),
    size: core::mem::size_of::<ScryptParams>() as c_long,
    sname: c"SCRYPT_PARAMS".as_ptr(),
};

/// The authority's `err:` label: cleanse the key when a length is known, free the decode, answer 0.
///
/// # Safety
/// `sparam` must be NULL or this call's own `SCRYPT_PARAMS` decode.
unsafe fn err_cleanup(
    sparam: *mut ScryptParams,
    key: &mut [u8; EVP_MAX_KEY_LENGTH],
    keylen: usize,
) {
    // SAFETY: `key` is the caller's own buffer and `keylen` is bounded by the caller's check.
    unsafe {
        if keylen != 0 && keylen <= key.len() {
            OPENSSL_cleanse(key.as_mut_ptr().cast(), keylen);
        }
        ASN1_item_free(sparam.cast::<c_void>(), &SCRYPT_PARAMS_ITEM);
    }
}

/// `int PKCS5_v2_scrypt_keyivgen_ex(EVP_CIPHER_CTX *ctx, const char *pass, int passlen,
/// ASN1_TYPE *param, const EVP_CIPHER *c, const EVP_MD *md, int en_de,
/// OSSL_LIB_CTX *libctx, const char *propq)` — `crypto/asn1/p5_scrypt.c:239`.
///
/// # Safety
/// `ctx` must be a live `EVP_CIPHER_CTX`; `pass` NULL or NUL-terminated (or `passlen` bytes when
/// `passlen != -1`); `param` NULL or a live `ASN1_TYPE`; `libctx` NULL or live; `propq` NULL or
/// NUL-terminated.
#[no_mangle]
pub unsafe extern "C" fn PKCS5_v2_scrypt_keyivgen_ex(
    ctx: *mut EvpCipherCtx,
    pass: *const c_char,
    passlen: c_int,
    param: *mut Asn1Type,
    c: *const EvpCipher,
    md: *const EvpMd,
    en_de: c_int,
    libctx: *mut c_void,
    propq: *const c_char,
) -> c_int {
    let mut key = [0u8; EVP_MAX_KEY_LENGTH];
    let mut p: u64 = 0;
    let mut r: u64 = 0;
    let mut n: u64 = 0;
    let mut keylen: usize = 0;
    let mut sparam: *mut ScryptParams = ptr::null_mut();
    /* The two unused parameters are the authority's: this body never reads `c` or `md`, because the
     * cipher is already on the context. */
    let _ = (c, md);

    // SAFETY: `ctx` is live per the contract and the accessor tolerates a NULL context.
    if unsafe { EVP_CIPHER_CTX_get0_cipher(ctx) }.is_null() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::P5_SCRYPT_252) };
        return 0;
    }

    /* Decode parameter. The authority calls the macro directly, which answers NULL for a NULL or
     * non-SEQUENCE value; the two tests are written out so the decode is not reached at all. */
    if !param.is_null() {
        // SAFETY: `param` is live per the check above.
        let (type_, seq) = unsafe { ((*param).type_, (*param).value.ptr.cast::<Asn1String>()) };
        if type_ == V_ASN1_SEQUENCE && !seq.is_null() {
            // SAFETY: `seq` is a live string and the item is this file's own static.
            sparam = unsafe { ASN1_item_unpack(seq, &SCRYPT_PARAMS_ITEM) }.cast::<ScryptParams>();
        }
    }
    if sparam.is_null() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::P5_SCRYPT_261) };
        return 0;
    }

    // SAFETY: `ctx` is live per the contract.
    let t = unsafe { EVP_CIPHER_CTX_get_key_length(ctx) };
    if t < 0 {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::P5_SCRYPT_267) };
        // SAFETY: `sparam` is this call's own decode; `keylen` is zero here.
        unsafe { err_cleanup(sparam, &mut key, keylen) };
        return 0;
    }
    keylen = t as usize;

    /* Now check the parameters of sparam. */
    // SAFETY: `sparam` is live and `key_length` is NULL or the decode's own integer.
    if !unsafe { (*sparam).key_length }.is_null() {
        let mut spkeylen: u64 = 0;
        // SAFETY: both pointers are live.
        let ok = unsafe { ASN1_INTEGER_get_uint64(&mut spkeylen, (*sparam).key_length) };
        if ok == 0 || spkeylen != keylen as u64 {
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&err_sites::P5_SCRYPT_278) };
            // SAFETY: `sparam` is this call's own decode.
            unsafe { err_cleanup(sparam, &mut key, keylen) };
            return 0;
        }
    }
    /* Check all parameters fit in uint64_t and are acceptable to scrypt. `&&`'s short circuit is
     * the authority's `||` inverted: it stops as soon as one of the three fails. */
    // SAFETY: `sparam` is live and its three mandatory integers are non-NULL after a decode.
    let fits = unsafe {
        ASN1_INTEGER_get_uint64(&mut n, (*sparam).cost_parameter) != 0
            && ASN1_INTEGER_get_uint64(&mut r, (*sparam).block_size) != 0
            && ASN1_INTEGER_get_uint64(&mut p, (*sparam).parallelization_parameter) != 0
    };
    // SAFETY: the two NULLs are the authority's "probe the parameters" call, with no output
    // buffer; every other argument is the caller's.
    let probe_ok = fits
        && unsafe {
            EVP_PBE_scrypt_ex(
                ptr::null(),
                0,
                ptr::null(),
                0,
                n,
                r,
                p,
                0,
                ptr::null_mut(),
                0,
                libctx,
                propq,
            )
        } != 0;
    if !probe_ok {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::P5_SCRYPT_289) };
        // SAFETY: `sparam` is this call's own decode.
        unsafe { err_cleanup(sparam, &mut key, keylen) };
        return 0;
    }

    /* it seems that its all OK */
    // SAFETY: `sparam` is live and `salt` is non-NULL after a decode.
    let salt = unsafe { (*(*sparam).salt).data };
    // SAFETY: as above.
    let saltlen = unsafe { (*(*sparam).salt).length } as usize;

    /* The authority copies into a 64-byte stack buffer without a bound test; this crate refuses
     * instead, which is a fault boundary named in the module doc and in RT-EVP-PBE. */
    if keylen > key.len() {
        // SAFETY: `sparam` is this call's own decode.
        unsafe { err_cleanup(sparam, &mut key, keylen) };
        return 0;
    }

    /* `passlen as usize` is the authority's own implicit conversion: `-1` arrives as `SIZE_MAX`
     * because this file does not normalise it. */
    // SAFETY: `salt` is the decode's own buffer of `saltlen` bytes, `key` is `keylen` writable
    // bytes, and `libctx`/`propq` are the caller's.
    if unsafe {
        EVP_PBE_scrypt_ex(
            pass,
            passlen as usize,
            salt,
            saltlen,
            n,
            r,
            p,
            0,
            key.as_mut_ptr(),
            keylen,
            libctx,
            propq,
        )
    } == 0
    {
        // SAFETY: `sparam` is this call's own decode.
        unsafe { err_cleanup(sparam, &mut key, keylen) };
        return 0;
    }
    // SAFETY: `ctx` is live; a NULL cipher means "the one already on the context" and a NULL IV
    // means "no IV parameter".
    let rv = unsafe {
        EVP_CipherInit_ex(
            ctx,
            ptr::null(),
            ptr::null_mut(),
            key.as_ptr(),
            ptr::null(),
            en_de,
        )
    };
    // SAFETY: `sparam` is this call's own decode.
    unsafe { err_cleanup(sparam, &mut key, keylen) };
    rv
}

/// `int PKCS5_v2_scrypt_keyivgen(EVP_CIPHER_CTX *ctx, const char *pass, int passlen,
/// ASN1_TYPE *param, const EVP_CIPHER *c, const EVP_MD *md, int en_de)` —
/// `crypto/asn1/p5_scrypt.c:309`.
///
/// # Safety
/// As [`PKCS5_v2_scrypt_keyivgen_ex`], with a NULL library context and property query.
#[no_mangle]
pub unsafe extern "C" fn PKCS5_v2_scrypt_keyivgen(
    ctx: *mut EvpCipherCtx,
    pass: *const c_char,
    passlen: c_int,
    param: *mut Asn1Type,
    c: *const EvpCipher,
    md: *const EvpMd,
    en_de: c_int,
) -> c_int {
    // SAFETY: the arguments are forwarded under this function's contract, with the two NULLs the
    // authority passes.
    unsafe {
        PKCS5_v2_scrypt_keyivgen_ex(
            ctx,
            pass,
            passlen,
            param,
            c,
            md,
            en_de,
            ptr::null_mut(),
            ptr::null(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The private item is the authority's: a SEQUENCE of five fields, the last optional, and the
    /// structure's own size.
    #[test]
    fn the_private_scrypt_params_item_has_the_authority_shape() {
        assert_eq!(SCRYPT_PARAMS_ITEM.itype, ASN1_ITYPE_SEQUENCE);
        assert_eq!(SCRYPT_PARAMS_ITEM.utype, V_ASN1_SEQUENCE as c_long);
        assert_eq!(SCRYPT_PARAMS_ITEM.tcount, 5);
        assert_eq!(SCRYPT_PARAMS_ITEM.size, 40);
        assert_eq!(SCRYPT_PARAMS_TT[4].flags, ASN1_TFLG_OPTIONAL);
    }

    /// The first refusal is the context's, and it fires before the parameter is looked at: a NULL
    /// context has no cipher, so a NULL parameter never reaches the decode's own reason.
    #[test]
    fn a_context_with_no_cipher_is_refused_first() {
        // SAFETY: a NULL context is the first refusal; nothing is dereferenced.
        let r = unsafe {
            PKCS5_v2_scrypt_keyivgen(
                ptr::null_mut(),
                c"p".as_ptr(),
                -1,
                ptr::null_mut(),
                ptr::null(),
                ptr::null(),
                1,
            )
        };
        assert_eq!(r, 0);
        /* `ERR_clear_error` is a safe entry point of this crate. */
        crate::runtime::err::ERR_clear_error();
    }
}
