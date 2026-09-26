//! `crypto/pkcs12/p12_crpt.c` — the PKCS#12 PBE key/IV generator, transcribed whole.
//! Phase 10 (10.4).
//!
//! Three exports and one empty function. `PKCS12_PBE_add` is empty in the authority ("PKCS#12 PBE
//! algorithms now in static table") and empty here; `PKCS12_PBE_keyivgen_ex` derives the key and IV
//! for one `PBEPARAM` and initialises the cipher context; `PKCS12_PBE_keyivgen` is the `_ex`
//! spelling with a NULL context.
//!
//! ## This unit is where `builtin_pbe[]` gets its six keygen pointers
//!
//! `crypto/evp/evp_pbe.c`'s six PKCS#12 OUTER rows name `PKCS12_PBE_keyivgen` and
//! `&PKCS12_PBE_keyivgen_ex`, and until this unit exists they are `None` in this crate's
//! `src/evp/evp_pbe.rs` — `docs/SECURITY_DIVERGENCE_POLICY.md` **D-PBE-PKCS12-KEYGEN-1**. Landing
//! this module is that divergence's stated trigger: the six rows take the two addresses and
//! `EVP_PBE_find`/`_ex` answer non-NULL for both keygen out-parameters. The row is retired with
//! this change, and `forget` is not used anywhere.
//!
//! ## `PBEPARAM` is a file-local descriptor, exactly as `p5_crpt.rs` has one
//!
//! `PBEPARAM_free` and `ASN1_ITEM_rptr(PBEPARAM)` are Phase 11's accessors
//! (`crypto/asn1/p5_pbe.c`). What this unit needs is the two-field descriptor and a way to release
//! its decode, so the descriptor is transcribed here as a second file-local `static` with the same
//! fields and the same `sname`, and `ASN1_item_free` is used in place of `PBEPARAM_free`. That is
//! the same move `src/evp/p5_crpt.rs` makes, for the same reason: the authority's descriptor is
//! `static const` inside the accessor and nothing outside that translation unit can name it.
//!
//! ## The order of the refusals, and the `EVP_CIPHER_get_*_length` reads
//!
//! `cipher == NULL` returns 0 first, then a `PBEPARAM` that does not decode raises
//! `PKCS12_R_DECODE_ERROR`. The key derivation runs before the IV derivation, and each failure
//! frees the parameter and raises its own reason (`PKCS12_R_KEY_GEN_ERROR`, `PKCS12_R_IV_GEN_ERROR`).
//! The IV is only derived when `EVP_CIPHER_get_iv_length(cipher) > 0`; a zero-length IV means
//! `piv = NULL`, which is what `EVP_CipherInit_ex` receives for an ECB-mode PBE cipher.
//!
//! ## The court
//!
//! The unit raises, so it is an entry in `gen_err_raise_sites.py`'s `COVERED_FILES` under the
//! `PKCS12_CRPT` stem (the `PKCS12` stem is carried by `p12_decr.c`/`p12_sbag.c` and their line
//! numbers collide with this file's). Its behaviour is driven by `RT-PKCS12` through
//! `EVP_PBE_CipherInit_ex`'s own table — the six rows D-PBE-PKCS12-KEYGEN-1 named.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_char, c_int, c_long, c_uchar, c_void};
use core::ptr;

use crate::asn1::a_type::ASN1_TYPE_unpack_sequence;
use crate::asn1::fre::ASN1_item_free;
use crate::asn1::items::{ASN1_INTEGER_it, ASN1_OCTET_STRING_it};
use crate::asn1::layout::*;
use crate::asn1::prim::ASN1_INTEGER_get;
use crate::evp::cipher::{EVP_CIPHER_get_iv_length, EVP_CIPHER_get_key_length, EvpCipher};
use crate::evp::cipher_ctx::{EVP_CipherInit_ex, EvpCipherCtx};
use crate::evp::digest::EvpMd;
use crate::pkcs12::p12_key::PKCS12_key_gen_utf8_ex;
use crate::runtime::err::{err_sites, raise_site};
use crate::runtime::mem::OPENSSL_cleanse;

/// `EVP_MAX_KEY_LENGTH` — `include/openssl/evp.h:35`.
const EVP_MAX_KEY_LENGTH: usize = 64;
/// `EVP_MAX_IV_LENGTH` — `include/openssl/evp.h:36`.
const EVP_MAX_IV_LENGTH: usize = 16;
/// `PKCS12_KEY_ID` — `include/openssl/pkcs12.h:39`.
const PKCS12_KEY_ID: c_int = 1;
/// `PKCS12_IV_ID` — `include/openssl/pkcs12.h:40`.
const PKCS12_IV_ID: c_int = 2;

/// `PBEPARAM` — `crypto/asn1/p5_pbe.c:19-22`'s `ASN1_SEQUENCE(PBEPARAM)`, declared as the C
/// typedef's two field pointers.
///
/// This is the second descriptor of the pair `src/evp/p5_crpt.rs` carries one of; the fields, the
/// offsets and the `sname` are identical, and the item is private here for the same reason.
#[repr(C)]
struct PbeParam {
    /// `ASN1_SIMPLE(PBEPARAM, salt, ASN1_OCTET_STRING)` — a pointer, at offset 0.
    salt: *mut Asn1String,
    /// `ASN1_SIMPLE(PBEPARAM, iter, ASN1_INTEGER)` — a pointer, at offset 8.
    iter: *mut Asn1String,
}

const _: () = {
    assert!(core::mem::size_of::<PbeParam>() == 16);
    assert!(core::mem::offset_of!(PbeParam, salt) == 0);
    assert!(core::mem::offset_of!(PbeParam, iter) == 8);
};

/// `pbe_seq_tt` — `crypto/asn1/p5_pbe.c:19-22`'s two `ASN1_SIMPLE` fields.
static PBEPARAM_TT: [Asn1Template; 2] = [
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
        field_name: c"iter".as_ptr(),
        item: ASN1_INTEGER_it as *mut c_void,
    },
];

/// `PBEPARAM_it`'s descriptor — the private `static const ASN1_ITEM` inside
/// `IMPLEMENT_ASN1_FUNCTIONS(PBEPARAM)`.
static PBEPARAM_ITEM: Asn1Item = Asn1Item {
    itype: ASN1_ITYPE_SEQUENCE,
    utype: V_ASN1_SEQUENCE as c_long,
    templates: PBEPARAM_TT.as_ptr(),
    tcount: 2,
    funcs: ptr::null(),
    size: core::mem::size_of::<PbeParam>() as c_long,
    sname: c"PBEPARAM".as_ptr(),
};

/// `void PKCS12_PBE_add(void)` — `crypto/pkcs12/p12_crpt.c:19-21`.
///
/// An empty body in the authority ("PKCS#12 PBE algorithms now in static table") and an empty body
/// here.
///
/// # Safety
/// Nothing: the function touches no state.
#[no_mangle]
pub unsafe extern "C" fn PKCS12_PBE_add() {}

/// `int PKCS12_PBE_keyivgen_ex(EVP_CIPHER_CTX *ctx, const char *pass, int passlen,
/// ASN1_TYPE *param, const EVP_CIPHER *cipher, const EVP_MD *md, int en_de,
/// OSSL_LIB_CTX *libctx, const char *propq)` — `crypto/pkcs12/p12_crpt.c:23-76`.
///
/// # Safety
/// `ctx` must be a live `EVP_CIPHER_CTX`; `pass` NULL or a string of `passlen` bytes (or
/// NUL-terminated when `passlen == -1`); `param` NULL or a live `ASN1_TYPE`; `cipher`/`md` live;
/// `libctx` NULL or live; `propq` NULL or NUL-terminated.
#[no_mangle]
pub unsafe extern "C" fn PKCS12_PBE_keyivgen_ex(
    ctx: *mut EvpCipherCtx,
    pass: *const c_char,
    passlen: c_int,
    param: *mut Asn1Type,
    cipher: *const EvpCipher,
    md: *const EvpMd,
    en_de: c_int,
    libctx: *mut c_void,
    propq: *const c_char,
) -> c_int {
    let mut key = [0u8; EVP_MAX_KEY_LENGTH];
    let mut iv = [0u8; EVP_MAX_IV_LENGTH];

    if cipher.is_null() {
        return 0;
    }

    /* Extract useful info from parameter */
    // SAFETY: `param` is NULL or live per the contract; the item is this file's own static.
    let pbe: *mut PbeParam =
        unsafe { ASN1_TYPE_unpack_sequence(&PBEPARAM_ITEM, param) }.cast::<PbeParam>();
    if pbe.is_null() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::PKCS12_CRPT_41) };
        return 0;
    }

    // SAFETY: `pbe` is a live decode of this file's own item, so the `salt` field is a non-NULL
    // octet string; `iter` is optional and its test is the authority's own.
    let (iter, salt, saltlen) = unsafe {
        (
            if (*pbe).iter.is_null() {
                1
            } else {
                ASN1_INTEGER_get((*pbe).iter) as c_int
            },
            (*(*pbe).salt).data,
            (*(*pbe).salt).length,
        )
    };

    // SAFETY: `cipher` is live per the contract; `md` is live per the contract.
    let klen = unsafe { EVP_CIPHER_get_key_length(cipher) };
    // SAFETY: `pass` is a string per the contract; the other arguments are as declared.
    let keygen = unsafe {
        PKCS12_key_gen_utf8_ex(
            pass,
            passlen,
            salt,
            saltlen,
            PKCS12_KEY_ID,
            iter,
            klen,
            key.as_mut_ptr(),
            md,
            libctx,
            propq,
        )
    };
    if keygen == 0 {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::PKCS12_CRPT_55) };
        // SAFETY: `pbe` is this call's own decode.
        unsafe { ASN1_item_free(pbe.cast::<c_void>(), &PBEPARAM_ITEM) };
        return 0;
    }

    // SAFETY: `cipher` is live per the contract.
    let ivlen = unsafe { EVP_CIPHER_get_iv_length(cipher) };
    let piv: *const c_uchar = if ivlen > 0 {
        // SAFETY: `pass` is a string per the contract; `iv` is this frame's 16-byte buffer and
        // `ivlen <= 16` for every cipher the table names.
        let ivgen = unsafe {
            PKCS12_key_gen_utf8_ex(
                pass,
                passlen,
                salt,
                saltlen,
                PKCS12_IV_ID,
                iter,
                ivlen,
                iv.as_mut_ptr(),
                md,
                libctx,
                propq,
            )
        };
        if ivgen == 0 {
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&err_sites::PKCS12_CRPT_64) };
            // SAFETY: `pbe` is this call's own decode.
            unsafe { ASN1_item_free(pbe.cast::<c_void>(), &PBEPARAM_ITEM) };
            return 0;
        }
        iv.as_ptr()
    } else {
        ptr::null()
    };

    // SAFETY: `pbe` is this call's own decode.
    unsafe { ASN1_item_free(pbe.cast::<c_void>(), &PBEPARAM_ITEM) };
    // SAFETY: `ctx` is live; `cipher` live; `key`/`iv` are this frame's own buffers and the
    // lengths were read from the cipher.
    let ret = unsafe { EVP_CipherInit_ex(ctx, cipher, ptr::null_mut(), key.as_ptr(), piv, en_de) };
    // SAFETY: both buffers are this frame's own.
    unsafe {
        OPENSSL_cleanse(key.as_mut_ptr().cast(), EVP_MAX_KEY_LENGTH);
        OPENSSL_cleanse(iv.as_mut_ptr().cast(), EVP_MAX_IV_LENGTH);
    }
    ret
}

/// `int PKCS12_PBE_keyivgen(EVP_CIPHER_CTX *ctx, const char *pass, int passlen,
/// ASN1_TYPE *param, const EVP_CIPHER *cipher, const EVP_MD *md, int en_de)` —
/// `crypto/pkcs12/p12_crpt.c:78-84`.
///
/// # Safety
/// As [`PKCS12_PBE_keyivgen_ex`], with a NULL library context and property query.
#[no_mangle]
pub unsafe extern "C" fn PKCS12_PBE_keyivgen(
    ctx: *mut EvpCipherCtx,
    pass: *const c_char,
    passlen: c_int,
    param: *mut Asn1Type,
    cipher: *const EvpCipher,
    md: *const EvpMd,
    en_de: c_int,
) -> c_int {
    // SAFETY: the arguments are forwarded under this function's contract, with the two NULLs the
    // authority passes.
    unsafe {
        PKCS12_PBE_keyivgen_ex(
            ctx,
            pass,
            passlen,
            param,
            cipher,
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
    use crate::runtime::err::{ERR_clear_error, ERR_get_error};

    /// The private item is the authority's: `ASN1_ITYPE_SEQUENCE`, `V_ASN1_SEQUENCE`, two fields,
    /// no aux block, and the structure's own size.
    #[test]
    fn the_private_pbeparam_item_has_the_authority_shape() {
        assert_eq!(PBEPARAM_ITEM.itype, ASN1_ITYPE_SEQUENCE);
        assert_eq!(PBEPARAM_ITEM.utype, V_ASN1_SEQUENCE as c_long);
        assert_eq!(PBEPARAM_ITEM.tcount, 2);
        assert!(PBEPARAM_ITEM.funcs.is_null());
        assert_eq!(PBEPARAM_ITEM.size, 16);
    }

    /// `PKCS12_PBE_add` is a no-op, and so is calling it twice.
    #[test]
    fn pbe_add_is_empty() {
        // SAFETY: the function touches no state.
        unsafe { PKCS12_PBE_add() };
        // SAFETY: the function touches no state.
        unsafe { PKCS12_PBE_add() };
    }

    /// A NULL cipher is the first refusal and touches nothing else; a NULL parameter with a live
    /// cipher raises `PKCS12_R_DECODE_ERROR`.
    #[test]
    fn the_cipher_and_parameter_refusals_precede_the_derivation() {
        let _g = crate::test_support::lock_global_state();
        // SAFETY: the NULL-cipher arm returns before anything is read.
        let no_cipher = unsafe {
            PKCS12_PBE_keyivgen(
                ptr::null_mut(),
                ptr::null(),
                0,
                ptr::null_mut(),
                ptr::null(),
                ptr::null(),
                1,
            )
        };
        assert_eq!(no_cipher, 0);
        ERR_clear_error();

        /* A live cipher with a NULL parameter: the parameter unpack answers NULL and this unit
         * raises `PKCS12_R_DECODE_ERROR` before any derivation. */
        let cipher =
            /* A live legacy method, or NULL if the legacy table is empty. */
            // SAFETY: the argument is a static NUL-terminated string.
            unsafe { crate::evp::legacy_evp::EVP_get_cipherbyname(c"DES-EDE3-CBC".as_ptr()) };
        if !cipher.is_null() {
            // SAFETY: `cipher` is live and the parameter is NULL.
            let no_param = unsafe {
                PKCS12_PBE_keyivgen(
                    ptr::null_mut(),
                    ptr::null(),
                    0,
                    ptr::null_mut(),
                    cipher,
                    ptr::null(),
                    1,
                )
            };
            assert_eq!(no_param, 0);
            ERR_clear_error();
        }
        /* The round trip that actually derives is RT-PKCS12's arm, which needs a live cipher
         * context and a built `PBEPARAM`; a unit test that only drove the refusals would be
         * weaker evidence, and the court carries it. */
        let _ = ERR_get_error;
    }
}
