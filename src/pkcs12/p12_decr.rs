//! `crypto/pkcs12/p12_decr.c` — the PBE buffer crypt and the ASN.1 decrypt/encrypt pair over
//! it, transcribed whole. Phase 10 (D368).
//!
//! The unit is six exports: `PKCS12_pbe_crypt_ex`/`PKCS12_pbe_crypt` crypt a buffer under an
//! `X509_ALGOR`-described PBE cipher, and
//! `PKCS12_item_decrypt_d2i_ex`/`PKCS12_item_decrypt_d2i`/`PKCS12_item_i2d_encrypt_ex`/
//! `PKCS12_item_i2d_encrypt` decode and encode an ASN.1 structure through it. `PKCS8_decrypt`
//! (`crypto/pkcs12/p12_p8d.c`) is the first caller this crate lands.
//!
//! ## The GOST arm is kept, and it is the reason the function is not just two cipher calls
//!
//! `EVP_CIPH_FLAG_CIPHER_WITH_MAC` marks the ciphers whose AEAD tag is *prepended/appended* by
//! the PBE layer rather than handled inside `EVP_CipherUpdate`: the authority reads the tag
//! length with `EVP_CTRL_AEAD_TLS1_AAD`, sets the tag from the input's tail on decrypt and
//! appends it on encrypt, and adds `mac_len` to the maximum output length. Reproducing that
//! verbatim is what makes a MAC-carrying PBE cipher's buffer the same length as the
//! authority's.
//!
//! ## `passlen == 0` selects the final-error message
//!
//! The authority's `ERR_raise_data` at `:95` picks `"empty password"` or `"maybe wrong
//! password"` from `passlen == 0`. Both are static, so the choice is made at the call site and
//! the site is a data site.
//!
//! ## The court
//!
//! The unit raises, so it is an entry in `gen_err_raise_sites.py`'s `COVERED_FILES`; the
//! `err_sites::PKCS12_*` coordinates below are generated from it. The evidence is the round
//! trip in the test module: a fixed passphrase, a fixed IV and a `PKCS12` PBE cipher built
//! through `EVP_PBE_CipherInit_ex`'s own table, driven once each way.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_char, c_int, c_long, c_uchar, c_void};
use core::ptr;

use crate::asn1::d2i::ASN1_item_d2i;
use crate::asn1::i2d::ASN1_item_i2d;
use crate::asn1::layout::{Asn1Item, Asn1String};
use crate::asn1::string::{ASN1_OCTET_STRING_free, ASN1_OCTET_STRING_new};
use crate::asn1::x_algor::X509Algor;
use crate::evp::cipher::EVP_CIPHER_get_flags;
use crate::evp::cipher_ctx::{
    EVP_CIPHER_CTX_ctrl, EVP_CIPHER_CTX_free, EVP_CIPHER_CTX_get0_cipher,
    EVP_CIPHER_CTX_get_block_size, EVP_CIPHER_CTX_is_encrypting, EVP_CIPHER_CTX_new,
    EVP_CipherFinal_ex, EVP_CipherUpdate,
};
use crate::evp::evp_pbe::EVP_PBE_CipherInit_ex;
use crate::runtime::err::{err_sites, raise_site, raise_site_data};
use crate::runtime::mem::OPENSSL_cleanse;
use crate::runtime::mem::{CRYPTO_free, CRYPTO_zalloc};

/// `crypto/pkcs12/p12_decr.c` — the authority's `__FILE__` string.
const FILE: &core::ffi::CStr = c"crypto/pkcs12/p12_decr.c";

/// `EVP_CIPH_FLAG_CIPHER_WITH_MAC` — `include/openssl/evp.h:364`.
const EVP_CIPH_FLAG_CIPHER_WITH_MAC: core::ffi::c_ulong = 0x2000000;
/// `EVP_CTRL_AEAD_TLS1_AAD` — `include/openssl/evp.h:388`.
const EVP_CTRL_AEAD_TLS1_AAD: c_int = 0x16;
/// `EVP_CTRL_AEAD_SET_TAG` — `include/openssl/evp.h:388`.
const EVP_CTRL_AEAD_SET_TAG: c_int = 0x11;
/// `EVP_CTRL_AEAD_GET_TAG` — `include/openssl/evp.h:388`.
const EVP_CTRL_AEAD_GET_TAG: c_int = 0x10;

/// `unsigned char *PKCS12_pbe_crypt_ex(const X509_ALGOR *algor, const char *pass, int passlen,
/// const unsigned char *in, int inlen, unsigned char **data, int *datalen, int en_de,
/// OSSL_LIB_CTX *libctx, const char *propq)` — `crypto/pkcs12/p12_decr.c:19-123`.
///
/// The answer is a fresh `OPENSSL_malloc`ed buffer on success and NULL otherwise; the caller
/// owns it. `data`/`datalen` are optional out-parameters carrying the same buffer and its
/// length.
///
/// # Safety
///
/// `algor` must be a live `X509_ALGOR`; `pass` must be NULL or a string of `passlen` bytes (or
/// `passlen == -1`); `in` must be readable for `inlen` bytes; `data`/`datalen` must each be NULL
/// or writable for their type; `libctx`/`propq` are the PBE lookup's.
#[no_mangle]
pub unsafe extern "C" fn PKCS12_pbe_crypt_ex(
    algor: *const X509Algor,
    pass: *const c_char,
    passlen: c_int,
    in_: *const c_uchar,
    inlen: c_int,
    data: *mut *mut c_uchar,
    datalen: *mut c_int,
    en_de: c_int,
    libctx: *mut c_void,
    propq: *const c_char,
) -> *mut c_uchar {
    let mut out: *mut c_uchar = ptr::null_mut();
    let mut i: c_int = 0;
    // SAFETY: no preconditions.
    let ctx = EVP_CIPHER_CTX_new();
    let mut mac_len: c_int = 0;

    if ctx.is_null() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::PKCS12_32) };
        // SAFETY: `ctx` is NULL.
        unsafe { EVP_CIPHER_CTX_free(ctx) };
        return out;
    }

    /* SAFETY: `algor` is live and its `algorithm`/`parameter` are its own; `ctx` is fresh. */
    let inited = unsafe {
        EVP_PBE_CipherInit_ex(
            (*algor).algorithm,
            pass,
            passlen,
            (*algor).parameter,
            ctx,
            en_de,
            libctx,
            propq,
        )
    };
    if inited == 0 {
        // SAFETY: `ctx` is live.
        unsafe { EVP_CIPHER_CTX_free(ctx) };
        return out;
    }

    // SAFETY: `ctx` is live.
    let block_size = unsafe { EVP_CIPHER_CTX_get_block_size(ctx) };
    if block_size == 0 {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::PKCS12_50) };
        // SAFETY: `ctx` is live.
        unsafe { EVP_CIPHER_CTX_free(ctx) };
        return out;
    }

    let mut max_out_len = inlen + block_size;
    /* SAFETY: `ctx` is live. */
    let with_mac = (unsafe { EVP_CIPHER_get_flags(EVP_CIPHER_CTX_get0_cipher(ctx)) }
        & EVP_CIPH_FLAG_CIPHER_WITH_MAC)
        != 0;
    let mut inlen = inlen;
    if with_mac {
        // SAFETY: `ctx` is live and `mac_len` is this frame's writable slot.
        if unsafe { EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_TLS1_AAD, 0, (&raw mut mac_len).cast()) }
            <= 0
        {
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&err_sites::PKCS12_60) };
            // SAFETY: `ctx` is live.
            unsafe { EVP_CIPHER_CTX_free(ctx) };
            return out;
        }
        // SAFETY: `ctx` is live.
        if unsafe { EVP_CIPHER_CTX_is_encrypting(ctx) } != 0 {
            max_out_len += mac_len;
        } else {
            if inlen < mac_len {
                // SAFETY: a compile-time-constant site.
                unsafe { raise_site(&err_sites::PKCS12_68) };
                // SAFETY: `ctx` is live.
                unsafe { EVP_CIPHER_CTX_free(ctx) };
                return out;
            }
            inlen -= mac_len;
            // SAFETY: `ctx` is live; the tail of `in_` is the tag the caller supplied.
            if unsafe {
                EVP_CIPHER_CTX_ctrl(
                    ctx,
                    EVP_CTRL_AEAD_SET_TAG,
                    mac_len,
                    in_.add(inlen as usize).cast_mut().cast(),
                )
            } <= 0
            {
                // SAFETY: a compile-time-constant site.
                unsafe { raise_site(&err_sites::PKCS12_75) };
                // SAFETY: `ctx` is live.
                unsafe { EVP_CIPHER_CTX_free(ctx) };
                return out;
            }
        }
    }

    /* `CRYPTO_zalloc` is the allocator `OPENSSL_zalloc` names; `max_out_len` is positive. */
    out = CRYPTO_zalloc(max_out_len.max(0) as usize, FILE.as_ptr(), 81).cast();
    if out.is_null() {
        // SAFETY: `ctx` is live.
        unsafe { EVP_CIPHER_CTX_free(ctx) };
        return out;
    }

    // SAFETY: `ctx` is live; `out` has `max_out_len` bytes; `in_`/`inlen` are the caller's.
    if unsafe { EVP_CipherUpdate(ctx, out, &raw mut i, in_, inlen) } == 0 {
        // SAFETY: `out` is this call's own buffer.
        unsafe { CRYPTO_free(out.cast(), FILE.as_ptr(), 85) };
        out = ptr::null_mut();
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::PKCS12_87) };
        // SAFETY: `ctx` is live.
        unsafe { EVP_CIPHER_CTX_free(ctx) };
        return out;
    }
    let mut outlen = i;
    // SAFETY: `ctx` is live; `out + i` is inside the buffer.
    if unsafe { EVP_CipherFinal_ex(ctx, out.add(i as usize), &raw mut i) } == 0 {
        // SAFETY: `out` is this call's own buffer.
        unsafe { CRYPTO_free(out.cast(), FILE.as_ptr(), 92) };
        out = ptr::null_mut();
        let msg = if passlen == 0 {
            c"empty password"
        } else {
            c"maybe wrong password"
        };
        // SAFETY: a compile-time-constant site; the message is NUL-terminated and static.
        unsafe { raise_site_data(&err_sites::PKCS12_95, msg.as_ptr()) };
        // SAFETY: `ctx` is live.
        unsafe { EVP_CIPHER_CTX_free(ctx) };
        return out;
    }
    outlen += i;
    if with_mac {
        // SAFETY: `ctx` is live.
        if unsafe { EVP_CIPHER_CTX_is_encrypting(ctx) } != 0 {
            // SAFETY: `ctx` is live; `out + outlen` is inside the buffer.
            if unsafe {
                EVP_CIPHER_CTX_ctrl(
                    ctx,
                    EVP_CTRL_AEAD_GET_TAG,
                    mac_len,
                    out.add(outlen as usize).cast(),
                )
            } <= 0
            {
                // SAFETY: `out` is this call's own buffer.
                unsafe { CRYPTO_free(out.cast(), FILE.as_ptr(), 105) };
                out = ptr::null_mut();
                // SAFETY: a compile-time-constant site.
                unsafe { raise_site(&err_sites::PKCS12_110) };
                // SAFETY: `ctx` is live.
                unsafe { EVP_CIPHER_CTX_free(ctx) };
                return out;
            }
            outlen += mac_len;
        }
    }
    if !datalen.is_null() {
        // SAFETY: `datalen` is this call's writable out-slot.
        unsafe { *datalen = outlen };
    }
    if !data.is_null() {
        // SAFETY: `data` is this call's writable out-slot.
        unsafe { *data = out };
    }
    // SAFETY: `ctx` is live.
    unsafe { EVP_CIPHER_CTX_free(ctx) };
    out
}

/// `unsigned char *PKCS12_pbe_crypt(const X509_ALGOR *algor, const char *pass, int passlen,
/// const unsigned char *in, int inlen, unsigned char **data, int *datalen, int en_de)` —
/// `crypto/pkcs12/p12_decr.c:125-132`.
///
/// # Safety
/// As [`PKCS12_pbe_crypt_ex`], without the context arguments.
#[no_mangle]
pub unsafe extern "C" fn PKCS12_pbe_crypt(
    algor: *const X509Algor,
    pass: *const c_char,
    passlen: c_int,
    in_: *const c_uchar,
    inlen: c_int,
    data: *mut *mut c_uchar,
    datalen: *mut c_int,
    en_de: c_int,
) -> *mut c_uchar {
    // SAFETY: the arguments are forwarded under this function's contract, with no context.
    unsafe {
        PKCS12_pbe_crypt_ex(
            algor,
            pass,
            passlen,
            in_,
            inlen,
            data,
            datalen,
            en_de,
            ptr::null_mut(),
            ptr::null(),
        )
    }
}

/// `void *PKCS12_item_decrypt_d2i_ex(const X509_ALGOR *algor, const ASN1_ITEM *it,
/// const char *pass, int passlen, const ASN1_OCTET_STRING *oct, int zbuf, OSSL_LIB_CTX *libctx,
/// const char *propq)` — `crypto/pkcs12/p12_decr.c:139-173`.
///
/// The decrypted buffer is Zeroed before it is released when `zbuf` is set, and the decode
/// failure raises `PKCS12_R_DECODE_ERROR` **after** that cleanse — the order the authority
/// spells.
///
/// # Safety
/// `algor` must be live; `it` must be the item the plaintext is; `pass`/`passlen` are the PBE
/// password; `oct` must be live; `libctx`/`propq` are the PBE lookup's.
#[no_mangle]
pub unsafe extern "C" fn PKCS12_item_decrypt_d2i_ex(
    algor: *const X509Algor,
    it: *const Asn1Item,
    pass: *const c_char,
    passlen: c_int,
    oct: *const Asn1String,
    zbuf: c_int,
    libctx: *mut c_void,
    propq: *const c_char,
) -> *mut c_void {
    if oct.is_null() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::PKCS12_151) };
        return ptr::null_mut();
    }
    let mut out: *mut c_uchar = ptr::null_mut();
    let mut outlen: c_int = 0;
    // SAFETY: `algor`/`oct` are live and the out-slots are this frame's.
    let crypted = unsafe {
        PKCS12_pbe_crypt_ex(
            algor,
            pass,
            passlen,
            (*oct).data,
            (*oct).length,
            &raw mut out,
            &raw mut outlen,
            0,
            libctx,
            propq,
        )
    };
    if crypted.is_null() {
        return ptr::null_mut();
    }
    let mut p: *const c_uchar = out;
    /* The authority's `OSSL_TRACE_BEGIN(PKCS12_DECRYPT)` block is a no-op on a build without
     * tracing, and reproducing the trace output is not part of this crate's surface. */
    // SAFETY: `p` is the buffer `out` points at and `it` is the caller's item.
    let ret = unsafe { ASN1_item_d2i(ptr::null_mut(), &raw mut p, c_long::from(outlen), it) };
    if zbuf != 0 {
        // SAFETY: `out` is this call's own buffer of `outlen` bytes.
        unsafe { OPENSSL_cleanse(out.cast(), outlen.max(0) as usize) };
    }
    if ret.is_null() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::PKCS12_170) };
    }
    // SAFETY: `out` is this call's own buffer.
    unsafe { CRYPTO_free(out.cast(), FILE.as_ptr(), 171) };
    ret
}

/// `void *PKCS12_item_decrypt_d2i(const X509_ALGOR *algor, const ASN1_ITEM *it, const char *pass,
/// int passlen, const ASN1_OCTET_STRING *oct, int zbuf)` — `crypto/pkcs12/p12_decr.c:175-181`.
///
/// # Safety
/// As [`PKCS12_item_decrypt_d2i_ex`], without the context arguments.
#[no_mangle]
pub unsafe extern "C" fn PKCS12_item_decrypt_d2i(
    algor: *const X509Algor,
    it: *const Asn1Item,
    pass: *const c_char,
    passlen: c_int,
    oct: *const Asn1String,
    zbuf: c_int,
) -> *mut c_void {
    // SAFETY: the arguments are forwarded under this function's contract, with no context.
    unsafe {
        PKCS12_item_decrypt_d2i_ex(
            algor,
            it,
            pass,
            passlen,
            oct,
            zbuf,
            ptr::null_mut(),
            ptr::null(),
        )
    }
}

/// `ASN1_OCTET_STRING *PKCS12_item_i2d_encrypt_ex(X509_ALGOR *algor, const ASN1_ITEM *it,
/// const char *pass, int passlen, void *obj, int zbuf, OSSL_LIB_CTX *ctx,
/// const char *propq)` — `crypto/pkcs12/p12_decr.c:188-221`.
///
/// The encoded plaintext is Zeroed before release when `zbuf` is set, and the answer is a fresh
/// `ASN1_OCTET_STRING` the caller owns.
///
/// # Safety
/// `algor` must be live; `it` must be the item `obj` is; `pass`/`passlen` are the PBE password;
/// `obj` must be a live value of `it`; `ctx`/`propq` are the PBE lookup's.
#[no_mangle]
pub unsafe extern "C" fn PKCS12_item_i2d_encrypt_ex(
    algor: *mut X509Algor,
    it: *const Asn1Item,
    pass: *const c_char,
    passlen: c_int,
    obj: *mut c_void,
    zbuf: c_int,
    ctx: *mut c_void,
    propq: *const c_char,
) -> *mut Asn1String {
    // SAFETY: no preconditions.
    let oct = ASN1_OCTET_STRING_new();
    if oct.is_null() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::PKCS12_200) };
        return ptr::null_mut();
    }
    let mut in_: *mut c_uchar = ptr::null_mut();
    // SAFETY: `obj` is live and `it` is the caller's item.
    let inlen = unsafe { ASN1_item_i2d(obj, &raw mut in_, it) };
    if in_.is_null() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::PKCS12_205) };
        // SAFETY: `oct` is this call's own.
        unsafe { ASN1_OCTET_STRING_free(oct) };
        return ptr::null_mut();
    }
    // SAFETY: `algor` is live; `oct` is live, so its `data`/`length` slots are writable; `in_`
    // is readable for `inlen` bytes.
    let crypted = unsafe {
        PKCS12_pbe_crypt_ex(
            algor,
            pass,
            passlen,
            in_,
            inlen,
            &raw mut (*oct).data,
            &raw mut (*oct).length,
            1,
            ctx,
            propq,
        )
    };
    if crypted.is_null() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::PKCS12_210) };
        // SAFETY: `in_` is this call's own encoding.
        unsafe { CRYPTO_free(in_.cast(), FILE.as_ptr(), 211) };
        // SAFETY: `oct` is this call's own.
        unsafe { ASN1_OCTET_STRING_free(oct) };
        return ptr::null_mut();
    }
    if zbuf != 0 {
        // SAFETY: `in_` is this call's own encoding of `inlen` bytes.
        unsafe { OPENSSL_cleanse(in_.cast(), inlen.max(0) as usize) };
    }
    // SAFETY: `in_` is this call's own encoding.
    unsafe { CRYPTO_free(in_.cast(), FILE.as_ptr(), 216) };
    oct
}

/// `ASN1_OCTET_STRING *PKCS12_item_i2d_encrypt(X509_ALGOR *algor, const ASN1_ITEM *it,
/// const char *pass, int passlen, void *obj, int zbuf)` — `crypto/pkcs12/p12_decr.c:223-229`.
///
/// # Safety
/// As [`PKCS12_item_i2d_encrypt_ex`], without the context arguments.
#[no_mangle]
pub unsafe extern "C" fn PKCS12_item_i2d_encrypt(
    algor: *mut X509Algor,
    it: *const Asn1Item,
    pass: *const c_char,
    passlen: c_int,
    obj: *mut c_void,
    zbuf: c_int,
) -> *mut Asn1String {
    // SAFETY: the arguments are forwarded under this function's contract, with no context.
    unsafe {
        PKCS12_item_i2d_encrypt_ex(
            algor,
            it,
            pass,
            passlen,
            obj,
            zbuf,
            ptr::null_mut(),
            ptr::null(),
        )
    }
}
