//! `crypto/pem/pem_pkey.c` — the `pem.h` `EVP_PKEY` reader and writer spellings Phase 8.9's read
//! half began (D369) and Phase 13.7 completes.
//!
//! ## The unit, and the two halves
//!
//! `crypto/pem/pem_pkey.c` is 452 lines and **16 exports**. The read half is the
//! `EVP_PKEY` reader: [`pem_read_bio_key`] tries a decoder first and the legacy
//! decoders second, and the four `PEM_read_bio_*`/four `PEM_read_*` spellings plus the
//! two `PEM_read_bio_Parameters*` ones are that body with a selection. D367 measured the
//! legacy leg's closure and named its last missing callee — `ossl_d2i_PUBKEY_legacy`
//! (`crypto/pem/pem_pkey.c:186`) — and D368 landed every other leg
//! (`ossl_d2i_PrivateKey_legacy`, `evp_pkcs82pkey_legacy`, `PKCS8_decrypt`). D369 lands
//! that internal, so the read half is whole.
//!
//! The write half is five spellings whose bodies are `crypto/pem/pem_local.h`'s
//! `IMPLEMENT_PEM_provided_write_body_*` macro expansions — `PEM_write_bio_PrivateKey[_ex]`,
//! `PEM_write_PrivateKey[_ex]` and `PEM_write_bio_Parameters`, `crypto/pem/pem_pkey.c:318-451`.
//! Their `legacy:` label falls through to `PEM_write_bio_PKCS8PrivateKey` (`crypto/pem/pem_pk8.c`)
//! and [`PEM_write_bio_PrivateKey_traditional`]. Phase 13.7 lands all five: the two dependencies
//! name — `pem_pk8.c`'s four writers in `src/pem/pem_pk8.rs`, and the traditional writer above —
//! are both in the crate, so nothing in the fall-through is missing.
//!
//! ## The decoder-first leg, and what this crate's empty decoder registry means
//!
//! [`pem_read_bio_key_decoder`] builds an `OSSL_DECODER_CTX` for `"PEM"` input and walks
//! `OSSL_DECODER_from_bio` over the BIO. This crate publishes **no provider decoder**
//! (`src/decoder_meth.rs`: every `OSSL_OP_DECODER` row is unimplemented here), so that
//! context carries no instances and the walk fails on its first iteration — which is
//! exactly what the authority does when no decoder is available. The function then returns
//! NULL and [`pem_read_bio_key`] rewinds the BIO and runs the legacy leg, which is the
//! authority's own fallback and the one every key this crate can build decodes through.
//! That is `docs/SECURITY_DIVERGENCE_POLICY.md`'s **D-DECODER-ABSENT-1**: a
//! decoder-dependent reader answers the legacy leg's answer, not the provider decoder's.
//!
//! **A measured consequence for `PEM_read_bio_Parameters[_ex]`.** Those two select
//! `EVP_PKEY_KEY_PARAMETERS`, and on this authority's revision the *only* arm that can answer
//! is the decoder leg: the legacy parameters arm is guarded by
//! `(selection & EVP_PKEY_KEYPAIR) == 0` (`:471`), and `EVP_PKEY_KEYPAIR` is
//! `EVP_PKEY_PUBLIC_KEY | SELECT_PRIVATE_KEY`, which contains every parameter bit — so the
//! guard is false for every parameter selection. Measured: on a written
//! `-----BEGIN DH PARAMETERS-----` block the authority answers a key (`EVP_PKEY_get_id` 28,
//! `EVP_PKEY_get0_DH` non-NULL) and this crate answers NULL. The two names are landed rather
//! than withheld because their body is whole and the difference is the documented
//! decoder-absence, not a stub; the arm is left to the decoder-dependent divergence record.
//!
//! ## The raise sites
//!
//! `crypto/pem/pem_pkey.c` is already in `gen_err_raise_sites.py`'s covered set (stem
//! `PEM_PKEY`): the read half raises `PEM_R_UNSUPPORTED_KEY_COMPONENTS` (`:87`),
//! `PEM_R_BAD_PASSWORD_READ` (`:161`) and `ERR_R_ASN1_LIB` (`:209`), the two stdio
//! `PEM_read_*_ex` spellings raise `ERR_R_BUF_LIB` (`:288`, `:418`), and the write half raises
//! `ERR_R_BUF_LIB` (`:439`), `PEM_R_UNSUPPORTED_PUBLIC_KEY_TYPE` (`:360`) and the traditional
//! writer's. No site is added by 13.7.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::cell::Cell;
use core::ffi::{c_char, c_int, c_long, c_uchar, c_ulong, c_void};
use core::ptr;

use crate::asn1::d2i_pr::ossl_d2i_PrivateKey_legacy;
use crate::asn1::i2d_evp::i2d_PrivateKey;
use crate::asn1::layout::I2dOfVoid;
use crate::asn1::p8_pkey::{d2i_PKCS8_PRIV_KEY_INFO, PKCS8_PRIV_KEY_INFO_free};
use crate::asn1::x_sig::{d2i_X509_SIG, X509_SIG_free};
use crate::decoder_lib::OSSL_DECODER_from_bio;
use crate::decoder_meth::OSSL_DECODER_CTX_free;
use crate::decoder_pkey::{OSSL_DECODER_CTX_new_for_pkey, OSSL_DECODER_CTX_set_pem_password_cb};
use crate::encoder_lib::{OSSL_ENCODER_CTX_get_num_encoders, OSSL_ENCODER_to_bio};
use crate::encoder_meth::OSSL_ENCODER_CTX_free;
use crate::encoder_pkey::{
    OSSL_ENCODER_CTX_new_for_pkey, OSSL_ENCODER_CTX_set_cipher, OSSL_ENCODER_CTX_set_passphrase,
    OSSL_ENCODER_CTX_set_pem_password_cb,
};
use crate::evp::cipher::{EVP_CIPHER_get0_name, EvpCipher};
use crate::evp::evp_pkey::evp_pkcs82pkey_legacy;
use crate::evp::keymgmt_lib::evp_keymgmt_util_has;
use crate::evp::pem_bridge::{ossl_pem_check_suffix, PemPasswordCb};
use crate::evp::pkey::{
    evp_pkey_copy_downgraded, evp_pkey_is_provided, EVP_PKEY_free, EVP_PKEY_new,
    EVP_PKEY_set_type_str, EvpPkey,
};
use crate::evp::pkey_asn1::EVP_PKEY_asn1_find_str;
use crate::passphrase::{
    ossl_pw_clear_passphrase_data, ossl_pw_enable_passphrase_caching, ossl_pw_pem_password,
    ossl_pw_set_pem_password_cb, OsslPassphraseData, PassphraseUnion,
};
use crate::pem::pem_lib::{
    PEM_ASN1_write_bio, PEM_bytes_read_bio, PEM_bytes_read_bio_secmem, PEM_def_callback,
    PEM_BUFSIZE, PEM_STRING_EVP_PKEY, PEM_STRING_PARAMETERS, PEM_STRING_PKCS8, PEM_STRING_PKCS8INF,
    PEM_STRING_PUBLIC,
};
use crate::pem::pem_pk8::PEM_write_bio_PKCS8PrivateKey;
use crate::pkcs12::p12_p8d::PKCS8_decrypt;
use crate::runtime::bio::bf_readbuff::BIO_f_readbuffer;
use crate::runtime::bio::bss_file::BIO_s_file;
use crate::runtime::bio::print::BIO_snprintf;
use crate::runtime::bio::{
    BIO_ctrl, BIO_free, BIO_new, BIO_new_fp, BIO_pop, BIO_push, Bio, BIO_CTRL_EOF, BIO_C_FILE_SEEK,
    BIO_C_FILE_TELL, BIO_C_SET_FILE_PTR, BIO_NOCLOSE,
};
use crate::runtime::err::{
    err_sites, peek_first_reason, raise_site, ERR_clear_last_mark, ERR_peek_last_error,
    ERR_pop_to_mark, ERR_set_mark,
};
use crate::runtime::secure::{CRYPTO_secure_clear_free, CRYPTO_secure_free};
use crate::x509::x_pubkey::ossl_d2i_PUBKEY_legacy;

unsafe extern "C" {
    /// The C library's `strcmp`, which the authority's two name tests are.
    fn strcmp(a: *const c_char, b: *const c_char) -> c_int;
    /// The C library's `strlen`, which the provided-write pass-phrase fallback calls when `u`
    /// stands in for a password string.
    fn strlen(s: *const c_char) -> usize;
}

/// The `OPENSSL_FILE` string for this unit's `OPENSSL_secure_free`/`_secure_clear_free` macro
/// expansions, and the lines each expands at.
const FILE: &core::ffi::CStr = c"crypto/pem/pem_pkey.c";
/// `pem_read_bio_key_legacy`'s `OPENSSL_secure_free(nm)` (`:211`).
const LINE_SECURE_FREE_NM: c_int = 211;
/// `pem_read_bio_key_legacy`'s `OPENSSL_secure_clear_free(data, len)` (`:212`).
const LINE_SECURE_CLEAR_FREE_DATA: c_int = 212;

/// `ERR_RFLAG_COMMON` — `include/openssl/err.h`, the bit every common reason carries.
const ERR_RFLAG_COMMON: c_int = 0x2 << 18;
/// `ERR_R_UNSUPPORTED` (`err.h`): `(268 | ERR_RFLAG_COMMON)`. The reason
/// `pem_read_bio_key_decoder` retries on.
const ERR_R_UNSUPPORTED: c_int = 268 | ERR_RFLAG_COMMON;

/// `EVP_PKEY_KEY_PARAMETERS` — `include/openssl/evp.h:106`, `OSSL_KEYMGMT_SELECT_ALL_PARAMETERS`.
const EVP_PKEY_KEY_PARAMETERS: c_int = 0x04 | 0x80;
/// `EVP_PKEY_PUBLIC_KEY` — `include/openssl/evp.h:110`.
const EVP_PKEY_PUBLIC_KEY: c_int = EVP_PKEY_KEY_PARAMETERS | 0x02;
/// `EVP_PKEY_KEYPAIR` — `include/openssl/evp.h:112`.
const EVP_PKEY_KEYPAIR: c_int = EVP_PKEY_PUBLIC_KEY | 0x01;

/// A zeroed `struct ossl_passphrase_data_st`, as the authority's `= { 0 }` initialiser
/// leaves one. `type_` is 0, which is no member of the authority's enum, so a stray read is
/// a failure rather than a branch.
fn blank_passphrase_data() -> OsslPassphraseData {
    OsslPassphraseData {
        type_: 0,
        payload: PassphraseUnion {
            expl_passphrase: crate::passphrase::ExplPassphrase {
                passphrase_copy: ptr::null_mut(),
                passphrase_len: 0,
            },
        },
        flag_cache_passphrase: 0,
        cached_passphrase: ptr::null_mut(),
        cached_passphrase_len: 0,
    }
}

/// `BIO_tell(b)` — `bio.h`'s macro over `BIO_ctrl(BIO_C_FILE_TELL)`.
///
/// # Safety
///
/// `b` is a live BIO.
unsafe fn bio_tell(b: *mut Bio) -> c_int {
    // SAFETY: `b` is live per the contract.
    unsafe { BIO_ctrl(b, BIO_C_FILE_TELL, 0, ptr::null_mut()) as c_int }
}

/// `BIO_eof(b)` — `bio.h`'s macro over `BIO_ctrl(BIO_CTRL_EOF)`.
///
/// # Safety
///
/// `b` is a live BIO.
unsafe fn bio_eof(b: *mut Bio) -> c_int {
    // SAFETY: `b` is live per the contract.
    unsafe { BIO_ctrl(b, BIO_CTRL_EOF, 0, ptr::null_mut()) as c_int }
}

/// `BIO_seek(b, ofs)` — `bio.h`'s macro over `BIO_ctrl(BIO_C_FILE_SEEK)`.
///
/// # Safety
///
/// `b` is a live BIO.
unsafe fn bio_seek(b: *mut Bio, ofs: c_long) -> c_int {
    // SAFETY: `b` is live per the contract.
    unsafe { BIO_ctrl(b, BIO_C_FILE_SEEK, ofs, ptr::null_mut()) as c_int }
}

/// `BIO_set_fp(b, fp, c)` — `bio.h`'s macro over `BIO_ctrl(BIO_C_SET_FILE_PTR)`.
///
/// # Safety
///
/// `b` is a live BIO; `fp` is the caller's open `FILE *`.
unsafe fn bio_set_fp(b: *mut Bio, fp: *mut c_void, close_flag: c_long) {
    // SAFETY: `b` is live per the contract.
    unsafe { BIO_ctrl(b, BIO_C_SET_FILE_PTR, close_flag, fp) };
}

/// `static EVP_PKEY *pem_read_bio_key_decoder(BIO *bp, EVP_PKEY **x, pem_password_cb *cb,
/// void *u, OSSL_LIB_CTX *libctx, const char *propq, int selection)` —
/// `crypto/pem/pem_pkey.c:35-99`.
///
/// The walk retries while the BIO has more data and the last refusal was
/// `ERR_R_UNSUPPORTED`; any other refusal is final. `BIO_tell` must work, which the
/// authority relies on the read buffer for — so the first test is the caller's BIO
/// answering a position at all.
///
/// # Safety
///
/// `bp` is a live BIO; `x` is NULL or a writable key slot; `libctx` is NULL or live and
/// `propq` NULL or NUL-terminated.
#[allow(clippy::too_many_arguments)] // mirrors the authority's signature exactly
unsafe fn pem_read_bio_key_decoder(
    bp: *mut Bio,
    x: *mut *mut EvpPkey,
    cb: Option<PemPasswordCb>,
    u: *mut c_void,
    libctx: *mut c_void,
    propq: *const c_char,
    selection: c_int,
) -> *mut EvpPkey {
    let mut pkey: *mut EvpPkey = ptr::null_mut();

    /* We can depend on `BIO_tell()` thanks to the `BIO_f_readbuffer()`. */
    // SAFETY: `bp` is live per the contract.
    let mut pos = unsafe { bio_tell(bp) };
    if pos < 0 {
        return ptr::null_mut();
    }

    // SAFETY: the four strings are literals or NULL and the context is the caller's.
    let dctx = unsafe {
        OSSL_DECODER_CTX_new_for_pkey(
            &raw mut pkey,
            c"PEM".as_ptr(),
            ptr::null(),
            ptr::null(),
            selection,
            libctx,
            propq,
        )
    };
    if dctx.is_null() {
        return ptr::null_mut();
    }

    let cb = match cb {
        // SAFETY: `PEM_def_callback` takes the authority's `pem_password_cb` signature.
        None => Some(PEM_def_callback as PemPasswordCb),
        Some(f) => Some(f),
    };

    // SAFETY: `dctx` is live and `cb` is a live callback.
    if unsafe { OSSL_DECODER_CTX_set_pem_password_cb(dctx, cb, u) } == 0 {
        // SAFETY: `dctx` is this call's own live context; `pkey` is NULL here.
        unsafe { OSSL_DECODER_CTX_free(dctx) };
        return ptr::null_mut();
    }

    ERR_set_mark();
    loop {
        // SAFETY: `dctx` is live and `bp` is the caller's readable BIO.
        if unsafe { OSSL_DECODER_from_bio(dctx, bp) } != 0 && !pkey.is_null() {
            break;
        }
        // SAFETY: `bp` is live.
        let newpos = unsafe { bio_tell(bp) };
        // SAFETY: `bp` is live.
        if unsafe { bio_eof(bp) } != 0 || newpos < 0 || newpos <= pos {
            ERR_clear_last_mark();
            // SAFETY: `dctx` is this call's own live context.
            unsafe { OSSL_DECODER_CTX_free(dctx) };
            return ptr::null_mut();
        }
        if peek_first_reason() == ERR_R_UNSUPPORTED as c_ulong {
            /* unsupported PEM data, try again */
            ERR_pop_to_mark();
            ERR_set_mark();
        } else {
            /* other error, bail out */
            ERR_clear_last_mark();
            // SAFETY: `dctx` is this call's own live context.
            unsafe { OSSL_DECODER_CTX_free(dctx) };
            return ptr::null_mut();
        }
        pos = newpos;
    }
    ERR_pop_to_mark();

    /* if we were asked for a private key, the public key is optional */
    let selection = if (selection & 0x01) != 0 {
        selection & !0x02
    } else {
        selection
    };

    // SAFETY: `pkey` is live.
    if unsafe { evp_keymgmt_util_has(pkey, selection) } == 0 {
        // SAFETY: `pkey` is this call's own live key.
        unsafe { EVP_PKEY_free(pkey) };
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::PEM_PKEY_87) };
        // SAFETY: `dctx` is this call's own live context.
        unsafe { OSSL_DECODER_CTX_free(dctx) };
        return ptr::null_mut();
    }

    if !x.is_null() {
        // SAFETY: `x` is a live slot.
        unsafe {
            EVP_PKEY_free(*x);
            *x = pkey;
        }
    }

    // SAFETY: `dctx` is this call's own live context.
    unsafe { OSSL_DECODER_CTX_free(dctx) };
    pkey
}

/// `static EVP_PKEY *pem_read_bio_key_legacy(BIO *bp, EVP_PKEY **x, pem_password_cb *cb,
/// void *u, OSSL_LIB_CTX *libctx, const char *propq, int selection)` —
/// `crypto/pem/pem_pkey.c:101-214`.
///
/// Four arms, chosen by the `PEM` name the block carried: a `PRIVATE KEY` block is PKCS#8 v1,
/// an encrypted one is PKCS#8 and goes through a pass phrase, a `<TYPE> PRIVATE KEY` block is
/// the type-specific decode, and a public-key-only request falls back to
/// [`ossl_d2i_PUBKEY_legacy`]. The pass phrase buffer is cleansed on the way out and the name
/// and data buffers are the secure heap's.
///
/// # Safety
///
/// `bp` is a live BIO; `x` is NULL or a writable key slot; `libctx` is NULL or live and
/// `propq` NULL or NUL-terminated.
#[allow(clippy::too_many_arguments)] // mirrors the authority's signature exactly
unsafe fn pem_read_bio_key_legacy(
    bp: *mut Bio,
    x: *mut *mut EvpPkey,
    cb: Option<PemPasswordCb>,
    u: *mut c_void,
    libctx: *mut c_void,
    propq: *const c_char,
    selection: c_int,
) -> *mut EvpPkey {
    let mut nm: *mut c_char = ptr::null_mut();
    let mut p: *const c_uchar;
    let mut data: *mut c_uchar = ptr::null_mut();
    let mut len: c_long = 0;
    let mut ret: *mut EvpPkey = ptr::null_mut();

    ERR_set_mark(); /* not interested in PEM read errors */
    if (selection & 0x01) != 0 {
        // SAFETY: `bp` is live; the four out-parameters are this frame's slots and `cb`/`u`
        // are the caller's.
        if unsafe {
            PEM_bytes_read_bio_secmem(
                &raw mut data,
                &raw mut len,
                &raw mut nm,
                PEM_STRING_EVP_PKEY,
                bp,
                cb,
                u,
            )
        } == 0
        {
            ERR_pop_to_mark();
            return ptr::null_mut();
        }
    } else {
        let mut pem_string = PEM_STRING_PARAMETERS;

        if (selection & 0x02) != 0 {
            pem_string = PEM_STRING_PUBLIC;
        }
        // SAFETY: `bp` is live; the four out-parameters are this frame's slots.
        if unsafe {
            PEM_bytes_read_bio(
                &raw mut data,
                &raw mut len,
                &raw mut nm,
                pem_string,
                bp,
                cb,
                u,
            )
        } == 0
        {
            ERR_pop_to_mark();
            return ptr::null_mut();
        }
    }
    ERR_clear_last_mark();
    p = data;

    let mut to_err = false;
    'body: {
        // SAFETY: `nm` is NUL-terminated by the reader above.
        if unsafe { strcmp(nm, PEM_STRING_PKCS8INF) } == 0 {
            // SAFETY: `p` is this frame's cursor for `len` bytes.
            let p8inf = unsafe { d2i_PKCS8_PRIV_KEY_INFO(ptr::null_mut(), &raw mut p, len) };
            if p8inf.is_null() {
                break 'body;
            }
            // SAFETY: `p8inf` is live; the two strings are the caller's.
            ret = unsafe { evp_pkcs82pkey_legacy(p8inf, libctx, propq) };
            if !x.is_null() {
                // SAFETY: `x` is a live slot.
                unsafe {
                    EVP_PKEY_free(*x);
                    *x = ret;
                }
            }
            // SAFETY: `p8inf` is this call's own live value.
            unsafe { PKCS8_PRIV_KEY_INFO_free(p8inf) };
        } else if
        // SAFETY: `nm` is NUL-terminated by the reader above and the literal is a constant.
        unsafe { strcmp(nm, PEM_STRING_PKCS8) } == 0 {
            let mut psbuf = [0 as c_char; PEM_BUFSIZE as usize];
            // SAFETY: `p` is this frame's cursor for `len` bytes.
            let p8 = unsafe { d2i_X509_SIG(ptr::null_mut(), &raw mut p, len) };
            if p8.is_null() {
                break 'body;
            }
            let klen = match cb {
                // SAFETY: the callback is the caller's, with the authority's signature.
                Some(f) => unsafe { f(psbuf.as_mut_ptr(), PEM_BUFSIZE, 0, u) },
                // SAFETY: `PEM_def_callback` takes the authority's `pem_password_cb` signature.
                None => unsafe { PEM_def_callback(psbuf.as_mut_ptr(), PEM_BUFSIZE, 0, u) },
            };
            if klen < 0 {
                // SAFETY: a compile-time-constant site.
                unsafe { raise_site(&err_sites::PEM_PKEY_161) };
                // SAFETY: `p8` is this call's own live value.
                unsafe { X509_SIG_free(p8) };
                /* The authority's `goto err`: the p8err raise is skipped. */
                to_err = true;
                break 'body;
            }
            // SAFETY: `p8` is live; the pass phrase is this frame's buffer of `klen` bytes.
            let p8inf = unsafe { PKCS8_decrypt(p8, psbuf.as_ptr(), klen) };
            // SAFETY: `p8` is this call's own live value.
            unsafe { X509_SIG_free(p8) };
            // SAFETY: `psbuf` is this frame's `PEM_BUFSIZE`-byte buffer, `klen` bytes used.
            unsafe {
                crate::runtime::mem::OPENSSL_cleanse(
                    psbuf.as_mut_ptr().cast::<c_void>(),
                    klen as usize,
                )
            };
            if p8inf.is_null() {
                break 'body;
            }
            // SAFETY: `p8inf` is live; the two strings are the caller's.
            ret = unsafe { evp_pkcs82pkey_legacy(p8inf, libctx, propq) };
            if !x.is_null() {
                // SAFETY: `x` is a live slot.
                unsafe {
                    EVP_PKEY_free(*x);
                    *x = ret;
                }
            }
            // SAFETY: `p8inf` is this call's own live value.
            unsafe { PKCS8_PRIV_KEY_INFO_free(p8inf) };
        } else {
            // SAFETY: `nm` and the literal are NUL-terminated.
            let slen = unsafe { ossl_pem_check_suffix(nm, c"PRIVATE KEY".as_ptr()) };
            if slen > 0 {
                // SAFETY: `nm` is NUL-terminated and `slen` its checked suffix length.
                let ameth = unsafe { EVP_PKEY_asn1_find_str(ptr::null_mut(), nm, slen) };
                if ameth.is_null() {
                    break 'body;
                }
                // SAFETY: `ameth` is a live method object.
                let (old_priv_decode, pkey_id) =
                    unsafe { ((*ameth).old_priv_decode, (*ameth).pkey_id) };
                if old_priv_decode.is_none() {
                    break 'body;
                }
                // SAFETY: `p` is this frame's cursor for `len` bytes; `x` is the caller's.
                ret = unsafe {
                    ossl_d2i_PrivateKey_legacy(pkey_id, x, &raw mut p, len, libctx, propq)
                };
            } else if (selection & 0x01) == 0 && (selection & 0x02) != 0 {
                /* Trying legacy PUBKEY decoding only if we do not want private key. */
                // SAFETY: `p` is this frame's cursor for `len` bytes; `x` is the caller's.
                ret = unsafe { ossl_d2i_PUBKEY_legacy(x, &raw mut p, len) };
            } else {
                // SAFETY: `nm` and the literal are NUL-terminated.
                let slen2 = unsafe { ossl_pem_check_suffix(nm, c"PARAMETERS".as_ptr()) };
                if (selection & EVP_PKEY_KEYPAIR) == 0 && slen2 > 0 {
                    /* Trying legacy params decoding only if we do not want a key. */
                    // SAFETY: no preconditions.
                    ret = unsafe { EVP_PKEY_new() };
                    if ret.is_null() {
                        /* The authority's `goto err`. */
                        to_err = true;
                        break 'body;
                    }
                    // SAFETY: `ret` is live and `nm` is NUL-terminated with suffix `slen2`.
                    let typed = unsafe { EVP_PKEY_set_type_str(ret, nm, slen2) };
                    let param_decode = if typed != 0 {
                        // SAFETY: `ret` is live.
                        let ameth = unsafe { (*ret).ameth };
                        if ameth.is_null() {
                            None
                        } else {
                            // SAFETY: `ameth` is the key's own method table.
                            unsafe { (*ameth).param_decode }
                        }
                    } else {
                        None
                    };
                    let ok = match param_decode {
                        // SAFETY: the callback is the key's own; `p` is this frame's cursor.
                        Some(dec) => (unsafe { dec(ret, &raw mut p, len as c_int) }) != 0,
                        None => false,
                    };
                    if !ok {
                        // SAFETY: `ret` is this call's own live key.
                        unsafe { EVP_PKEY_free(ret) };
                        ret = ptr::null_mut();
                        /* The authority's `goto err`. */
                        to_err = true;
                        break 'body;
                    }
                    if !x.is_null() {
                        // SAFETY: `x` is a live slot.
                        unsafe {
                            EVP_PKEY_free(*x);
                            *x = ret;
                        }
                    }
                }
            }
        }
    }

    if !to_err && ret.is_null() && ERR_peek_last_error() == 0 {
        /* ensure some error is reported but do not hide the real one */
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::PEM_PKEY_209) };
    }
    // SAFETY: the two buffers are this call's own.
    unsafe { legacy_err_out(ret, data, len, nm) };
    ret
}

/// The authority's `err:` label of [`pem_read_bio_key_legacy`] — `pem_pkey.c:210-213` — as the
/// release half the several early exits share.
///
/// The name buffer is released with `OPENSSL_secure_free` and the data buffer with
/// `OPENSSL_secure_clear_free`, both on the secure heap because
/// `PEM_bytes_read_bio_secmem` allocated them there.
///
/// # Safety
///
/// `nm` is NULL or the name buffer; `data` is NULL or `len` bytes; both came from the
/// matching reader.
unsafe fn legacy_err_out(_ret: *mut EvpPkey, data: *mut c_uchar, len: c_long, nm: *mut c_char) {
    // SAFETY: `nm` is NULL or a secure-heap buffer from the reader.
    unsafe { CRYPTO_secure_free(nm.cast::<c_void>(), FILE.as_ptr(), LINE_SECURE_FREE_NM) };
    // SAFETY: `data` is NULL or a secure-heap buffer of `len` bytes.
    unsafe {
        CRYPTO_secure_clear_free(
            data.cast::<c_void>(),
            len.max(0) as usize,
            FILE.as_ptr(),
            LINE_SECURE_CLEAR_FREE_DATA,
        )
    };
}

/// `static EVP_PKEY *pem_read_bio_key(BIO *bp, EVP_PKEY **x, pem_password_cb *cb, void *u,
/// OSSL_LIB_CTX *libctx, const char *propq, int selection)` — `crypto/pem/pem_pkey.c:216-263`.
///
/// The reader every export here is one call to: a BIO that cannot report a position gets a
/// read buffer pushed on it, the callback is defaulted, pass-phrase caching is enabled for
/// the duration, and the decoder leg is tried first with the legacy leg as the fallback —
/// which is why a failed decoder leg leaves the mark cleared rather than popped.
///
/// # Safety
///
/// `bp` is a live BIO; `x` is NULL or a writable key slot; `libctx` is NULL or live and
/// `propq` NULL or NUL-terminated.
#[allow(clippy::too_many_arguments)] // mirrors the authority's signature exactly
unsafe fn pem_read_bio_key(
    bp: *mut Bio,
    x: *mut *mut EvpPkey,
    cb: Option<PemPasswordCb>,
    u: *mut c_void,
    libctx: *mut c_void,
    propq: *const c_char,
    selection: c_int,
) -> *mut EvpPkey {
    let mut bp = bp;
    let mut new_bio: *mut Bio = ptr::null_mut();
    let mut pwdata = blank_passphrase_data();

    // SAFETY: `bp` is a live BIO per the contract.
    let mut pos = unsafe { bio_tell(bp) };
    if pos < 0 {
        // SAFETY: `BIO_f_readbuffer()` answers a static method.
        new_bio = unsafe { BIO_new(BIO_f_readbuffer()) };
        if new_bio.is_null() {
            return ptr::null_mut();
        }
        // SAFETY: `new_bio` and `bp` are live BIOs.
        bp = unsafe { BIO_push(new_bio, bp) };
        // SAFETY: `bp` is live.
        pos = unsafe { bio_tell(bp) };
    }

    let cb = match cb {
        // SAFETY: `PEM_def_callback` takes the authority's `pem_password_cb` signature.
        None => Some(PEM_def_callback as PemPasswordCb),
        Some(f) => Some(f),
    };

    // SAFETY: `pwdata` is this frame's live struct and `cb` is live.
    if unsafe { ossl_pw_set_pem_password_cb(&raw mut pwdata, cb, u) } == 0
        // SAFETY: `pwdata` is this frame's live struct.
        || unsafe { ossl_pw_enable_passphrase_caching(&raw mut pwdata) } == 0
    {
        // SAFETY: `pwdata` is this frame's live struct; `new_bio` is NULL or this call's own.
        unsafe {
            ossl_pw_clear_passphrase_data(&raw mut pwdata);
            if !new_bio.is_null() {
                BIO_pop(new_bio);
                BIO_free(new_bio);
            }
        }
        return ptr::null_mut();
    }

    ERR_set_mark();
    // SAFETY: `bp` is live, `x` is the caller's, and `pwdata` is this frame's.
    let mut ret = unsafe {
        pem_read_bio_key_decoder(
            bp,
            x,
            Some(ossl_pw_pem_password as PemPasswordCb),
            (&raw mut pwdata).cast::<c_void>(),
            libctx,
            propq,
            selection,
        )
    };
    if !ret.is_null() {
        ERR_pop_to_mark();
    } else {
        /* The authority's `BIO_seek` runs only on this arm, so a decoded key never rewinds. */
        // SAFETY: `bp` is live.
        let seek_failed = unsafe { bio_seek(bp, pos as c_long) } < 0;
        if !seek_failed {
            // SAFETY: `bp` is live, `x` is the caller's, and `pwdata` is this frame's.
            ret = unsafe {
                pem_read_bio_key_legacy(
                    bp,
                    x,
                    Some(ossl_pw_pem_password as PemPasswordCb),
                    (&raw mut pwdata).cast::<c_void>(),
                    libctx,
                    propq,
                    selection,
                )
            };
        }
        if ret.is_null() {
            ERR_clear_last_mark();
        } else {
            ERR_pop_to_mark();
        }
    }

    // SAFETY: `pwdata` is this frame's live struct; `new_bio` is NULL or this call's own.
    unsafe {
        ossl_pw_clear_passphrase_data(&raw mut pwdata);
        if !new_bio.is_null() {
            BIO_pop(new_bio);
            BIO_free(new_bio);
        }
    }
    ret
}

/// `static int no_password_cb(char *buf, int num, int rwflag, void *userdata)` —
/// `crypto/pem/pem_pkey.c:372-375`.
///
/// `PEM_read_bio_Parameters(_ex)` should never ask for a password: any attempt fails.
///
/// # Safety
///
/// The authority's `pem_password_cb` signature; this arm reads nothing.
unsafe extern "C" fn no_password_cb(
    _buf: *mut c_char,
    _num: c_int,
    _rwflag: c_int,
    _userdata: *mut c_void,
) -> c_int {
    -1
}

/// `EVP_PKEY *PEM_read_bio_PUBKEY_ex(BIO *bp, EVP_PKEY **x, pem_password_cb *cb, void *u,
/// OSSL_LIB_CTX *libctx, const char *propq)` — `crypto/pem/pem_pkey.c:265-271`.
///
/// # Safety
///
/// `bp` is a live BIO; `x` is NULL or a writable key slot; `libctx` is NULL or live and
/// `propq` NULL or NUL-terminated.
#[no_mangle]
pub unsafe extern "C" fn PEM_read_bio_PUBKEY_ex(
    bp: *mut Bio,
    x: *mut *mut EvpPkey,
    cb: Option<PemPasswordCb>,
    u: *mut c_void,
    libctx: *mut c_void,
    propq: *const c_char,
) -> *mut EvpPkey {
    // SAFETY: the caller's contract.
    unsafe { pem_read_bio_key(bp, x, cb, u, libctx, propq, EVP_PKEY_PUBLIC_KEY) }
}

/// `EVP_PKEY *PEM_read_bio_PUBKEY(BIO *bp, EVP_PKEY **x, pem_password_cb *cb, void *u)` —
/// `crypto/pem/pem_pkey.c:273-277`.
///
/// # Safety
///
/// `bp` is a live BIO; `x` is NULL or a writable key slot.
#[no_mangle]
pub unsafe extern "C" fn PEM_read_bio_PUBKEY(
    bp: *mut Bio,
    x: *mut *mut EvpPkey,
    cb: Option<PemPasswordCb>,
    u: *mut c_void,
) -> *mut EvpPkey {
    // SAFETY: the caller's contract.
    unsafe { PEM_read_bio_PUBKEY_ex(bp, x, cb, u, ptr::null_mut(), ptr::null()) }
}

/// `EVP_PKEY *PEM_read_PUBKEY_ex(FILE *fp, EVP_PKEY **x, pem_password_cb *cb, void *u,
/// OSSL_LIB_CTX *libctx, const char *propq)` — `crypto/pem/pem_pkey.c:280-295`.
///
/// # Safety
///
/// `fp` is the caller's open `FILE *`; `x` is NULL or a writable key slot; `libctx` is NULL
/// or live and `propq` NULL or NUL-terminated.
#[no_mangle]
pub unsafe extern "C" fn PEM_read_PUBKEY_ex(
    fp: *mut c_void,
    x: *mut *mut EvpPkey,
    cb: Option<PemPasswordCb>,
    u: *mut c_void,
    libctx: *mut c_void,
    propq: *const c_char,
) -> *mut EvpPkey {
    // SAFETY: `BIO_s_file()` answers a static method.
    let b = unsafe { BIO_new(BIO_s_file()) };
    if b.is_null() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::PEM_PKEY_288) };
        return ptr::null_mut();
    }
    // SAFETY: `b` is a live file BIO and `fp` is the caller's stream.
    unsafe { bio_set_fp(b, fp, BIO_NOCLOSE as c_long) };
    // SAFETY: `b` is live; the rest is the caller's.
    let ret = unsafe { PEM_read_bio_PUBKEY_ex(b, x, cb, u, libctx, propq) };
    // SAFETY: `b` is this call's own live BIO.
    unsafe { BIO_free(b) };
    ret
}

/// `EVP_PKEY *PEM_read_PUBKEY(FILE *fp, EVP_PKEY **x, pem_password_cb *cb, void *u)` —
/// `crypto/pem/pem_pkey.c:297-300`.
///
/// # Safety
///
/// `fp` is the caller's open `FILE *`; `x` is NULL or a writable key slot.
#[no_mangle]
pub unsafe extern "C" fn PEM_read_PUBKEY(
    fp: *mut c_void,
    x: *mut *mut EvpPkey,
    cb: Option<PemPasswordCb>,
    u: *mut c_void,
) -> *mut EvpPkey {
    // SAFETY: the caller's contract.
    unsafe { PEM_read_PUBKEY_ex(fp, x, cb, u, ptr::null_mut(), ptr::null()) }
}

/// `EVP_PKEY *PEM_read_bio_PrivateKey_ex(BIO *bp, EVP_PKEY **x, pem_password_cb *cb, void *u,
/// OSSL_LIB_CTX *libctx, const char *propq)` — `crypto/pem/pem_pkey.c:303-310`.
///
/// # Safety
///
/// `bp` is a live BIO; `x` is NULL or a writable key slot; `libctx` is NULL or live and
/// `propq` NULL or NUL-terminated.
#[no_mangle]
pub unsafe extern "C" fn PEM_read_bio_PrivateKey_ex(
    bp: *mut Bio,
    x: *mut *mut EvpPkey,
    cb: Option<PemPasswordCb>,
    u: *mut c_void,
    libctx: *mut c_void,
    propq: *const c_char,
) -> *mut EvpPkey {
    /* we also want the public key, if available */
    // SAFETY: the caller's contract.
    unsafe { pem_read_bio_key(bp, x, cb, u, libctx, propq, EVP_PKEY_KEYPAIR) }
}

/// `EVP_PKEY *PEM_read_bio_PrivateKey(BIO *bp, EVP_PKEY **x, pem_password_cb *cb, void *u)` —
/// `crypto/pem/pem_pkey.c:312-316`.
///
/// # Safety
///
/// `bp` is a live BIO; `x` is NULL or a writable key slot.
#[no_mangle]
pub unsafe extern "C" fn PEM_read_bio_PrivateKey(
    bp: *mut Bio,
    x: *mut *mut EvpPkey,
    cb: Option<PemPasswordCb>,
    u: *mut c_void,
) -> *mut EvpPkey {
    // SAFETY: the caller's contract.
    unsafe { PEM_read_bio_PrivateKey_ex(bp, x, cb, u, ptr::null_mut(), ptr::null()) }
}

/// `EVP_PKEY *PEM_read_PrivateKey_ex(FILE *fp, EVP_PKEY **x, pem_password_cb *cb, void *u,
/// OSSL_LIB_CTX *libctx, const char *propq)` — `crypto/pem/pem_pkey.c:410-425`.
///
/// # Safety
///
/// `fp` is the caller's open `FILE *`; `x` is NULL or a writable key slot; `libctx` is NULL
/// or live and `propq` NULL or NUL-terminated.
#[no_mangle]
pub unsafe extern "C" fn PEM_read_PrivateKey_ex(
    fp: *mut c_void,
    x: *mut *mut EvpPkey,
    cb: Option<PemPasswordCb>,
    u: *mut c_void,
    libctx: *mut c_void,
    propq: *const c_char,
) -> *mut EvpPkey {
    // SAFETY: `BIO_s_file()` answers a static method.
    let b = unsafe { BIO_new(BIO_s_file()) };
    if b.is_null() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::PEM_PKEY_418) };
        return ptr::null_mut();
    }
    // SAFETY: `b` is a live file BIO and `fp` is the caller's stream.
    unsafe { bio_set_fp(b, fp, BIO_NOCLOSE as c_long) };
    // SAFETY: `b` is live; the rest is the caller's.
    let ret = unsafe { PEM_read_bio_PrivateKey_ex(b, x, cb, u, libctx, propq) };
    // SAFETY: `b` is this call's own live BIO.
    unsafe { BIO_free(b) };
    ret
}

/// `EVP_PKEY *PEM_read_PrivateKey(FILE *fp, EVP_PKEY **x, pem_password_cb *cb, void *u)` —
/// `crypto/pem/pem_pkey.c:427-431`. One of the six names `src/pem/key_legacy.rs`'s private-key
/// readers wraps.
///
/// # Safety
///
/// `fp` is the caller's open `FILE *`; `x` is NULL or a writable key slot.
#[no_mangle]
pub unsafe extern "C" fn PEM_read_PrivateKey(
    fp: *mut c_void,
    x: *mut *mut EvpPkey,
    cb: Option<PemPasswordCb>,
    u: *mut c_void,
) -> *mut EvpPkey {
    // SAFETY: the caller's contract.
    unsafe { PEM_read_PrivateKey_ex(fp, x, cb, u, ptr::null_mut(), ptr::null()) }
}

// The `i2d`-shaped adapter `PEM_write_bio_Parameters`'s `legacy:` arm needs.
//
// The authority casts `x->ameth->param_encode` — a runtime function pointer whose parameter is
// the typed `EVP_PKEY *` — to `i2d_of_void *` and hands it to `PEM_ASN1_write_bio`. A C cast of
// that shape has no Rust counterpart for a `fn` pointer of a different parameter list, so the
// pointer is parked here for the duration of the one synchronous call and this adapter reads it
// back. The parking is thread-local because the writer is re-entrant-safe and callable from any
// thread.
thread_local! {
    static PARAM_ENCODE: Cell<
        Option<unsafe extern "C" fn(*const EvpPkey, *mut *mut c_uchar) -> c_int>,
    > = const { Cell::new(None) };
}

/// `PEM_ASN1_write_bio`'s `i2d_of_void` view of the parked `param_encode`.
///
/// # Safety
/// `x` and `out` must be the parked encoder's own arguments.
unsafe extern "C" fn param_encode_void(x: *const c_void, out: *mut *mut c_uchar) -> c_int {
    PARAM_ENCODE.with(|slot| match slot.get() {
        // SAFETY: `x` and `out` are the parked encoder's own arguments per the contract.
        Some(f) => unsafe { f(x.cast::<EvpPkey>(), out) },
        None => 0,
    })
}

/// The `legacy:` label `PEM_write_cb_ex_fnsig(PrivateKey, …)` falls through to —
/// `crypto/pem/pem_pkey.c:325-329`.
///
/// A key whose method has a `priv_encode` (or has no method at all) is written through
/// [`PEM_write_bio_PKCS8PrivateKey`] (`crypto/pem/pem_pk8.c`); every other key through
/// [`PEM_write_bio_PrivateKey_traditional`]. The same label serves `PEM_write_PrivateKey*`
/// because the `FILE *` spellings wrap the BIO ones.
///
/// # Safety
/// As [`PEM_write_bio_PKCS8PrivateKey`] and [`PEM_write_bio_PrivateKey_traditional`]; `x` is NULL
/// or a live key and the trailing arguments are the caller's.
unsafe fn pem_write_private_key_legacy(
    out: *mut Bio,
    x: *const EvpPkey,
    enc: *const EvpCipher,
    kstr: *const c_uchar,
    klen: c_int,
    cb: Option<PemPasswordCb>,
    u: *mut c_void,
) -> c_int {
    if !x.is_null() {
        // SAFETY: `x` is live per the contract.
        let ameth = unsafe { (*x).ameth };
        let priv_encode = if ameth.is_null() {
            None
        } else {
            // SAFETY: `ameth` is `x`'s own method table.
            unsafe { (*ameth).priv_encode }
        };
        if ameth.is_null() || priv_encode.is_some() {
            // SAFETY: every argument is the caller's; the cast restates the typed key argument.
            return unsafe {
                PEM_write_bio_PKCS8PrivateKey(out, x, enc, kstr.cast::<c_char>(), klen, cb, u)
            };
        }
    }
    // SAFETY: every argument is the caller's.
    unsafe { PEM_write_bio_PrivateKey_traditional(out, x, enc.cast::<c_void>(), kstr, klen, cb, u) }
}

/// `int PEM_write_bio_PrivateKey_ex(BIO *out, const EVP_PKEY *x, const EVP_CIPHER *enc, const
/// unsigned char *kstr, int klen, pem_password_cb *cb, void *u, OSSL_LIB_CTX *libctx, const char
/// *propq)` — the `PEM_write_cb_ex_fnsig(PrivateKey, EVP_PKEY, BIO, write_bio)` expansion,
/// `crypto/pem/pem_pkey.c:318-330`.
///
/// The provided-encoder arm is transcribed whole from `pem_local.h`'s
/// `IMPLEMENT_PEM_provided_write_body_{vars,pass,main}`; because this crate publishes no encoder
/// instances for a legacy key (`encode_key2any.c` is blocked), that arm reaches the `legacy:`
/// label exactly as the authority's does, which is what makes the bytes comparable.
///
/// # Safety
/// `out` a live BIO; `x` NULL or a live `EVP_PKEY`; `enc` NULL or a live cipher; `kstr`/`klen`
/// the pass phrase or `u`; `libctx` unread (the macro's parameter is unused by this body) and
/// `propq` NULL or NUL-terminated.
#[no_mangle]
#[allow(clippy::too_many_arguments)] // mirrors the authority's signature exactly
pub unsafe extern "C" fn PEM_write_bio_PrivateKey_ex(
    out: *mut Bio,
    x: *const EvpPkey,
    enc: *const EvpCipher,
    kstr: *const c_uchar,
    klen: c_int,
    cb: Option<PemPasswordCb>,
    u: *mut c_void,
    libctx: *mut c_void,
    propq: *const c_char,
) -> c_int {
    // The authority's `IMPLEMENT_PEM_provided_write_body_vars` passes only the property string:
    // the `libctx` parameter of the `_ex` spelling is not read by this body.
    let _ = libctx;
    // SAFETY: `x` is NULL or live and the four strings are NULL or literals.
    let ctx = unsafe {
        OSSL_ENCODER_CTX_new_for_pkey(
            x,
            EVP_PKEY_KEYPAIR,
            c"PEM".as_ptr(),
            c"PrivateKeyInfo".as_ptr(),
            propq,
        )
    };
    // SAFETY: `ctx` is NULL or live; `get_num_encoders(NULL)` answers 0, which is the authority's
    // own NULL path.
    if unsafe { OSSL_ENCODER_CTX_get_num_encoders(ctx) } == 0 {
        // SAFETY: `ctx` is NULL or this call's own.
        unsafe { OSSL_ENCODER_CTX_free(ctx) };
        // SAFETY: every argument is the caller's.
        return unsafe { pem_write_private_key_legacy(out, x, enc, kstr, klen, cb, u) };
    }

    // `IMPLEMENT_PEM_provided_write_body_pass`.
    let mut kstr = kstr;
    let mut klen = klen;
    let mut cb = cb;
    let mut ret = 1;
    if kstr.is_null() && cb.is_none() {
        if !u.is_null() {
            kstr = u.cast::<c_uchar>();
            // SAFETY: `u` is a NUL-terminated string per this arm's contract.
            klen = unsafe { strlen(u.cast::<c_char>()) } as c_int;
        } else {
            cb = Some(PEM_def_callback);
        }
    }
    if !enc.is_null() {
        ret = 0;
        // SAFETY: `ctx` and `enc` are live; the property string is NULL.
        if unsafe { OSSL_ENCODER_CTX_set_cipher(ctx, EVP_CIPHER_get0_name(enc), ptr::null()) } != 0
        {
            ret = 1;
            // The authority's `if … else if` is over the whole conjuncts, so a non-NULL `kstr`
            // whose `set_passphrase` succeeds still reaches the callback arm.
            if !kstr.is_null()
                // SAFETY: `ctx` is live and `kstr` is the caller's or `u`.
                && unsafe { OSSL_ENCODER_CTX_set_passphrase(ctx, kstr, klen as usize) } == 0
            {
                ret = 0;
            } else if let Some(f) = cb {
                // SAFETY: `ctx` is live and `f`/`u` are the caller's.
                if unsafe { OSSL_ENCODER_CTX_set_pem_password_cb(ctx, Some(f), u) } == 0 {
                    ret = 0;
                }
            }
        }
    }
    if ret == 0 {
        // SAFETY: `ctx` is this call's own.
        unsafe { OSSL_ENCODER_CTX_free(ctx) };
        return 0;
    }
    // `IMPLEMENT_PEM_provided_write_body_main`.
    // SAFETY: `ctx` is live and `out` is the caller's.
    let ret = unsafe { OSSL_ENCODER_to_bio(ctx, out) };
    // SAFETY: `ctx` is this call's own.
    unsafe { OSSL_ENCODER_CTX_free(ctx) };
    ret
}

/// `int PEM_write_bio_PrivateKey(BIO *out, const EVP_PKEY *x, const EVP_CIPHER *enc, const
/// unsigned char *kstr, int klen, pem_password_cb *cb, void *u)` — the
/// `PEM_write_cb_fnsig(PrivateKey, EVP_PKEY, BIO, write_bio)` expansion,
/// `crypto/pem/pem_pkey.c:332-336`.
///
/// # Safety
/// As [`PEM_write_bio_PrivateKey_ex`] with a NULL context and property string.
#[no_mangle]
pub unsafe extern "C" fn PEM_write_bio_PrivateKey(
    out: *mut Bio,
    x: *const EvpPkey,
    enc: *const EvpCipher,
    kstr: *const c_uchar,
    klen: c_int,
    cb: Option<PemPasswordCb>,
    u: *mut c_void,
) -> c_int {
    // SAFETY: every argument is the caller's.
    unsafe {
        PEM_write_bio_PrivateKey_ex(out, x, enc, kstr, klen, cb, u, ptr::null_mut(), ptr::null())
    }
}

/// `int PEM_write_PrivateKey_ex(FILE *out, const EVP_PKEY *x, const EVP_CIPHER *enc, const
/// unsigned char *kstr, int klen, pem_password_cb *cb, void *u, OSSL_LIB_CTX *libctx, const char
/// *propq)` — the `PEM_write_cb_ex_fnsig(PrivateKey, EVP_PKEY, FILE, write)` expansion,
/// `crypto/pem/pem_pkey.c:433-446`.
///
/// # Safety
/// `out` the caller's open `FILE *`; the rest as [`PEM_write_bio_PrivateKey_ex`].
#[no_mangle]
#[allow(clippy::too_many_arguments)] // mirrors the authority's signature exactly
pub unsafe extern "C" fn PEM_write_PrivateKey_ex(
    out: *mut c_void,
    x: *const EvpPkey,
    enc: *const EvpCipher,
    kstr: *const c_uchar,
    klen: c_int,
    cb: Option<PemPasswordCb>,
    u: *mut c_void,
    libctx: *mut c_void,
    propq: *const c_char,
) -> c_int {
    // SAFETY: `out` is the caller's stream and `BIO_NOCLOSE` leaves it open.
    let b = unsafe { BIO_new_fp(out, BIO_NOCLOSE) };
    if b.is_null() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::PEM_PKEY_439) };
        return 0;
    }
    // SAFETY: `b` is live; every other argument is the caller's.
    let ret = unsafe { PEM_write_bio_PrivateKey_ex(b, x, enc, kstr, klen, cb, u, libctx, propq) };
    // SAFETY: `b` is this call's own live BIO.
    unsafe { BIO_free(b) };
    ret
}

/// `int PEM_write_PrivateKey(FILE *out, const EVP_PKEY *x, const EVP_CIPHER *enc, const unsigned
/// char *kstr, int klen, pem_password_cb *cb, void *u)` — the
/// `PEM_write_cb_fnsig(PrivateKey, EVP_PKEY, FILE, write)` expansion,
/// `crypto/pem/pem_pkey.c:448-451`.
///
/// # Safety
/// `out` the caller's open `FILE *`; the rest as [`PEM_write_PrivateKey_ex`].
#[no_mangle]
pub unsafe extern "C" fn PEM_write_PrivateKey(
    out: *mut c_void,
    x: *const EvpPkey,
    enc: *const EvpCipher,
    kstr: *const c_uchar,
    klen: c_int,
    cb: Option<PemPasswordCb>,
    u: *mut c_void,
) -> c_int {
    // SAFETY: every argument is the caller's.
    unsafe { PEM_write_PrivateKey_ex(out, x, enc, kstr, klen, cb, u, ptr::null_mut(), ptr::null()) }
}

/// `int PEM_write_bio_Parameters(BIO *out, const EVP_PKEY *x)` — the
/// `PEM_write_fnsig(Parameters, EVP_PKEY, BIO, write_bio)` expansion,
/// `crypto/pem/pem_pkey.c:393-407`.
///
/// The provided-encoder arm is `IMPLEMENT_PEM_provided_write_body_{vars,main}`; the `legacy:`
/// label writes through the key method's own `param_encode` under the method's
/// `"<pem_str> PARAMETERS"` name.
///
/// # Safety
/// `out` a live BIO; `x` a live `EVP_PKEY` (the authority's `legacy:` arm dereferences it without
/// a NULL test).
#[no_mangle]
pub unsafe extern "C" fn PEM_write_bio_Parameters(out: *mut Bio, x: *const EvpPkey) -> c_int {
    let mut pem_str = [0 as c_char; 80];
    // SAFETY: `x` is live per the contract and the two strings are NULL or literals.
    let ctx = unsafe {
        OSSL_ENCODER_CTX_new_for_pkey(
            x,
            EVP_PKEY_KEY_PARAMETERS,
            c"PEM".as_ptr(),
            c"type-specific".as_ptr(),
            ptr::null(),
        )
    };
    // SAFETY: `ctx` is NULL or live; `get_num_encoders(NULL)` answers 0.
    if unsafe { OSSL_ENCODER_CTX_get_num_encoders(ctx) } != 0 {
        // SAFETY: `ctx` is live and `out` is the caller's.
        let ret = unsafe { OSSL_ENCODER_to_bio(ctx, out) };
        // SAFETY: `ctx` is this call's own.
        unsafe { OSSL_ENCODER_CTX_free(ctx) };
        return ret;
    }
    // SAFETY: `ctx` is NULL or this call's own.
    unsafe { OSSL_ENCODER_CTX_free(ctx) };

    // The authority's `legacy:` label.
    // SAFETY: `x` is live per the contract.
    let ameth = unsafe { (*x).ameth };
    let param_encode = if ameth.is_null() {
        None
    } else {
        // SAFETY: `ameth` is `x`'s own method table.
        unsafe { (*ameth).param_encode }
    };
    let Some(param_encode) = param_encode else {
        return 0;
    };
    // SAFETY: `ameth` is non-NULL because `param_encode` was read from it; `pem_str` is 80 bytes.
    unsafe {
        BIO_snprintf(
            pem_str.as_mut_ptr(),
            pem_str.len(),
            c"%s PARAMETERS".as_ptr(),
            (*ameth).pem_str,
        )
    };
    PARAM_ENCODE.with(|slot| slot.set(Some(param_encode)));
    let i2d: I2dOfVoid = param_encode_void;
    // SAFETY: every argument is live; the two NULLs are the authority's no-cipher arms.
    let ret = unsafe {
        PEM_ASN1_write_bio(
            Some(i2d),
            pem_str.as_ptr(),
            out,
            x.cast::<c_void>(),
            ptr::null(),
            ptr::null(),
            0,
            None,
            ptr::null_mut(),
        )
    };
    PARAM_ENCODE.with(|slot| slot.set(None));
    ret
}

/// `EVP_PKEY *PEM_read_bio_Parameters_ex(BIO *bp, EVP_PKEY **x, OSSL_LIB_CTX *libctx, const char
/// *propq)` — `crypto/pem/pem_pkey.c:377-386`.
///
/// **A measured divergence (`D-DECODER-ABSENT-1`).** The reader is one call to
/// [`pem_read_bio_key`] with `EVP_PKEY_KEY_PARAMETERS`, and on this crate that selection can only
/// be answered by the provider-decoder leg — which publishes no instance here (see the module
/// header). The authority answers a key for a written `-----BEGIN DH PARAMETERS-----` block; this
/// crate answers NULL by the same path its other decoder-first readers take. The name is landed
/// because `pem_read_bio_key` is whole and the divergence is the documented one, not a stub.
///
/// # Safety
/// `bp` a live BIO; `x` NULL or a writable key slot; `libctx` NULL or live and `propq` NULL or
/// NUL-terminated.
#[no_mangle]
pub unsafe extern "C" fn PEM_read_bio_Parameters_ex(
    bp: *mut Bio,
    x: *mut *mut EvpPkey,
    libctx: *mut c_void,
    propq: *const c_char,
) -> *mut EvpPkey {
    // SAFETY: the caller's contract; `no_password_cb` never reads its arguments.
    unsafe {
        pem_read_bio_key(
            bp,
            x,
            Some(no_password_cb),
            ptr::null_mut(),
            libctx,
            propq,
            EVP_PKEY_KEY_PARAMETERS,
        )
    }
}

/// `EVP_PKEY *PEM_read_bio_Parameters(BIO *bp, EVP_PKEY **x)` —
/// `crypto/pem/pem_pkey.c:388-391`.
///
/// # Safety
/// `bp` a live BIO; `x` NULL or a writable key slot.
#[no_mangle]
pub unsafe extern "C" fn PEM_read_bio_Parameters(
    bp: *mut Bio,
    x: *mut *mut EvpPkey,
) -> *mut EvpPkey {
    // SAFETY: the caller's contract.
    unsafe { PEM_read_bio_Parameters_ex(bp, x, ptr::null_mut(), ptr::null()) }
}

/// `int PEM_write_bio_PrivateKey_traditional(BIO *bp, const EVP_PKEY *x, const EVP_CIPHER *enc,
/// const unsigned char *kstr, int klen, pem_password_cb *cb, void *u)` —
/// `crypto/pem/pem_pkey.c:342-370`.
///
/// The one writer of Phase 10.6's set. A provided key that is also assigned is **downgraded to a
/// legacy copy first** (`evp_pkey_copy_downgraded`), because the traditional spelling is defined by
/// the legacy method's `old_priv_encode` and a provider key has none; if that method is absent the
/// authority refuses `PEM_R_UNSUPPORTED_PUBLIC_KEY_TYPE`. The block name is the method's own
/// `pem_str` plus `" PRIVATE KEY"`, and the body is `PEM_ASN1_write_bio` over `i2d_PrivateKey`.
///
/// # Safety
/// `bp` must be a live BIO; `x` NULL or a live `EVP_PKEY`; the four trailing arguments as
/// `PEM_ASN1_write_bio`'s contract.
#[no_mangle]
pub unsafe extern "C" fn PEM_write_bio_PrivateKey_traditional(
    bp: *mut Bio,
    x: *const EvpPkey,
    enc: *const c_void,
    kstr: *const c_uchar,
    klen: c_int,
    cb: Option<PemPasswordCb>,
    u: *mut c_void,
) -> c_int {
    // SAFETY: `x` is NULL or live per the contract.
    if x.is_null() {
        return 0;
    }

    let mut copy: *mut EvpPkey = ptr::null_mut();
    let mut x = x;
    // SAFETY: `x` is live per the contract.
    let assigned_and_provided =
        unsafe { evp_pkey_is_assigned(x) != 0 && evp_pkey_is_provided(x) != 0 };
    if assigned_and_provided {
        // SAFETY: `copy` is this frame's slot and `x` is live.
        if unsafe { evp_pkey_copy_downgraded(&raw mut copy, x) } != 0 {
            x = copy;
        }
    }

    // SAFETY: `x` is live per the contract.
    let ameth = unsafe { (*x).ameth };
    let old_priv_encode = if ameth.is_null() {
        None
    } else {
        // SAFETY: `ameth` is `x`'s own method table.
        unsafe { (*ameth).old_priv_encode }
    };
    if old_priv_encode.is_none() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::PEM_PKEY_360) };
        // SAFETY: `copy` is NULL or this frame's own allocation.
        unsafe { EVP_PKEY_free(copy) };
        return 0;
    }

    let mut pem_str = [0 as c_char; 80];
    // SAFETY: `ameth` is non-NULL because `old_priv_encode` was read from it; `pem_str` is 80 bytes
    // and the format the authority's own.
    unsafe {
        BIO_snprintf(
            pem_str.as_mut_ptr(),
            pem_str.len(),
            c"%s PRIVATE KEY".as_ptr(),
            (*ameth).pem_str,
        )
    };

    // SAFETY: this wrapper restates `i2d_PrivateKey`'s contract in `I2dOfVoid`'s terms.
    unsafe extern "C" fn i2d_void(v: *const c_void, out: *mut *mut c_uchar) -> c_int {
        // SAFETY: the caller's contract, restated in the typed encoder's terms.
        unsafe { i2d_PrivateKey(v.cast::<EvpPkey>(), out) }
    }
    let i2d: I2dOfVoid = i2d_void;

    // SAFETY: every argument is the caller's; `x` is live and `pem_str` is NUL-terminated.
    let ret = unsafe {
        PEM_ASN1_write_bio(
            Some(i2d),
            pem_str.as_ptr(),
            bp,
            x.cast::<c_void>(),
            enc.cast::<crate::evp::cipher::EvpCipher>(),
            kstr,
            klen,
            cb,
            u,
        )
    };
    // SAFETY: `copy` is NULL or this frame's own allocation.
    unsafe { EVP_PKEY_free(copy) };
    ret
}

// ---------------------------------------------------------------------------------------------
// All sixteen exports of `crypto/pem/pem_pkey.c` are above: the read half (Phase 8.9) plus the
// five write spellings and the two `PEM_read_bio_Parameters*` ones (Phase 13.7).
// ---------------------------------------------------------------------------------------------
//
// With 13.7 there is nothing withheld from this unit. The five writers' `legacy:` fall-through
// reaches `PEM_write_bio_PKCS8PrivateKey` (`src/pem/pem_pk8.rs`, landed here) and
// [`PEM_write_bio_PrivateKey_traditional`] (10.6), and the provided-encoder `pass` body reaches
// the landed `OSSL_ENCODER_CTX_set_cipher`/`_set_passphrase`/`_set_pem_password_cb`. The two
// `PEM_read_bio_Parameters*` spellings are landed with the decoder-absence divergence the module
// header records: their body is whole, so the difference is the documented one. `no_password_cb`
// is now called by both of them.

/// `#define evp_pkey_is_assigned(pk)` — `include/crypto/evp.h:643`, `(pk)->pkey.ptr != NULL ||
/// (pk)->keydata != NULL`.
///
/// # Safety
/// `pkey` must be live.
unsafe fn evp_pkey_is_assigned(pkey: *const EvpPkey) -> c_int {
    // SAFETY: `pkey` is live per the contract.
    c_int::from(unsafe { !(*pkey).pkey.is_null() || !(*pkey).keydata.is_null() })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The six selection words the reader's four public spellings pass are the authority's, so a
    /// transcription that transposed two bits would be caught here rather than in a court.
    #[test]
    fn the_selection_words_match_the_authority() {
        assert_eq!(EVP_PKEY_KEY_PARAMETERS, 0x84);
        assert_eq!(EVP_PKEY_PUBLIC_KEY, 0x86);
        assert_eq!(EVP_PKEY_KEYPAIR, 0x87);
    }

    /// A NULL BIO is refused by the decoder leg before any decode is attempted, and the refusal
    /// is the same NULL the legacy entry points answer.
    #[test]
    fn a_null_bio_is_refused() {
        let mut x: *mut EvpPkey = ptr::null_mut();
        // SAFETY: `x` is a live slot and the BIO is NULL, which the reader refuses.
        let r =
            unsafe { PEM_read_bio_PrivateKey(ptr::null_mut(), &raw mut x, None, ptr::null_mut()) };
        assert!(r.is_null());
    }

    /// An empty BIO is refused by both legs and the reader answers NULL without faulting: the
    /// decoder leg carries no instance, and the legacy leg finds no `BEGIN` line.
    #[test]
    fn an_empty_bio_is_refused() {
        // SAFETY: `BIO_s_mem()` answers a static method.
        let bp = unsafe { crate::runtime::bio::BIO_new(crate::runtime::bio::bss_mem::BIO_s_mem()) };
        assert!(!bp.is_null());
        let mut x: *mut EvpPkey = ptr::null_mut();
        // SAFETY: `bp` is a live memory BIO and `x` is a live slot.
        let r = unsafe { PEM_read_bio_PrivateKey(bp, &raw mut x, None, ptr::null_mut()) };
        assert!(r.is_null());
        assert!(x.is_null());
        // SAFETY: `bp` is this test's own live BIO.
        unsafe { BIO_free(bp) };
        crate::runtime::err::ERR_clear_error();
    }
}
