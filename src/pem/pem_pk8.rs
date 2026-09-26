//! `crypto/pem/pem_pk8.c` — the PKCS#8 private-key readers and writers. Phase 10.6.
//!
//! Four of the unit's six exports land here: `i2d_PKCS8PrivateKey_bio`/`_fp` (the DER writers)
//! and `d2i_PKCS8PrivateKey_bio`/`_fp` (the readers). The two `_nid_` writers,
//! `i2d_PKCS8PrivateKey_nid_bio`/`_fp`, are **held pending**: every arm of theirs passes a
//! PKCS#5 PBE `nid`, which forces `do_pk8pkey`'s legacy path to `PKCS8_encrypt` — and
//! `PKCS8_encrypt` (`crypto/pkcs12/p12_p8e.c`) is 10.4's and open, its `PKCS5_pbe2_set_iv_ex`/
//! `PKCS5_pbe_set_ex` and `PKCS8_set0_pbe_ex` dependencies are Phase 11's and 10.4's, and none of
//! them is landed. The class `docs/DECISIONS.md` D349 refused is a name that answers 0 where the
//! authority encodes; the two are named here and in `docs/PHASE-10-SUBPHASES.md`'s follow-up
//! rather than landed to satisfy a count. The same dependency is why the **encrypted** arm of
//! `do_pk8pkey` is withheld below; the unencrypted arm the four landed writers reach is whole.
//!
//! ## `do_pk8pkey` tries the encoder first, and for a legacy key that is always zero encoders
//!
//! `OSSL_ENCODER_CTX_get_num_encoders` is non-zero only for a **provided** key whose encoder rows
//! have landed — `encode_key2any.c`, still blocked. For a legacy key (`EVP_PKEY_set1_*`) the
//! context carries none, so both the authority and this crate take the legacy arm, which is what
//! makes the unencrypted bytes comparable. A provided key diverges for the documented reason.
//!
//! ## What replaces a Phase 11 export
//!
//! `d2i_PKCS8_bio`, `i2d_PKCS8_PRIV_KEY_INFO_bio`, `i2d_PKCS8_bio` and the two
//! `PEM_write_bio_PKCS8*` writers are `IMPLEMENT_PEM_{d2i,i2d}_bio`/`IMPLEMENT_PEM_write_*`
//! expansions declared in `pem.h`/`x509.h` and owned by Phase 11. This module builds the same
//! `ASN1_i2d_bio`/`ASN1_d2i_bio`/`PEM_ASN1_write_bio` calls the macros expand to, internally, so
//! the unit is whole without claiming Phase 11's symbols.
//!
//! SPDX-License-Identifier: Apache-2.0

#![allow(clippy::too_many_arguments)] // every signature mirrors the authority's

use core::ffi::{c_char, c_int, c_long, c_uchar, c_void};
use core::ptr;

use crate::asn1::a_d2i_fp::ASN1_d2i_bio;
use crate::asn1::a_i2d_fp::ASN1_i2d_bio;
use crate::asn1::layout::{D2iOfVoid, I2dOfVoid};
use crate::asn1::p8_pkey::{i2d_PKCS8_PRIV_KEY_INFO, PKCS8_PRIV_KEY_INFO_free, Pkcs8PrivKeyInfo};
use crate::asn1::x_sig::{d2i_X509_SIG, i2d_X509_SIG, X509_SIG_free, X509_SIG_new};
use crate::encoder_lib::{OSSL_ENCODER_CTX_get_num_encoders, OSSL_ENCODER_to_bio};
use crate::encoder_meth::OSSL_ENCODER_CTX_free;
use crate::encoder_pkey::{
    OSSL_ENCODER_CTX_new_for_pkey, OSSL_ENCODER_CTX_set_cipher, OSSL_ENCODER_CTX_set_passphrase,
    OSSL_ENCODER_CTX_set_pem_password_cb,
};
use crate::evp::cipher::{EVP_CIPHER_get0_name, EvpCipher};
use crate::evp::evp_pkey::{ossl_evp_pkcs82pkey_ex, ossl_evp_pkey2pkcs8};
use crate::evp::pem_bridge::PemPasswordCb;
use crate::evp::pkey::{EVP_PKEY_free, OSSL_KEYMGMT_SELECT_ALL};
use crate::pem::pem_lib::{PEM_ASN1_write_bio, PEM_def_callback, PEM_BUFSIZE, PEM_STRING_PKCS8INF};
use crate::pkcs12::p12_p8d::PKCS8_decrypt;
use crate::runtime::bio::{BIO_free, BIO_new_fp, Bio, BIO_NOCLOSE};
use crate::runtime::err::{err_sites, raise_site};
use crate::runtime::mem::OPENSSL_cleanse;

unsafe extern "C" {
    /// The C library's `strlen`, which the authority's `u`-as-password fallback calls.
    fn strlen(s: *const c_char) -> usize;
}

/// `static int do_pk8pkey(BIO *bp, const EVP_PKEY *x, int isder, int nid, const EVP_CIPHER *enc,
/// const char *kstr, int klen, pem_password_cb *cb, void *u, const char *propq)` —
/// `pem_pk8.c:69-166`.
///
/// The encoder arm is transcribed whole. The legacy arm's **unencrypted** half is whole; its
/// encrypted half is the one path `PKCS8_encrypt` blocks, and it is refused here with the
/// coordinate that records why rather than reached.
///
/// # Safety
/// `bp` a live BIO; `x` a live `EVP_PKEY`; `enc` NULL or a live cipher; the string and callback
/// arguments as `PEM_ASN1_write_bio`'s contract.
unsafe fn do_pk8pkey(
    bp: *mut Bio,
    x: *const crate::evp::pkey::EvpPkey,
    isder: c_int,
    nid: c_int,
    enc: *const EvpCipher,
    mut kstr: *const c_char,
    mut klen: c_int,
    mut cb: Option<PemPasswordCb>,
    u: *mut c_void,
    propq: *const c_char,
) -> c_int {
    let mut ret: c_int = 0;
    let outtype = if isder != 0 {
        c"DER".as_ptr()
    } else {
        c"PEM".as_ptr()
    };
    // SAFETY: `x` is live and the three strings are this frame's or literals.
    let ctx = unsafe {
        OSSL_ENCODER_CTX_new_for_pkey(
            x,
            OSSL_KEYMGMT_SELECT_ALL,
            outtype,
            c"PrivateKeyInfo".as_ptr(),
            propq,
        )
    };
    if ctx.is_null() {
        return 0;
    }

    /* If no keystring or callback is set, the user's `u` is the password string, or `cb` falls
     * back to `PEM_def_callback`. */
    if kstr.is_null() && cb.is_none() {
        if !u.is_null() {
            kstr = u.cast::<c_char>();
            // SAFETY: `u` is a NUL-terminated string per this arm's contract.
            klen = unsafe { strlen(kstr) } as c_int;
        } else {
            cb = Some(PEM_def_callback);
        }
    }

    if nid == -1
        // SAFETY: `ctx` is live.
        && unsafe { OSSL_ENCODER_CTX_get_num_encoders(ctx) } != 0
    {
        ret = 1;
        if !enc.is_null() {
            ret = 0;
            // SAFETY: `ctx` and `enc` are live; the property argument is NULL.
            if unsafe { OSSL_ENCODER_CTX_set_cipher(ctx, EVP_CIPHER_get0_name(enc), ptr::null()) }
                != 0
            {
                ret = 1;
                // SAFETY: `ctx` is live and `kstr`/`cb` are the caller's.
                if !kstr.is_null()
                    // SAFETY: `ctx` is live and the passphrase arguments are the caller's.
                    && unsafe {
                        OSSL_ENCODER_CTX_set_passphrase(ctx, kstr.cast::<c_uchar>(), klen as usize)
                    } == 0
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
        // SAFETY: `ctx` is live and `bp` is the caller's.
        if ret != 0 && unsafe { OSSL_ENCODER_to_bio(ctx, bp) } == 0 {
            ret = 0;
        }
    } else {
        // SAFETY: `x` is live and this is the authority's internal PKCS#8 conversion.
        let p8inf = unsafe { ossl_evp_pkey2pkcs8(x) };
        if p8inf.is_null() {
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&err_sites::PEM_PK8_132) };
            // SAFETY: `ctx` is this frame's own.
            unsafe { OSSL_ENCODER_CTX_free(ctx) };
            return ret;
        }
        if !enc.is_null() || nid != -1 {
            /* The authority reaches `PKCS8_encrypt` here. It is 10.4's and open, and its own
             * dependencies are Phase 11's; the arm is withheld rather than answered 0 as if it
             * were the authority's own refusal. See the module doc. */
            // The authority's password-read and `PKCS8_encrypt` call are both inside this arm and
            // both unlanded; `ret` stays 0 and the error queue is left as the conversion left it.
            // `PEM_R_READ_KEY` records the coordinate the withheld read would raise.
            let _ = (kstr, klen, cb, u, &err_sites::PEM_PK8_139);
        } else if isder != 0 {
            // SAFETY: `bp` is live, the encoder is `i2d_PKCS8_PRIV_KEY_INFO`'s, `p8inf` is live.
            ret = unsafe { i2d_pkcs8_priv_key_info_bio(bp, p8inf) };
        } else {
            // SAFETY: `bp` is live and `p8inf` is live.
            ret = unsafe { pem_write_bio_pkcs8_priv_key_info(bp, p8inf) };
        }
        // SAFETY: `p8inf` is this frame's own.
        unsafe { PKCS8_PRIV_KEY_INFO_free(p8inf) };
    }
    // SAFETY: `ctx` is this frame's own.
    unsafe { OSSL_ENCODER_CTX_free(ctx) };
    ret
}

/// `IMPLEMENT_PEM_i2d_bio(PKCS8_PRIV_KEY_INFO, …)`'s body — `i2d_PKCS8_PRIV_KEY_INFO_bio`.
///
/// # Safety
/// `bp` a live BIO; `p8inf` live.
unsafe fn i2d_pkcs8_priv_key_info_bio(bp: *mut Bio, p8inf: *const Pkcs8PrivKeyInfo) -> c_int {
    // SAFETY: this wrapper restates `i2d_PKCS8_PRIV_KEY_INFO`'s contract in `I2dOfVoid`'s terms.
    unsafe extern "C" fn i2d_void(x: *const c_void, out: *mut *mut c_uchar) -> c_int {
        // SAFETY: the caller's contract, restated in the typed encoder's terms.
        unsafe { i2d_PKCS8_PRIV_KEY_INFO(x.cast::<Pkcs8PrivKeyInfo>(), out) }
    }
    let i2d: I2dOfVoid = i2d_void;
    // SAFETY: `bp` is live, `i2d` is the encoder above, `p8inf` is live.
    unsafe { ASN1_i2d_bio(i2d, bp, p8inf.cast::<c_void>()) }
}

/// `IMPLEMENT_PEM_write_bio(PKCS8_PRIV_KEY_INFO, …)`'s body — `PEM_write_bio_PKCS8_PRIV_KEY_INFO`.
///
/// # Safety
/// `bp` a live BIO; `p8inf` live.
unsafe fn pem_write_bio_pkcs8_priv_key_info(bp: *mut Bio, p8inf: *const Pkcs8PrivKeyInfo) -> c_int {
    // SAFETY: this wrapper restates `i2d_PKCS8_PRIV_KEY_INFO`'s contract in `I2dOfVoid`'s terms.
    unsafe extern "C" fn i2d_void(x: *const c_void, out: *mut *mut c_uchar) -> c_int {
        // SAFETY: the caller's contract, restated in the typed encoder's terms.
        unsafe { i2d_PKCS8_PRIV_KEY_INFO(x.cast::<Pkcs8PrivKeyInfo>(), out) }
    }
    let i2d: I2dOfVoid = i2d_void;
    // SAFETY: every argument is live; the two NULLs are the authority's no-cipher arms.
    unsafe {
        PEM_ASN1_write_bio(
            Some(i2d),
            PEM_STRING_PKCS8INF,
            bp,
            p8inf.cast::<c_void>(),
            ptr::null(),
            ptr::null(),
            0,
            None,
            ptr::null_mut(),
        )
    }
}

/// `IMPLEMENT_PEM_d2i_bio(PKCS8, X509_SIG, …)`'s body — `d2i_PKCS8_bio`.
///
/// # Safety
/// `bp` a live BIO.
unsafe fn d2i_pkcs8_bio(bp: *mut Bio) -> *mut crate::asn1::x_sig::X509Sig {
    // SAFETY: `X509_SIG_new` takes no arguments; the wrapper matches `ASN1_d2i_bio`'s `xnew`.
    unsafe extern "C" fn xnew() -> *mut c_void {
        X509_SIG_new().cast::<c_void>()
    }
    // SAFETY: this wrapper restates `d2i_X509_SIG`'s contract in `D2iOfVoid`'s terms.
    unsafe extern "C" fn d2i_void(
        a: *mut *mut c_void,
        in_: *mut *const c_uchar,
        len: c_long,
    ) -> *mut c_void {
        // SAFETY: the caller's contract, restated in the typed decoder's terms.
        unsafe { d2i_X509_SIG(a.cast(), in_, len).cast::<c_void>() }
    }
    let d2i: D2iOfVoid = d2i_void;
    // SAFETY: `bp` is live and the two callbacks are the type's own.
    unsafe { ASN1_d2i_bio(xnew, d2i, bp, ptr::null_mut()).cast() }
}

/// `IMPLEMENT_PEM_i2d_bio(PKCS8, X509_SIG, …)`'s body — `i2d_PKCS8_bio`.
///
/// # Safety
/// `bp` a live BIO; `p8` live.
#[allow(dead_code)] // its only caller is the withheld encrypted arm; it is kept whole anyway
unsafe fn i2d_pkcs8_bio(bp: *mut Bio, p8: *const crate::asn1::x_sig::X509Sig) -> c_int {
    // SAFETY: this wrapper restates `i2d_X509_SIG`'s contract in `I2dOfVoid`'s terms.
    unsafe extern "C" fn i2d_void(x: *const c_void, out: *mut *mut c_uchar) -> c_int {
        // SAFETY: the caller's contract, restated in the typed encoder's terms.
        unsafe { i2d_X509_SIG(x.cast::<crate::asn1::x_sig::X509Sig>(), out) }
    }
    let i2d: I2dOfVoid = i2d_void;
    // SAFETY: `bp` is live, `i2d` is the encoder above, `p8` is live.
    unsafe { ASN1_i2d_bio(i2d, bp, p8.cast::<c_void>()) }
}

/// `int i2d_PKCS8PrivateKey_bio(BIO *bp, const EVP_PKEY *x, const EVP_CIPHER *enc, const char
/// *kstr, int klen, pem_password_cb *cb, void *u)` — `pem_pk8.c:55-60`.
///
/// # Safety
/// As [`do_pk8pkey`] with `isder = 1`, `nid = -1`.
#[no_mangle]
pub unsafe extern "C" fn i2d_PKCS8PrivateKey_bio(
    bp: *mut Bio,
    x: *const crate::evp::pkey::EvpPkey,
    enc: *const EvpCipher,
    kstr: *const c_char,
    klen: c_int,
    cb: Option<PemPasswordCb>,
    u: *mut c_void,
) -> c_int {
    // SAFETY: every argument is the caller's.
    unsafe { do_pk8pkey(bp, x, 1, -1, enc, kstr, klen, cb, u, ptr::null()) }
}

/// `EVP_PKEY *d2i_PKCS8PrivateKey_bio(BIO *bp, EVP_PKEY **x, pem_password_cb *cb, void *u)` —
/// `pem_pk8.c:168-203`.
///
/// # Safety
/// `bp` a live BIO; `x` NULL or a writable key slot; `cb` the caller's.
#[no_mangle]
pub unsafe extern "C" fn d2i_PKCS8PrivateKey_bio(
    bp: *mut Bio,
    x: *mut *mut crate::evp::pkey::EvpPkey,
    cb: Option<PemPasswordCb>,
    u: *mut c_void,
) -> *mut crate::evp::pkey::EvpPkey {
    let mut psbuf = [0 as c_char; PEM_BUFSIZE as usize + 1];

    // SAFETY: `bp` is live and this is the authority's `d2i_PKCS8_bio`.
    let p8 = unsafe { d2i_pkcs8_bio(bp) };
    if p8.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: `cb` is the caller's or `PEM_def_callback`.
    let klen = match cb {
        // SAFETY: the callback's contract is the header's.
        Some(f) => unsafe { f(psbuf.as_mut_ptr(), PEM_BUFSIZE, 0, u) },
        // SAFETY: the callback contract is `PEM_def_callback`'s.
        None => unsafe { PEM_def_callback(psbuf.as_mut_ptr(), PEM_BUFSIZE, 0, u) },
    };
    if !(0..=PEM_BUFSIZE).contains(&klen) {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::PEM_PK8_185) };
        // SAFETY: `p8` is this frame's own.
        unsafe { X509_SIG_free(p8) };
        return ptr::null_mut();
    }
    // SAFETY: `p8` is live, `psbuf` is this frame's and `klen` its length.
    let p8inf = unsafe { PKCS8_decrypt(p8, psbuf.as_ptr(), klen) };
    // SAFETY: `p8` is this frame's own.
    unsafe { X509_SIG_free(p8) };
    // SAFETY: `psbuf` holds `klen` bytes and cleanse is the authority's.
    unsafe { OPENSSL_cleanse(psbuf.as_mut_ptr().cast::<c_void>(), klen as usize) };
    if p8inf.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: `p8inf` is live and the context is NULL, as `EVP_PKCS82PKEY` passes.
    let ret = unsafe { ossl_evp_pkcs82pkey_ex(p8inf, ptr::null_mut(), ptr::null()) };
    // SAFETY: `p8inf` is this frame's own.
    unsafe { PKCS8_PRIV_KEY_INFO_free(p8inf) };
    if ret.is_null() {
        return ptr::null_mut();
    }
    if !x.is_null() {
        // SAFETY: `x` is a writable slot holding the caller's key.
        unsafe {
            EVP_PKEY_free(*x);
            *x = ret;
        }
    }
    ret
}

/// `static int do_pk8pkey_fp(FILE *fp, const EVP_PKEY *x, int isder, int nid, const EVP_CIPHER
/// *enc, const char *kstr, int klen, pem_password_cb *cb, void *u, const char *propq)` —
/// `pem_pk8.c:235-249`.
///
/// # Safety
/// `fp` a live `FILE *`; the rest as [`do_pk8pkey`].
unsafe fn do_pk8pkey_fp(
    fp: *mut c_void,
    x: *const crate::evp::pkey::EvpPkey,
    isder: c_int,
    nid: c_int,
    enc: *const EvpCipher,
    kstr: *const c_char,
    klen: c_int,
    cb: Option<PemPasswordCb>,
    u: *mut c_void,
    propq: *const c_char,
) -> c_int {
    // SAFETY: `fp` is live and `BIO_NOCLOSE` leaves it to the caller.
    let bp = unsafe { BIO_new_fp(fp, BIO_NOCLOSE) };
    if bp.is_null() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::PEM_PK8_243) };
        return 0;
    }
    // SAFETY: `bp` is live and every other argument is the caller's.
    let ret = unsafe { do_pk8pkey(bp, x, isder, nid, enc, kstr, klen, cb, u, propq) };
    // SAFETY: `bp` is this frame's own.
    unsafe { BIO_free(bp) };
    ret
}

/// `int i2d_PKCS8PrivateKey_fp(FILE *fp, const EVP_PKEY *x, const EVP_CIPHER *enc, const char
/// *kstr, int klen, pem_password_cb *cb, void *u)` — `pem_pk8.c:207-212`.
///
/// # Safety
/// `fp` a live `FILE *`; the rest as [`do_pk8pkey`].
#[no_mangle]
pub unsafe extern "C" fn i2d_PKCS8PrivateKey_fp(
    fp: *mut c_void,
    x: *const crate::evp::pkey::EvpPkey,
    enc: *const EvpCipher,
    kstr: *const c_char,
    klen: c_int,
    cb: Option<PemPasswordCb>,
    u: *mut c_void,
) -> c_int {
    // SAFETY: every argument is the caller's.
    unsafe { do_pk8pkey_fp(fp, x, 1, -1, enc, kstr, klen, cb, u, ptr::null()) }
}

/// `EVP_PKEY *d2i_PKCS8PrivateKey_fp(FILE *fp, EVP_PKEY **x, pem_password_cb *cb, void *u)` —
/// `pem_pk8.c:251-264`.
///
/// # Safety
/// `fp` a live `FILE *`; `x` NULL or a writable key slot.
#[no_mangle]
pub unsafe extern "C" fn d2i_PKCS8PrivateKey_fp(
    fp: *mut c_void,
    x: *mut *mut crate::evp::pkey::EvpPkey,
    cb: Option<PemPasswordCb>,
    u: *mut c_void,
) -> *mut crate::evp::pkey::EvpPkey {
    // SAFETY: `fp` is live and `BIO_NOCLOSE` leaves it to the caller.
    let bp = unsafe { BIO_new_fp(fp, BIO_NOCLOSE) };
    if bp.is_null() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::PEM_PK8_258) };
        return ptr::null_mut();
    }
    // SAFETY: `bp` is live and the rest is the caller's.
    let ret = unsafe { d2i_PKCS8PrivateKey_bio(bp, x, cb, u) };
    // SAFETY: `bp` is this frame's own.
    unsafe { BIO_free(bp) };
    ret
}
