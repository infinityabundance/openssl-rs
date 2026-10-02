//! `crypto/pem/pem_info.c` — the `X509_INFO` bundle reader and writer. Phase 11.6.
//!
//! `crypto/pem/pem_info.c` is 312 lines and the five exports [`PEM_X509_INFO_read_ex`],
//! [`PEM_X509_INFO_read`], [`PEM_X509_INFO_read_bio_ex`], [`PEM_X509_INFO_read_bio`] and
//! [`PEM_X509_INFO_write_bio`]. The reader reads a *bundle*: it walks the blocks of a PEM stream
//! with [`PEM_read_bio`] and classifies each by its `name` — an `X509`/`X509 CERTIFICATE`/
//! `TRUSTED CERTIFICATE` block into `xi->x509`, an `X509 CRL` block into `xi->crl`, a
//! `PRIVATE KEY`-suffixed block into `xi->x_pkey`, and a not-yet-decrypted key into
//! `xi->enc_data` — pushing onto a `STACK_OF(X509_INFO)` as each slot fills. The writer emits a
//! record's private key and certificate back out.
//!
//! ## What this slice lands beyond its own unit
//!
//! The record is `crypto/asn1/x_info.c`'s [`crate::asn1::x_info`] and the private-key slot is
//! `crypto/asn1/x_pkey.c`'s [`crate::asn1::x_pkey`] — both 11.7's units, landed with this
//! subphase because no arm of this reader can be written without them (their module docs say so,
//! and `docs/PHASE-11-SUBPHASES.md` section 5 records the discovery rather than forcing the row).
//! This is what makes `crypto/x509/by_file.c`'s `X509_load_cert_crl_file_ex` transcribable; that
//! unit's remaining blocker is the store it needs a court to build (`X509_STORE_new`, `x509_lu.c`)
//! and `X509_get_default_cert_file` (`x509_def.c`, the directory plane), not this reader.
//!
//! ## The `PKCS7` arm is Phase 12's, and is printed rather than driven
//!
//! Section 3.4's subtlety is measured here: a `PKCS7` block reaches the reader's classification
//! and, because `pkcs7.h` is Phase 12's, the reader leaves it in the `else` (unknown) arm with
//! `d2i = NULL` and pushes nothing for it. The court prints that arm as `pending.` rather than
//! claiming it.
//!
//! ## The error coordinates
//!
//! `pem_info.c` raises at seven sites: `:36` (`ERR_R_BUF_LIB`, the file-BIO constructor),
//! `:70` (`ERR_R_CRYPTO_LIB`, the stack constructor), `:166` and `:170` (`ERR_R_ASN1_LIB`, the
//! two `d2i` refusals), and `:243`, `:256`, `:272` (the writer's cipher checks). Every one is a
//! coordinate, so the unit is added to `gen_err_raise_sites.py`'s covered set with stem
//! `PEM_INFO`.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_char, c_int, c_long, c_uchar, c_uint, c_void};
use core::ptr;

use crate::asn1::d2i_pr::{d2i_AutoPrivateKey, d2i_PrivateKey_ex};
use crate::asn1::layout::D2iOfVoid;
use crate::asn1::x_info::{X509Info, X509_INFO_free, X509_INFO_new};
use crate::asn1::x_pkey::X509_PKEY_new;
use crate::evp::cipher::{EVP_CIPHER_get0_name, EVP_CIPHER_get_iv_length, EvpCipher};
use crate::evp::p_legacy_assign::EVP_PKEY_get0_RSA;
use crate::evp::pem_bridge::{PEM_get_EVP_CIPHER_INFO, PEM_read_bio, PEM_write_bio, PemPasswordCb};
use crate::evp::pkey::{evp_pkey_name2type, EvpPkey};
use crate::pem::key_legacy::PEM_write_bio_RSAPrivateKey;
use crate::pem::pem_lib::{
    PEM_dek_info, PEM_do_header, PEM_proc_type, PEM_BUFSIZE, PEM_STRING_PKCS8, PEM_STRING_PKCS8INF,
    PEM_STRING_RSA, PEM_STRING_X509, PEM_STRING_X509_CRL, PEM_STRING_X509_OLD,
    PEM_STRING_X509_TRUSTED, PEM_TYPE_ENCRYPTED,
};
use crate::pem::pem_x509::PEM_write_bio_X509;
use crate::runtime::bio::bss_file::BIO_s_file;
use crate::runtime::bio::{BIO_ctrl, BIO_free, BIO_new, Bio, BIO_C_SET_FILE_PTR};
use crate::runtime::err::err_reasons::PEM_R_NO_START_LINE;
use crate::runtime::err::{
    err_sites, peek_last_reason, raise_site, ERR_clear_last_mark, ERR_pop_to_mark, ERR_set_mark,
};
use crate::runtime::mem::{CRYPTO_free, OPENSSL_cleanse};
use crate::runtime::stack::{
    OPENSSL_sk_free, OPENSSL_sk_new_null, OPENSSL_sk_num, OPENSSL_sk_push, OPENSSL_sk_value,
    OpenSslStack,
};
use crate::x509::x_crl::d2i_X509_CRL;
use crate::x509::x_x509::{d2i_X509_AUX, X509_new_ex, X509};

unsafe extern "C" {
    /// The C library's `strstr`, which the reader's `PRIVATE KEY` classification calls.
    fn strstr(haystack: *const c_char, needle: *const c_char) -> *mut c_char;
}

use crate::runtime::bio::sys::{strcmp, strlen};

/// `EVP_MAX_IV_LENGTH` — `include/openssl/evp.h`'s 16-byte IV bound. The crate's
/// `EvpCipherInfo` carries the same array.
const EVP_MAX_IV_LENGTH: usize = 16;

/// `OPENSSL_FILE` at every `OPENSSL_free` in `crypto/pem/pem_info.c`.
const FILE: *const c_char = c"crypto/pem/pem_info.c".as_ptr();

/// `PEM_X509_INFO_read_bio_ex`'s four `OPENSSL_free` sites (`:181`, `:183`, `:185`, and the
/// `err:` block's `:211-213`). All three buffers share one line number per site.
const LINE_FREE_NAME: c_int = 181;
/// The `header` free (`:183`).
const LINE_FREE_HEADER: c_int = 183;
/// The `data` free (`:185`).
const LINE_FREE_DATA: c_int = 185;
/// The `err:` block's three frees (`:211-213`).
const LINE_FREE_ERR_NAME: c_int = 211;
const LINE_FREE_ERR_HEADER: c_int = 212;
const LINE_FREE_ERR_DATA: c_int = 213;

/// `EVP_PKEY_NONE` — `include/openssl/evp.h`, spelled `NID_undef` = 0. The `ptype` sentinel the
/// `PRIVATE KEY` arm sets when the header carries no key-type prefix.
const EVP_PKEY_NONE: c_uint = 0;

/// `(d2i_of_void *)d2i_X509_AUX`.
///
/// # Safety
/// The `void *` arguments must be `d2i_X509_AUX`'s own.
unsafe extern "C" fn d2i_void_x509_aux(
    a: *mut *mut c_void,
    in_: *mut *const c_uchar,
    len: c_long,
) -> *mut c_void {
    // SAFETY: the caller's contract, restated in the typed decoder's terms.
    unsafe { d2i_X509_AUX(a.cast::<*mut X509>(), in_, len).cast::<c_void>() }
}

/// `(d2i_of_void *)d2i_X509`.
///
/// # Safety
/// The `void *` arguments must be `d2i_X509`'s own.
unsafe extern "C" fn d2i_void_x509(
    a: *mut *mut c_void,
    in_: *mut *const c_uchar,
    len: c_long,
) -> *mut c_void {
    // SAFETY: the caller's contract, restated in the typed decoder's terms.
    unsafe { crate::x509::x_x509::d2i_X509(a.cast::<*mut X509>(), in_, len).cast::<c_void>() }
}

/// `(d2i_of_void *)d2i_X509_CRL`.
///
/// # Safety
/// The `void *` arguments must be `d2i_X509_CRL`'s own.
unsafe extern "C" fn d2i_void_x509_crl(
    a: *mut *mut c_void,
    in_: *mut *const c_uchar,
    len: c_long,
) -> *mut c_void {
    // SAFETY: the caller's contract, restated in the typed decoder's terms.
    unsafe { d2i_X509_CRL(a.cast::<*mut crate::x509::x_crl::X509Crl>(), in_, len).cast::<c_void>() }
}

/// `(d2i_of_void *)d2i_AutoPrivateKey`.
///
/// # Safety
/// The `void *` arguments must be `d2i_AutoPrivateKey`'s own.
unsafe extern "C" fn d2i_void_auto(
    a: *mut *mut c_void,
    in_: *mut *const c_uchar,
    len: c_long,
) -> *mut c_void {
    // SAFETY: the caller's contract, restated in the typed decoder's terms.
    unsafe { d2i_AutoPrivateKey(a.cast::<*mut EvpPkey>(), in_, len).cast::<c_void>() }
}

/// `STACK_OF(X509_INFO) *PEM_X509_INFO_read_ex(FILE *fp, STACK_OF(X509_INFO) *sk,
/// pem_password_cb *cb, void *u, OSSL_LIB_CTX *libctx, const char *propq)` —
/// `crypto/pem/pem_info.c:28-43`.
///
/// The `FILE *` spelling: wrap the stream in a file BIO (`BIO_NOCLOSE`), read, release the BIO.
///
/// # Safety
/// `fp` an open readable stream; `sk` NULL or a live stack; `cb`/`u` as the BIO reader's;
/// `libctx` NULL or live; `propq` NULL or NUL-terminated.
#[no_mangle]
pub unsafe extern "C" fn PEM_X509_INFO_read_ex(
    fp: *mut c_void,
    sk: *mut OpenSslStack,
    cb: Option<PemPasswordCb>,
    u: *mut c_void,
    libctx: *mut c_void,
    propq: *const c_char,
) -> *mut OpenSslStack {
    // SAFETY: `BIO_s_file` is a static method table.
    let b = unsafe { BIO_new(BIO_s_file()) };
    if b.is_null() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::PEM_INFO_36) };
        return ptr::null_mut();
    }
    // `BIO_set_fp(b, fp, BIO_NOCLOSE)`.
    // SAFETY: `b` is live and `fp` is the caller's stream.
    unsafe { BIO_ctrl(b, BIO_C_SET_FILE_PTR, 0, fp) };
    // SAFETY: `b` is a live file BIO and the rest is the caller's.
    let ret = unsafe { PEM_X509_INFO_read_bio_ex(b, sk, cb, u, libctx, propq) };
    // SAFETY: `b` is this frame's own BIO.
    unsafe { BIO_free(b) };
    ret
}

/// `STACK_OF(X509_INFO) *PEM_X509_INFO_read(FILE *fp, STACK_OF(X509_INFO) *sk,
/// pem_password_cb *cb, void *u)` — `crypto/pem/pem_info.c:45-49`.
///
/// # Safety
/// As [`PEM_X509_INFO_read_ex`] with a NULL `libctx`/`propq`.
#[no_mangle]
pub unsafe extern "C" fn PEM_X509_INFO_read(
    fp: *mut c_void,
    sk: *mut OpenSslStack,
    cb: Option<PemPasswordCb>,
    u: *mut c_void,
) -> *mut OpenSslStack {
    // SAFETY: the caller's contract with a NULL context.
    unsafe { PEM_X509_INFO_read_ex(fp, sk, cb, u, ptr::null_mut(), ptr::null()) }
}

/// `STACK_OF(X509_INFO) *PEM_X509_INFO_read_bio_ex(BIO *bp, STACK_OF(X509_INFO) *sk,
/// pem_password_cb *cb, void *u, OSSL_LIB_CTX *libctx, const char *propq)` —
/// `crypto/pem/pem_info.c:52-215`.
///
/// The classification loop. A block whose `name` is one of the three certificate spellings
/// becomes `xi->x509` (with `d2i_X509_AUX` for `TRUSTED CERTIFICATE`), an `X509 CRL` block
/// becomes `xi->crl`, a `*PRIVATE KEY` block becomes `xi->x_pkey` (decoded with `d2i_AutoPrivateKey`
/// when unencrypted, or held in `xi->enc_data` when the header is long enough to be an encryption
/// header), and anything else is left unclassified. A record is pushed when its current slot is
/// already occupied, so a bundle groups consecutive like blocks.
///
/// # Safety
/// `bp` a live readable BIO; `sk` NULL or a live `STACK_OF(X509_INFO)`; `cb`/`u` as the reader's;
/// `libctx` NULL or live; `propq` NULL or NUL-terminated.
#[no_mangle]
pub unsafe extern "C" fn PEM_X509_INFO_read_bio_ex(
    bp: *mut Bio,
    sk: *mut OpenSslStack,
    cb: Option<PemPasswordCb>,
    u: *mut c_void,
    libctx: *mut c_void,
    propq: *const c_char,
) -> *mut OpenSslStack {
    let mut xi: *mut X509Info = ptr::null_mut();
    let mut name: *mut c_char = ptr::null_mut();
    let mut header: *mut c_char = ptr::null_mut();
    let mut data: *mut c_uchar = ptr::null_mut();
    let mut len: c_long = 0;
    let mut ok = false;
    let mut ret: *mut OpenSslStack = sk;

    'err: {
        if ret.is_null() {
            // SAFETY: no preconditions.
            ret = OPENSSL_sk_new_null();
            if ret.is_null() {
                // SAFETY: a compile-time-constant site.
                unsafe { raise_site(&err_sites::PEM_INFO_70) };
                break 'err;
            }
        }

        // SAFETY: no preconditions; the constructor cannot fail on a valid size.
        xi = X509_INFO_new();
        if xi.is_null() {
            break 'err;
        }

        loop {
            let mut raw: c_uint = 0;
            let mut ptype: c_uint = 0;
            // SAFETY: the mark functions take no arguments.
            ERR_set_mark();
            // SAFETY: `bp` is live and the four out-parameters are this frame's own.
            let read = unsafe { PEM_read_bio(bp, &mut name, &mut header, &mut data, &mut len) };
            if read == 0 {
                // SAFETY: no precondition; reads this thread's queue.
                let error = peek_last_reason() as c_long;
                if error == PEM_R_NO_START_LINE as c_long {
                    // SAFETY: no preconditions.
                    ERR_pop_to_mark();
                    break;
                }
                // SAFETY: no preconditions.
                ERR_clear_last_mark();
                break 'err;
            }
            // SAFETY: no preconditions.
            ERR_clear_last_mark();

            'start: loop {
                // SAFETY: `name` is NUL-terminated by the reader.
                let is_x509 = unsafe { strcmp(name, PEM_STRING_X509) } == 0
                    || unsafe { strcmp(name, PEM_STRING_X509_OLD) } == 0
                    || unsafe { strcmp(name, PEM_STRING_X509_TRUSTED) } == 0;
                // SAFETY: `name` is NUL-terminated by the reader.
                let is_crl = unsafe { strcmp(name, PEM_STRING_X509_CRL) } == 0;
                // SAFETY: both strings are NUL-terminated.
                let priv_suffix = unsafe { strstr(name, PEM_STRING_PKCS8INF) };

                let d2i: Option<D2iOfVoid>;
                let pp: *mut c_void;

                if is_x509 {
                    // SAFETY: `xi` is live.
                    if !unsafe { (*xi).x509 }.is_null() {
                        // SAFETY: `ret` and `xi` are live.
                        if unsafe { OPENSSL_sk_push(ret, xi.cast()) } == 0 {
                            break 'err;
                        }
                        // SAFETY: no preconditions.
                        xi = X509_INFO_new();
                        if xi.is_null() {
                            break 'err;
                        }
                        continue 'start;
                    }
                    // SAFETY: `name` is NUL-terminated.
                    if unsafe { strcmp(name, PEM_STRING_X509_TRUSTED) } == 0 {
                        d2i = Some(d2i_void_x509_aux);
                    } else {
                        d2i = Some(d2i_void_x509);
                    }
                    // SAFETY: `libctx`/`propq` are the caller's.
                    let x = unsafe { X509_new_ex(libctx, propq) };
                    // SAFETY: `xi` is live.
                    unsafe { (*xi).x509 = x };
                    if x.is_null() {
                        break 'err;
                    }
                    // SAFETY: `xi` is live and `x509` is its own field.
                    pp = unsafe { ptr::addr_of_mut!((*xi).x509) }.cast::<c_void>();
                } else if is_crl {
                    d2i = Some(d2i_void_x509_crl);
                    // SAFETY: `xi` is live.
                    if !unsafe { (*xi).crl }.is_null() {
                        // SAFETY: `ret` and `xi` are live.
                        if unsafe { OPENSSL_sk_push(ret, xi.cast()) } == 0 {
                            break 'err;
                        }
                        // SAFETY: no preconditions.
                        xi = X509_INFO_new();
                        if xi.is_null() {
                            break 'err;
                        }
                        continue 'start;
                    }
                    // SAFETY: `xi` is live and `crl` is its own field.
                    pp = unsafe { ptr::addr_of_mut!((*xi).crl) }.cast::<c_void>();
                } else if !priv_suffix.is_null() {
                    // SAFETY: `xi` is live.
                    if !unsafe { (*xi).x_pkey }.is_null() {
                        // SAFETY: `ret` and `xi` are live.
                        if unsafe { OPENSSL_sk_push(ret, xi.cast()) } == 0 {
                            break 'err;
                        }
                        // SAFETY: no preconditions.
                        xi = X509_INFO_new();
                        if xi.is_null() {
                            break 'err;
                        }
                        continue 'start;
                    }
                    // SAFETY: `name` is NUL-terminated.
                    if priv_suffix == name || unsafe { strcmp(name, PEM_STRING_PKCS8) } == 0 {
                        ptype = EVP_PKEY_NONE;
                    } else {
                        /* chop " PRIVATE KEY" */
                        // SAFETY: `priv_suffix` points one past the space the suffix begins with.
                        unsafe { *priv_suffix.sub(1) = 0 };
                        // SAFETY: `name` is now NUL-terminated at the chopped position.
                        ptype = unsafe { evp_pkey_name2type(name) } as c_uint;
                    }
                    // SAFETY: `xi` is live.
                    unsafe {
                        (*xi).enc_data = ptr::null_mut();
                        (*xi).enc_len = 0;
                    }
                    d2i = Some(d2i_void_auto);
                    // SAFETY: no preconditions.
                    let xp = X509_PKEY_new();
                    // SAFETY: `xi` is live.
                    unsafe { (*xi).x_pkey = xp };
                    if xp.is_null() {
                        break 'err;
                    }
                    // SAFETY: `xi` and `xp` are live and `dec_pkey` is `xp`'s own field.
                    pp = unsafe { ptr::addr_of_mut!((*(*xi).x_pkey).dec_pkey) }.cast::<c_void>();
                    /* assume encrypted */
                    // SAFETY: `header` is NUL-terminated by the reader.
                    let header_long = unsafe { strlen(header) } > 10;
                    // SAFETY: `name` is NUL-terminated by the reader.
                    let encrypted_name = unsafe { strcmp(name, PEM_STRING_PKCS8) } == 0;
                    if header_long || encrypted_name {
                        raw = 1;
                    }
                } else {
                    /* unknown */
                    d2i = None;
                    pp = ptr::null_mut();
                }

                if let Some(d2i_fn) = d2i {
                    if raw == 0 {
                        let mut cipher = crate::evp::pem_bridge::EvpCipherInfo {
                            cipher: ptr::null(),
                            iv: [0; EVP_MAX_IV_LENGTH],
                        };
                        // SAFETY: `header` is NUL-terminated and `cipher` is this frame's.
                        if unsafe { PEM_get_EVP_CIPHER_INFO(header, &mut cipher) } == 0 {
                            break 'err;
                        }
                        // SAFETY: `data` is the reader's buffer for `len` bytes.
                        if unsafe { PEM_do_header(&mut cipher, data, &mut len, cb, u) } == 0 {
                            break 'err;
                        }
                        let mut p: *const c_uchar = data;
                        if ptype != 0 {
                            // SAFETY: `pp` is the decoder's destination and `p` is the cursor.
                            let r = unsafe {
                                d2i_PrivateKey_ex(
                                    ptype as c_int,
                                    pp.cast::<*mut EvpPkey>(),
                                    &mut p,
                                    len,
                                    libctx,
                                    propq,
                                )
                            };
                            if r.is_null() {
                                // SAFETY: a compile-time-constant site.
                                unsafe { raise_site(&err_sites::PEM_INFO_166) };
                                break 'err;
                            }
                        } else {
                            // SAFETY: `pp` is the decoder's destination and `p` is the cursor.
                            let r = unsafe { d2i_fn(pp.cast::<*mut c_void>(), &mut p, len) };
                            if r.is_null() {
                                // SAFETY: a compile-time-constant site.
                                unsafe { raise_site(&err_sites::PEM_INFO_170) };
                                break 'err;
                            }
                        }
                    } else {
                        /* encrypted key data */
                        // SAFETY: `header` is NUL-terminated and `xi` is live.
                        if unsafe {
                            PEM_get_EVP_CIPHER_INFO(header, ptr::addr_of_mut!((*xi).enc_cipher))
                        } == 0
                        {
                            break 'err;
                        }
                        // SAFETY: `xi` is live; it takes ownership of `data`, which is cleared
                        // below so the buffer is not freed twice.
                        unsafe {
                            (*xi).enc_data = data.cast::<c_char>();
                            (*xi).enc_len = len as c_int;
                        }
                        data = ptr::null_mut();
                    }
                }

                // SAFETY: each buffer is this frame's own (or NULL when ownership moved).
                unsafe {
                    CRYPTO_free(name.cast::<c_void>(), FILE, LINE_FREE_NAME);
                    name = ptr::null_mut();
                    CRYPTO_free(header.cast::<c_void>(), FILE, LINE_FREE_HEADER);
                    header = ptr::null_mut();
                    CRYPTO_free(data.cast::<c_void>(), FILE, LINE_FREE_DATA);
                    data = ptr::null_mut();
                }
                break 'start;
            }
        }

        /*
         * if the last one hasn't been pushed yet and there is anything in it
         * then add it to the stack ...
         */
        // SAFETY: `xi` is live.
        let nonempty = unsafe {
            !(*xi).x509.is_null()
                || !(*xi).crl.is_null()
                || !(*xi).x_pkey.is_null()
                || !(*xi).enc_data.is_null()
        };
        if nonempty {
            // SAFETY: `ret` and `xi` are live.
            if unsafe { OPENSSL_sk_push(ret, xi.cast()) } == 0 {
                break 'err;
            }
            xi = ptr::null_mut();
        }
        ok = true;
    }

    // err:
    // SAFETY: `xi` is NULL or this frame's own record.
    unsafe { X509_INFO_free(xi) };
    if !ok {
        let mut i: c_int = 0;
        // SAFETY: `ret` is NULL or a live stack.
        while i < unsafe { OPENSSL_sk_num(ret) } {
            // SAFETY: `i` is within the stack.
            let item = unsafe { OPENSSL_sk_value(ret, i) }.cast::<X509Info>();
            // SAFETY: `item` is an element this reader pushed.
            unsafe { X509_INFO_free(item) };
            i += 1;
        }
        if ret != sk {
            // SAFETY: `ret` is this frame's own stack.
            unsafe { OPENSSL_sk_free(ret) };
        }
        ret = ptr::null_mut();
    }

    // SAFETY: each is NULL or this frame's own buffer.
    unsafe {
        CRYPTO_free(name.cast::<c_void>(), FILE, LINE_FREE_ERR_NAME);
        CRYPTO_free(header.cast::<c_void>(), FILE, LINE_FREE_ERR_HEADER);
        CRYPTO_free(data.cast::<c_void>(), FILE, LINE_FREE_ERR_DATA);
    }
    ret
}

/// `STACK_OF(X509_INFO) *PEM_X509_INFO_read_bio(BIO *bp, STACK_OF(X509_INFO) *sk,
/// pem_password_cb *cb, void *u)` — `crypto/pem/pem_info.c:217-221`.
///
/// # Safety
/// As [`PEM_X509_INFO_read_bio_ex`] with a NULL `libctx`/`propq`.
#[no_mangle]
pub unsafe extern "C" fn PEM_X509_INFO_read_bio(
    bp: *mut Bio,
    sk: *mut OpenSslStack,
    cb: Option<PemPasswordCb>,
    u: *mut c_void,
) -> *mut OpenSslStack {
    // SAFETY: the caller's contract with a NULL context.
    unsafe { PEM_X509_INFO_read_bio_ex(bp, sk, cb, u, ptr::null_mut(), ptr::null()) }
}

/// `int PEM_X509_INFO_write_bio(BIO *bp, const X509_INFO *xi, EVP_CIPHER *enc, const unsigned
/// char *kstr, int klen, pem_password_cb *cb, void *u)` — `crypto/pem/pem_info.c:224-312`.
///
/// Writes the record's private key (re-encrypting a not-yet-decrypted one from its stored
/// `enc_data`) and then its certificate. The `buf` is cleansed on every exit, as the authority's
/// `err:` arm does.
///
/// # Safety
/// `bp` a live writable BIO; `xi` a live record; `enc` NULL or a live cipher; `kstr`/`klen`/`cb`/`u`
/// as the private-key writer's contract.
#[no_mangle]
pub unsafe extern "C" fn PEM_X509_INFO_write_bio(
    bp: *mut Bio,
    xi: *const X509Info,
    enc: *mut EvpCipher,
    kstr: *const c_uchar,
    klen: c_int,
    cb: Option<PemPasswordCb>,
    u: *mut c_void,
) -> c_int {
    let mut ret: c_int = 0;
    let mut buf = [0 as c_char; PEM_BUFSIZE as usize];

    'err: {
        if !enc.is_null() {
            // SAFETY: `enc` is live.
            let objstr = unsafe { EVP_CIPHER_get0_name(enc) };
            // SAFETY: `objstr` is NULL or NUL-terminated; `enc` is live.
            let too_long = objstr.is_null()
                || (unsafe { strlen(objstr) }
                    + 23
                    + 2 * (unsafe { EVP_CIPHER_get_iv_length(enc) } as usize)
                    + 13)
                    > PEM_BUFSIZE as usize;
            if too_long {
                // SAFETY: a compile-time-constant site.
                unsafe { raise_site(&err_sites::PEM_INFO_243) };
                break 'err;
            }
        }

        // SAFETY: `xi` is live per the contract.
        if !unsafe { (*xi).x_pkey }.is_null() {
            // SAFETY: `xi` is live.
            if !unsafe { (*xi).enc_data }.is_null() && unsafe { (*xi).enc_len } > 0 {
                if enc.is_null() {
                    // SAFETY: a compile-time-constant site.
                    unsafe { raise_site(&err_sites::PEM_INFO_256) };
                    break 'err;
                }
                // SAFETY: `xi` is live and its `enc_cipher` is its own.
                let iv = unsafe { (*xi).enc_cipher.iv.as_ptr() };
                // SAFETY: `xi` is live.
                let data = unsafe { (*xi).enc_data.cast::<c_uchar>() };
                // SAFETY: `xi` is live.
                let mut i: c_int = unsafe { (*xi).enc_len };

                // SAFETY: `xi` is live.
                let objstr = unsafe { EVP_CIPHER_get0_name((*xi).enc_cipher.cipher) };
                if objstr.is_null() {
                    // SAFETY: a compile-time-constant site.
                    unsafe { raise_site(&err_sites::PEM_INFO_272) };
                    break 'err;
                }

                /* Create the right magic header stuff */
                buf[0] = 0;
                // SAFETY: `buf` is `PEM_BUFSIZE` bytes and NUL-terminated.
                unsafe { PEM_proc_type(buf.as_mut_ptr(), PEM_TYPE_ENCRYPTED) };
                // SAFETY: `buf` is NUL-terminated, `objstr` is NUL-terminated, `iv` is readable
                // for the cipher's IV length.
                unsafe {
                    PEM_dek_info(
                        buf.as_mut_ptr(),
                        objstr,
                        EVP_CIPHER_get_iv_length(enc),
                        iv.cast::<c_char>(),
                    )
                };

                /* use the normal code to write things out */
                // SAFETY: `bp` is live, `buf`/`data` are readable for the given lengths.
                i = unsafe { PEM_write_bio(bp, PEM_STRING_RSA, buf.as_ptr(), data, i as c_long) };
                if i <= 0 {
                    break 'err;
                }
            } else {
                /* Add DSA/DH -- normal optionally encrypted stuff */
                // SAFETY: `xi` is live and `dec_pkey` is the record's own borrowed key.
                let pkey = unsafe { (*(*xi).x_pkey).dec_pkey };
                // SAFETY: `bp`/`pkey` are live and the rest is the caller's.
                if unsafe {
                    PEM_write_bio_RSAPrivateKey(bp, EVP_PKEY_get0_RSA(pkey), enc, kstr, klen, cb, u)
                } <= 0
                {
                    break 'err;
                }
            }
        }

        /* if we have a certificate then write it out now */
        // SAFETY: `xi` is live.
        if !unsafe { (*xi).x509 }.is_null()
            // SAFETY: `bp` and the certificate are live.
            && unsafe { PEM_write_bio_X509(bp, (*xi).x509) } <= 0
        {
            break 'err;
        }

        ret = 1;
    }

    // SAFETY: `buf` is this frame's `PEM_BUFSIZE` bytes.
    unsafe { OPENSSL_cleanse(buf.as_mut_ptr().cast::<c_void>(), PEM_BUFSIZE as usize) };
    ret
}
