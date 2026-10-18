//! Phase 10.14.2 — `crypto/x509/x509spki.c`: the Netscape SPKI convenience surface.
//!
//! `crypto/x509/x509spki.c` is 75 lines and publishes four functions over the `NETSCAPE_SPKI`
//! object this subphase lands in `src/asn1/x_spki.rs`: the public-key setter/getter, and the
//! base64 decode/encode pair.
//!
//! The two base64 functions allocate through `OPENSSL_malloc`/`OPENSSL_malloc_array`, which are
//! the macros `CRYPTO_malloc(n, __FILE__, __LINE__)`/`CRYPTO_malloc_array(n, m, __FILE__, __LINE__)`
//! (`include/openssl/crypto.h`); the transcription calls the `CRYPTO_*` spellings with this
//! file's coordinates. The three scratch blocks those calls produce are owned by [`OwnedBuf`],
//! whose `Drop` is the authority's own single `OPENSSL_free` on every path.
//!
//! One `ERR_raise` site: `NETSCAPE_SPKI_b64_decode`'s base64 refusal (`:42`,
//! `ERR_LIB_X509`/`X509_R_BASE64_DECODE_ERROR`). Its coordinate is the generated
//! `X509_SPKI_42` constant, so `crypto/x509/x509spki.c` joins `gen_err_raise_sites.py`'s covered
//! set with this subphase.
//!
//! SPDX-License-Identifier: Apache-2.0

#![allow(non_snake_case)]

use core::ffi::{c_char, c_int, c_long, c_uchar, CStr};
use core::ptr;

use crate::asn1::x_spki::{d2i_NETSCAPE_SPKI, i2d_NETSCAPE_SPKI, NetScapeSpki};
use crate::evp::encode::{EVP_DecodeBlock, EVP_EncodeBlock};
use crate::evp::pkey::EvpPkey;
use crate::runtime::err::{err_sites, raise_site};
use crate::runtime::mem_coords::SeamFile;
use crate::runtime::owned_buf::OwnedBuf;
use crate::x509::x_pubkey::{X509_PUBKEY_get, X509_PUBKEY_set};

/// The `__FILE__` the authority's `OPENSSL_malloc` macro expands to in this unit.
const FILE_NAME: &CStr = c"crypto/x509/x509spki.c";
/// The line the allocation-tracking record carries. Zero, as every landed allocator call site
/// uses: the number is unobservable and only the file's identity is contract.
const LINE: c_int = 0;

/// `int NETSCAPE_SPKI_set_pubkey(NETSCAPE_SPKI *x, EVP_PKEY *pkey)` —
/// `crypto/x509/x509spki.c:14-19`.
///
/// A NULL SPKI or a NULL `spkac` answers 0; otherwise the key is installed on the `spkac`'s
/// `pubkey` through `X509_PUBKEY_set`.
///
/// # Safety
///
/// `x` must be NULL or live; `pkey` a live key.
#[no_mangle]
pub unsafe extern "C" fn NETSCAPE_SPKI_set_pubkey(
    x: *mut NetScapeSpki,
    pkey: *mut EvpPkey,
) -> c_int {
    if x.is_null() {
        return 0;
    }
    // SAFETY: `x` is live per the check above.
    if unsafe { (*x).spkac.is_null() } {
        return 0;
    }
    // SAFETY: `x`'s `spkac` is live per the check above; `pkey` is the caller's.
    unsafe { X509_PUBKEY_set(&raw mut (*(*x).spkac).pubkey, pkey) }
}

/// `EVP_PKEY *NETSCAPE_SPKI_get_pubkey(NETSCAPE_SPKI *x)` — `crypto/x509/x509spki.c:21-26`.
///
/// # Safety
///
/// `x` must be NULL or live.
#[no_mangle]
pub unsafe extern "C" fn NETSCAPE_SPKI_get_pubkey(x: *mut NetScapeSpki) -> *mut EvpPkey {
    if x.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: `x` is live per the check above.
    if unsafe { (*x).spkac.is_null() } {
        return ptr::null_mut();
    }
    // SAFETY: `x`'s `spkac` is live per the check above.
    unsafe { X509_PUBKEY_get((*(*x).spkac).pubkey) }
}

/// `NETSCAPE_SPKI *NETSCAPE_SPKI_b64_decode(const char *str, int len)` —
/// `crypto/x509/x509spki.c:30-50`.
///
/// A `len` of 0 or less means "use `strlen`". The base64 is decoded into a `len + 1` byte buffer
/// and handed to `d2i_NETSCAPE_SPKI`; an invalid base64 is refused with
/// `X509_R_BASE64_DECODE_ERROR`.
///
/// # Safety
///
/// `str` must be a NUL-terminated readable buffer of at least `len` bytes when `len > 0`.
#[no_mangle]
pub unsafe extern "C" fn NETSCAPE_SPKI_b64_decode(
    str_: *const c_char,
    len: c_int,
) -> *mut NetScapeSpki {
    let len = if len <= 0 {
        // SAFETY: `str_` is NUL-terminated per the contract when a length is not given.
        unsafe { CStr::from_ptr(str_) }.to_bytes().len() as c_int
    } else {
        len
    };
    // `spki_der` owns the fresh `len + 1`-byte scratch block; every exit below drops it, which is
    // the authority's own `OPENSSL_free` at this unit's line.
    let spki_der = match OwnedBuf::new(len as usize + 1, SeamFile::new(FILE_NAME), LINE) {
        Some(buf) => buf,
        None => return ptr::null_mut(),
    };
    // SAFETY: `spki_der` has room for `len + 1` bytes and `str_` is readable for `len`.
    let spki_len = unsafe { EVP_DecodeBlock(spki_der.as_ptr(), str_.cast::<c_uchar>(), len) };
    if spki_len < 0 {
        // SAFETY: a compile-time-constant site, exactly as `ERR_raise` is.
        unsafe { raise_site(&err_sites::X509_SPKI_42) };
        return ptr::null_mut();
    }
    let mut p: *const c_uchar = spki_der.as_ptr();
    // SAFETY: `spki_der` holds `spki_len` bytes and `p` is this frame's cursor.
    unsafe { d2i_NETSCAPE_SPKI(ptr::null_mut(), &raw mut p, c_long::from(spki_len)) }
}

/// `char *NETSCAPE_SPKI_b64_encode(NETSCAPE_SPKI *spki)` — `crypto/x509/x509spki.c:54-75`.
///
/// Encodes the SPKI to DER, base64s it into a `2 * der_len` byte buffer and returns it. A
/// sizing failure (`der_len <= 0`) answers NULL with no raise; an allocation failure releases
/// whatever was allocated and answers NULL.
///
/// # Safety
///
/// `spki` must be a live `NETSCAPE_SPKI`.
#[no_mangle]
pub unsafe extern "C" fn NETSCAPE_SPKI_b64_encode(spki: *mut NetScapeSpki) -> *mut c_char {
    // SAFETY: `spki` is live per the contract and a null destination asks for the size.
    let der_len = unsafe { i2d_NETSCAPE_SPKI(spki, ptr::null_mut()) };
    if der_len <= 0 {
        return ptr::null_mut();
    }
    // `der_spki` owns the fresh `der_len`-byte DER scratch block and `b64_str` the doubled base64
    // block; a failed allocation drops the other, which is the authority's own `OPENSSL_free`.
    let der_spki = match OwnedBuf::new(der_len as usize, SeamFile::new(FILE_NAME), LINE) {
        Some(buf) => buf,
        None => return ptr::null_mut(),
    };
    // SAFETY: `der_len * 2` is the authority's exact base64 expansion extent; the product is
    // checked and an overflow refuses the allocation.
    let b64_str =
        match unsafe { OwnedBuf::new_array(der_len as usize, 2, SeamFile::new(FILE_NAME), LINE) } {
            Some(buf) => buf,
            None => return ptr::null_mut(),
        };
    let mut p = der_spki.as_ptr();
    // SAFETY: `der_spki` has room for `der_len` bytes and `p` is this frame's cursor.
    unsafe { i2d_NETSCAPE_SPKI(spki, &raw mut p) };
    // SAFETY: `b64_str` has room for the base64 expansion and `der_spki` is readable for
    // `der_len` bytes.
    unsafe { EVP_EncodeBlock(b64_str.as_ptr(), der_spki.as_ptr(), der_len) };
    // `der_spki` drops here, the authority's own `OPENSSL_free`; `b64_str` is handed to the caller.
    b64_str.into_raw().cast::<c_char>()
}
