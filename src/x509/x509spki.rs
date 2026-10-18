//! Phase 10.14.2 — `crypto/x509/x509spki.c`: the Netscape SPKI convenience surface.
//!
//! `crypto/x509/x509spki.c` is 75 lines and publishes four functions over the `NETSCAPE_SPKI`
//! object this subphase lands in `src/asn1/x_spki.rs`: the public-key setter/getter, and the
//! base64 decode/encode pair.
//!
//! The two base64 functions allocate through `OPENSSL_malloc`, which is the macro
//! `CRYPTO_malloc(n, __FILE__, __LINE__)` (`include/openssl/crypto.h`); the transcription calls
//! the `CRYPTO_*` spelling with this file's coordinates. The scratch blocks those calls produce
//! are owned by [`OwnedBuf`], whose `Drop` is the authority's own single `OPENSSL_free` on every
//! path.
//!
//! `NETSCAPE_SPKI_b64_encode` allocates the encoder's **exact** extent
//! (`4 * ceil(der_len / 3) + 1`) rather than the authority's `OPENSSL_malloc_array(der_len, 2)`:
//! `2 * der_len` is smaller than that extent for `der_len = 1`, `2` and `4` (it happens to fit at
//! `3` and `5`), so the authority can write past its allocation. The correction is recorded as a
//! deliberate §17 divergence.
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

/// The byte extent `EVP_EncodeBlock` writes for `der_len` input bytes: four base64 characters
/// per three input bytes, rounded up, plus the NUL terminator — `4 * ceil(der_len / 3) + 1`.
/// Answers `None` when the computation is unrepresentable.
fn base64_encoded_len(der_len: usize) -> Option<usize> {
    der_len
        .checked_add(2)?
        .checked_div(3)?
        .checked_mul(4)?
        .checked_add(1)
}

/// Encode `der_len` readable bytes at `der` into a fresh block of exactly the encoder's output
/// extent, or `None` when the length overflows or the allocation fails.
///
/// # Safety
///
/// `der` is readable for `der_len` bytes.
unsafe fn encode_der_to_base64(der: *const c_uchar, der_len: c_int) -> Option<OwnedBuf> {
    let len = usize::try_from(der_len).ok()?;
    let b64_len = base64_encoded_len(len)?;
    // The allocation is the encoder's exact output size. The authority allocates `2 * der_len`
    // here, which is smaller than this extent for `der_len = 1`, `2` and `4`; reproducing that
    // would be an out-of-bounds write, so this is a deliberate §17 correction.
    let b64 = OwnedBuf::new(b64_len, SeamFile::new(FILE_NAME), LINE)?;
    // SAFETY: `der` is readable for `der_len` bytes, and `b64` is writable for the encoder's
    // `4 * ceil(der_len / 3) + 1` output, which is exactly `b64_len`.
    unsafe { EVP_EncodeBlock(b64.as_ptr(), der, der_len) };
    Some(b64)
}

/// `char *NETSCAPE_SPKI_b64_encode(NETSCAPE_SPKI *spki)` — `crypto/x509/x509spki.c:54-75`.
///
/// Encodes the SPKI to DER, base64s it into a buffer of exactly the encoder's extent
/// (`4 * ceil(der_len / 3) + 1` bytes) and returns it. A sizing failure (`der_len <= 0`)
/// answers NULL with no raise; an allocation failure releases whatever was allocated and
/// answers NULL.
///
/// The authority allocates `2 * der_len` bytes, which the encoder overruns for `der_len = 1`,
/// `2` and `4`. Per §17 the overrun is corrected rather than reproduced; the returned string's
/// observable content is unchanged.
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
    let mut p = der_spki.as_ptr();
    // SAFETY: `der_spki` has room for `der_len` bytes and `p` is this frame's cursor.
    unsafe { i2d_NETSCAPE_SPKI(spki, &raw mut p) };
    // `der_spki` drops after the encoding, the authority's own `OPENSSL_free`; the encoded block
    // is handed to the caller.
    // SAFETY: `der_spki` is readable for `der_len` bytes (the sizing call and the write above).
    unsafe { encode_der_to_base64(der_spki.as_ptr(), der_len) }
        .map_or(ptr::null_mut(), |buf| buf.into_raw().cast::<c_char>())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    /// The authority's `2 * der_len` extent is smaller than the encoder's output for the
    /// shortest inputs, which is the overrun this unit corrects.
    #[test]
    fn base64_extent_is_exact_for_the_shortest_inputs() {
        for n in 1..=5usize {
            let got = base64_encoded_len(n).expect("a small length cannot overflow");
            assert_eq!(got, 4 * n.div_ceil(3) + 1, "input length {n}");
            // `2*n` under-sizes the encoder for exactly n = 1, 2 and 4 among the first five.
            assert_eq!(
                got > 2 * n,
                matches!(n, 1 | 2 | 4),
                "2*n sufficiency for n={n}"
            );
        }
        assert_eq!(base64_encoded_len(1), Some(5));
        assert_eq!(base64_encoded_len(2), Some(5));
        assert_eq!(base64_encoded_len(3), Some(5));
        assert_eq!(base64_encoded_len(4), Some(9));
        assert_eq!(base64_encoded_len(5), Some(9));
    }

    #[test]
    fn base64_extent_is_checked_for_a_large_input_and_at_the_bound() {
        let n = 1_000_000usize;
        assert_eq!(base64_encoded_len(n), Some(4 * n.div_ceil(3) + 1));
        assert_eq!(
            base64_encoded_len(usize::MAX),
            None,
            "the `n + 2` step must be checked"
        );
    }

    /// Negative control for the extent: an allocation of exactly the computed length plus a
    /// 16-byte canary tail is encoded into, and the tail must survive for every input size
    /// that the authority's `2*n` extent would have under-sized.
    #[test]
    fn the_encoder_stays_inside_the_computed_extent() {
        for n in [1usize, 2, 3, 4, 5, 4096] {
            let len = base64_encoded_len(n).expect("the test lengths cannot overflow");
            let buf = OwnedBuf::new(len + 16, SeamFile::new(FILE_NAME), LINE)
                .expect("the canary block must allocate");
            // SAFETY: `buf` owns `len + 16` writable bytes.
            unsafe { ptr::write_bytes(buf.as_ptr(), 0xA5, len + 16) };
            let input = vec![0x11u8; n];
            // SAFETY: `input` is readable for `n` bytes and the encoder's exact output extent
            // `len` is inside `buf`; the canary tail is beyond that extent.
            let written = unsafe { EVP_EncodeBlock(buf.as_ptr(), input.as_ptr(), n as c_int) };
            assert_eq!(
                written as usize + 1,
                len,
                "the encoder must write exactly the computed extent"
            );
            // SAFETY: `len + 16` bytes are allocated and the tail starts at `len`.
            let tail = unsafe { core::slice::from_raw_parts(buf.as_ptr().add(len), 16) };
            assert!(
                tail.iter().all(|&b| b == 0xA5),
                "the encoder wrote past the computed extent for n={n}"
            );
            // SAFETY: the byte before the tail was written by the encoder.
            assert_eq!(unsafe { *buf.as_ptr().add(len - 1) }, 0, "terminator");
        }
    }

    /// The production helper allocates its own block; this checks the encoded bytes and that
    /// the terminator is present at the computed position.
    #[test]
    fn the_production_helper_encodes_into_its_exact_extent() {
        // "f" encodes to "Zg==".
        let input = [0x66u8];
        // SAFETY: `input` is readable for one byte.
        let b64 = unsafe { encode_der_to_base64(input.as_ptr(), input.len() as c_int) }
            .expect("the exact-size block must allocate");
        let expected = b"Zg==\0";
        // SAFETY: `b64` is a live block the helper filled with the encoded bytes and terminator.
        let got = unsafe { core::slice::from_raw_parts(b64.as_ptr(), expected.len()) };
        assert_eq!(got, expected);
    }
}
