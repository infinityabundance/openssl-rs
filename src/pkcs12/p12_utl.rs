//! `crypto/pkcs12/p12_utl.c` — the cheap Unicode helpers and the `PKCS12` BIO/`FILE` readers.
//! Phase 10 (10.2).
//!
//! Four of the unit's eight exports are the ASCII/BMPString/UTF-8 conversions:
//! `OPENSSL_asc2uni`/`OPENSSL_uni2asc` (the naive pair) and `OPENSSL_utf82uni`/
//! `OPENSSL_uni2utf8` (the UTF-8-aware pair, with `bmp_to_utf8` as their shared helper).
//! `PKCS12_get_friendlyname` (`crypto/pkcs12/p12_attr.c`) reaches `OPENSSL_uni2utf8`, which is
//! why the unit lands with this subphase.
//!
//! ## The four BIO/`FILE` wrappers are held open, and the reason is a Phase 12 dependency
//!
//! `d2i_PKCS12_bio`/`d2i_PKCS12_fp`/`i2d_PKCS12_bio`/`i2d_PKCS12_fp` each call an
//! `ASN1_item_*_bio`/`_fp` over `ASN1_ITEM_rptr(PKCS12)`, and the two `d2i` spellings also read
//! the previous value's `PKCS7_CTX` through `ossl_pkcs12_get0_pkcs7ctx`. Both reach the `PKCS12`
//! item and the `PKCS7` object, neither of which can be built here: `PKCS12_it` is named above
//! and `PKCS7_it` is Phase 12's (`crypto/pkcs7/pk7_asn1.c`). They are left `open` rather than
//! stubbed, and `PKCS12`'s own item group lands in the slice that can build the `PKCS7` it needs.
//!
//! ## The naive/UTF-8 asymmetry is the authority's, and it round-trips through the fallback
//!
//! `OPENSSL_utf82uni` decodes with `UTF8_getc` and, on a decode failure, **falls back** to
//! `OPENSSL_asc2uni`; `OPENSSL_uni2utf8` falls back to `OPENSSL_uni2asc` on a bad BMPString pair.
//! Those fallbacks are what let a file written by an old OpenSSL (which used `asc2uni` all along)
//! still load, and they are observable, so they are transcribed rather than dropped.
//!
//! The unit raises nothing, so it is deliberately **not** an entry in `gen_err_raise_sites.py`'s
//! `COVERED_FILES`: an entry for it would read as coverage that does not exist.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_char, c_int, c_uchar, c_ulong};

use crate::asn1::a_utf8::{UTF8_getc, UTF8_putc};
use crate::runtime::bio::sys::strlen;
use crate::runtime::mem::{CRYPTO_free, CRYPTO_malloc};

/// `crypto/pkcs12/p12_utl.c` — the authority's `__FILE__` string, for the allocator's bookkeeping.
const FILE: &core::ffi::CStr = c"crypto/pkcs12/p12_utl.c";
/// The line the authority's `OPENSSL_malloc` call expands to, as the authority spells it (the
/// allocation site is the file's own `OPENSSL_malloc`, without a pin line, so the crate uses 0).
const LINE: c_int = 0;

/// `unsigned char *OPENSSL_asc2uni(const char *asc, int asclen, unsigned char **uni,
/// int *unilen)` — `crypto/pkcs12/p12_utl.c:18-43`.
///
/// `asclen == -1` means "use `strlen`"; a negative length answers NULL. The result is
/// `asclen * 2 + 2` bytes: each input byte becomes a big-endian UTF-16 code unit, and the buffer
/// ends with **two** zero bytes rather than the single NUL `OPENSSL_uni2asc` expects.
///
/// # Safety
/// `asc` is NULL or a string of `asclen` bytes (or NUL-terminated when `asclen == -1`);
/// `uni`/`unilen` are each NULL or writable for their type. The answer is a fresh
/// `OPENSSL_malloc` buffer the caller owns, also returned through `*uni` when that is non-NULL.
#[no_mangle]
pub unsafe extern "C" fn OPENSSL_asc2uni(
    asc: *const c_char,
    asclen: c_int,
    uni: *mut *mut c_uchar,
    unilen: *mut c_int,
) -> *mut c_uchar {
    let mut asclen = asclen;
    if asclen == -1 {
        // SAFETY: `asc` is a NUL-terminated string per the contract.
        asclen = unsafe { strlen(asc) } as c_int;
    }
    if asclen < 0 {
        return core::ptr::null_mut();
    }
    let ulen = asclen * 2 + 2;
    // SAFETY: `ulen` is a positive byte count.
    let unitmp = CRYPTO_malloc(ulen as usize, FILE.as_ptr(), LINE).cast::<c_uchar>();
    if unitmp.is_null() {
        return core::ptr::null_mut();
    }
    let mut i = 0;
    while i < ulen - 2 {
        // SAFETY: `unitmp` has `ulen` writable bytes and `asc` has `asclen` readable ones;
        // `i >> 1 < asclen` throughout.
        unsafe {
            *unitmp.add(i as usize) = 0;
            *unitmp.add(i as usize + 1) = *asc.add((i >> 1) as usize) as c_uchar;
        }
        i += 2;
    }
    // Make result double null terminated.
    // SAFETY: the last two bytes are within the allocation.
    unsafe {
        *unitmp.add((ulen - 2) as usize) = 0;
        *unitmp.add((ulen - 1) as usize) = 0;
        if !unilen.is_null() {
            *unilen = ulen;
        }
        if !uni.is_null() {
            *uni = unitmp;
        }
    }
    unitmp
}

/// `char *OPENSSL_uni2asc(const unsigned char *uni, int unilen)` — `crypto/pkcs12/p12_utl.c:45-66`.
///
/// An odd or negative `unilen` answers NULL. The odd bytes of `uni` are the ASCII characters; a
/// missing final NUL is allowed for and one is written. The answer is an `OPENSSL_malloc` string.
///
/// # Safety
/// `uni` is NULL or readable for `unilen` bytes. The answer is a fresh `OPENSSL_malloc` buffer the
/// caller owns.
#[no_mangle]
pub unsafe extern "C" fn OPENSSL_uni2asc(uni: *const c_uchar, unilen: c_int) -> *mut c_char {
    // String must contain an even number of bytes.
    if unilen & 1 != 0 {
        return core::ptr::null_mut();
    }
    if unilen < 0 {
        return core::ptr::null_mut();
    }
    let mut asclen = unilen / 2;
    // If no terminating zero allow for one.
    // SAFETY: `unilen` is even and non-negative, so `uni[unilen-1]` is in range when non-zero.
    if unilen == 0 || unsafe { *uni.add((unilen - 1) as usize) } != 0 {
        asclen += 1;
    }
    // SAFETY: `uni` is readable for `unilen` bytes; skipping the leading byte is in range.
    let uni = unsafe { uni.add(1) };
    // SAFETY: `asclen` is a positive byte count.
    let asctmp = CRYPTO_malloc(asclen as usize, FILE.as_ptr(), LINE).cast::<c_char>();
    if asctmp.is_null() {
        return core::ptr::null_mut();
    }
    let mut i = 0;
    while i < unilen {
        // SAFETY: `asctmp` has `asclen` bytes and `uni` has `unilen - 1` readable bytes after the
        // skip; `i >> 1 < asclen` and `i < unilen - 1` throughout.
        unsafe {
            *asctmp.add((i >> 1) as usize) = *uni.add(i as usize) as c_char;
        }
        i += 2;
    }
    // SAFETY: the final byte is within the allocation.
    unsafe {
        *asctmp.add((asclen - 1) as usize) = 0;
    }
    asctmp
}

/// `unsigned char *OPENSSL_utf82uni(const char *asc, int asclen, unsigned char **uni,
/// int *unilen)` — `crypto/pkcs12/p12_utl.c:77-148`.
///
/// Decodes `asc` as UTF-8 (falling back to [`OPENSSL_asc2uni`] on a decode failure, the
/// authority's old-file allowance) and writes big-endian UTF-16, surrogate pairs included, then
/// two trailing zero bytes.
///
/// # Safety
/// As [`OPENSSL_asc2uni`]. The answer is a fresh `OPENSSL_malloc` buffer the caller owns.
#[no_mangle]
pub unsafe extern "C" fn OPENSSL_utf82uni(
    asc: *const c_char,
    asclen: c_int,
    uni: *mut *mut c_uchar,
    unilen: *mut c_int,
) -> *mut c_uchar {
    let mut asclen = asclen;
    if asclen == -1 {
        // SAFETY: `asc` is a NUL-terminated string per the contract.
        asclen = unsafe { strlen(asc) } as c_int;
    }
    let mut ulen: c_int = 0;
    let mut utf32chr: c_ulong = 0;
    let mut i: c_int = 0;
    while i < asclen {
        // SAFETY: `asc` is readable for `asclen` bytes and `i < asclen`.
        let j = unsafe {
            UTF8_getc(
                asc.cast::<c_uchar>().add(i as usize),
                asclen - i,
                &raw mut utf32chr,
            )
        };
        // A decode failure is the authority's *indirect* signal that the input is really
        // extended ASCII, so the naive conversion is used rather than failing.
        if j < 0 {
            // SAFETY: the arguments are forwarded under this function's contract.
            return unsafe { OPENSSL_asc2uni(asc, asclen, uni, unilen) };
        }
        if utf32chr > 0x10FFFF {
            // UTF-16 cap.
            return core::ptr::null_mut();
        }
        ulen += if utf32chr >= 0x10000 { 2 * 2 } else { 2 };
        i += j;
    }
    ulen += 2; // for the trailing UTF-16 zero

    // SAFETY: `ulen` is a positive byte count.
    let ret = CRYPTO_malloc(ulen as usize, FILE.as_ptr(), LINE).cast::<c_uchar>();
    if ret.is_null() {
        return core::ptr::null_mut();
    }
    let mut unitmp = ret;
    let mut i: c_int = 0;
    while i < asclen {
        // SAFETY: as in the sizing loop, but the value slot is only read.
        let j = unsafe {
            UTF8_getc(
                asc.cast::<c_uchar>().add(i as usize),
                asclen - i,
                &raw mut utf32chr,
            )
        };
        if utf32chr >= 0x10000 {
            // A pair of UTF-16 characters.
            let v = utf32chr - 0x10000;
            let hi = 0xD800 + (v >> 10);
            let lo = 0xDC00 + (v & 0x3ff);
            // SAFETY: the sizing loop reserved four bytes for this code point.
            unsafe {
                *unitmp = (hi >> 8) as c_uchar;
                *unitmp.add(1) = hi as c_uchar;
                *unitmp.add(2) = (lo >> 8) as c_uchar;
                *unitmp.add(3) = lo as c_uchar;
                unitmp = unitmp.add(4);
            }
        } else {
            // Or just one.
            // SAFETY: the sizing loop reserved two bytes for this code point.
            unsafe {
                *unitmp = (utf32chr >> 8) as c_uchar;
                *unitmp.add(1) = utf32chr as c_uchar;
                unitmp = unitmp.add(2);
            }
        }
        i += j;
    }
    // Make result double null terminated.
    // SAFETY: two bytes remain for the trailing zeros.
    unsafe {
        *unitmp = 0;
        *unitmp.add(1) = 0;
        if !unilen.is_null() {
            *unilen = ulen;
        }
        if !uni.is_null() {
            *uni = ret;
        }
    }
    ret
}

/// `static int bmp_to_utf8(char *str, const unsigned char *utf16, int len)` —
/// `crypto/pkcs12/p12_utl.c:150-179`.
///
/// A null `str` asks for the width only. A truncated pair or a bad low surrogate answers `-1`,
/// which is what sends [`OPENSSL_uni2utf8`] to its `OPENSSL_uni2asc` fallback.
///
/// # Safety
/// `str` is NULL or writable for four bytes; `utf16` is readable for `len` bytes.
unsafe fn bmp_to_utf8(str_: *mut c_char, utf16: *const c_uchar, len: c_int) -> c_int {
    if len == 0 {
        return 0;
    }
    if len < 2 {
        return -1;
    }
    // Pull the UTF-16 character in big-endian order.
    // SAFETY: `len >= 2`, so two bytes are readable.
    let mut utf32chr =
        (c_ulong::from(unsafe { *utf16 }) << 8) | c_ulong::from(unsafe { *utf16.add(1) });
    if (0xD800..0xE000).contains(&utf32chr) {
        // Two chars.
        if len < 4 {
            return -1;
        }
        utf32chr -= 0xD800;
        utf32chr <<= 10;
        // SAFETY: `len >= 4`, so the low surrogate pair is readable.
        let lo = (c_ulong::from(unsafe { *utf16.add(2) }) << 8)
            | c_ulong::from(unsafe { *utf16.add(3) });
        if !(0xDC00..0xE000).contains(&lo) {
            return -1;
        }
        utf32chr |= lo - 0xDC00;
        utf32chr += 0x10000;
    }
    // SAFETY: `str_` is NULL or writable, and `utf32chr` is a valid code point.
    unsafe { UTF8_putc(str_.cast::<c_uchar>(), 4, utf32chr) }
}

/// `char *OPENSSL_uni2utf8(const unsigned char *uni, int unilen)` — `crypto/pkcs12/p12_utl.c:181-235`.
///
/// Two passes: the first sizes the UTF-8 output, the second writes it. A bad BMPString falls back
/// to [`OPENSSL_uni2asc`] for symmetry with [`OPENSSL_utf82uni`]'s fallback.
///
/// # Safety
/// `uni` is NULL or readable for `unilen` bytes. The answer is a fresh `OPENSSL_malloc` string the
/// caller owns.
#[no_mangle]
pub unsafe extern "C" fn OPENSSL_uni2utf8(uni: *const c_uchar, unilen: c_int) -> *mut c_char {
    // String must contain an even number of bytes.
    if unilen & 1 != 0 {
        return core::ptr::null_mut();
    }
    if unilen < 0 {
        return core::ptr::null_mut();
    }
    let mut asclen: c_int = 0;
    let mut i: c_int = 0;
    while i < unilen {
        // SAFETY: `uni` is readable for `unilen` bytes and `i < unilen`.
        let j = unsafe { bmp_to_utf8(core::ptr::null_mut(), uni.add(i as usize), unilen - i) };
        if j < 0 {
            // SAFETY: the arguments are forwarded under this function's contract.
            return unsafe { OPENSSL_uni2asc(uni, unilen) };
        }
        i += if j == 4 { 4 } else { 2 };
        asclen += j;
    }
    // If no terminating zero allow for one; the same condition decides whether the write pass
    // finishes with a NUL, so it is computed once.
    // SAFETY: `unilen` is even; the last two bytes are in range when non-zero.
    let needs_nul = unilen == 0
        || unsafe { *uni.add((unilen - 2) as usize) | *uni.add((unilen - 1) as usize) } != 0;
    if needs_nul {
        asclen += 1;
    }

    // SAFETY: `asclen` is a positive byte count.
    let asctmp = CRYPTO_malloc(asclen as usize, FILE.as_ptr(), LINE).cast::<c_char>();
    if asctmp.is_null() {
        return core::ptr::null_mut();
    }
    let mut written: c_int = 0;
    let mut i: c_int = 0;
    while i < unilen {
        // SAFETY: `asctmp + written` has room for the four bytes `bmp_to_utf8` may write, since
        // the sizing pass counted every code point's width.
        let j = unsafe {
            bmp_to_utf8(
                asctmp.add(written as usize),
                uni.add(i as usize),
                unilen - i,
            )
        };
        if j < 0 {
            // When `UTF8_putc` fails.
            // SAFETY: `asctmp` is this call's allocation.
            unsafe { CRYPTO_free(asctmp.cast(), FILE.as_ptr(), LINE) };
            return core::ptr::null_mut();
        }
        i += if j == 4 { 4 } else { 2 };
        written += j;
    }
    // If no terminating zero write one.
    if needs_nul {
        // SAFETY: a NUL is needed only when `needs_nul` set, in which case the sizing pass added
        // the extra byte, so `written` is in range.
        unsafe {
            *asctmp.add(written as usize) = 0;
        }
    }
    asctmp
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime::mem::CRYPTO_free;

    /// The naive pair round-trips a fixed ASCII string, including the double-NUL tail
    /// `asc2uni` writes and the single NUL `uni2asc` produces.
    #[test]
    fn asc_uni_round_trip() {
        // The allocator touches process-global state.
        let _guard = crate::test_support::lock_global_state();
        let input = c"hello";
        let mut uni: *mut c_uchar = core::ptr::null_mut();
        let mut unilen: c_int = 0;
        // SAFETY: `input` is NUL-terminated and the out-slots are this frame's.
        let u = unsafe { OPENSSL_asc2uni(input.as_ptr(), -1, &raw mut uni, &raw mut unilen) };
        assert!(!u.is_null());
        assert_eq!(unilen, 12);
        // SAFETY: `u` has `unilen` bytes.
        assert_eq!(unsafe { *u.add(10) }, 0);
        // SAFETY: `u` has `unilen` bytes.
        assert_eq!(unsafe { *u.add(11) }, 0);
        // SAFETY: `u`/`unilen` describe the fresh buffer.
        let back = unsafe { OPENSSL_uni2asc(u, unilen) };
        assert!(!back.is_null());
        // SAFETY: `back` is a NUL-terminated string.
        let bytes = unsafe { core::ffi::CStr::from_ptr(back) }.to_bytes();
        assert_eq!(bytes, b"hello");
        // SAFETY: both buffers are this call's.
        unsafe { CRYPTO_free(back.cast(), FILE.as_ptr(), LINE) };
        // SAFETY: as above.
        unsafe { CRYPTO_free(u.cast(), FILE.as_ptr(), LINE) };
    }

    /// The UTF-8 pair round-trips a string with a non-ASCII code point, and the surrogate-pair
    /// path is exercised by an astral code point.
    #[test]
    fn utf8_uni_round_trip_with_astral() {
        // The allocator touches process-global state.
        let _guard = crate::test_support::lock_global_state();
        let input = c"a\u{1F600}b"; // 'a', U+1F600 (a surrogate pair), 'b'
        let mut uni: *mut c_uchar = core::ptr::null_mut();
        let mut unilen: c_int = 0;
        // SAFETY: `input` is NUL-terminated and the out-slots are this frame's.
        let u = unsafe { OPENSSL_utf82uni(input.as_ptr(), -1, &raw mut uni, &raw mut unilen) };
        assert!(!u.is_null());
        // 1 ASCII + 2 (surrogate pair) + 1 ASCII + 1 terminating zero = 5 code units = 10 bytes.
        assert_eq!(unilen, 10);
        // SAFETY: `u`/`unilen` describe the fresh buffer.
        let back = unsafe { OPENSSL_uni2utf8(u, unilen) };
        assert!(!back.is_null());
        // SAFETY: `back` is a NUL-terminated string.
        let bytes = unsafe { core::ffi::CStr::from_ptr(back) }.to_bytes();
        assert_eq!(bytes, "a\u{1F600}b".as_bytes());
        // SAFETY: both buffers are this call's.
        unsafe { CRYPTO_free(back.cast(), FILE.as_ptr(), LINE) };
        // SAFETY: as above.
        unsafe { CRYPTO_free(u.cast(), FILE.as_ptr(), LINE) };
    }

    /// Odd and negative lengths are refused, which is the pair's only guard.
    #[test]
    fn odd_length_is_refused() {
        // The allocator touches process-global state.
        let _guard = crate::test_support::lock_global_state();
        let data: [c_uchar; 3] = [0, b'a', 0];
        // SAFETY: `data` is three readable bytes.
        assert!(unsafe { OPENSSL_uni2asc(data.as_ptr(), 3) }.is_null());
        // SAFETY: as above; the length is negative so nothing is read.
        assert!(unsafe { OPENSSL_uni2asc(data.as_ptr(), -2) }.is_null());
        // SAFETY: as above.
        assert!(unsafe { OPENSSL_uni2utf8(data.as_ptr(), 3) }.is_null());
    }
}
