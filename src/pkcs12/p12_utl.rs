//! `crypto/pkcs12/p12_utl.c` — the cheap Unicode helpers and the `PKCS12` BIO/`FILE` readers.
//! Phase 10 (10.2).
//!
//! Four of the unit's eight exports are the ASCII/BMPString/UTF-8 conversions:
//! `OPENSSL_asc2uni`/`OPENSSL_uni2asc` (the naive pair) and `OPENSSL_utf82uni`/
//! `OPENSSL_uni2utf8` (the UTF-8-aware pair, with `bmp_to_utf8` as their shared helper).
//! `PKCS12_get_friendlyname` (`crypto/pkcs12/p12_attr.c`) reaches `OPENSSL_uni2utf8`, which is
//! why the unit lands with this subphase.
//!
//! ## The four BIO/`FILE` wrappers, and the `PKCS7` dependency that held them
//!
//! `d2i_PKCS12_bio`/`d2i_PKCS12_fp`/`i2d_PKCS12_bio`/`i2d_PKCS12_fp` each call an
//! `ASN1_item_*_bio`/`_fp` over `ASN1_ITEM_rptr(PKCS12)`, and the two `d2i` spellings also read
//! the previous value's `PKCS7_CTX` through `ossl_pkcs12_get0_pkcs7ctx`. Both reached the
//! `PKCS12` item and the `PKCS7` object, and `PKCS7_it` is Phase 12's
//! (`crypto/pkcs7/pk7_asn1.c`). **All four land here** now that the `PKCS7` subset is pulled
//! forward: the `ASN1_item_*_bio`/`_fp` layer is Phase 5's and landed, the `PKCS12` item is this
//! crate's `p12_asn.rs`, and the context borrow is `p12_init.rs`'s.
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

use core::ffi::{c_char, c_int, c_uchar, c_ulong, c_void};

use crate::asn1::a_d2i_fp::{ASN1_item_d2i_bio_ex, ASN1_item_d2i_fp_ex};
use crate::asn1::a_i2d_fp::{ASN1_item_i2d_bio, ASN1_item_i2d_fp};
use crate::asn1::a_utf8::{UTF8_getc, UTF8_putc};
use crate::pkcs12::p12_asn::{PKCS12_it, Pkcs12};
use crate::pkcs12::p12_init::ossl_pkcs12_get0_pkcs7ctx;
use crate::pkcs7::{ossl_pkcs7_ctx_get0_libctx, ossl_pkcs7_ctx_get0_propq};
use crate::runtime::bio::sys::{strlen, FILE as StdioFile};
use crate::runtime::bio::Bio;
use crate::runtime::mem::{CRYPTO_free, CRYPTO_malloc};
use crate::runtime::mem_coords::SeamFile;

/// `crypto/pkcs12/p12_utl.c` — the authority's `__FILE__` string, for the allocator's bookkeeping.
const FILE: &core::ffi::CStr = c"crypto/pkcs12/p12_utl.c";
/// The line the authority's `OPENSSL_malloc` call expands to, as the authority spells it (the
/// allocation site is the file's own `OPENSSL_malloc`, without a pin line, so the crate uses 0).
const LINE: c_int = 0;

// ---------------------------------------------------------------------------------------------
// Ownership of the conversion buffers
// ---------------------------------------------------------------------------------------------

/// An owned heap buffer from this unit's `OPENSSL_malloc`/`OPENSSL_free` seam.
///
/// The block stays a `CRYPTO_malloc` at the authority's exact size and `file`/`line` -- a Rust
/// `Box`/`Vec` would hide both the allocation and its release from a caller-installed
/// `CRYPTO_set_mem_functions` hook -- and only its *ownership* is this type: [`Self::new`] allocates
/// it, `Drop` is its single release, [`Self::into_raw`] hands the finished string to the caller that
/// takes it over, and [`Self::as_mut_slice`] lends the writable interior the writers fill, so the
/// byte writes are checked indexing rather than raw pointer arithmetic.
struct OwnedBuf {
    ptr: *mut c_uchar,
    len: usize,
    file: *const c_char,
    line: c_int,
}

impl OwnedBuf {
    /// `CRYPTO_malloc(len, file, line)`, or `None` when the allocator answers NULL.
    fn new(len: usize, file: SeamFile, line: c_int) -> Option<OwnedBuf> {
        let file = file.as_ptr();
        let raw = unsafe {
            // SAFETY: `file` is NULL or a NUL-terminated coordinate valid for the call (a static literal/default, or a precondition established by the calling boundary), so `malloc_request`/the installed hook may read it.
            CRYPTO_malloc(len, file, line)
        }
        .cast::<c_uchar>();
        if raw.is_null() {
            return None;
        }
        Some(OwnedBuf {
            ptr: raw,
            len,
            file,
            line,
        })
    }

    /// The block as a writable slice of exactly the length it was allocated with.
    fn as_mut_slice(&mut self) -> &mut [u8] {
        // SAFETY: `self.ptr` is the live block `new` allocated with `self.len` writable bytes, and
        // this handle is its only owner and lends it exclusively for this borrow.
        unsafe { core::slice::from_raw_parts_mut(self.ptr, self.len) }
    }

    /// The start of the block, for the caller that takes the block's address.
    fn as_ptr(&self) -> *mut c_uchar {
        self.ptr
    }

    /// Give up ownership of the block to the caller that takes it over.
    fn into_raw(self) -> *mut c_uchar {
        let p = self.ptr;
        core::mem::forget(self);
        p
    }
}

impl Drop for OwnedBuf {
    /// The block's single release, through the same seam and at the authority's own `file`/`line`.
    fn drop(&mut self) {
        // SAFETY: `self.ptr` is the block this handle owns and has not released; the authority's own
        // `CRYPTO_free` accepts NULL.
        unsafe { CRYPTO_free(self.ptr.cast::<c_void>(), self.file, self.line) };
    }
}

/// `unsigned char *OPENSSL_asc2uni(const char *asc, int asclen, unsigned char **uni,
/// int *unilen)` — `crypto/pkcs12/p12_utl.c:18-43`.
///
/// `asclen == -1` means "use `strlen`"; a negative length answers NULL. The result is
/// `asclen * 2 + 2` bytes: each input byte becomes a big-endian UTF-16 code unit, and the buffer
/// ends with **two** zero bytes rather than the single NUL `OPENSSL_uni2asc` expects.
///
/// # Safety
/// `asc` is NULL only when `asclen == 0`; otherwise it is a string of `asclen` bytes (or
/// NUL-terminated when `asclen == -1`). `uni`/`unilen` are each NULL or writable for their type.
/// The answer is a fresh `OPENSSL_malloc` buffer the caller owns, also returned through `*uni`
/// when that is non-NULL.
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
    // The authority's `asclen * 2 + 2` is unchecked signed arithmetic; refuse an overflow
    // before it can wrap the allocation size, so the refusal is an ordinary NULL answer.
    let Some(ulen) = asclen.checked_mul(2).and_then(|v| v.checked_add(2)) else {
        return core::ptr::null_mut();
    };
    // SAFETY: `ulen` is a positive byte count.
    let Some(mut buf) = OwnedBuf::new(ulen as usize, SeamFile::new(FILE), LINE) else {
        return core::ptr::null_mut();
    };
    {
        let out = buf.as_mut_slice();
        let mut i: c_int = 0;
        while i < ulen - 2 {
            out[i as usize] = 0;
            // SAFETY: `asc` has `asclen` readable bytes per the contract; `i >> 1 < asclen`
            // throughout.
            out[i as usize + 1] = unsafe { *asc.add((i >> 1) as usize) } as c_uchar;
            i += 2;
        }
        // Make result double null terminated.
        out[(ulen - 2) as usize] = 0;
        out[(ulen - 1) as usize] = 0;
    }
    // SAFETY: `unilen`/`uni` are each NULL or writable per the contract.
    unsafe {
        if !unilen.is_null() {
            *unilen = ulen;
        }
        if !uni.is_null() {
            *uni = buf.as_ptr();
        }
    }
    buf.into_raw()
}

/// `char *OPENSSL_uni2asc(const unsigned char *uni, int unilen)` — `crypto/pkcs12/p12_utl.c:45-66`.
///
/// An odd or negative `unilen` answers NULL. The odd bytes of `uni` are the ASCII characters; a
/// missing final NUL is allowed for and one is written. The answer is an `OPENSSL_malloc` string.
///
/// # Safety
/// `uni` is readable for `unilen` bytes, and may be NULL only when `unilen == 0`. The answer is a
/// fresh `OPENSSL_malloc` buffer the caller owns.
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
    // SAFETY: `uni` is readable for `unilen` bytes; skipping the leading byte is in range. With
    // `unilen == 0` there is no byte to skip, and the contract permits NULL then, so the pointer
    // must not be advanced (the authority's `uni++` is UB for that case).
    let uni = if unilen == 0 {
        uni
    } else {
        // SAFETY: `unilen > 0`, so `uni` is readable for `unilen` bytes and the first byte is in
        // range.
        unsafe { uni.add(1) }
    };
    // SAFETY: `asclen` is a positive byte count.
    let Some(mut buf) = OwnedBuf::new(asclen as usize, SeamFile::new(FILE), LINE) else {
        return core::ptr::null_mut();
    };
    {
        let out = buf.as_mut_slice();
        let mut i = 0;
        while i < unilen {
            // SAFETY: `uni` has `unilen - 1` readable bytes after the skip; `i >> 1 < asclen`
            // and `i < unilen - 1` throughout.
            out[(i >> 1) as usize] = unsafe { *uni.add(i as usize) };
            i += 2;
        }
        // The final byte is within the allocation.
        out[(asclen - 1) as usize] = 0;
    }
    buf.into_raw().cast::<c_char>()
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
        let Some(next) = ulen.checked_add(if utf32chr >= 0x10000 { 2 * 2 } else { 2 }) else {
            return core::ptr::null_mut();
        };
        ulen = next;
        i += j;
    }
    // Checked for the same reason as [`OPENSSL_asc2uni`]: the authority's signed accumulation is
    // undefined on overflow, so the conversion refuses with an ordinary NULL answer.
    let Some(ulen) = ulen.checked_add(2) else {
        return core::ptr::null_mut();
    };

    // SAFETY: `ulen` is a positive byte count.
    let Some(mut buf) = OwnedBuf::new(ulen as usize, SeamFile::new(FILE), LINE) else {
        return core::ptr::null_mut();
    };
    {
        let out = buf.as_mut_slice();
        let mut w: c_int = 0;
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
                // The sizing loop reserved four bytes for this code point.
                out[w as usize] = (hi >> 8) as c_uchar;
                out[w as usize + 1] = hi as c_uchar;
                out[w as usize + 2] = (lo >> 8) as c_uchar;
                out[w as usize + 3] = lo as c_uchar;
                w += 4;
            } else {
                // Or just one.
                // The sizing loop reserved two bytes for this code point.
                out[w as usize] = (utf32chr >> 8) as c_uchar;
                out[w as usize + 1] = utf32chr as c_uchar;
                w += 2;
            }
            i += j;
        }
        // Make result double null terminated.
        out[w as usize] = 0;
        out[w as usize + 1] = 0;
    }
    // SAFETY: `unilen`/`uni` are each NULL or writable per the contract.
    unsafe {
        if !unilen.is_null() {
            *unilen = ulen;
        }
        if !uni.is_null() {
            *uni = buf.as_ptr();
        }
    }
    buf.into_raw()
}

/// `static int bmp_to_utf8(char *str, const unsigned char *utf16, int len)` —
/// `crypto/pkcs12/p12_utl.c:150-179`.
///
/// A null `str` asks for the width only. A truncated pair or a bad low surrogate answers `-1`,
/// which is what sends [`OPENSSL_uni2utf8`] to its `OPENSSL_uni2asc` fallback.
///
/// # Safety
/// `str` is NULL or writable for four bytes; `utf16` is readable for `len` bytes and may be NULL
/// only when `len == 0`.
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
/// `uni` is readable for `unilen` bytes, and may be NULL only when `unilen == 0`. The answer is a
/// fresh `OPENSSL_malloc` string the caller owns.
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
        let Some(next) = asclen.checked_add(j) else {
            return core::ptr::null_mut();
        };
        asclen = next;
    }
    // If no terminating zero allow for one; the same condition decides whether the write pass
    // finishes with a NUL, so it is computed once.
    // SAFETY: `unilen` is even; the last two bytes are in range when non-zero.
    let needs_nul = unilen == 0
        || unsafe { *uni.add((unilen - 2) as usize) | *uni.add((unilen - 1) as usize) } != 0;
    if needs_nul {
        let Some(next) = asclen.checked_add(1) else {
            return core::ptr::null_mut();
        };
        asclen = next;
    }

    // SAFETY: `asclen` is a positive byte count.
    let Some(mut buf) = OwnedBuf::new(asclen as usize, SeamFile::new(FILE), LINE) else {
        return core::ptr::null_mut();
    };
    {
        let out = buf.as_mut_slice();
        let mut written: c_int = 0;
        let mut i: c_int = 0;
        while i < unilen {
            // SAFETY: `out[written..]` has room for the four bytes `bmp_to_utf8` may write, since
            // the sizing pass counted every code point's width, and `uni` is readable for
            // `unilen` bytes with `i < unilen`.
            let j = unsafe {
                bmp_to_utf8(
                    out[written as usize..].as_mut_ptr().cast(),
                    uni.add(i as usize),
                    unilen - i,
                )
            };
            if j < 0 {
                // When `UTF8_putc` fails. `buf`'s `Drop` is the authority's own
                // `OPENSSL_free(asctmp)`, at the same `file`/`line`.
                return core::ptr::null_mut();
            }
            i += if j == 4 { 4 } else { 2 };
            written += j;
        }
        // If no terminating zero, write one; the sizing pass added the extra byte, so `written`
        // is in range.
        if needs_nul {
            out[written as usize] = 0;
        }
    }
    buf.into_raw().cast::<c_char>()
}

/// `int i2d_PKCS12_bio(BIO *bp, const PKCS12 *p12)` — `crypto/pkcs12/p12_utl.c:237-240`.
///
/// # Safety
/// `bp` is a live BIO; `p12` is null or a live `PKCS12`.
#[no_mangle]
pub unsafe extern "C" fn i2d_PKCS12_bio(bp: *mut Bio, p12: *const Pkcs12) -> c_int {
    // SAFETY: the arguments are forwarded under this function's contract.
    unsafe { ASN1_item_i2d_bio(PKCS12_it(), bp, p12.cast()) }
}

/// `int i2d_PKCS12_fp(FILE *fp, const PKCS12 *p12)` — `crypto/pkcs12/p12_utl.c:243-246`.
///
/// # Safety
/// `fp` is a live `FILE *`; `p12` is null or a live `PKCS12`.
#[no_mangle]
pub unsafe extern "C" fn i2d_PKCS12_fp(fp: *mut StdioFile, p12: *const Pkcs12) -> c_int {
    // SAFETY: the arguments are forwarded under this function's contract.
    unsafe { ASN1_item_i2d_fp(PKCS12_it(), fp, p12.cast()) }
}

/// `PKCS12 *d2i_PKCS12_bio(BIO *bp, PKCS12 **p12)` — `crypto/pkcs12/p12_utl.c:249-263`.
///
/// When a previous value is supplied, its `authsafes` object's `PKCS7_CTX` — when there is one —
/// supplies the library context and property query the decode runs in; otherwise both are null.
///
/// # Safety
/// `bp` is a live BIO; `p12` is NULL or a writable slot holding a live `PKCS12`.
#[no_mangle]
pub unsafe extern "C" fn d2i_PKCS12_bio(bp: *mut Bio, p12: *mut *mut Pkcs12) -> *mut Pkcs12 {
    let mut libctx: *mut core::ffi::c_void = core::ptr::null_mut();
    let mut propq: *const c_char = core::ptr::null();
    // SAFETY: `p12` is NULL or the caller's slot; the borrowed context is read only when live.
    unsafe {
        if !p12.is_null() {
            let p7ctx = ossl_pkcs12_get0_pkcs7ctx(*p12);
            if !p7ctx.is_null() {
                libctx = ossl_pkcs7_ctx_get0_libctx(p7ctx);
                propq = ossl_pkcs7_ctx_get0_propq(p7ctx);
            }
        }
        ASN1_item_d2i_bio_ex(PKCS12_it(), bp, p12.cast(), libctx, propq).cast::<Pkcs12>()
    }
}

/// `PKCS12 *d2i_PKCS12_fp(FILE *fp, PKCS12 **p12)` — `crypto/pkcs12/p12_utl.c:266-280`.
///
/// # Safety
/// `fp` is a live `FILE *`; `p12` is NULL or a writable slot holding a live `PKCS12`.
#[no_mangle]
pub unsafe extern "C" fn d2i_PKCS12_fp(fp: *mut StdioFile, p12: *mut *mut Pkcs12) -> *mut Pkcs12 {
    let mut libctx: *mut core::ffi::c_void = core::ptr::null_mut();
    let mut propq: *const c_char = core::ptr::null();
    // SAFETY: `p12` is NULL or the caller's slot; the borrowed context is read only when live.
    unsafe {
        if !p12.is_null() {
            let p7ctx = ossl_pkcs12_get0_pkcs7ctx(*p12);
            if !p7ctx.is_null() {
                libctx = ossl_pkcs7_ctx_get0_libctx(p7ctx);
                propq = ossl_pkcs7_ctx_get0_propq(p7ctx);
            }
        }
        ASN1_item_d2i_fp_ex(PKCS12_it(), fp, p12.cast(), libctx, propq).cast::<Pkcs12>()
    }
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

    /// Empty input is NULL-safe: the authority's `uni++` is undefined on a null pointer, while
    /// the conversion must still answer the same empty string. An allocation size that would
    /// overflow is refused before any read of the input.
    #[test]
    fn empty_input_is_null_safe_and_overflow_is_refused() {
        // The allocator touches process-global state.
        let _guard = crate::test_support::lock_global_state();

        // SAFETY: `unilen == 0` permits the null pointer.
        let asc = unsafe { OPENSSL_uni2asc(core::ptr::null(), 0) };
        assert!(!asc.is_null());
        // SAFETY: `asc` is the fresh one-byte string above.
        assert_eq!(unsafe { *asc }, 0);
        // SAFETY: `asc` is this call's.
        unsafe { CRYPTO_free(asc.cast(), FILE.as_ptr(), LINE) };

        // SAFETY: `unilen == 0` permits the null pointer.
        let utf8 = unsafe { OPENSSL_uni2utf8(core::ptr::null(), 0) };
        assert!(!utf8.is_null());
        // SAFETY: `utf8` is the fresh one-byte string above.
        assert_eq!(unsafe { *utf8 }, 0);
        // SAFETY: `utf8` is this call's.
        unsafe { CRYPTO_free(utf8.cast(), FILE.as_ptr(), LINE) };

        let mut uni: *mut c_uchar = core::ptr::null_mut();
        let mut unilen: c_int = 0;
        // SAFETY: `asclen == 0` permits the null pointer.
        let u = unsafe { OPENSSL_asc2uni(core::ptr::null(), 0, &raw mut uni, &raw mut unilen) };
        assert!(!u.is_null());
        assert_eq!(unilen, 2);
        // SAFETY: `u` is this call's.
        unsafe { CRYPTO_free(u.cast(), FILE.as_ptr(), LINE) };

        // The input is not read: the checked size computation refuses first.
        let dummy = [0u8; 1];
        // SAFETY: the overflowing length is refused before the input is dereferenced.
        let overflow = unsafe {
            OPENSSL_asc2uni(
                dummy.as_ptr().cast(),
                c_int::MAX / 2 + 1,
                &raw mut uni,
                &raw mut unilen,
            )
        };
        assert!(overflow.is_null());
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
