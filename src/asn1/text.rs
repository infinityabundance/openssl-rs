//! Phase 5 — the text conversions: the `i2a_*` writers a BIO receives and the
//! `a2i_*` readers.
//!
//! ## Uppercase hex, and a two-digit group per octet
//!
//! Every one of these writers spells an octet with `ossl_to_hex`, whose digit
//! table is `"0123456789ABCDEF"` — **uppercase**. That is not cosmetic: a caller
//! that compares the text a BIO received would see a difference, and the
//! differential court compares exactly that text. The group separator is a
//! backslash-newline every 35 octets, which is why the writers count characters
//! rather than trusting the BIO's return value.
//!
//! ## The integer writer prints the *stored magnitude*, not the DER content
//!
//! `i2a_ASN1_INTEGER` writes a leading `-` when `V_ASN1_NEG` is set, then the
//! magnitude bytes as hex. An integer whose length is zero prints `00`, not the
//! empty string: the encoding would be a single zero octet and the text says so.
//! The bytes are the internal magnitude, so a negative prints the magnitude with a
//! `-` in front rather than its two's-complement form — the reading is not
//! `openssl asn1parse`'s.
//!
//! ## `i2a_ASN1_OBJECT` has three answers
//!
//! A null object, or one with no `data`, writes the four octets `NULL`. An object
//! whose text does not fit an 80-byte buffer is re-rendered into a heap buffer and
//! the buffer is written. An object whose text is *empty* writes `<INVALID>`
//! followed by `BIO_dump` of its raw content — so a caller that parses the output
//! sees the content bytes, not a diagnostic string.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_char, c_int, c_void};

use crate::asn1::layout::*;
use crate::ffi::guard_ffi;
use crate::runtime::bio::{BIO_dump, BIO_write};
use crate::runtime::err::err_sites;
use crate::runtime::err::raise_site;
use crate::runtime::mem::{CRYPTO_free, CRYPTO_malloc};
use crate::runtime::obj::{Asn1Object, OBJ_obj2txt};

/// The authority translation unit for the integer text conversion.
pub(crate) const INT_FILE: &core::ffi::CStr = c"crypto/asn1/f_int.c";
/// The authority translation unit for the string text conversion.
pub(crate) const STRING_FILE: &core::ffi::CStr = c"crypto/asn1/f_string.c";
/// The authority translation unit for `i2a_ASN1_OBJECT`.
pub(crate) const OBJECT_FILE: &core::ffi::CStr = c"crypto/asn1/a_object.c";
/// The authority passes `__LINE__`, inert under `OPENSSL_NO_CRYPTO_MDEBUG`.
pub(crate) const LINE: c_int = 0;

/// `ossl_to_hex`'s digit table. Uppercase, as the authority's is.
const HEX_DIGITS: &[u8; 16] = b"0123456789ABCDEF";

/// The size of the stack buffer `i2a_ASN1_OBJECT` renders into.
const OBJ_BUF: usize = 80;

/// Write one octet as two uppercase hex digits. Returns 2, the count the callers
/// add to their own.
fn to_hex(out: &mut [u8; 2], n: u8) {
    out[0] = HEX_DIGITS[(n >> 4) as usize];
    out[1] = HEX_DIGITS[(n & 0x0f) as usize];
}

/// `i2t_ASN1_OBJECT(char *buf, int buf_len, const ASN1_OBJECT *a)`
///
/// # Safety
///
/// `buf` must be writable for `buf_len` bytes, or `buf_len` may be 0 with `buf`
/// null; `a` must be null or a live object.
#[no_mangle]
pub unsafe extern "C" fn i2t_ASN1_OBJECT(
    buf: *mut c_char,
    buf_len: c_int,
    a: *const Asn1Object,
) -> c_int {
    guard_ffi(0, || {
        // SAFETY: null-or-valid per this function's `# Safety` section. `no_name`
        // is 0, which is what the authority passes here.
        unsafe { OBJ_obj2txt(buf, buf_len, a, 0) }
    })
}

/// `int i2a_ASN1_OBJECT(BIO *bp, const ASN1_OBJECT *a)`
///
/// # Safety
///
/// `bp` must be null or a live BIO; `a` must be null or a live object.
#[no_mangle]
pub unsafe extern "C" fn i2a_ASN1_OBJECT(
    bp: *mut crate::runtime::bio::Bio,
    a: *const Asn1Object,
) -> c_int {
    guard_ffi(0, || {
        if a.is_null() {
            // SAFETY: `bp` is null or live.
            return unsafe { BIO_write(bp, c"NULL".as_ptr().cast(), 4) };
        }
        // SAFETY: `a` is live.
        let obj = unsafe { &*a };
        if obj.data.is_null() {
            // SAFETY: `bp` is null or live.
            return unsafe { BIO_write(bp, c"NULL".as_ptr().cast(), 4) };
        }
        let mut buf = [0 as c_char; OBJ_BUF];
        // SAFETY: `buf` is `OBJ_BUF` writable bytes.
        // SAFETY: `buf` is `OBJ_BUF` writable bytes; `a` is live.
        let i = unsafe { i2t_ASN1_OBJECT(buf.as_mut_ptr(), OBJ_BUF as c_int, a) };
        let mut heap: *mut c_char = core::ptr::null_mut();
        if i > (OBJ_BUF - 1) as c_int {
            if i > c_int::MAX - 1 {
                // SAFETY: a compile-time-constant site.
                unsafe { raise_site(&err_sites::A_OBJECT_198) };
                return -1;
            }
            // SAFETY: `CRYPTO_malloc` answers null or `i + 1` writable bytes.
            let p = CRYPTO_malloc(i as usize + 1, OBJECT_FILE.as_ptr(), LINE) as *mut c_char;
            if p.is_null() {
                return -1;
            }
            heap = p;
            // SAFETY: `p` is `i + 1` bytes.
            unsafe { i2t_ASN1_OBJECT(p, i + 1, a) };
        }
        let p = if heap.is_null() {
            buf.as_mut_ptr()
        } else {
            heap
        };
        if i <= 0 {
            // SAFETY: `bp` is null or live.
            let mut n = unsafe { BIO_write(bp, c"<INVALID>".as_ptr().cast(), 9) };
            if n > 0 {
                // SAFETY: `obj.data` is readable for `obj.length` bytes; `bp` is
                // null or live.
                n += unsafe { BIO_dump(bp, obj.data.cast::<c_void>(), obj.length) };
            }
            if !heap.is_null() {
                // SAFETY: `heap` came from this layer's allocator.
                unsafe { CRYPTO_free(heap.cast::<c_void>(), OBJECT_FILE.as_ptr(), LINE) };
            }
            return n;
        }
        // SAFETY: `p` holds at least `i` readable bytes; `bp` is null or live.
        let n = unsafe { BIO_write(bp, p.cast::<c_void>(), i) };
        if !heap.is_null() {
            // SAFETY: `heap` came from this layer's allocator.
            unsafe { CRYPTO_free(heap.cast::<c_void>(), OBJECT_FILE.as_ptr(), LINE) };
        }
        // The authority ignores `BIO_write`'s answer here and returns `i`. That is
        // observable when the BIO is short, so it is reproduced.
        let _ = n;
        i
    })
}

/// `int i2a_ASN1_STRING(BIO *bp, const ASN1_STRING *a, int type)`
///
/// The `type` argument is accepted and unused, as it is in the authority.
///
/// # Safety
///
/// `bp` must be null or a live BIO; `a` must be null or a live string.
#[no_mangle]
pub unsafe extern "C" fn i2a_ASN1_STRING(
    bp: *mut crate::runtime::bio::Bio,
    a: *const Asn1String,
    type_: c_int,
) -> c_int {
    guard_ffi(0, || {
        let _ = type_;
        if a.is_null() {
            return 0;
        }
        // SAFETY: `a` is live.
        let s = unsafe { &*a };
        let mut n: c_int = 0;
        if s.length == 0 {
            // SAFETY: `bp` is null or live.
            if unsafe { BIO_write(bp, c"0".as_ptr().cast(), 1) } != 1 {
                return -1;
            }
            return 1;
        }
        let mut i = 0i32;
        while i < s.length {
            if i != 0 && i % 35 == 0 {
                // SAFETY: `bp` is null or live.
                if unsafe { BIO_write(bp, c"\\\n".as_ptr().cast(), 2) } != 2 {
                    return -1;
                }
                n += 2;
            }
            let mut pair = [0u8; 2];
            // SAFETY: `s.data` is readable for `s.length` bytes.
            to_hex(&mut pair, unsafe { *s.data.add(i as usize) });
            // SAFETY: `pair` is two readable bytes; `bp` is null or live.
            if unsafe { BIO_write(bp, pair.as_ptr().cast(), 2) } != 2 {
                return -1;
            }
            n += 2;
            i += 1;
        }
        let _ = STRING_FILE;
        n
    })
}

/// `int i2a_ASN1_INTEGER(BIO *bp, const ASN1_INTEGER *a)`
///
/// # Safety
///
/// `bp` must be null or a live BIO; `a` must be null or a live integer.
#[no_mangle]
pub unsafe extern "C" fn i2a_ASN1_INTEGER(
    bp: *mut crate::runtime::bio::Bio,
    a: *const Asn1String,
) -> c_int {
    guard_ffi(0, || {
        if a.is_null() {
            return 0;
        }
        // SAFETY: `a` is live.
        let s = unsafe { &*a };
        let mut n: c_int = 0;
        if s.type_ & V_ASN1_NEG != 0 {
            // SAFETY: `bp` is null or live.
            if unsafe { BIO_write(bp, c"-".as_ptr().cast(), 1) } != 1 {
                return -1;
            }
            n = 1;
        }
        if s.length == 0 {
            // SAFETY: `bp` is null or live.
            if unsafe { BIO_write(bp, c"00".as_ptr().cast(), 2) } != 2 {
                return -1;
            }
            return n + 2;
        }
        let mut i = 0i32;
        while i < s.length {
            if i != 0 && i % 35 == 0 {
                // SAFETY: `bp` is null or live.
                if unsafe { BIO_write(bp, c"\\\n".as_ptr().cast(), 2) } != 2 {
                    return -1;
                }
                n += 2;
            }
            let mut pair = [0u8; 2];
            // SAFETY: `s.data` is readable for `s.length` bytes.
            to_hex(&mut pair, unsafe { *s.data.add(i as usize) });
            // SAFETY: `pair` is two readable bytes; `bp` is null or live.
            if unsafe { BIO_write(bp, pair.as_ptr().cast(), 2) } != 2 {
                return -1;
            }
            n += 2;
            i += 1;
        }
        let _ = INT_FILE;
        n
    })
}

/// `int i2a_ASN1_ENUMERATED(BIO *bp, const ASN1_ENUMERATED *a)`
///
/// Exactly `i2a_ASN1_INTEGER`: the authority's body is a one-line forwarding call,
/// because the stored magnitude and the sign bit are laid out the same way.
///
/// # Safety
///
/// `bp` must be null or a live BIO; `a` must be null or a live enumerated value.
#[no_mangle]
pub unsafe extern "C" fn i2a_ASN1_ENUMERATED(
    bp: *mut crate::runtime::bio::Bio,
    a: *const Asn1String,
) -> c_int {
    guard_ffi(0, || {
        // SAFETY: forwarded per this function's `# Safety` section.
        unsafe { i2a_ASN1_INTEGER(bp, a) }
    })
}
