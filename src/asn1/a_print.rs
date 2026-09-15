//! Phase 5 — `crypto/asn1/a_print.c`: the two type classifiers and the raw printer.
//!
//! Three exports, and each of them is a *classification* rather than a conversion:
//!
//! * `ASN1_PRINTABLE_type` answers which of `Printablestring`, `IA5String` and
//!   `T61String` a buffer can be held in, from the coarsest to the finest. It is
//!   used by `ASN1_UNIVERSALSTRING_to_string` and by every caller that has
//!   character data and needs to pick a string type for it.
//! * `ASN1_UNIVERSALSTRING_to_string` narrows a four-byte-per-character string
//!   whose characters are all below `0x100` down to one byte per character, and
//!   then reclassifies it. The narrowing is in place, and it writes a NUL one byte
//!   past the compacted content — inside the original allocation, because the
//!   content shrinks by exactly the factor it compacts by.
//! * `ASN1_STRING_print` writes the content with every byte outside printable
//!   ASCII, and every control byte other than `\n` and `\r`, replaced by `.`. It
//!   has no escaping and no type awareness: the authority's own
//!   `ASN1_STRING_print_ex` is the one that escapes.
//!
//! ## The signed-char question, which `ASN1_STRING_print` actually turns on
//!
//! The classifier test is written over a `const char *` on a target where `char`
//! is signed, so a byte with the high bit set arrives as a *negative* integer.
//! `p[i] > '~'` is then false for `0x80`..`0xFF` — the second test, `p[i] < ' '`,
//! is what catches them. The two readings agree on the resulting set (every byte
//! outside `0x20..=0x7E` except `\n` and `\r` becomes `.`), but the reproduced
//! form is the signed one, because `0x7F` is the single byte where the two tests
//! overlap and a rewrite that dropped either one would diverge there.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_char, c_int, c_uchar};

use crate::asn1::layout::*;
use crate::asn1::string::{as_str, bytes};
use crate::runtime::bio::iolib::BIO_write;
use crate::runtime::bio::Bio;
use crate::runtime::ctype::{ossl_isascii, ossl_isasn1print};
use crate::runtime::str::OPENSSL_strnlen;

/// The width of the authority's stack buffer in `ASN1_STRING_print`.
const PRINT_BUF: usize = 80;

/// `int ASN1_PRINTABLE_type(const unsigned char *s, int len)`
///
/// A null buffer is a `Printablestring` without reading anything; a negative
/// length means "measure the NUL-terminated string". The two flags are sticky, so
/// the *worst* character decides: one non-ASCII byte makes the whole thing a
/// `T61String` even if a later byte is only non-printable.
///
/// # Safety
///
/// `s` must be null or readable for `len` bytes, or NUL-terminated when `len` is
/// negative.
#[no_mangle]
pub unsafe extern "C" fn ASN1_PRINTABLE_type(s: *const c_uchar, len: c_int) -> c_int {
    if s.is_null() {
        return V_ASN1_PRINTABLESTRING;
    }
    let len = if len < 0 {
        // SAFETY: the caller's contract makes `s` NUL-terminated.
        unsafe { OPENSSL_strnlen(s.cast::<c_char>(), usize::MAX) as c_int }
    } else {
        len
    };
    let mut ia5 = false;
    let mut t61 = false;
    for i in 0..len.max(0) {
        // SAFETY: the caller's contract makes `s` readable for `len` bytes, and
        // `i < len`.
        let c = c_int::from(unsafe { *s.add(i as usize) });
        if !ossl_isasn1print(c) {
            ia5 = true;
        }
        if !ossl_isascii(c) {
            t61 = true;
        }
    }
    if t61 {
        V_ASN1_T61STRING
    } else if ia5 {
        V_ASN1_IA5STRING
    } else {
        V_ASN1_PRINTABLESTRING
    }
}

/// `int ASN1_UNIVERSALSTRING_to_string(ASN1_UNIVERSALSTRING *s)`
///
/// The first loop is the *test*: every group of four must have a zero in each of
/// its first three bytes, or the string does not fit in one byte per character
/// and nothing is written. When it does, the second loop preserves only the last
/// byte of each group and the string is reclassified from the compacted content.
///
/// # Safety
///
/// `s` must be null or a live, uniquely-owned `ASN1_UNIVERSALSTRING`.
#[no_mangle]
pub unsafe extern "C" fn ASN1_UNIVERSALSTRING_to_string(s: *mut Asn1String) -> c_int {
    // SAFETY: the caller's contract makes `s` live and uniquely owned.
    let Some(st) = (unsafe { as_str(s) }) else {
        return 0;
    };
    let (type_, length, data) = (st.type_, st.length, st.data);
    if type_ != V_ASN1_UNIVERSALSTRING {
        return 0;
    }
    if length % 4 != 0 {
        return 0;
    }
    if data.is_null() {
        // Upstream dereferences `s->data` unconditionally; see
        // `docs/SECURITY_DIVERGENCE_POLICY.md`.
        return 0;
    }
    // SAFETY: the string's own contract makes `data` readable and writable for
    // `length` bytes, and `ASN1_STRING_set` always allocates one byte more.
    let buf = unsafe { core::slice::from_raw_parts_mut(data, length as usize) };

    // The test loop: every group of four must have a zero in each of its first
    // three bytes before anything is written.
    let mut i = 0;
    while i < length {
        let o = i as usize;
        if buf[o] != 0 || buf[o + 1] != 0 || buf[o + 2] != 0 {
            return 0;
        }
        i += 4;
    }

    let mut w = 0;
    let mut r = 3;
    while r < length as usize {
        buf[w] = buf[r];
        w += 1;
        r += 4;
    }
    let _ = buf;
    // The terminator is **one past the compacted content**, which is at most
    // `length` and therefore inside the `length + 1` bytes the string owns — not
    // inside the `length` bytes this function treats as content. That is why it is
    // a raw store: for an empty string the write is at offset 0 of an allocation
    // whose content is zero bytes long.
    // SAFETY: `data` owns `length + 1` bytes from `ASN1_STRING_set`, and
    // `w <= length / 4 <= length`.
    unsafe { *data.add(w) = 0 };

    let new_len = length / 4;
    // SAFETY: `data` now holds the compacted content of `new_len` bytes.
    let new_type = unsafe { ASN1_PRINTABLE_type(data, new_len) };
    // SAFETY: the caller's contract makes `s` live and uniquely owned.
    unsafe {
        (*s).length = new_len;
        (*s).type_ = new_type;
    }
    1
}

/// `int ASN1_STRING_print(BIO *bp, const ASN1_STRING *v)`
///
/// Writes in blocks of at most 80 bytes, stopping at the first `BIO_write` that
/// does not report a positive count. A null value is a success-with-no-output in
/// the sense that it answers 0 without touching the BIO, which is the authority's
/// behaviour and is courted.
///
/// # Safety
///
/// `bp` must be a live BIO; `v` must be null or a live `ASN1_STRING`.
#[no_mangle]
pub unsafe extern "C" fn ASN1_STRING_print(bp: *mut Bio, v: *const Asn1String) -> c_int {
    // SAFETY: the caller's contract is `as_str`'s.
    if unsafe { as_str(v) }.is_none() {
        return 0;
    }
    // SAFETY: the caller's contract is `bytes`'s.
    let content = unsafe { bytes(v) };
    let mut buf = [0 as c_char; PRINT_BUF];
    let mut n: usize = 0;
    for &b in content {
        let c = b as i8;
        buf[n] = if c > b'~' as i8 || (c < b' ' as i8 && c != b'\n' as i8 && c != b'\r' as i8) {
            b'.' as c_char
        } else {
            c as c_char
        };
        n += 1;
        if n >= PRINT_BUF {
            // SAFETY: `buf` holds `n` bytes and `bp` is a live BIO.
            if unsafe { BIO_write(bp, buf.as_ptr().cast(), n as c_int) } <= 0 {
                return 0;
            }
            n = 0;
        }
    }
    if n > 0 {
        // SAFETY: `buf` holds `n` bytes and `bp` is a live BIO.
        if unsafe { BIO_write(bp, buf.as_ptr().cast(), n as c_int) } <= 0 {
            return 0;
        }
    }
    1
}
