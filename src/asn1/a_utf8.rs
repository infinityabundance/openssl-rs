//! Phase 5 — `a_utf8.c`: one UTF-8 character at a time.
//!
//! These two are the whole of the authority's UTF-8 primitive layer, and
//! `ASN1_mbstring_ncopy` is written on top of them. Neither raises: every failure is a
//! **negative return**, and the four distinct codes are the entire contract:
//!
//! ```text
//! -1  the string is too short for the length the leading byte claims
//! -2  an illegal character: a leading byte no encoding starts with, or a surrogate
//! -3  a continuation byte that is not of the form 10xxxxxx
//! -4  the encoding is not minimal — the same value has a shorter form
//! ```
//!
//! `-4` is the one that is easy to omit and impossible to notice: `C1 81` and `81` both
//! carry the value 1, and a reader that accepts both makes two different byte strings
//! compare equal. The check is "the value decoded is at least as large as the smallest
//! value this length can represent" — `0x80` for two bytes, `0x800` for three and
//! `0x10000` for four.
//!
//! ## The asymmetry between the two
//!
//! `UTF8_getc` rejects a **surrogate** (`0xd800`-`0xdfff`) with `-2`, and it can only do so
//! for the three-byte form, because that is the only form it fits in. `UTF8_putc` rejects
//! it with `-2` too, and there the check comes *before* the length check — so a caller that
//! passes a one-byte buffer and a surrogate gets `-2` rather than `-1`. Both are observable
//! and both are reproduced.
//!
//! A null `str` to `UTF8_putc` is the sizing convention: `len` is forced to 4 and the
//! answer is the number of octets the value *would* need. That is the only way to ask for
//! the width, and it is why `len` is not consulted on that path.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_int, c_ulong};

use crate::ffi::guard_ffi;

/// `SURROGATE_MIN` / `SURROGATE_MAX` — the range no encoding may carry.
const SURROGATE_MIN: c_ulong = 0xd800;
const SURROGATE_MAX: c_ulong = 0xdfff;
/// `UNICODE_LIMIT` — one past `UNICODE_MAX`, the first value no encoding can carry.
const UNICODE_LIMIT: c_ulong = 0x11_0000;

/// `is_unicode_surrogate(value)`
fn is_unicode_surrogate(value: c_ulong) -> bool {
    (SURROGATE_MIN..=SURROGATE_MAX).contains(&value)
}

/// `int UTF8_getc(const unsigned char *str, int len, unsigned long *val)`
///
/// Answers the number of octets the character occupies and writes its value through
/// `val`, or one of the four negative codes above. A `len` of zero or less answers `0`
/// rather than an error, which is how a caller advancing through a buffer terminates.
///
/// The value is written **only on success**: an error return leaves the caller's slot
/// untouched, so a caller that ignores the return keeps whatever it had rather than a
/// partially decoded value.
///
/// # Safety
///
/// `str` must be readable for `len` bytes when `len > 0`; `val` must be a live slot.
#[no_mangle]
pub unsafe extern "C" fn UTF8_getc(
    str_: *const core::ffi::c_uchar,
    len: c_int,
    val: *mut c_ulong,
) -> c_int {
    guard_ffi(-1, || {
        if len <= 0 {
            return 0;
        }
        // SAFETY: `len >= 1`, so the leading byte is readable.
        let b0 = c_ulong::from(unsafe { *str_ });
        let mut p = str_;
        let value: c_ulong;
        let ret: c_int;

        if b0 & 0x80 == 0 {
            value = b0 & 0x7f;
            // SAFETY: advancing within the readable extent.
            p = unsafe { p.add(1) };
            ret = 1;
        } else if b0 & 0xe0 == 0xc0 {
            if len < 2 {
                return -1;
            }
            // SAFETY: `len >= 2`.
            if unsafe { *p.add(1) } & 0xc0 != 0x80 {
                return -3;
            }
            // SAFETY: as above.
            value = ((b0 & 0x1f) << 6) | c_ulong::from(unsafe { *p.add(1) } & 0x3f);
            // SAFETY: as above.
            p = unsafe { p.add(2) };
            if value < 0x80 {
                return -4;
            }
            ret = 2;
        } else if b0 & 0xf0 == 0xe0 {
            if len < 3 {
                return -1;
            }
            // SAFETY: `len >= 3`.
            let (b1, b2) = unsafe { (*p.add(1), *p.add(2)) };
            if (b1 & 0xc0 != 0x80) || (b2 & 0xc0 != 0x80) {
                return -3;
            }
            value = ((b0 & 0xf) << 12) | (c_ulong::from(b1 & 0x3f) << 6) | c_ulong::from(b2 & 0x3f);
            // SAFETY: as above.
            p = unsafe { p.add(3) };
            if value < 0x800 {
                return -4;
            }
            if is_unicode_surrogate(value) {
                return -2;
            }
            ret = 3;
        } else if b0 & 0xf8 == 0xf0 {
            if len < 4 {
                return -1;
            }
            // SAFETY: `len >= 4`.
            let (b1, b2, b3) = unsafe { (*p.add(1), *p.add(2), *p.add(3)) };
            if (b1 & 0xc0 != 0x80) || (b2 & 0xc0 != 0x80) || (b3 & 0xc0 != 0x80) {
                return -3;
            }
            value = ((b0 & 0x7) << 18)
                | (c_ulong::from(b1 & 0x3f) << 12)
                | (c_ulong::from(b2 & 0x3f) << 6)
                | c_ulong::from(b3 & 0x3f);
            // SAFETY: as above.
            p = unsafe { p.add(4) };
            // The authority spells this `value < 0x10000 || value >= UNICODE_LIMIT`; the
            // negated range is the same test and says what it means: a four-byte form
            // must carry a value that needs four bytes.
            if !(0x10000..UNICODE_LIMIT).contains(&value) {
                return -4;
            }
            ret = 4;
        } else {
            // A leading byte that starts no encoding at all.
            return -2;
        }
        let _ = p;
        // SAFETY: `val` is the caller's live slot.
        unsafe { *val = value };
        ret
    })
}

/// `int UTF8_putc(unsigned char *str, int len, unsigned long value)`
///
/// Writes the encoding of `value`, or answers how many octets it would need when `str` is
/// null. A buffer too small is `-1` and a value out of range is `-2`; for a surrogate the
/// range check comes first, so `-2` is answered even when `len` is also too small.
///
/// # Safety
///
/// `str` must be null or writable for `len` bytes.
#[no_mangle]
pub unsafe extern "C" fn UTF8_putc(
    str_: *mut core::ffi::c_uchar,
    len_in: c_int,
    value: c_ulong,
) -> c_int {
    guard_ffi(-1, || {
        // A null destination asks for the width, so `len` is not consulted.
        let len = if str_.is_null() { 4 } else { len_in };
        if !str_.is_null() && len <= 0 {
            return -1;
        }
        if value < 0x80 {
            if !str_.is_null() {
                // SAFETY: `len >= 1` and the destination is the caller's.
                unsafe { *str_ = value as core::ffi::c_uchar };
            }
            return 1;
        }
        if value < 0x800 {
            if len < 2 {
                return -1;
            }
            if !str_.is_null() {
                // SAFETY: a two-octet write into a buffer of at least two.
                unsafe {
                    *str_ = (((value >> 6) & 0x1f) | 0xc0) as core::ffi::c_uchar;
                    *str_.add(1) = ((value & 0x3f) | 0x80) as core::ffi::c_uchar;
                }
            }
            return 2;
        }
        if value < 0x10000 {
            // The surrogate check precedes the length check, which is observable: a
            // one-byte buffer and a surrogate answer -2, not -1.
            if is_unicode_surrogate(value) {
                return -2;
            }
            if len < 3 {
                return -1;
            }
            if !str_.is_null() {
                // SAFETY: a three-octet write into a buffer of at least three.
                unsafe {
                    *str_ = (((value >> 12) & 0xf) | 0xe0) as core::ffi::c_uchar;
                    *str_.add(1) = (((value >> 6) & 0x3f) | 0x80) as core::ffi::c_uchar;
                    *str_.add(2) = ((value & 0x3f) | 0x80) as core::ffi::c_uchar;
                }
            }
            return 3;
        }
        if value < UNICODE_LIMIT {
            if len < 4 {
                return -1;
            }
            if !str_.is_null() {
                // SAFETY: a four-octet write into a buffer of at least four.
                unsafe {
                    *str_ = (((value >> 18) & 0x7) | 0xf0) as core::ffi::c_uchar;
                    *str_.add(1) = (((value >> 12) & 0x3f) | 0x80) as core::ffi::c_uchar;
                    *str_.add(2) = (((value >> 6) & 0x3f) | 0x80) as core::ffi::c_uchar;
                    *str_.add(3) = ((value & 0x3f) | 0x80) as core::ffi::c_uchar;
                }
            }
            return 4;
        }
        // Beyond the code space, including every surrogate that got this far.
        -2
    })
}
