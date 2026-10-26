//! Phase 5 — `crypto/asn1/a_mbstr.c`: pick the narrowest string type a buffer fits.
//!
//! Two exports, and the second is the first with size limits. The authority's own
//! comment calls the job "horrible: it has to be", and the reason is that it is
//! doing three things at once:
//!
//! * **Decoding** the input from one of four forms (`UTF8`, `ASC`, `BMP`,
//!   `UNIV`) into a stream of Unicode scalar values, via `traverse_string`.
//! * **Classifying** each value against a *mask* of permitted string types, by
//!   clearing from the mask every type the value cannot be held in — so the mask
//!   narrows as the string is read and what survives is the narrowest type that
//!   holds every character.
//! * **Encoding** the values into the surviving type's form.
//!
//! ## The three places the mask decides, and why they can disagree
//!
//! `type_str` narrows the mask; the `if (mask & B_ASN1_…)` ladder after it picks
//! the *type* in a fixed order (Numeric, Printable, IA5, T61, BMP, Universal,
//! else UTF8); and the `switch (outform)` picks the *encoding*. The ladder's order
//! is what makes the answer the narrowest rather than merely a legal one, and the
//! authority notes that the checks must be kept in step with `type_str`'s.
//!
//! Two details of `type_str` are easy to get wrong and are courted:
//!
//! * `native` is the value truncated to `int`, saturating at `INT_MAX` — and the
//!   *numeric* class accepts a space as well as a digit, which is the authority's
//!   allowance for a digit string written with separators.
//! * A mask bit outside the seven character types is not an error: it is treated
//!   as "UTF8 was asked for" and `B_ASN1_UTF8STRING` is added back. That is what
//!   makes `DIRSTRING_TYPE`'s BMP and UTF8 bits behave as the caller expects.
//!
//! ## `out` is an input and an output, and the failure paths differ
//!
//! When `*out` is non-null the caller's string is *reused*: `ASN1_STRING_set0`
//! releases whatever it held and its type is overwritten. When the function
//! allocated the string itself it frees it on every failure path and stores null,
//! but a caller-supplied string is left as it was — which is why `free_out`
//! exists rather than a single cleanup label.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_char, c_int, c_long, c_uchar, c_ulong, c_void};

use crate::asn1::a_utf8::{UTF8_getc, UTF8_putc};
use crate::asn1::layout::*;
use crate::asn1::owned::OwnedBlock;
use crate::asn1::string::string_type_new;
use crate::asn1::string::{ASN1_STRING_free, ASN1_STRING_set, ASN1_STRING_set0};
use crate::ffi::guard_ffi;
use crate::runtime::ctype::{ossl_isascii, ossl_isasn1print, ossl_isdigit};
use crate::runtime::err::err_sites;
use crate::runtime::err::{raise_site, raise_site_data};
use crate::runtime::mem_coords::SeamFile;
use crate::runtime::str::OPENSSL_strnlen;

/// The authority translation unit for the multibyte conversions.
pub(crate) const FILE: &core::ffi::CStr = c"crypto/asn1/a_mbstr.c";
/// The authority passes `__LINE__`, inert under `OPENSSL_NO_CRYPTO_MDEBUG`.
pub(crate) const LINE: c_int = 0;

/// `UNICODE_MAX` — the highest scalar value, from `internal/unicode.h`.
const UNICODE_MAX: c_ulong = 0x10ffff;
/// `SURROGATE_MIN`.
const SURROGATE_MIN: c_ulong = 0xd800;
/// `SURROGATE_MAX`.
const SURROGATE_MAX: c_ulong = 0xdfff;

/// `static int is_unicode_valid(unsigned long value)`
fn is_unicode_valid(value: c_ulong) -> bool {
    value <= UNICODE_MAX && !(SURROGATE_MIN..=SURROGATE_MAX).contains(&value)
}

/// `static int traverse_string(const unsigned char *p, int len, int inform,
/// int (*rfunc)(unsigned long value, void *in), void *arg)`
///
/// Answers 1 when the whole input was consumed, and otherwise the callback's own
/// non-positive answer — which is how `in_utf8`'s `-2` for an invalid scalar and
/// `out_utf8`'s `-1` for an over-long output reach the caller.
///
/// The authority passes a C function pointer plus an untyped `void *arg`; this
/// reconstruction passes an `FnMut` instead, so the per-character work is a closure
/// that borrows the counter or write cursor it updates (`&mut c_int`, `&mut c_ulong`
/// or `&mut [u8]`). No `void *` argument is reconstructed and no `unsafe extern "C"`
/// callback definition remains, so the state a callback may touch is expressed by the
/// borrow rather than asserted in a comment.
///
/// The `ASC`, `BMP` and `UNIV` arms consume a *fixed* number of bytes per
/// character, so a length that is not a multiple of the unit would run past the
/// end; the caller has already rejected that for `BMP` and `UNIV`, and `ASC` is
/// one byte per character by definition. Only the `UTF8` arm is variable-length,
/// and it is the one that can fail.
///
/// # Safety
///
/// `p` must be readable for `len` bytes and `inform` must be one of the four
/// `MBSTRING_*` forms, or the `UTF8` arm is taken.
unsafe fn traverse_string(
    p: *const c_uchar,
    len: c_int,
    inform: c_int,
    mut rfunc: impl FnMut(c_ulong) -> c_int,
) -> c_int {
    let mut len = len;
    let mut p = p;
    while len != 0 {
        let value: c_ulong;
        if inform == MBSTRING_ASC {
            // SAFETY: the caller's contract makes `p` readable for `len` bytes,
            // and `len != 0`.
            value = c_ulong::from(unsafe { *p });
            // SAFETY: one byte was consumed and at least one was available.
            p = unsafe { p.add(1) };
            len -= 1;
        } else if inform == MBSTRING_BMP {
            // SAFETY: the caller guarantees a multiple of two bytes remain.
            value = (c_ulong::from(unsafe { *p }) << 8) | c_ulong::from(unsafe { *p.add(1) });
            // SAFETY: two bytes were consumed.
            p = unsafe { p.add(2) };
            len -= 2;
        } else if inform == MBSTRING_UNIV {
            // SAFETY: the caller guarantees a multiple of four bytes remain.
            value = (c_ulong::from(unsafe { *p }) << 24)
                | (c_ulong::from(unsafe { *p.add(1) }) << 16)
                | (c_ulong::from(unsafe { *p.add(2) }) << 8)
                | c_ulong::from(unsafe { *p.add(3) });
            // SAFETY: four bytes were consumed.
            p = unsafe { p.add(4) };
            len -= 4;
        } else {
            let mut v: c_ulong = 0;
            // SAFETY: the caller's contract makes `p` readable for `len` bytes;
            // `UTF8_getc` reads at most `len`.
            let ret = unsafe { UTF8_getc(p, len, &mut v) };
            if ret < 0 {
                return -1;
            }
            value = v;
            len -= ret;
            // SAFETY: `ret` bytes were consumed and `len >= 0` after the
            // subtraction.
            p = unsafe { p.add(ret as usize) };
        }
        let ret = rfunc(value);
        if ret <= 0 {
            return ret;
        }
    }
    1
}

/// `static int in_utf8(unsigned long value, void *arg)` — count, rejecting an
/// invalid scalar.
///
/// The authority's `arg` is an `int *`; here the counter is a `&mut c_int`, so the
/// function reads and writes no raw pointer and needs no caller contract.
fn in_utf8(value: c_ulong, nchar: &mut c_int) -> c_int {
    if !is_unicode_valid(value) {
        return -2;
    }
    *nchar += 1;
    1
}

/// `static int out_utf8(unsigned long value, void *arg)` — measure, with the
/// authority's `INT_MAX - len` guard against an output length that would overflow.
///
/// The authority's `arg` is an `int *`; here the accumulator is a `&mut c_int`.
fn out_utf8(value: c_ulong, outlen: &mut c_int) -> c_int {
    // A null destination asks `UTF8_putc` for the width.
    // SAFETY: a null destination is explicitly the width query.
    let len = unsafe { UTF8_putc(core::ptr::null_mut(), -1, value) };
    if len <= 0 {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::A_MBSTR_305) };
        return len;
    }
    if *outlen >= c_int::MAX - len {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::A_MBSTR_310) };
        return -1;
    }
    *outlen += len;
    1
}

/// `static int type_str(unsigned long value, void *arg)` — clear from the mask
/// every type this value cannot be held in, and fail when nothing is left.
///
/// The authority's `arg` is an `unsigned long *`; here the mask is a `&mut c_ulong`.
fn type_str(value: c_ulong, mask: &mut c_ulong) -> c_int {
    let usable_types = *mask;
    let mut types = usable_types;
    // `value > INT_MAX ? INT_MAX : ossl_fromascii(value)` — the cast is a
    // truncation on this profile, and the saturation is what keeps the signed
    // classifiers from seeing a wrapped value.
    let native: c_int = if value > c_int::MAX as c_ulong {
        c_int::MAX
    } else {
        value as c_int
    };

    types &= B_ASN1_NUMERICSTRING
        | B_ASN1_PRINTABLESTRING
        | B_ASN1_IA5STRING
        | B_ASN1_T61STRING
        | B_ASN1_BMPSTRING
        | B_ASN1_UNIVERSALSTRING
        | B_ASN1_UTF8STRING;
    // A bit outside those seven is not an error: it means UTF8 was asked for.
    if types != usable_types {
        types |= B_ASN1_UTF8STRING;
    }

    if (types & B_ASN1_NUMERICSTRING) != 0 && !(ossl_isdigit(native) || native == c_int::from(b' '))
    {
        types &= !B_ASN1_NUMERICSTRING;
    }
    if (types & B_ASN1_PRINTABLESTRING) != 0 && !ossl_isasn1print(native) {
        types &= !B_ASN1_PRINTABLESTRING;
    }
    if (types & B_ASN1_IA5STRING) != 0 && !ossl_isascii(native) {
        types &= !B_ASN1_IA5STRING;
    }
    if (types & B_ASN1_T61STRING) != 0 && value > 0xff {
        types &= !B_ASN1_T61STRING;
    }
    if (types & B_ASN1_BMPSTRING) != 0 && value > 0xffff {
        types &= !B_ASN1_BMPSTRING;
    }
    if (types & B_ASN1_UTF8STRING) != 0 && !is_unicode_valid(value) {
        types &= !B_ASN1_UTF8STRING;
    }
    if types == 0 {
        return -1;
    }
    *mask = types;
    1
}

/// `static int cpy_asc(unsigned long value, void *arg)` — one byte per character.
///
/// The authority's `arg` is the address of a write cursor into a buffer it sized as one byte per
/// character. Here the cursor is `out` (the content bytes of the block `ASN1_mbstring_ncopy`
/// allocated) plus the position, so every write is bounds-checked by the slice rather than
/// asserted in a comment.
fn cpy_asc(value: c_ulong, out: &mut [u8], pos: &mut usize) -> c_int {
    let Some(slot) = out.get_mut(*pos) else {
        return -1;
    };
    *slot = value as c_uchar;
    *pos += 1;
    1
}

/// `static int cpy_bmp(unsigned long value, void *arg)` — two bytes, big-endian.
///
/// As [`cpy_asc`]: `out` was sized as two bytes per character, so the two-byte window is checked
/// against the slice.
fn cpy_bmp(value: c_ulong, out: &mut [u8], pos: &mut usize) -> c_int {
    let Some(end) = pos.checked_add(2) else {
        return -1;
    };
    let Some(window) = out.get_mut(*pos..end) else {
        return -1;
    };
    window[0] = ((value >> 8) & 0xff) as c_uchar;
    window[1] = (value & 0xff) as c_uchar;
    *pos = end;
    1
}

/// `static int cpy_univ(unsigned long value, void *arg)` — four bytes, big-endian.
///
/// As [`cpy_asc`]: `out` was sized as four bytes per character, so the four-byte window is
/// checked against the slice.
fn cpy_univ(value: c_ulong, out: &mut [u8], pos: &mut usize) -> c_int {
    let Some(end) = pos.checked_add(4) else {
        return -1;
    };
    let Some(window) = out.get_mut(*pos..end) else {
        return -1;
    };
    window[0] = ((value >> 24) & 0xff) as c_uchar;
    window[1] = ((value >> 16) & 0xff) as c_uchar;
    window[2] = ((value >> 8) & 0xff) as c_uchar;
    window[3] = (value & 0xff) as c_uchar;
    *pos = end;
    1
}

/// `static int cpy_utf8(unsigned long value, void *arg)` — `UTF8_putc` with the
/// length guard already discharged by `out_utf8`, so the authority passes `0xff`.
///
/// This reconstruction passes the **actual remaining room** instead of the authority's `0xff`.
/// The measuring pass (`out_utf8`) sized `out` so every character's encoding fits, so the two
/// forms agree on every input the guard admits; passing the real length makes `UTF8_putc`'s own
/// bounds check (`len` too small answers `-1`) the enforcement, instead of an unconditional
/// `0xff` that would let a mis-sized buffer be overrun.
fn cpy_utf8(value: c_ulong, out: &mut [u8], pos: &mut usize) -> c_int {
    let Some(rest) = out.get_mut(*pos..) else {
        return -1;
    };
    // `out` is at most `INT_MAX` bytes by construction: `outlen` is `nchar`, `nchar << 1`,
    // `nchar << 2` or the measuring pass's `int` result, and each of those is an `int`.
    let Ok(room) = c_int::try_from(rest.len()) else {
        return -1;
    };
    // SAFETY: `rest` is a live mutable slice of `room` bytes and `UTF8_putc` writes at most `room`
    // bytes (it answers `-1` rather than writing when the encoding does not fit), so the write
    // stays inside the slice.
    let ret = unsafe { UTF8_putc(rest.as_mut_ptr(), room, value) };
    if ret < 0 {
        return ret;
    }
    *pos += ret as usize;
    1
}

/// `int ASN1_mbstring_copy(ASN1_STRING **out, const unsigned char *in, int len,
/// int inform, unsigned long mask)`
///
/// The unlimited form: minimum and maximum of zero, which `ncopy` treats as "no
/// bound" because both tests are `> 0`.
///
/// # Safety
///
/// `out` must be null or point at a writable `ASN1_STRING *`; `in` must be
/// readable for `len` bytes, or NUL-terminated when `len` is `-1`.
#[no_mangle]
pub unsafe extern "C" fn ASN1_mbstring_copy(
    out: *mut *mut Asn1String,
    in_: *const c_uchar,
    len: c_int,
    inform: c_int,
    mask: c_ulong,
) -> c_int {
    // SAFETY: the caller's contract is `ASN1_mbstring_ncopy`'s.
    unsafe { ASN1_mbstring_ncopy(out, in_, len, inform, mask, 0, 0) }
}

/// `int ASN1_mbstring_ncopy(ASN1_STRING **out, const unsigned char *in, int len,
/// int inform, unsigned long mask, long minsize, long maxsize)`
///
/// A null `out` is legal and makes this a *classifier*: it answers the string type
/// the input would be held in, without converting anything. That is the form the
/// authority's `ASN1_mbstring_copy` is usually asked for.
///
/// # Safety
///
/// `out` must be null or point at a writable `ASN1_STRING *`; `in` must be
/// readable for `len` bytes, or NUL-terminated when `len` is `-1`.
#[no_mangle]
#[allow(clippy::too_many_arguments)]
// The authority's own test is `len >= INT_MAX`, which is *satisfiable* — it fires
// only at exactly `INT_MAX` — but which clippy reads as an equator that should have
// been written as one. Reproducing the test is the point, so the lint is allowed
// here rather than the comparison rewritten.
#[allow(clippy::absurd_extreme_comparisons)]
pub unsafe extern "C" fn ASN1_mbstring_ncopy(
    out: *mut *mut Asn1String,
    in_: *const c_uchar,
    len: c_int,
    inform: c_int,
    mask_in: c_ulong,
    minsize: c_long,
    maxsize: c_long,
) -> c_int {
    guard_ffi(-1, || {
        let mut len = len;
        let mut mask = mask_in;
        if len == -1 {
            // SAFETY: the caller's contract makes `in` NUL-terminated.
            let len_s = unsafe { OPENSSL_strnlen(in_.cast::<c_char>(), usize::MAX) };
            if len_s >= c_int::MAX as usize {
                // SAFETY: a compile-time-constant site.
                unsafe { raise_site(&err_sites::A_MBSTR_58) };
                return -1;
            }
            len = len_s as c_int;
        }
        if mask == 0 {
            mask = DIRSTRING_TYPE;
        }
        if len < 0 {
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&err_sites::A_MBSTR_66) };
            return -1;
        } else if len >= c_int::MAX {
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&err_sites::A_MBSTR_69) };
            return -1;
        }

        // The character count, which is also the input's syntax check. The
        // authority leaves it uninitialised and every arm below either sets it or
        // returns, so the declaration is uninitialised here too and the compiler
        // enforces the property the authority relies on.
        let mut nchar: c_int;
        match inform {
            MBSTRING_BMP => {
                if len & 1 != 0 {
                    // SAFETY: a compile-time-constant site.
                    unsafe { raise_site(&err_sites::A_MBSTR_78) };
                    return -1;
                }
                nchar = len >> 1;
            }
            MBSTRING_UNIV => {
                if len & 3 != 0 {
                    // SAFETY: a compile-time-constant site.
                    unsafe { raise_site(&err_sites::A_MBSTR_86) };
                    return -1;
                }
                nchar = len >> 2;
            }
            MBSTRING_UTF8 => {
                nchar = 0;
                // SAFETY: `in` is readable for `len` bytes and `UTF8` is a legal
                // `inform`.
                if unsafe {
                    traverse_string(in_, len, MBSTRING_UTF8, |value| in_utf8(value, &mut nchar))
                } < 0
                {
                    // SAFETY: a compile-time-constant site.
                    unsafe { raise_site(&err_sites::A_MBSTR_97) };
                    return -1;
                }
            }
            MBSTRING_ASC => nchar = len,
            _ => {
                // SAFETY: a compile-time-constant site.
                unsafe { raise_site(&err_sites::A_MBSTR_107) };
                return -1;
            }
        }

        if minsize > 0 && c_long::from(nchar) < minsize {
            let mut msg = [0 as c_char; 48];
            // SAFETY: `msg` is a 48-byte buffer and the format is the authority's.
            unsafe {
                crate::runtime::bio::print::BIO_snprintf(
                    msg.as_mut_ptr(),
                    msg.len(),
                    c"minsize=%ld".as_ptr(),
                    minsize,
                )
            };
            // SAFETY: a compile-time-constant site; the message is NUL-terminated.
            unsafe { raise_site_data(&err_sites::A_MBSTR_112, msg.as_ptr()) };
            return -1;
        }
        if maxsize > 0 && c_long::from(nchar) > maxsize {
            let mut msg = [0 as c_char; 48];
            // SAFETY: `msg` is a 48-byte buffer and the format is the authority's.
            unsafe {
                crate::runtime::bio::print::BIO_snprintf(
                    msg.as_mut_ptr(),
                    msg.len(),
                    c"maxsize=%ld".as_ptr(),
                    maxsize,
                )
            };
            // SAFETY: a compile-time-constant site; the message is NUL-terminated.
            unsafe { raise_site_data(&err_sites::A_MBSTR_118, msg.as_ptr()) };
            return -1;
        }

        // Narrow the mask to the types that hold every character.
        {
            // SAFETY: `in` is readable for `len` bytes and `inform` is one of the
            // four legal forms — the match above rejected anything else.
            if unsafe { traverse_string(in_, len, inform, |value| type_str(value, &mut mask)) } < 0
            {
                // SAFETY: a compile-time-constant site.
                unsafe { raise_site(&err_sites::A_MBSTR_125) };
                return -1;
            }
        }

        // The type ladder, in the order that makes the answer the narrowest.
        let mut outform = MBSTRING_ASC;
        let str_type;
        if mask & B_ASN1_NUMERICSTRING != 0 {
            str_type = V_ASN1_NUMERICSTRING;
        } else if mask & B_ASN1_PRINTABLESTRING != 0 {
            str_type = V_ASN1_PRINTABLESTRING;
        } else if mask & B_ASN1_IA5STRING != 0 {
            str_type = V_ASN1_IA5STRING;
        } else if mask & B_ASN1_T61STRING != 0 {
            str_type = V_ASN1_T61STRING;
        } else if mask & B_ASN1_BMPSTRING != 0 {
            str_type = V_ASN1_BMPSTRING;
            outform = MBSTRING_BMP;
        } else if mask & B_ASN1_UNIVERSALSTRING != 0 {
            str_type = V_ASN1_UNIVERSALSTRING;
            outform = MBSTRING_UNIV;
        } else {
            str_type = V_ASN1_UTF8STRING;
            outform = MBSTRING_UTF8;
        }

        if out.is_null() {
            return str_type;
        }

        // A caller-supplied destination is reused; one this function made is freed
        // on every failure below and the caller's slot is cleared.
        let free_out;
        let dest;
        // SAFETY: the caller's contract makes `out` readable.
        let existing = unsafe { *out };
        if !existing.is_null() {
            free_out = false;
            dest = existing;
            // SAFETY: the caller's contract makes `dest` live and uniquely owned.
            unsafe { ASN1_STRING_set0(dest, core::ptr::null_mut(), 0) };
            // SAFETY: `dest` is live.
            unsafe { (*dest).type_ = str_type };
        } else {
            free_out = true;
            dest = string_type_new(str_type);
            if dest.is_null() {
                // SAFETY: a compile-time-constant site.
                unsafe { raise_site(&err_sites::A_MBSTR_163) };
                return -1;
            }
            // SAFETY: the caller's contract makes `out` writable.
            unsafe { *out = dest };
        }

        // Same form in and out: copy the bytes across unchanged.
        if inform == outform {
            // SAFETY: `dest` is live and uniquely owned; `in` is readable for
            // `len` bytes.
            if unsafe { ASN1_STRING_set(dest, in_.cast::<c_void>(), len) } == 0 {
                if free_out {
                    // SAFETY: `dest` was allocated above and is not shared.
                    unsafe { ASN1_STRING_free(dest) };
                    // SAFETY: the caller's contract makes `out` writable.
                    unsafe { *out = core::ptr::null_mut() };
                }
                // SAFETY: a compile-time-constant site.
                unsafe { raise_site(&err_sites::A_MBSTR_175) };
                return -1;
            }
            return str_type;
        }

        // The output length, and the copier that will fill it.
        // The copier is a safe `fn` over the output slice and its position; the authority's
        // `int (*)(unsigned long, void *)` plus cursor `void *` is not reconstructed.
        let cpyfunc: fn(c_ulong, &mut [u8], &mut usize) -> c_int;
        let outlen: c_int;
        match outform {
            MBSTRING_ASC => {
                outlen = nchar;
                cpyfunc = cpy_asc;
            }
            MBSTRING_BMP => {
                if nchar > c_int::MAX / 2 {
                    // SAFETY: a compile-time-constant site.
                    unsafe { raise_site(&err_sites::A_MBSTR_190) };
                    if free_out {
                        // SAFETY: `dest` was allocated above and is not shared.
                        unsafe { ASN1_STRING_free(dest) };
                        // SAFETY: the caller's contract makes `out` writable.
                        unsafe { *out = core::ptr::null_mut() };
                    }
                    return -1;
                }
                outlen = nchar << 1;
                cpyfunc = cpy_bmp;
            }
            MBSTRING_UNIV => {
                if nchar > c_int::MAX / 4 {
                    // SAFETY: a compile-time-constant site.
                    unsafe { raise_site(&err_sites::A_MBSTR_203) };
                    if free_out {
                        // SAFETY: `dest` was allocated above and is not shared.
                        unsafe { ASN1_STRING_free(dest) };
                        // SAFETY: the caller's contract makes `out` writable.
                        unsafe { *out = core::ptr::null_mut() };
                    }
                    return -1;
                }
                outlen = nchar << 2;
                cpyfunc = cpy_univ;
            }
            _ => {
                let mut o: c_int = 0;
                // SAFETY: `in` is readable for `len` bytes and `inform` is legal.
                if unsafe { traverse_string(in_, len, inform, |value| out_utf8(value, &mut o)) } < 0
                {
                    if free_out {
                        // SAFETY: `dest` was allocated above and is not shared.
                        unsafe { ASN1_STRING_free(dest) };
                        // SAFETY: the caller's contract makes `out` writable.
                        unsafe { *out = core::ptr::null_mut() };
                    }
                    return -1;
                }
                outlen = o;
                cpyfunc = cpy_utf8;
            }
        }

        // The authority's `CRYPTO_malloc(outlen + 1)`. Both the conversion from the signed
        // length and the `+ 1` are checked, so a negative or overflowing request never reaches
        // the allocator; either is the same refusal as a refused allocation. `OwnedBlock` owns
        // the block until it is transferred to `dest` below.
        let Some(count) = usize::try_from(outlen).ok().and_then(|n| n.checked_add(1)) else {
            if free_out {
                // SAFETY: `dest` was allocated above and is not shared.
                unsafe { ASN1_STRING_free(dest) };
                // SAFETY: the caller's contract makes `out` writable.
                unsafe { *out = core::ptr::null_mut() };
            }
            return -1;
        };
        let Some(p) = OwnedBlock::<c_uchar>::malloc(count, SeamFile::new(FILE), LINE) else {
            if free_out {
                // SAFETY: `dest` was allocated above and is not shared.
                unsafe { ASN1_STRING_free(dest) };
                // SAFETY: the caller's contract makes `out` writable.
                unsafe { *out = core::ptr::null_mut() };
            }
            return -1;
        };
        let outlen_usize = count - 1;
        let dst = p.as_ptr();
        // SAFETY: `dest` is live and uniquely owned, and `dst` is not owned by
        // anything else, which is what `ASN1_STRING_set0` requires.
        unsafe {
            (*dest).length = outlen;
            (*dest).data = dst;
            *dst.add(outlen_usize) = 0;
        }
        // The block is now `dest`'s: give up the local owner so it is not released here. The
        // authority transfers it by the field store above, and `dest` releases it through
        // `ASN1_STRING_free` later.
        let cursor = p.into_raw();
        // The content view of the block: `outlen_usize` bytes, the block being `outlen + 1` so the
        // NUL at `[outlen]` written above is outside this slice. The slice is derived from the
        // block this frame exclusively owns and is not used after the owner is given to `dest`.
        // SAFETY: `cursor` is the `count = outlen + 1`-byte block `OwnedBlock::malloc` returned and
        // this frame still owns (the block was handed to `dest` by the field stores above, and
        // `into_raw` gave up the local owner so it is not released here); `outlen_usize = count - 1`
        // bytes are live and writable, and nothing else aliases them.
        let out_slice = unsafe { core::slice::from_raw_parts_mut(cursor, outlen_usize) };
        let mut pos = 0usize;
        // SAFETY: `in` is readable for `len` bytes and `inform` is legal; the copier is bounds-checked
        // against `out_slice`, so the traversal writes only inside the block that was allocated for it.
        unsafe {
            traverse_string(in_, len, inform, |value| {
                cpyfunc(value, out_slice, &mut pos)
            })
        };
        str_type
    })
}

#[cfg(test)]
mod asn1_ocsp_mbstr_tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;

    /// A BMP conversion writes exactly the `nchar * 2` content bytes the measuring pass sized,
    /// and leaves the authority's single NUL at `data[length]`: the writer is bounded by the
    /// output slice, so the block is written neither short nor past its content.
    #[test]
    fn asn1_ocsp_mbstr_bmp_output_is_exactly_the_sized_block() {
        let input = *b"AB";
        let mut out: *mut Asn1String = core::ptr::null_mut();
        // SAFETY: `out` is a writable slot that starts NULL; `in` is readable for two bytes and
        // `B_ASN1_BMPSTRING` is a legal mask, so the function allocates the result.
        let ret = unsafe {
            ASN1_mbstring_ncopy(
                &raw mut out,
                input.as_ptr(),
                input.len() as c_int,
                MBSTRING_UTF8,
                B_ASN1_BMPSTRING,
                0,
                0,
            )
        };
        assert_eq!(ret, V_ASN1_BMPSTRING);
        assert!(!out.is_null());
        // SAFETY: `out` is the fresh object this call produced and this frame owns.
        unsafe {
            assert_eq!((*out).length, 4, "two BMP characters are four bytes");
            let data = (*out).data;
            assert_eq!((*data, *data.add(1)), (0x00, b'A'));
            assert_eq!((*data.add(2), *data.add(3)), (0x00, b'B'));
            assert_eq!(*data.add(4), 0, "the authority's NUL sits past the content");
            ASN1_STRING_free(out);
        }
    }

    /// A length at `INT_MAX` is refused by the site's own arithmetic guard before any allocation
    /// or conversion: the caller's slot is untouched and no block is created.
    #[test]
    fn asn1_ocsp_mbstr_refuses_a_length_at_int_max() {
        let input = *b"x";
        let mut out: *mut Asn1String = core::ptr::null_mut();
        // SAFETY: `out` is a writable slot; the input is never read because the length guard
        // fires first.
        let ret = unsafe {
            ASN1_mbstring_ncopy(
                &raw mut out,
                input.as_ptr(),
                c_int::MAX,
                MBSTRING_ASC,
                DIRSTRING_TYPE,
                0,
                0,
            )
        };
        assert_eq!(ret, -1, "a length at INT_MAX is refused");
        assert!(out.is_null(), "the refusal writes no output");
    }
}
