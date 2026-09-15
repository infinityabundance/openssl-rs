//! Phase 5 — the time family: `crypto/asn1/a_time.c`, `a_utctm.c`, `a_gentm.c`.
//!
//! This is the largest single behaviour in the ASN.1 stratum that is a *parser*
//! rather than a codec. `ossl_asn1_time_to_tm` is the authority's only
//! implementation of the two RFC 5280 time syntaxes, and everything else in the
//! family is a wrapper over it: the two `_check` functions, the two
//! `_set_string`/`_adj` constructors, `ASN1_TIME_diff`, `ASN1_TIME_compare`,
//! the three `_cmp_time_t` functions and the four printers.
//!
//! ## What the parser actually accepts
//!
//! It is a hand-written field reader, and the interesting parts are the
//! asymmetries between the strict and non-strict modes:
//!
//! * Without `ASN1_STRING_FLAG_X509_TIME`, field 5 of a UTCTime (field 6 of a
//!   GeneralizedTime) may be where the *timezone* begins rather than seconds,
//!   and `+hhmm`/`-hhmm` offsets are accepted with the hour limited to 12.
//! * With the flag, seconds and `Z` are mandatory, fractions are forbidden, and
//!   a `+`/`-` offset is a parse failure — that is the RFC 5280 profile.
//! * The offset is applied with `OPENSSL_gmtime_adj` **only when `tm` is
//!   non-null**. `ASN1_TIME_check` passes null, so it validates the offset
//!   without applying it, and a value whose offset would push the day number
//!   negative is accepted by the checker and rejected by a fill. That asymmetry
//!   is the authority's and is courted.
//! * The two `set_string` constructors build a *stack* time string over the
//!   caller's buffer — `data` points at the caller's string — and only copy it
//!   into `s` after the check passes. That is why `ASN1_TIME_set_string_X509`
//!   has to allocate before it can hand a shortened string to `ASN1_STRING_copy`.
//!
//! ## Where behaviour is deliberately not reproduced
//!
//! Upstream dereferences `d`, `bp` and the `struct tm *` outputs without a null
//! test in several places. Those calls fault rather than return; each is
//! answered with the function's documented failure value here and recorded in
//! `docs/SECURITY_DIVERGENCE_POLICY.md`.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_char, c_int, c_long, c_uchar, c_ulong, c_void};

use crate::asn1::a_dup::ASN1_item_dup;
use crate::asn1::items::{ASN1_GENERALIZEDTIME_it, ASN1_TIME_it, ASN1_UTCTIME_it};
use crate::asn1::layout::*;
use crate::asn1::string::ASN1_STRING_set;
use crate::asn1::string::{as_str, ASN1_STRING_copy, ASN1_STRING_free, ASN1_STRING_new};
use crate::ffi::guard_ffi;
use crate::runtime::bio::iolib::BIO_write;
use crate::runtime::bio::print::{BIO_printf, BIO_snprintf};
use crate::runtime::bio::sys::time;
use crate::runtime::bio::Bio;
use crate::runtime::ctype::ossl_isdigit;
use crate::runtime::err::err_sites;
use crate::runtime::err::raise_site;
use crate::runtime::mem::{CRYPTO_free, CRYPTO_zalloc};
use crate::runtime::str::OPENSSL_strnlen;
use crate::runtime::time::{OPENSSL_gmtime, OPENSSL_gmtime_adj, OPENSSL_gmtime_diff, TimeT, Tm};

/// The authority translation unit for the `ASN1_TIME` behaviour.
///
/// This module is three translation units — `a_time.c`, `a_utctm.c` and
/// `a_gentm.c` — and only `a_time.c` allocates, so it is the only one whose name
/// reaches an allocator or a raise site. The other two are wrappers and have no
/// coordinates of their own to record.
pub(crate) const FILE: &core::ffi::CStr = c"crypto/asn1/a_time.c";
/// The authority passes `__LINE__`, inert under `OPENSSL_NO_CRYPTO_MDEBUG`.
pub(crate) const LINE: c_int = 0;

/// `min[]` — the lowest legal value of each two-digit field, index 0 first.
const MIN: [c_int; 9] = [0, 0, 1, 1, 0, 0, 0, 0, 0];
/// `max[]` — the highest legal value of each two-digit field. Indices 7 and 8 are
/// the timezone hour (12) and minute, which exist only in the offset branch.
const MAX: [c_int; 9] = [99, 99, 12, 31, 23, 59, 59, 12, 59];
/// `mdays[]` — the days in each month, before the February adjustment.
const MDAYS: [c_int; 12] = [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
/// `ydays[]` — the day of the year each month starts on.
const YDAYS: [c_int; 12] = [0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334];
/// `_asn1_mon[]` — the English month names the RFC 822 form prints.
const ASN1_MON: [&core::ffi::CStr; 12] = [
    c"Jan", c"Feb", c"Mar", c"Apr", c"May", c"Jun", c"Jul", c"Aug", c"Sep", c"Oct", c"Nov", c"Dec",
];

/// An all-zero `struct tm`, which is what the authority's `memset` produces.
#[inline]
fn zeroed_tm() -> Tm {
    // SAFETY: `Tm` is nine `int`s, one `long` and one pointer; all-zero is a
    // valid value of it.
    unsafe { core::mem::zeroed() }
}

/// A stack-built `ASN1_STRING` over the caller's buffer.
///
/// The authority builds these as plain locals and never frees them, which is what
/// makes `data` borrowed rather than owned here.
#[inline]
fn stack_string(type_: c_int, data: *mut c_uchar, length: c_int, flags: c_long) -> Asn1String {
    Asn1String {
        length,
        type_,
        data,
        flags,
    }
}

/// `static int is_utc(const int year)`
///
/// The argument is `tm_year`, not the civil year: the window is 1950-2049.
fn is_utc(year: c_int) -> bool {
    (50..=149).contains(&year)
}

/// `static int leap_year(const int year)`
fn leap_year(year: c_int) -> c_int {
    if year.wrapping_rem(400) == 0 || (year.wrapping_rem(100) != 0 && year.wrapping_rem(4) == 0) {
        1
    } else {
        0
    }
}

/// `static void determine_days(struct tm *tm)` — the weekday and the day of the
/// year, the latter by a form of Zeller's congruence with March as month 1.
fn determine_days(tm: &mut Tm) {
    let mut y = tm.tm_year.wrapping_add(1900);
    let mut m = tm.tm_mon;
    let d = tm.tm_mday;

    tm.tm_yday = YDAYS[m as usize].wrapping_add(d).wrapping_sub(1);
    if m >= 2 {
        tm.tm_yday = tm.tm_yday.wrapping_add(leap_year(y));
        m = m.wrapping_add(2);
    } else {
        m = m.wrapping_add(14);
        y = y.wrapping_sub(1);
    }
    let c = y.wrapping_div(100);
    y = y.wrapping_rem(100);
    tm.tm_wday = d
        .wrapping_add(13_i32.wrapping_mul(m).wrapping_div(5))
        .wrapping_add(y)
        .wrapping_add(y.wrapping_div(4))
        .wrapping_add(c.wrapping_div(4))
        .wrapping_add(5_i32.wrapping_mul(c))
        .wrapping_add(6)
        .wrapping_rem(7);
}

/// `int ossl_asn1_time_to_tm(struct tm *tm, const ASN1_TIME *d)`
///
/// The two time syntaxes' only parser. `tm` may be null, in which case the value
/// is validated but not filled — and, because the timezone offset is applied
/// through the local `struct tm` only when `tm` is non-null, not normalised
/// either. Returns 1 on success.
///
/// This is an internal symbol: `include/crypto/asn1.h` declares it and the
/// authority's DSO does not export it, so neither does the candidate.
///
/// # Safety
///
/// `d` must be null or a live `ASN1_TIME`; `tm` must be null or writable.
pub(crate) unsafe fn ossl_asn1_time_to_tm(tm: *mut Tm, d: *const Asn1String) -> c_int {
    // SAFETY: the caller's contract makes `d` readable when non-null.
    let Some(s) = (unsafe { as_str(d) }) else {
        return 0;
    };
    let type_ = s.type_;
    // `min_l` is the shortest legal spelling, `end` the number of two-digit
    // fields before the timezone, and `btz` the index at which the timezone may
    // begin in place of a field.
    let (end, btz, min_l, strict) = if type_ == V_ASN1_UTCTIME {
        (6, 5, 13, s.flags & ASN1_STRING_FLAG_X509_TIME != 0)
    } else if type_ == V_ASN1_GENERALIZEDTIME {
        (7, 6, 15, s.flags & ASN1_STRING_FLAG_X509_TIME != 0)
    } else {
        return 0;
    };

    let l = s.length;
    if l < min_l || s.data.is_null() {
        return 0;
    }
    // SAFETY: `l >= min_l >= 13` and `data` is non-null, so the string's own
    // contract makes `length` bytes readable at `data`.
    let buf = unsafe { core::slice::from_raw_parts(s.data, l as usize) };
    let mut o: usize = 0;
    let mut tmp = zeroed_tm();

    let mut i: c_int = 0;
    while i < end {
        if !strict && i == btz && (buf[o] == b'Z' || buf[o] == b'+' || buf[o] == b'-') {
            break;
        }
        if !ossl_isdigit(c_int::from(buf[o])) {
            return 0;
        }
        let mut n = c_int::from(buf[o]) - c_int::from(b'0');
        o += 1;
        if o == l as usize {
            return 0;
        }
        if !ossl_isdigit(c_int::from(buf[o])) {
            return 0;
        }
        n = n
            .wrapping_mul(10)
            .wrapping_add(c_int::from(buf[o]) - c_int::from(b'0'));
        o += 1;
        if o == l as usize {
            return 0;
        }
        let i2 = if type_ == V_ASN1_UTCTIME { i + 1 } else { i };
        if n < MIN[i2 as usize] || n > MAX[i2 as usize] {
            return 0;
        }
        match i2 {
            0 => tmp.tm_year = n.wrapping_mul(100).wrapping_sub(1900),
            1 => {
                if type_ == V_ASN1_UTCTIME {
                    tmp.tm_year = if n < 50 { n + 100 } else { n };
                } else {
                    tmp.tm_year = tmp.tm_year.wrapping_add(n);
                }
            }
            2 => tmp.tm_mon = n - 1,
            3 => {
                let md = if tmp.tm_mon == 1 {
                    MDAYS[1].wrapping_add(leap_year(tmp.tm_year.wrapping_add(1900)))
                } else {
                    MDAYS[tmp.tm_mon as usize]
                };
                if n > md {
                    return 0;
                }
                tmp.tm_mday = n;
                determine_days(&mut tmp);
            }
            4 => tmp.tm_hour = n,
            5 => tmp.tm_min = n,
            6 => tmp.tm_sec = n,
            _ => {}
        }
        i += 1;
    }

    // Optional fractional seconds, GeneralizedTime only, one or more digits.
    if type_ == V_ASN1_GENERALIZEDTIME && buf[o] == b'.' {
        if strict {
            return 0;
        }
        o += 1;
        if o == l as usize {
            return 0;
        }
        let start = o;
        while o < l as usize && ossl_isdigit(c_int::from(buf[o])) {
            o += 1;
        }
        if start == o {
            return 0;
        }
        if o == l as usize {
            return 0;
        }
    }

    if buf[o] == b'Z' {
        o += 1;
    } else if !strict && (buf[o] == b'+' || buf[o] == b'-') {
        let offsign: c_int = if buf[o] == b'-' { 1 } else { -1 };
        let mut offset: c_int = 0;

        o += 1;
        if o + 4 != l as usize {
            return 0;
        }
        let mut i = end;
        while i < end + 2 {
            if !ossl_isdigit(c_int::from(buf[o])) {
                return 0;
            }
            let mut n = c_int::from(buf[o]) - c_int::from(b'0');
            o += 1;
            if !ossl_isdigit(c_int::from(buf[o])) {
                return 0;
            }
            n = n
                .wrapping_mul(10)
                .wrapping_add(c_int::from(buf[o]) - c_int::from(b'0'));
            let i2 = if type_ == V_ASN1_UTCTIME { i + 1 } else { i };
            if n < MIN[i2 as usize] || n > MAX[i2 as usize] {
                return 0;
            }
            // The offset is only accumulated when there is somewhere to put the
            // normalised result, which is why `ASN1_TIME_check` does not reject a
            // value whose offset would move the day number below zero.
            if !tm.is_null() {
                if i == end {
                    offset = n.wrapping_mul(3600);
                } else if i == end + 1 {
                    offset = offset.wrapping_add(n.wrapping_mul(60));
                }
            }
            o += 1;
            i += 1;
        }
        if offset != 0 {
            let secs = c_long::from(offset.wrapping_mul(offsign));
            // SAFETY: `tmp` is a live local and `secs` is an integer offset.
            if unsafe { OPENSSL_gmtime_adj(&mut tmp, 0, secs) } == 0 {
                return 0;
            }
        }
    } else {
        return 0;
    }

    if o == l as usize {
        if !tm.is_null() {
            // SAFETY: the caller's contract makes `tm` writable.
            unsafe { *tm = tmp };
        }
        return 1;
    }
    0
}

/// The authority's `err:` label of `ossl_asn1_time_from_tm`.
///
/// `tmps` is the value under construction and `s` the caller's; they are the same
/// pointer when the caller supplied one, and only a value this function allocated
/// itself is released.
///
/// # Safety
///
/// `tmps` must be null or a live string; `s` must be the caller's own pointer.
unsafe fn from_tm_fail(tmps: *mut Asn1String, s: *mut Asn1String) -> *mut Asn1String {
    if tmps != s {
        // SAFETY: `tmps` was allocated by this function and is not owned
        // elsewhere; `ASN1_STRING_free` accepts null.
        unsafe { ASN1_STRING_free(tmps) };
    }
    core::ptr::null_mut()
}

/// `ASN1_TIME *ossl_asn1_time_from_tm(ASN1_TIME *s, struct tm *ts, int type)`
///
/// Renders a `struct tm` back into a time string. `type` of `V_ASN1_UNDEF` picks
/// the syntax from the year; `V_ASN1_UTCTIME` additionally *requires* the year to
/// be inside the 1950-2049 window, so a caller cannot be given a UTCTime that
/// cannot be parsed.
///
/// The buffer is 20 bytes and the rendered string is 19, so `BIO_snprintf`'s
/// return value — the length it *would* have written — is what becomes `length`.
/// That is why an over-long year truncates silently: the content is what fits and
/// the length is a number one too large for it.
///
/// # Safety
///
/// `s` must be null or a live time string; `ts` must be a readable `struct tm`.
pub(crate) unsafe fn ossl_asn1_time_from_tm(
    s: *mut Asn1String,
    ts: *mut Tm,
    type_in: c_int,
) -> *mut Asn1String {
    guard_ffi(core::ptr::null_mut(), || {
        // SAFETY: the caller's contract makes `ts` readable; a null `ts` faults
        // upstream and answers null here.
        let Some(t) = (unsafe { ts.as_ref() }) else {
            return core::ptr::null_mut();
        };
        let mut type_ = type_in;
        if type_ == V_ASN1_UNDEF {
            type_ = if is_utc(t.tm_year) {
                V_ASN1_UTCTIME
            } else {
                V_ASN1_GENERALIZEDTIME
            };
        } else if type_ == V_ASN1_UTCTIME {
            if !is_utc(t.tm_year) {
                return core::ptr::null_mut();
            }
        } else if type_ != V_ASN1_GENERALIZEDTIME {
            return core::ptr::null_mut();
        }

        let tmps = if s.is_null() { ASN1_STRING_new() } else { s };
        if tmps.is_null() {
            return core::ptr::null_mut();
        }

        const LEN: usize = 20;
        // SAFETY: `tmps` is live and uniquely owned; a null data pointer with a
        // non-negative length only sizes the buffer.
        if unsafe { ASN1_STRING_set(tmps, core::ptr::null::<c_void>(), LEN as c_int) } == 0 {
            // SAFETY: the caller's contract is `from_tm_fail`'s.
            return unsafe { from_tm_fail(tmps, s) };
        }
        // SAFETY: `tmps` is live and uniquely owned.
        unsafe { (*tmps).type_ = type_ };
        // SAFETY: the set above succeeded, so `data` owns `LEN + 1` bytes.
        let p = unsafe { (*tmps).data };

        if t.tm_mon > c_int::MAX - 1 {
            // SAFETY: the caller's contract is `from_tm_fail`'s.
            return unsafe { from_tm_fail(tmps, s) };
        }

        let n = if type_ == V_ASN1_GENERALIZEDTIME {
            if t.tm_year > c_int::MAX - 1900 {
                // SAFETY: the caller's contract is `from_tm_fail`'s.
                return unsafe { from_tm_fail(tmps, s) };
            }
            // SAFETY: `p` owns `LEN + 1` bytes and the format matches the
            // arguments.
            unsafe {
                BIO_snprintf(
                    p.cast::<c_char>(),
                    LEN,
                    c"%04d%02d%02d%02d%02d%02dZ".as_ptr(),
                    t.tm_year.wrapping_add(1900),
                    t.tm_mon.wrapping_add(1),
                    t.tm_mday,
                    t.tm_hour,
                    t.tm_min,
                    t.tm_sec,
                )
            }
        } else {
            // SAFETY: as above; the year is taken modulo 100 as the authority
            // does, which is a truncating remainder rather than a modulus.
            unsafe {
                BIO_snprintf(
                    p.cast::<c_char>(),
                    LEN,
                    c"%02d%02d%02d%02d%02d%02dZ".as_ptr(),
                    t.tm_year.wrapping_rem(100),
                    t.tm_mon.wrapping_add(1),
                    t.tm_mday,
                    t.tm_hour,
                    t.tm_min,
                    t.tm_sec,
                )
            }
        };
        // SAFETY: `tmps` is live and uniquely owned.
        unsafe { (*tmps).length = n };
        tmps
    })
}

// ---------------------------------------------------------------------------
// ASN1_UTCTIME — a_utctm.c
// ---------------------------------------------------------------------------

/// `int ossl_asn1_utctime_to_tm(struct tm *tm, const ASN1_UTCTIME *d)`
///
/// The type guard is the whole of it: a `GENERALIZEDTIME` handed to a UTCTime
/// entry point is rejected before the parser sees it.
///
/// # Safety
///
/// `d` must be null or a live `ASN1_UTCTIME`; `tm` must be null or writable.
pub(crate) unsafe fn ossl_asn1_utctime_to_tm(tm: *mut Tm, d: *const Asn1String) -> c_int {
    // SAFETY: the caller's contract makes `d` readable when non-null.
    let Some(s) = (unsafe { as_str(d) }) else {
        return 0;
    };
    if s.type_ != V_ASN1_UTCTIME {
        return 0;
    }
    // SAFETY: the caller's contract is `ossl_asn1_time_to_tm`'s.
    unsafe { ossl_asn1_time_to_tm(tm, d) }
}

/// The `(string, out)` form of [`ossl_asn1_utctime_to_tm`], so that the two
/// `_cmp_time_t` bodies can share one argument order.
///
/// # Safety
///
/// As [`ossl_asn1_utctime_to_tm`], with the two arguments exchanged.
unsafe extern "C" fn utctime_to_tm(s: *const Asn1String, tm: *mut Tm) -> c_int {
    // SAFETY: the caller's contract is `ossl_asn1_utctime_to_tm`'s.
    unsafe { ossl_asn1_utctime_to_tm(tm, s) }
}

/// `int ASN1_UTCTIME_check(const ASN1_UTCTIME *d)`
///
/// # Safety
///
/// `d` must be null or live.
#[no_mangle]
pub unsafe extern "C" fn ASN1_UTCTIME_check(d: *const Asn1String) -> c_int {
    // SAFETY: the caller's contract is `ossl_asn1_utctime_to_tm`'s.
    unsafe { ossl_asn1_utctime_to_tm(core::ptr::null_mut(), d) }
}

/// `int ASN1_GENERALIZEDTIME_check(const ASN1_GENERALIZEDTIME *d)`
///
/// The authority spells this through a `static` wrapper,
/// `asn1_generalizedtime_to_tm`, whose only difference from the UTCTime one is
/// the type it guards on.
///
/// # Safety
///
/// `d` must be null or live.
#[no_mangle]
pub unsafe extern "C" fn ASN1_GENERALIZEDTIME_check(d: *const Asn1String) -> c_int {
    // SAFETY: the caller's contract makes `d` readable when non-null.
    let Some(s) = (unsafe { as_str(d) }) else {
        return 0;
    };
    if s.type_ != V_ASN1_GENERALIZEDTIME {
        return 0;
    }
    // SAFETY: the caller's contract is `ossl_asn1_time_to_tm`'s.
    unsafe { ossl_asn1_time_to_tm(core::ptr::null_mut(), d) }
}

/// `ASN1_UTCTIME *ASN1_UTCTIME_dup(const ASN1_UTCTIME *x)`
///
/// # Safety
///
/// `x` must be null or a live `ASN1_UTCTIME`.
#[no_mangle]
pub unsafe extern "C" fn ASN1_UTCTIME_dup(x: *const Asn1String) -> *mut Asn1String {
    // SAFETY: `ASN1_UTCTIME_it()` answers the item for this type, and the
    // caller's contract makes `x` a value of it.
    unsafe { ASN1_item_dup(ASN1_UTCTIME_it(), x.cast()).cast() }
}

/// `ASN1_GENERALIZEDTIME *ASN1_GENERALIZEDTIME_dup(const ASN1_GENERALIZEDTIME *x)`
///
/// # Safety
///
/// `x` must be null or a live `ASN1_GENERALIZEDTIME`.
#[no_mangle]
pub unsafe extern "C" fn ASN1_GENERALIZEDTIME_dup(x: *const Asn1String) -> *mut Asn1String {
    // SAFETY: `ASN1_GENERALIZEDTIME_it()` answers the item for this type, and
    // the caller's contract makes `x` a value of it.
    unsafe { ASN1_item_dup(ASN1_GENERALIZEDTIME_it(), x.cast()).cast() }
}

/// `ASN1_TIME *ASN1_TIME_dup(const ASN1_TIME *x)`
///
/// The MSTRING item, so the duplicate keeps whatever syntax the original was.
///
/// # Safety
///
/// `x` must be null or a live `ASN1_TIME`.
#[no_mangle]
pub unsafe extern "C" fn ASN1_TIME_dup(x: *const Asn1String) -> *mut Asn1String {
    // SAFETY: `ASN1_TIME_it()` answers the item for this type, and the caller's
    // contract makes `x` a value of it.
    unsafe { ASN1_item_dup(ASN1_TIME_it(), x.cast()).cast() }
}

/// The shared body of the two `_set_string` constructors.
///
/// Builds a stack time string over the caller's buffer, checks it, and copies it
/// into `s` only if `s` is non-null. A null `s` therefore *validates* the string,
/// which is how `ASN1_TIME_set_string` chooses between the two syntaxes.
///
/// The `INT_MAX` test is the authority's own: a string that long cannot be an
/// `ASN1_STRING`, whose length is an `int`.
///
/// # Safety
///
/// `str` must be a NUL-terminated string; `s` must be null or a live time string
/// of the type `want` names.
unsafe fn set_string_body(
    s: *mut Asn1String,
    str_: *const c_char,
    want: c_int,
    check: unsafe extern "C" fn(*const Asn1String) -> c_int,
) -> c_int {
    // SAFETY: the caller's contract makes `str` a NUL-terminated string.
    let len = unsafe { OPENSSL_strnlen(str_, usize::MAX) };
    if len >= c_int::MAX as usize {
        return 0;
    }
    let t = stack_string(want, str_.cast_mut().cast::<c_uchar>(), len as c_int, 0);
    // SAFETY: `t` is a live local and `check` is the authority's checker for
    // `want`.
    if unsafe { check(&t) } == 0 {
        return 0;
    }
    if !s.is_null() {
        // SAFETY: `s` is live and uniquely owned, and `t` is readable.
        if unsafe { ASN1_STRING_copy(s, &t) } == 0 {
            return 0;
        }
    }
    1
}

/// `int ASN1_UTCTIME_set_string(ASN1_UTCTIME *s, const char *str)`
///
/// # Safety
///
/// `str` must be a NUL-terminated string; `s` must be null or a live
/// `ASN1_UTCTIME`.
#[no_mangle]
pub unsafe extern "C" fn ASN1_UTCTIME_set_string(s: *mut Asn1String, str_: *const c_char) -> c_int {
    guard_ffi(0, || {
        // SAFETY: the caller's contract is `set_string_body`'s.
        unsafe { set_string_body(s, str_, V_ASN1_UTCTIME, ASN1_UTCTIME_check) }
    })
}

/// `int ASN1_GENERALIZEDTIME_set_string(ASN1_GENERALIZEDTIME *s, const char *str)`
///
/// # Safety
///
/// `str` must be a NUL-terminated string; `s` must be null or a live
/// `ASN1_GENERALIZEDTIME`.
#[no_mangle]
pub unsafe extern "C" fn ASN1_GENERALIZEDTIME_set_string(
    s: *mut Asn1String,
    str_: *const c_char,
) -> c_int {
    guard_ffi(0, || {
        // SAFETY: the caller's contract is `set_string_body`'s.
        unsafe { set_string_body(s, str_, V_ASN1_GENERALIZEDTIME, ASN1_GENERALIZEDTIME_check) }
    })
}

/// The shared body of the four `_adj` constructors.
///
/// All four are the same three steps — convert the `time_t`, apply the offset if
/// there is one, render — and differ only in the type they render and whether a
/// failed conversion raises. `ASN1_TIME_adj` raises `ASN1_R_ERROR_GETTING_TIME`;
/// the two typed ones do not, which is why the flag is a parameter.
///
/// # Safety
///
/// `s` must be null or a live time string of the type `type_` names.
unsafe fn adj_body(
    s: *mut Asn1String,
    t: TimeT,
    offset_day: c_int,
    offset_sec: c_long,
    type_: c_int,
    raise: bool,
) -> *mut Asn1String {
    let mut data = zeroed_tm();
    // SAFETY: `data` is a live local.
    let ts = unsafe { OPENSSL_gmtime(&t, &mut data) };
    if ts.is_null() {
        if raise {
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&err_sites::A_TIME_336) };
        }
        return core::ptr::null_mut();
    }
    if offset_day != 0 || offset_sec != 0 {
        // SAFETY: `ts` is the live local `data`.
        if unsafe { OPENSSL_gmtime_adj(ts, offset_day, offset_sec) } == 0 {
            return core::ptr::null_mut();
        }
    }
    // SAFETY: `ts` is `&mut data` and live.
    unsafe { ossl_asn1_time_from_tm(s, ts, type_) }
}

/// `ASN1_UTCTIME *ASN1_UTCTIME_set(ASN1_UTCTIME *s, time_t t)`
///
/// # Safety
///
/// `s` must be null or a live `ASN1_UTCTIME`.
#[no_mangle]
pub unsafe extern "C" fn ASN1_UTCTIME_set(s: *mut Asn1String, t: TimeT) -> *mut Asn1String {
    // SAFETY: the caller's contract is `adj_body`'s.
    unsafe { adj_body(s, t, 0, 0, V_ASN1_UTCTIME, false) }
}

/// `ASN1_UTCTIME *ASN1_UTCTIME_adj(ASN1_UTCTIME *s, time_t t, int offset_day,
/// long offset_sec)`
///
/// # Safety
///
/// `s` must be null or a live `ASN1_UTCTIME`.
#[no_mangle]
pub unsafe extern "C" fn ASN1_UTCTIME_adj(
    s: *mut Asn1String,
    t: TimeT,
    offset_day: c_int,
    offset_sec: c_long,
) -> *mut Asn1String {
    // SAFETY: the caller's contract is `adj_body`'s.
    unsafe { adj_body(s, t, offset_day, offset_sec, V_ASN1_UTCTIME, false) }
}

/// `ASN1_GENERALIZEDTIME *ASN1_GENERALIZEDTIME_set(ASN1_GENERALIZEDTIME *s,
/// time_t t)`
///
/// # Safety
///
/// `s` must be null or a live `ASN1_GENERALIZEDTIME`.
#[no_mangle]
pub unsafe extern "C" fn ASN1_GENERALIZEDTIME_set(s: *mut Asn1String, t: TimeT) -> *mut Asn1String {
    // SAFETY: the caller's contract is `adj_body`'s.
    unsafe { adj_body(s, t, 0, 0, V_ASN1_GENERALIZEDTIME, false) }
}

/// `ASN1_GENERALIZEDTIME *ASN1_GENERALIZEDTIME_adj(ASN1_GENERALIZEDTIME *s,
/// time_t t, int offset_day, long offset_sec)`
///
/// # Safety
///
/// `s` must be null or a live `ASN1_GENERALIZEDTIME`.
#[no_mangle]
pub unsafe extern "C" fn ASN1_GENERALIZEDTIME_adj(
    s: *mut Asn1String,
    t: TimeT,
    offset_day: c_int,
    offset_sec: c_long,
) -> *mut Asn1String {
    // SAFETY: the caller's contract is `adj_body`'s.
    unsafe { adj_body(s, t, offset_day, offset_sec, V_ASN1_GENERALIZEDTIME, false) }
}

/// The shared body of the three `_cmp_time_t` functions.
///
/// `-2` is the authority's "could not compare" answer and is distinct from `-1`:
/// a caller that only tests the sign cannot tell a parse failure from a value
/// that is earlier, which is why it is reproduced rather than tightened.
///
/// # Safety
///
/// `to_tm` must be a converter of the string being compared.
unsafe fn cmp_time_t_body(
    s: *const Asn1String,
    t: TimeT,
    to_tm: unsafe extern "C" fn(*const Asn1String, *mut Tm) -> c_int,
) -> c_int {
    let mut stm = zeroed_tm();
    // SAFETY: `stm` is a live local and `s` is the caller's string.
    if unsafe { to_tm(s, &mut stm) } == 0 {
        return -2;
    }
    let mut ttm = zeroed_tm();
    // SAFETY: `ttm` is a live local.
    if unsafe { OPENSSL_gmtime(&t, &mut ttm) }.is_null() {
        return -2;
    }
    let (mut day, mut sec) = (0, 0);
    // SAFETY: both `tm`s and both outputs are live locals.
    if unsafe { OPENSSL_gmtime_diff(&mut day, &mut sec, &ttm, &stm) } == 0 {
        return -2;
    }
    if day > 0 || sec > 0 {
        return 1;
    }
    if day < 0 || sec < 0 {
        return -1;
    }
    0
}

/// `int ASN1_UTCTIME_cmp_time_t(const ASN1_UTCTIME *s, time_t t)`
///
/// # Safety
///
/// `s` must be null or a live `ASN1_UTCTIME`.
#[no_mangle]
pub unsafe extern "C" fn ASN1_UTCTIME_cmp_time_t(s: *const Asn1String, t: TimeT) -> c_int {
    // SAFETY: the caller's contract is `cmp_time_t_body`'s, with the UTCTime
    // type-guarded converter.
    unsafe { cmp_time_t_body(s, t, utctime_to_tm) }
}

/// The shared body of the two `_print` wrappers: a type guard, then the printer.
///
/// # Safety
///
/// `bp` must be a live BIO; `tm` must be null or a live string.
unsafe fn print_guarded(bp: *mut Bio, tm: *const Asn1String, want: c_int) -> c_int {
    // SAFETY: the caller's contract makes `tm` readable when non-null.
    let Some(s) = (unsafe { as_str(tm) }) else {
        return 0;
    };
    if s.type_ != want {
        return 0;
    }
    // SAFETY: the caller's contract is `ASN1_TIME_print`'s.
    unsafe { ASN1_TIME_print(bp, tm) }
}

/// `int ASN1_UTCTIME_print(BIO *bp, const ASN1_UTCTIME *tm)`
///
/// # Safety
///
/// `bp` must be a live BIO; `tm` must be null or a live `ASN1_UTCTIME`.
#[no_mangle]
pub unsafe extern "C" fn ASN1_UTCTIME_print(bp: *mut Bio, tm: *const Asn1String) -> c_int {
    // SAFETY: the caller's contract is `print_guarded`'s.
    unsafe { print_guarded(bp, tm, V_ASN1_UTCTIME) }
}

/// `int ASN1_GENERALIZEDTIME_print(BIO *bp, const ASN1_GENERALIZEDTIME *tm)`
///
/// # Safety
///
/// `bp` must be a live BIO; `tm` must be null or a live `ASN1_GENERALIZEDTIME`.
#[no_mangle]
pub unsafe extern "C" fn ASN1_GENERALIZEDTIME_print(bp: *mut Bio, tm: *const Asn1String) -> c_int {
    // SAFETY: the caller's contract is `print_guarded`'s.
    unsafe { print_guarded(bp, tm, V_ASN1_GENERALIZEDTIME) }
}

// ---------------------------------------------------------------------------
// ASN1_TIME — a_time.c
// ---------------------------------------------------------------------------

/// `ASN1_TIME *ASN1_TIME_set(ASN1_TIME *s, time_t t)`
///
/// # Safety
///
/// `s` must be null or a live `ASN1_TIME`.
#[no_mangle]
pub unsafe extern "C" fn ASN1_TIME_set(s: *mut Asn1String, t: TimeT) -> *mut Asn1String {
    // SAFETY: the caller's contract is `adj_body`'s, with `V_ASN1_UNDEF` so the
    // syntax follows the year.
    unsafe { adj_body(s, t, 0, 0, V_ASN1_UNDEF, true) }
}

/// `ASN1_TIME *ASN1_TIME_adj(ASN1_TIME *s, time_t t, int offset_day,
/// long offset_sec)`
///
/// # Safety
///
/// `s` must be null or a live `ASN1_TIME`.
#[no_mangle]
pub unsafe extern "C" fn ASN1_TIME_adj(
    s: *mut Asn1String,
    t: TimeT,
    offset_day: c_int,
    offset_sec: c_long,
) -> *mut Asn1String {
    // SAFETY: the caller's contract is `adj_body`'s.
    unsafe { adj_body(s, t, offset_day, offset_sec, V_ASN1_UNDEF, true) }
}

/// `int ASN1_TIME_check(const ASN1_TIME *t)`
///
/// Dispatches on the string's own type, so a value with any other type is a
/// failure rather than a parse attempt.
///
/// # Safety
///
/// `t` must be null or live.
#[no_mangle]
pub unsafe extern "C" fn ASN1_TIME_check(t: *const Asn1String) -> c_int {
    // SAFETY: the caller's contract makes `t` readable when non-null.
    let Some(s) = (unsafe { as_str(t) }) else {
        return 0;
    };
    if s.type_ == V_ASN1_GENERALIZEDTIME {
        // SAFETY: the caller's contract is `ASN1_GENERALIZEDTIME_check`'s.
        return unsafe { ASN1_GENERALIZEDTIME_check(t) };
    } else if s.type_ == V_ASN1_UTCTIME {
        // SAFETY: the caller's contract is `ASN1_UTCTIME_check`'s.
        return unsafe { ASN1_UTCTIME_check(t) };
    }
    0
}

/// `ASN1_GENERALIZEDTIME *ASN1_TIME_to_generalizedtime(const ASN1_TIME *t,
/// ASN1_GENERALIZEDTIME **out)`
///
/// `out` is both an input and an output: when non-null the value it points at is
/// reused as the destination, and it is only written back on success. A caller
/// that passes the address of its own pointer therefore keeps the old value when
/// the conversion fails.
///
/// # Safety
///
/// `t` must be null or a live `ASN1_TIME`; `out` must be null or point at a
/// writable `ASN1_GENERALIZEDTIME *`.
#[no_mangle]
pub unsafe extern "C" fn ASN1_TIME_to_generalizedtime(
    t: *const Asn1String,
    out: *mut *mut Asn1String,
) -> *mut Asn1String {
    guard_ffi(core::ptr::null_mut(), || {
        let mut tm = zeroed_tm();
        // SAFETY: `tm` is a live local and `t` is the caller's string.
        if unsafe { ASN1_TIME_to_tm(t, &mut tm) } == 0 {
            return core::ptr::null_mut();
        }
        let mut ret: *mut Asn1String = core::ptr::null_mut();
        if !out.is_null() {
            // SAFETY: the caller's contract makes `out` readable.
            ret = unsafe { *out };
        }
        // SAFETY: `ret` is null or the caller's destination, and `tm` is live.
        ret = unsafe { ossl_asn1_time_from_tm(ret, &mut tm, V_ASN1_GENERALIZEDTIME) };
        if !out.is_null() && !ret.is_null() {
            // SAFETY: the caller's contract makes `out` writable.
            unsafe { *out = ret };
        }
        ret
    })
}

/// `int ASN1_TIME_set_string(ASN1_TIME *s, const char *str)`
///
/// Try UTCTime, then GeneralizedTime. The order is observable for a string both
/// syntaxes would accept.
///
/// # Safety
///
/// `str` must be a NUL-terminated string; `s` must be null or a live
/// `ASN1_TIME`.
#[no_mangle]
pub unsafe extern "C" fn ASN1_TIME_set_string(s: *mut Asn1String, str_: *const c_char) -> c_int {
    guard_ffi(0, || {
        // SAFETY: the caller's contract is `ASN1_UTCTIME_set_string`'s.
        if unsafe { ASN1_UTCTIME_set_string(s, str_) } != 0 {
            return 1;
        }
        // SAFETY: the caller's contract is `ASN1_GENERALIZEDTIME_set_string`'s.
        unsafe { ASN1_GENERALIZEDTIME_set_string(s, str_) }
    })
}

/// `int ASN1_TIME_set_string_X509(ASN1_TIME *s, const char *str)`
///
/// The RFC 5280 profile, plus one reformatting step: a `YYYYMMDDHHMMSSZ` string
/// whose year falls inside the UTCTime window is *shortened* to `YYMMDDHHMMSSZ`
/// before being copied, because RFC 5280 requires the shorter form there. The
/// shortened buffer is a fresh allocation and is released before returning, which
/// is why the `t.data != str` test guards the free rather than a flag.
///
/// # Safety
///
/// `str` must be a NUL-terminated string; `s` must be null or a live
/// `ASN1_TIME`.
#[no_mangle]
pub unsafe extern "C" fn ASN1_TIME_set_string_X509(
    s: *mut Asn1String,
    str_: *const c_char,
) -> c_int {
    guard_ffi(0, || {
        // SAFETY: the caller's contract makes `str` a NUL-terminated string.
        let len = unsafe { OPENSSL_strnlen(str_, usize::MAX) };
        if len >= c_int::MAX as usize {
            return 0;
        }
        let mut t = stack_string(
            V_ASN1_UTCTIME,
            str_.cast_mut().cast::<c_uchar>(),
            len as c_int,
            ASN1_STRING_FLAG_X509_TIME,
        );
        let mut tm = zeroed_tm();

        // SAFETY: `t` is a live local.
        if unsafe { ASN1_TIME_check(&t) } == 0 {
            t.type_ = V_ASN1_GENERALIZEDTIME;
            // SAFETY: `t` is a live local.
            if unsafe { ASN1_TIME_check(&t) } == 0 {
                return 0;
            }
        }

        if !s.is_null() && t.type_ == V_ASN1_GENERALIZEDTIME {
            // SAFETY: `t` is a live local and `tm` is a live local.
            if unsafe { ossl_asn1_time_to_tm(&mut tm, &t) } == 0 {
                return 0;
            }
            if is_utc(tm.tm_year) {
                t.length -= 2;
                // SAFETY: `CRYPTO_zalloc` answers null or that many zeroed bytes.
                t.data =
                    CRYPTO_zalloc((t.length + 1) as usize, FILE.as_ptr(), LINE).cast::<c_uchar>();
                if t.data.is_null() {
                    return 0;
                }
                // SAFETY: `t.data` owns `t.length + 1` bytes and the source is
                // the caller's string, which is at least `t.length + 2` bytes
                // long because it was just parsed as a GeneralizedTime.
                unsafe {
                    core::ptr::copy_nonoverlapping(
                        str_.add(2).cast::<c_uchar>(),
                        t.data,
                        t.length as usize,
                    );
                }
                t.type_ = V_ASN1_UTCTIME;
            }
        }

        let mut rv = 0;
        if s.is_null() {
            rv = 1;
        } else {
            // SAFETY: `s` is live and uniquely owned, and `t` is readable.
            if unsafe { ASN1_STRING_copy(s, &t) } != 0 {
                rv = 1;
            }
        }

        if t.data != str_.cast_mut().cast::<c_uchar>() {
            // SAFETY: `t.data` came from this allocator on the only path that
            // reassigns it, and that path is also the only one on which it can
            // differ from `str`.
            unsafe { CRYPTO_free(t.data.cast(), FILE.as_ptr(), LINE) };
        }
        rv
    })
}

/// `int ASN1_TIME_to_tm(const ASN1_TIME *s, struct tm *tm)`
///
/// A null `s` means "now": the authority reads the wall clock, zeroes the output
/// and fills it from UTC. That is documented and is what makes
/// `ASN1_TIME_diff(NULL, to)` mean "from now until `to`".
///
/// # Safety
///
/// `s` must be null or live; `tm` must be writable.
#[no_mangle]
pub unsafe extern "C" fn ASN1_TIME_to_tm(s: *const Asn1String, tm: *mut Tm) -> c_int {
    guard_ffi(0, || {
        if s.is_null() {
            let mut now_t: TimeT = 0;
            // SAFETY: `now_t` is a live local.
            unsafe { time(&mut now_t) };
            if tm.is_null() {
                // Upstream faults here; see `docs/SECURITY_DIVERGENCE_POLICY.md`.
                return 0;
            }
            // SAFETY: the caller's contract makes `tm` writable.
            unsafe { core::ptr::write_bytes(tm, 0, 1) };
            // SAFETY: `now_t` is a live local and `tm` is writable.
            if !unsafe { OPENSSL_gmtime(&now_t, tm) }.is_null() {
                return 1;
            }
            return 0;
        }
        // SAFETY: the caller's contract is `ossl_asn1_time_to_tm`'s.
        unsafe { ossl_asn1_time_to_tm(tm, s) }
    })
}

/// `int ASN1_TIME_diff(int *pday, int *psec, const ASN1_TIME *from,
/// const ASN1_TIME *to)`
///
/// The argument order is `from` then `to` and the answer is `to - from`, which is
/// the opposite of `ASN1_TIME_compare`'s argument order with the same body.
/// Reproduced as written, because that inversion is observable.
///
/// # Safety
///
/// `from` and `to` must be null or live; `pday` and `psec` must be null or
/// writable.
#[no_mangle]
pub unsafe extern "C" fn ASN1_TIME_diff(
    pday: *mut c_int,
    psec: *mut c_int,
    from: *const Asn1String,
    to: *const Asn1String,
) -> c_int {
    guard_ffi(0, || {
        let mut tm_from = zeroed_tm();
        let mut tm_to = zeroed_tm();
        // SAFETY: `tm_from` is a live local and `from` is the caller's string.
        if unsafe { ASN1_TIME_to_tm(from, &mut tm_from) } == 0 {
            return 0;
        }
        // SAFETY: `tm_to` is a live local and `to` is the caller's string.
        if unsafe { ASN1_TIME_to_tm(to, &mut tm_to) } == 0 {
            return 0;
        }
        // SAFETY: both `tm`s and both outputs are live locals; a null output is
        // allowed and simply not written.
        unsafe { OPENSSL_gmtime_diff(pday, psec, &tm_from, &tm_to) }
    })
}

/// `int ASN1_TIME_cmp_time_t(const ASN1_TIME *s, time_t t)`
///
/// Unlike the UTCTime one, this accepts either syntax: the converter it passes is
/// `ASN1_TIME_to_tm`, which dispatches on the type. A null `s` therefore compares
/// *now* against `t`, because that is what `ASN1_TIME_to_tm` does with null.
///
/// # Safety
///
/// `s` must be null or live.
#[no_mangle]
pub unsafe extern "C" fn ASN1_TIME_cmp_time_t(s: *const Asn1String, t: TimeT) -> c_int {
    // SAFETY: the caller's contract is `cmp_time_t_body`'s, with the
    // type-dispatching converter.
    unsafe { cmp_time_t_body(s, t, ASN1_TIME_to_tm) }
}

/// `int ASN1_TIME_normalize(ASN1_TIME *t)`
///
/// Re-parses and re-renders in place, which is how a GeneralizedTime inside the
/// UTCTime window becomes a UTCTime. A value that does not parse is left alone.
///
/// # Safety
///
/// `t` must be null or a live `ASN1_TIME`.
#[no_mangle]
pub unsafe extern "C" fn ASN1_TIME_normalize(t: *mut Asn1String) -> c_int {
    guard_ffi(0, || {
        if t.is_null() {
            return 0;
        }
        let mut tm = zeroed_tm();
        // SAFETY: `tm` is a live local and `t` is the caller's string.
        if unsafe { ASN1_TIME_to_tm(t, &mut tm) } == 0 {
            return 0;
        }
        // SAFETY: `t` is live and uniquely owned, and `tm` is live.
        if unsafe { ossl_asn1_time_from_tm(t, &mut tm, V_ASN1_UNDEF) }.is_null() {
            return 0;
        }
        1
    })
}

/// `int ASN1_TIME_compare(const ASN1_TIME *a, const ASN1_TIME *b)`
///
/// `ASN1_TIME_diff(&day, &sec, b, a)` — the arguments are reversed relative to
/// `ASN1_TIME_diff`'s own so that the answer is `a - b`. `-2` means the
/// comparison could not be made.
///
/// # Safety
///
/// `a` and `b` must be null or live.
#[no_mangle]
pub unsafe extern "C" fn ASN1_TIME_compare(a: *const Asn1String, b: *const Asn1String) -> c_int {
    guard_ffi(0, || {
        let (mut day, mut sec) = (0, 0);
        // SAFETY: both outputs are live locals and both strings are the
        // caller's.
        if unsafe { ASN1_TIME_diff(&mut day, &mut sec, b, a) } == 0 {
            return -2;
        }
        if day > 0 || sec > 0 {
            return 1;
        }
        if day < 0 || sec < 0 {
            return -1;
        }
        0
    })
}

/// `int ossl_asn1_time_print_ex(BIO *bp, const ASN1_TIME *tm,
/// unsigned long flags)`
///
/// Three answers, not two: `1` on success, `-1` when the value does not parse
/// (after writing `Bad time value`), and `0` when the BIO write failed. The
/// fractional-seconds form is GeneralizedTime-only and is only recognised when
/// the fraction point is exactly at offset 14 of a string longer than 15 bytes.
///
/// This is an internal symbol: `include/crypto/asn1.h` declares it and the
/// authority's DSO does not export it.
///
/// # Safety
///
/// `bp` must be a live BIO; `tm` must be null or live.
pub(crate) unsafe fn ossl_asn1_time_print_ex(
    bp: *mut Bio,
    tm: *const Asn1String,
    flags: c_ulong,
) -> c_int {
    guard_ffi(0, || {
        let mut stm = zeroed_tm();
        // SAFETY: `stm` is a live local and `tm` is the caller's string.
        if unsafe { ossl_asn1_time_to_tm(&mut stm, tm) } == 0 {
            // SAFETY: the caller's contract makes `bp` a live BIO.
            let wrote = unsafe { BIO_write(bp, c"Bad time value".as_ptr().cast(), 14) };
            return if wrote != 0 { -1 } else { 0 };
        }
        // SAFETY: the conversion succeeded, so `tm` is readable.
        let Some(s) = (unsafe { as_str(tm) }) else {
            return 0;
        };
        let l = s.length;
        let v = s.data;

        if s.type_ == V_ASN1_GENERALIZEDTIME && l > 15 && !v.is_null() {
            let mut f: *mut c_char = core::ptr::null_mut();
            let mut f_len: c_int = 0;

            // SAFETY: `l > 15` puts offset 14 inside the content.
            if unsafe { *v.add(14) } == b'.' {
                // SAFETY: `l > 15` puts offset 15 at or before the last byte.
                f = unsafe { v.add(15) }.cast::<c_char>();
                f_len = 0;
                while 15 + f_len < l {
                    // SAFETY: `15 + f_len < l` puts the read inside the content;
                    // the value is promoted from `char`, as the authority's
                    // `ossl_ascii_isdigit(f[f_len])` does.
                    if !ossl_isdigit(c_int::from(unsafe { *f.add(f_len as usize) })) {
                        break;
                    }
                    f_len += 1;
                }
            }

            if f_len > 0 {
                if (flags & ASN1_DTFLGS_TYPE_MASK) == ASN1_DTFLGS_ISO8601 {
                    // SAFETY: `bp` is a live BIO and the format matches the
                    // arguments, including the `int` precision for `%.*s`.
                    let n = unsafe {
                        BIO_printf(
                            bp,
                            c"%4d-%02d-%02d %02d:%02d:%02d.%.*sZ".as_ptr(),
                            stm.tm_year + 1900,
                            stm.tm_mon + 1,
                            stm.tm_mday,
                            stm.tm_hour,
                            stm.tm_min,
                            stm.tm_sec,
                            f_len,
                            f,
                        )
                    };
                    return if n > 0 { 1 } else { 0 };
                }
                // SAFETY: as above.
                let n = unsafe {
                    BIO_printf(
                        bp,
                        c"%s %2d %02d:%02d:%02d.%.*s %d GMT".as_ptr(),
                        ASN1_MON[stm.tm_mon as usize].as_ptr(),
                        stm.tm_mday,
                        stm.tm_hour,
                        stm.tm_min,
                        stm.tm_sec,
                        f_len,
                        f,
                        stm.tm_year + 1900,
                    )
                };
                return if n > 0 { 1 } else { 0 };
            }
        }

        if (flags & ASN1_DTFLGS_TYPE_MASK) == ASN1_DTFLGS_ISO8601 {
            // SAFETY: `bp` is a live BIO and the format matches the arguments.
            let n = unsafe {
                BIO_printf(
                    bp,
                    c"%4d-%02d-%02d %02d:%02d:%02dZ".as_ptr(),
                    stm.tm_year + 1900,
                    stm.tm_mon + 1,
                    stm.tm_mday,
                    stm.tm_hour,
                    stm.tm_min,
                    stm.tm_sec,
                )
            };
            return if n > 0 { 1 } else { 0 };
        }
        // SAFETY: as above.
        let n = unsafe {
            BIO_printf(
                bp,
                c"%s %2d %02d:%02d:%02d %d GMT".as_ptr(),
                ASN1_MON[stm.tm_mon as usize].as_ptr(),
                stm.tm_mday,
                stm.tm_hour,
                stm.tm_min,
                stm.tm_sec,
                stm.tm_year + 1900,
            )
        };
        if n > 0 {
            1
        } else {
            0
        }
    })
}

/// `int ASN1_TIME_print(BIO *bp, const ASN1_TIME *tm)`
///
/// Goes through the *public* `ASN1_TIME_print_ex`, not straight to the internal
/// printer, and so collapses its three-valued answer to an indicator. A caller
/// cannot therefore tell an unparseable value from a failing sink through this
/// entry point either.
///
/// # Safety
///
/// `bp` must be a live BIO; `tm` must be null or live.
#[no_mangle]
pub unsafe extern "C" fn ASN1_TIME_print(bp: *mut Bio, tm: *const Asn1String) -> c_int {
    // SAFETY: the caller's contract is `ASN1_TIME_print_ex`'s.
    unsafe { ASN1_TIME_print_ex(bp, tm, ASN1_DTFLGS_RFC822) }
}

/// `int ASN1_TIME_print_ex(BIO *bp, const ASN1_TIME *tm, unsigned long flags)`
///
/// Collapses the three-valued answer above to an indicator, so a caller using
/// this entry point cannot tell an unparseable value from a failing sink.
///
/// # Safety
///
/// `bp` must be a live BIO; `tm` must be null or live.
#[no_mangle]
pub unsafe extern "C" fn ASN1_TIME_print_ex(
    bp: *mut Bio,
    tm: *const Asn1String,
    flags: c_ulong,
) -> c_int {
    // SAFETY: the caller's contract is `ossl_asn1_time_print_ex`'s.
    if unsafe { ossl_asn1_time_print_ex(bp, tm, flags) } > 0 {
        1
    } else {
        0
    }
}
