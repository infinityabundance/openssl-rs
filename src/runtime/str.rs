//! `crypto/o_str.c` — the string and hex codecs `libcrypto` shares across every
//! subsystem, and the byte-comparison primitives the error paths rely on.
//!
//! ## Why this module is in Phase 3's family
//!
//! It was in **no** phase's symbol family. None of the prefixes any ledger listed
//! matched `OPENSSL_strlcpy`, `OPENSSL_strcasecmp`, `OPENSSL_hexstr2buf` or the
//! other eight exports here, so they were invisible to every obligation table —
//! the same defect class `docs/DECISIONS.md` D49 recorded for
//! `OPENSSL_INIT_*`, found this time by the ownership audit
//! (`forensics/tools/ownership_audit.py`) rather than by reading a header. The
//! CONF reader needs `OPENSSL_strlcpy`, `OPENSSL_strlcat` and
//! `OPENSSL_strcasecmp`, which is how it surfaced. The module is core runtime
//! surface, so it belongs to Phase 3; see D51.
//!
//! ## The two places where "obviously equivalent" is wrong
//!
//! * `OPENSSL_strcasecmp` is **not** `strcasecmp`. It lowercases through
//!   `ossl_tolower`, which is ASCII-only and, crucially, leaves bytes with the
//!   high bit set alone — and because `char` is signed on the admitted profile,
//!   those bytes reach the subtraction as *negative* integers. A locale-aware or
//!   `u8`-based comparison would return a different sign for inputs like `"\xC3"`
//!   against `"a"`, and the return value is observable.
//! * `OPENSSL_hexstr2buf`'s separator is a `char`, so a `sep` with the high bit
//!   set is negative and can never equal a byte of the input. The separator test
//!   is therefore an integer comparison, not a byte comparison.
//!
//! ## What is not here
//!
//! `crypto/o_str.c` also defines `ossl_hexstr2buf_sep`, `ossl_buf2hexstr_sep`
//! and `ossl_to_hex`; none is exported, so they are private functions of this
//! module. `openssl_strerror_r` is likewise internal and is not reproduced: it
//! exists to paper over the two `strerror_r` ABIs, and the admitted profile has
//! exactly one of them.

use core::ffi::{c_char, c_int, c_long, c_uchar, c_ulong, c_void};

use crate::ffi::guard_ffi;
use crate::runtime::err::err_sites::{
    O_STR_229, O_STR_235, O_STR_241, O_STR_270, O_STR_303, O_STR_315, O_STR_352,
};
use crate::runtime::err::raise_site;
use crate::runtime::mem::{CRYPTO_free, CRYPTO_malloc, CRYPTO_zalloc};

use crate::runtime::bio::sys;

/// `DEFAULT_SEPARATOR` — the `:` the two convenience entry points separate with.
const DEFAULT_SEPARATOR: c_char = b':' as c_char;

/// `ossl_tolower(c)` from `crypto/ctype.c`.
///
/// `ossl_toascii` is the identity on a non-EBCDIC platform, so this reduces to
/// the ASCII upper-case test and the `0x20` bit flip. A negative argument (which
/// is what a byte at or above `0x80` becomes once `char` is sign-extended into an
/// `int`) fails the test and is returned unchanged — that is the authority's
/// behaviour, not an oversight to be normalized away.
fn ossl_tolower(c: c_int) -> c_int {
    if (0x41..=0x5A).contains(&c) {
        c ^ 0x20
    } else {
        c
    }
}

/// The value a `char` from the authority's input contributes to a comparison:
/// sign-extended to `int`, as C's integer promotion does.
fn promoted(c: c_char) -> c_int {
    c_int::from(c)
}

/// `to_hex(buf, n, hexdig)` — two upper-case digits in `buf`, returning 2.
///
/// # Safety
/// `buf` must be writable for at least 2 bytes.
unsafe fn to_hex(buf: *mut c_char, n: u8) -> usize {
    const HEXDIG: &[u8; 16] = b"0123456789ABCDEF";
    // SAFETY: the caller guarantees room for two bytes.
    unsafe {
        *buf = HEXDIG[((n >> 4) & 0x0f) as usize] as c_char;
        *buf.add(1) = HEXDIG[(n & 0x0f) as usize] as c_char;
    }
    2
}

/// `size_t OPENSSL_strnlen(const char *str, size_t maxlen)`
///
/// Bounded `strlen`.
///
/// # Safety
/// `str` must be readable for `maxlen` bytes.
#[no_mangle]
pub unsafe extern "C" fn OPENSSL_strnlen(str_: *const c_char, maxlen: usize) -> usize {
    guard_ffi(0, || {
        let mut p = str_;
        let mut n = maxlen;
        while n != 0 {
            n -= 1;
            // SAFETY: `str` is readable for `maxlen` bytes and `n < maxlen`.
            if unsafe { *p } == 0 {
                break;
            }
            // SAFETY: still within the caller's `maxlen` bytes.
            p = unsafe { p.add(1) };
        }
        (p as usize) - (str_ as usize)
    })
}

/// `size_t OPENSSL_strlcpy(char *dst, const char *src, size_t size)`
///
/// Copies at most `size - 1` bytes, always terminates when `size > 0`, and
/// returns the length the copy *would* have had — the standard `strlcpy`
/// contract. Sizes are counted down rather than compared against an index
/// because a zero `size` cannot underflow that way.
///
/// # Safety
/// `dst` must be writable for `size` bytes; `src` must be NUL-terminated.
#[no_mangle]
pub unsafe extern "C" fn OPENSSL_strlcpy(
    dst: *mut c_char,
    src: *const c_char,
    size: usize,
) -> usize {
    guard_ffi(0, || {
        let mut size = size;
        let mut d = dst;
        let mut s = src;
        let mut l = 0usize;
        // SAFETY: `s` starts at `src`, which is NUL-terminated per the caller's
        // contract, and advances only while the byte read was non-zero, so it
        // never moves past the terminator.
        while size > 1 && unsafe { *s } != 0 {
            // SAFETY: `d` is within the caller's `size` bytes and `size > 1`.
            unsafe {
                *d = *s;
                d = d.add(1);
                s = s.add(1);
            }
            l += 1;
            size -= 1;
        }
        if size != 0 {
            // SAFETY: `size != 0` means `d` still points into `dst`.
            unsafe { *d = 0 };
        }
        // SAFETY: `src` is NUL-terminated per the caller's contract.
        l + unsafe { sys::strlen(s) }
    })
}

/// `size_t OPENSSL_strlcat(char *dst, const char *src, size_t size)`
///
/// Appends to whatever is already in `dst`, where `size` is the total size of
/// `dst`. Returns the length the result would have had. Note that a `dst` that
/// is not NUL-terminated within `size` consumes the whole budget and the append
/// copies nothing — `strlcpy` then writes the terminator into the final byte.
///
/// # Safety
/// `dst` must be readable and writable for `size` bytes; `src` must be
/// NUL-terminated.
#[no_mangle]
pub unsafe extern "C" fn OPENSSL_strlcat(
    dst: *mut c_char,
    src: *const c_char,
    size: usize,
) -> usize {
    guard_ffi(0, || {
        let mut size = size;
        let mut d = dst;
        let mut l = 0usize;
        // SAFETY: `d` starts at `dst`, readable for `size` bytes per the
        // caller's contract, and advances only within that budget and only
        // while the byte read was non-zero.
        while size > 0 && unsafe { *d } != 0 {
            size -= 1;
            // SAFETY: `d` is within the caller's `size` bytes and `size > 0`.
            d = unsafe { d.add(1) };
            l += 1;
        }
        // SAFETY: `d` is one past the last byte examined, inside `dst`; `src` is
        // NUL-terminated.
        l + unsafe { OPENSSL_strlcpy(d, src, size) }
    })
}

/// `int OPENSSL_strtoul(const char *str, char **endptr, int base, unsigned long *num)`
///
/// `strtoul` plus three extra rejection rules: a leading `-`, any `errno` the
/// conversion set, and — when the caller did **not** supply an `endptr` — any
/// input left unconsumed. Since a caller who passes `endptr` is expected to check
/// consumption themselves, the asymmetry is the contract.
///
/// # Safety
/// `str` must be NULL or NUL-terminated; `endptr` NULL or writable; `num` NULL or
/// writable.
#[no_mangle]
pub unsafe extern "C" fn OPENSSL_strtoul(
    str_: *const c_char,
    endptr: *mut *mut c_char,
    base: c_int,
    num: *mut c_ulong,
) -> c_int {
    guard_ffi(0, || {
        let mut tmp: *mut c_char = core::ptr::null_mut();
        let internal: *mut *mut c_char = if endptr.is_null() { &mut tmp } else { endptr };
        // SAFETY: `internal` is either the caller's pointer or our own `tmp`.
        unsafe { sys::set_errno(0) };
        // SAFETY: `internal` is writable as established above.
        unsafe { *internal = str_ as *mut c_char };
        if num.is_null() || str_.is_null() {
            return 0;
        }
        // SAFETY: `str_` is non-NULL and NUL-terminated.
        if unsafe { *str_ } == b'-' as c_char {
            return 0;
        }
        // SAFETY: `str_` is NUL-terminated and `internal` is writable.
        let value = unsafe { sys::strtoul(str_, internal, base) };
        // SAFETY: `num` is non-NULL per the guard above.
        unsafe { *num = value };
        // SAFETY: `internal` is readable and points at the caller's or our string.
        let err = unsafe { sys::errno() };
        // SAFETY: `internal` and `str_` are readable.
        let consumed_none = std::ptr::eq(unsafe { *internal }, str_);
        // SAFETY: `*internal` is a pointer into `str_`, hence NUL-terminated.
        let trailing = unsafe { **internal } != 0;
        if err != 0 || (endptr.is_null() && trailing) || consumed_none {
            return 0;
        }
        1
    })
}

/// `int OPENSSL_hexchar2int(unsigned char c)`
///
/// The value of one hexadecimal digit, or `-1`. The parameter is `unsigned char`,
/// so only `0..=255` reach the switch.
#[no_mangle]
pub extern "C" fn OPENSSL_hexchar2int(c: c_uchar) -> c_int {
    guard_ffi(-1, || match c {
        b'0'..=b'9' => c_int::from(c - b'0'),
        b'a'..=b'f' => c_int::from(c - b'a') + 0x0A,
        b'A'..=b'F' => c_int::from(c - b'A') + 0x0A,
        _ => -1,
    })
}

/// `static int hexstr2buf_sep(unsigned char *buf, size_t buf_n, size_t *buflen,
/// const char *str, const char sep)`
///
/// The scanning half of the hex decoder. `buf` may be NULL, in which case the
/// call only measures: `cnt` still counts the digits, and `buf_n` is not
/// consulted.
///
/// # Safety
/// `str` must be NUL-terminated; `buf` NULL or writable for `buf_n` bytes;
/// `buflen` NULL or writable.
unsafe fn hexstr2buf_sep(
    buf: *mut c_uchar,
    buf_n: usize,
    buflen: *mut usize,
    str_: *const c_char,
    sep: c_char,
) -> c_int {
    let sep_int = promoted(sep);
    let mut q = buf;
    let mut cnt = 0usize;
    let mut p = str_ as *const c_uchar;
    // SAFETY: `str_` is NUL-terminated, so the scan stops within it.
    while unsafe { *p } != 0 {
        // SAFETY: the loop condition read `*p` and found it non-zero, so this
        // byte exists and is readable.
        let ch = unsafe { *p };
        // SAFETY: `*p` was not the terminator, so the next byte is inside `str_`.
        p = unsafe { p.add(1) };
        // A separator of `CH_ZERO` means there is no separator, and a separator
        // with the high bit set is negative once `char` is promoted — so it can
        // never equal a byte. The comparison is therefore on `int`, as in C.
        if c_int::from(ch) == sep_int && sep_int != 0 {
            continue;
        }
        // SAFETY: `p` is inside `str_`; the byte may be the terminator.
        let cl = unsafe { *p };
        if cl == 0 {
            // The high nibble was read and there is no low nibble, so the
            // digit count is odd. `p` is deliberately not advanced past the
            // terminator: the function returns here either way.
            // SAFETY: `O_STR_229` is a generated `ErrSite` constant whose
            // `file` and `func` pointers are static.
            unsafe { raise_site(&O_STR_229) };
            return 0;
        }
        // SAFETY: `cl` was not the terminator, so advancing stays inside `str_`.
        p = unsafe { p.add(1) };
        let cli = OPENSSL_hexchar2int(cl);
        let chi = OPENSSL_hexchar2int(ch);
        if cli < 0 || chi < 0 {
            // SAFETY: `O_STR_235` is a generated `ErrSite` constant whose
            // `file` and `func` pointers are static.
            unsafe { raise_site(&O_STR_235) };
            return 0;
        }
        cnt += 1;
        if !q.is_null() {
            if cnt > buf_n {
                // SAFETY: `O_STR_241` is a generated `ErrSite` constant whose
                // `file` and `func` pointers are static.
                unsafe { raise_site(&O_STR_241) };
                return 0;
            }
            // SAFETY: `cnt <= buf_n`, so `q` has room for one more byte.
            unsafe {
                *q = (((chi << 4) | cli) & 0xff) as c_uchar;
                q = q.add(1);
            }
        }
    }

    if !buflen.is_null() {
        // SAFETY: `buflen` is writable per the caller's contract.
        unsafe { *buflen = cnt };
    }
    1
}

/// `int OPENSSL_hexstr2buf_ex(unsigned char *buf, size_t buf_n, size_t *buflen,
/// const char *str, const char sep)`
///
/// The bounded, caller-supplied-buffer decoder.
///
/// # Safety
/// As [`hexstr2buf_sep`].
#[no_mangle]
pub unsafe extern "C" fn OPENSSL_hexstr2buf_ex(
    buf: *mut c_uchar,
    buf_n: usize,
    buflen: *mut usize,
    str_: *const c_char,
    sep: c_char,
) -> c_int {
    guard_ffi(0, || {
        // SAFETY: forwarded under the caller's contract.
        unsafe { hexstr2buf_sep(buf, buf_n, buflen, str_, sep) }
    })
}

/// `unsigned char *ossl_hexstr2buf_sep(const char *str, long *buflen,
/// const char sep)`
///
/// The allocating decoder. It refuses a string of one byte or fewer *before*
/// allocating, because the caller meant "a hex string" and a single digit cannot
/// be one.
///
/// # Safety
/// `str` must be NUL-terminated; `buflen` NULL or writable.
unsafe fn ossl_hexstr2buf_sep(
    str_: *const c_char,
    buflen: *mut c_long,
    sep: c_char,
) -> *mut c_uchar {
    // SAFETY: `str_` is NUL-terminated per the caller's contract.
    let mut buf_n = unsafe { sys::strlen(str_) };
    if buf_n <= 1 {
        // SAFETY: `O_STR_270` is a generated `ErrSite` constant whose `file`
        // and `func` pointers are static.
        unsafe { raise_site(&O_STR_270) };
        return core::ptr::null_mut();
    }
    buf_n /= 2;
    // SAFETY: a plain allocation of `buf_n` bytes.
    let buf = CRYPTO_malloc(buf_n, core::ptr::null(), 0).cast::<c_uchar>();
    if buf.is_null() {
        return core::ptr::null_mut();
    }
    if !buflen.is_null() {
        // SAFETY: `buflen` is writable per the caller's contract.
        unsafe { *buflen = 0 };
    }
    let mut tmp_buflen = 0usize;
    // SAFETY: `buf` is writable for `buf_n` bytes; `str_` is NUL-terminated.
    if unsafe { hexstr2buf_sep(buf, buf_n, &mut tmp_buflen, str_, sep) } != 0 {
        if !buflen.is_null() {
            // SAFETY: `buflen` is writable per the caller's contract.
            unsafe { *buflen = tmp_buflen as c_long };
        }
        return buf;
    }
    // SAFETY: `buf` came from `CRYPTO_malloc` above.
    unsafe { CRYPTO_free(buf.cast::<c_void>(), core::ptr::null(), 0) };
    core::ptr::null_mut()
}

/// `unsigned char *OPENSSL_hexstr2buf(const char *str, long *buflen)`
///
/// # Safety
/// `str` must be NUL-terminated; `buflen` NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn OPENSSL_hexstr2buf(
    str_: *const c_char,
    buflen: *mut c_long,
) -> *mut c_uchar {
    guard_ffi(core::ptr::null_mut(), || {
        // SAFETY: forwarded under the caller's contract.
        unsafe { ossl_hexstr2buf_sep(str_, buflen, DEFAULT_SEPARATOR) }
    })
}

/// `static int buf2hexstr_sep(char *str, size_t str_n, size_t *strlength,
/// const unsigned char *buf, size_t buflen, const char sep)`
///
/// The other direction. Two things here are easy to "fix" into incompatibility:
/// the length is computed with wrapping arithmetic *before* the bound check that
/// rejects the wrapped cases, and a `str` of NULL is a legitimate *measuring*
/// call that reports the length and succeeds.
///
/// # Safety
/// `str` NULL or writable for `str_n` bytes; `buf` readable for `buflen` bytes;
/// `strlength` NULL or writable.
unsafe fn buf2hexstr_sep(
    str_: *mut c_char,
    str_n: usize,
    strlength: *mut usize,
    buf: *const c_uchar,
    buflen: usize,
    sep: c_char,
) -> c_int {
    let has_sep = promoted(sep) != 0;
    // The authority computes this wrapped value and only then rejects the inputs
    // for which it wrapped, so the wrap itself is unreachable, not load-bearing.
    let len = if has_sep {
        buflen.wrapping_mul(3)
    } else {
        1usize.wrapping_add(buflen.wrapping_mul(2))
    };

    let bound = if has_sep {
        usize::MAX / 3
    } else {
        (usize::MAX - 1) / 2
    };
    if buflen > bound {
        // SAFETY: `O_STR_303` is a generated `ErrSite` constant whose `file`
        // and `func` pointers are static.
        unsafe { raise_site(&O_STR_303) };
        return 0;
    }

    if !strlength.is_null() {
        // SAFETY: `strlength` is writable per the caller's contract.
        unsafe { *strlength = len };
    }
    if str_.is_null() {
        return 1;
    }
    if str_n < len {
        // SAFETY: `O_STR_315` is a generated `ErrSite` constant whose `file`
        // and `func` pointers are static.
        unsafe { raise_site(&O_STR_315) };
        return 0;
    }

    let mut q = str_;
    for i in 0..buflen {
        // SAFETY: `buf` is readable for `buflen` bytes and `i < buflen`.
        let byte = unsafe { *buf.add(i) };
        // SAFETY: the loop writes exactly `len` bytes, which `str_n >= len`
        // covers, and `q` advances by 2 or 3 per iteration.
        unsafe {
            q = q.add(to_hex(q, byte));
            if has_sep {
                *q = sep;
                q = q.add(1);
            }
        }
    }
    if has_sep && buflen > 0 {
        // SAFETY: `q > str_`, since at least one separator was written.
        q = unsafe { q.sub(1) };
    }
    // SAFETY: `q` is inside the caller's buffer and is the last byte written.
    unsafe { *q = 0 };
    1
}

/// `int OPENSSL_buf2hexstr_ex(char *str, size_t str_n, size_t *strlength,
/// const unsigned char *buf, size_t buflen, const char sep)`
///
/// # Safety
/// As [`buf2hexstr_sep`].
#[no_mangle]
pub unsafe extern "C" fn OPENSSL_buf2hexstr_ex(
    str_: *mut c_char,
    str_n: usize,
    strlength: *mut usize,
    buf: *const c_uchar,
    buflen: usize,
    sep: c_char,
) -> c_int {
    guard_ffi(0, || {
        // SAFETY: forwarded under the caller's contract.
        unsafe { buf2hexstr_sep(str_, str_n, strlength, buf, buflen, sep) }
    })
}

/// `char *ossl_buf2hexstr_sep(const unsigned char *buf, long buflen, char sep)`
///
/// A `buflen` of 0 is the empty string — and specifically a *zeroed* byte, so an
/// empty encoding is a readable NUL string, not a NULL pointer. A negative
/// `buflen` is caught by the bound check, because the cast to `size_t` puts it far
/// above every bound.
///
/// # Safety
/// `buf` readable for `buflen` bytes when `buflen > 0`.
unsafe fn ossl_buf2hexstr_sep(buf: *const c_uchar, buflen: c_long, sep: c_char) -> *mut c_char {
    if buflen == 0 {
        // SAFETY: a plain zeroed allocation of one byte.
        return CRYPTO_zalloc(1, core::ptr::null(), 0).cast::<c_char>();
    }

    let has_sep = promoted(sep) != 0;
    let bound = if has_sep {
        usize::MAX / 3
    } else {
        (usize::MAX - 1) / 2
    };
    let wide = buflen as usize;
    if wide > bound {
        // SAFETY: `O_STR_352` is a generated `ErrSite` constant whose `file`
        // and `func` pointers are static.
        unsafe { raise_site(&O_STR_352) };
        return core::ptr::null_mut();
    }

    let tmp_n = if has_sep { wide * 3 } else { 1 + wide * 2 };
    // SAFETY: a plain allocation of `tmp_n` bytes.
    let tmp = CRYPTO_malloc(tmp_n, core::ptr::null(), 0).cast::<c_char>();
    if tmp.is_null() {
        return core::ptr::null_mut();
    }

    // SAFETY: `tmp` is writable for `tmp_n` bytes; `buf` is readable for `wide`.
    if unsafe { buf2hexstr_sep(tmp, tmp_n, core::ptr::null_mut(), buf, wide, sep) } != 0 {
        return tmp;
    }
    // SAFETY: `tmp` came from `CRYPTO_malloc` above.
    unsafe { CRYPTO_free(tmp.cast::<c_void>(), core::ptr::null(), 0) };
    core::ptr::null_mut()
}

/// `char *OPENSSL_buf2hexstr(const unsigned char *buf, long buflen)`
///
/// The colon-separated form.
///
/// # Safety
/// `buf` readable for `buflen` bytes when `buflen > 0`.
#[no_mangle]
pub unsafe extern "C" fn OPENSSL_buf2hexstr(buf: *const c_uchar, buflen: c_long) -> *mut c_char {
    guard_ffi(core::ptr::null_mut(), || {
        // SAFETY: forwarded under the caller's contract.
        unsafe { ossl_buf2hexstr_sep(buf, buflen, DEFAULT_SEPARATOR) }
    })
}

/// `int OPENSSL_strcasecmp(const char *s1, const char *s2)`
///
/// ASCII-only case folding, over signed `char` values. The exact magnitude of a
/// non-zero result is a difference of `ossl_tolower` results, so it is
/// reproducible rather than merely "negative or positive".
///
/// # Safety
/// Both arguments must be NUL-terminated.
#[no_mangle]
pub unsafe extern "C" fn OPENSSL_strcasecmp(s1: *const c_char, s2: *const c_char) -> c_int {
    guard_ffi(0, || {
        let mut a = s1;
        let mut b = s2;
        loop {
            // SAFETY: both strings are NUL-terminated; the loop stops at the
            // first NUL, so neither pointer leaves its string.
            let (ca, cb) = unsafe { (*a, *b) };
            // SAFETY: as above.
            b = unsafe { b.add(1) };
            let t = ossl_tolower(promoted(ca)) - ossl_tolower(promoted(cb));
            if t != 0 {
                return t;
            }
            if ca == 0 {
                return 0;
            }
            // SAFETY: `ca` was not the terminator, so the next byte exists.
            a = unsafe { a.add(1) };
        }
    })
}

/// `int OPENSSL_strncasecmp(const char *s1, const char *s2, size_t n)`
///
/// As [`OPENSSL_strcasecmp`], bounded by `n` and returning 0 when the bound is
/// reached without a difference.
///
/// # Safety
/// Both arguments must be readable for `n` bytes or NUL-terminated, whichever is
/// shorter.
#[no_mangle]
pub unsafe extern "C" fn OPENSSL_strncasecmp(
    s1: *const c_char,
    s2: *const c_char,
    n: usize,
) -> c_int {
    guard_ffi(0, || {
        let mut a = s1;
        let mut b = s2;
        let mut i = 0usize;
        while i < n {
            // SAFETY: both strings are readable for the shorter of `n` bytes and
            // their length, per the caller's contract.
            let (ca, cb) = unsafe { (*a, *b) };
            // SAFETY: as above.
            b = unsafe { b.add(1) };
            let t = ossl_tolower(promoted(ca)) - ossl_tolower(promoted(cb));
            if t != 0 {
                return t;
            }
            if ca == 0 {
                return 0;
            }
            // SAFETY: `ca` was not the terminator and `i + 1 < n`, so the next
            // byte is within the caller's bound.
            a = unsafe { a.add(1) };
            i += 1;
        }
        0
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CString;

    #[test]
    fn strlcpy_and_strlcat_report_the_untruncated_length() {
        let Ok(src) = CString::new("abcdef") else {
            unreachable!("the literal has no interior NUL");
        };
        let mut buf = [0i8; 4];
        // SAFETY: `buf` is writable for 4 bytes and `src` is NUL-terminated.
        let n = unsafe { OPENSSL_strlcpy(buf.as_mut_ptr(), src.as_ptr(), buf.len()) };
        assert_eq!(n, 6, "the return is the length the copy wanted");
        assert_eq!(&buf[..3], &b"abc".map(|b| b as i8)[..]);
        assert_eq!(buf[3], 0);

        // A zero size writes nothing at all, not even a terminator.
        let mut one = [7i8; 1];
        // SAFETY: a zero size is explicitly safe.
        let n = unsafe { OPENSSL_strlcpy(one.as_mut_ptr(), src.as_ptr(), 0) };
        assert_eq!(n, 6);
        assert_eq!(one[0], 7);

        // Appending into a full buffer copies nothing.
        let mut full = *b"abcd\0\0\0\0";
        // SAFETY: `full` is writable for 8 bytes and `src` is NUL-terminated.
        let n = unsafe { OPENSSL_strlcat(full.as_mut_ptr() as *mut c_char, src.as_ptr(), 4) };
        assert_eq!(n, 10, "4 existing + 6 appended, even though nothing was");
        assert_eq!(&full[..4], &b"abcd"[..]);
    }

    #[test]
    fn strcasecmp_is_ascii_only_and_sign_extends() {
        // The high-byte cases are raw bytes, not `&str`, because a Rust string
        // literal would encode them as UTF-8 and test the wrong thing.
        let Ok(hi) = CString::new(vec![0xC3u8]) else {
            unreachable!("the literal has no interior NUL");
        };
        let Ok(hi_lower) = CString::new(vec![0xE3u8]) else {
            unreachable!("the literal has no interior NUL");
        };
        let cases: &[(&str, &str, c_int)] = &[
            ("abc", "ABC", 0),
            ("abc", "abd", -1),
            ("abd", "abc", 1),
            ("ABC", "abc", 0),
            ("", "", 0),
            ("a", "", 97),
            ("", "a", -97),
        ];
        for (a, b, want) in cases {
            let Ok(ca) = CString::new(*a) else {
                unreachable!("the test inputs contain no interior NUL");
            };
            let Ok(cb) = CString::new(*b) else {
                unreachable!("the test inputs contain no interior NUL");
            };
            // SAFETY: both are live NUL-terminated strings.
            let got = unsafe { OPENSSL_strcasecmp(ca.as_ptr(), cb.as_ptr()) };
            assert_eq!(got, *want, "OPENSSL_strcasecmp({a:?}, {b:?})");
        }
        // 0xC3 sign-extends to -61 and 'a' is 97, so the difference is -158.
        let Ok(a_char) = CString::new("a") else {
            unreachable!("the literal has no interior NUL");
        };
        // SAFETY: both are live NUL-terminated strings.
        unsafe {
            assert_eq!(OPENSSL_strcasecmp(hi.as_ptr(), a_char.as_ptr()), -158);
            assert_eq!(OPENSSL_strcasecmp(a_char.as_ptr(), hi.as_ptr()), 158);
            // High bytes are not case-folded: -61 against -29.
            assert_eq!(OPENSSL_strcasecmp(hi.as_ptr(), hi_lower.as_ptr()), -32);
        }
    }

    #[test]
    fn strncasecmp_stops_at_the_bound() {
        let Ok(a) = CString::new("abcdef") else {
            unreachable!("the literal has no interior NUL");
        };
        let Ok(b) = CString::new("abcxyz") else {
            unreachable!("the literal has no interior NUL");
        };
        // SAFETY: both are NUL-terminated and 3 bytes is within both.
        assert_eq!(unsafe { OPENSSL_strncasecmp(a.as_ptr(), b.as_ptr(), 3) }, 0);
        // SAFETY: both strings are NUL-terminated; a bound of 4 stays inside
        // the six bytes each holds, so the fourth byte (`d` against `x`) is the
        // first difference.
        let got = unsafe { OPENSSL_strncasecmp(a.as_ptr(), b.as_ptr(), 4) };
        assert_eq!(got, -20);
        // SAFETY: a zero bound never reads anything.
        assert_eq!(unsafe { OPENSSL_strncasecmp(a.as_ptr(), b.as_ptr(), 0) }, 0);
    }

    #[test]
    fn hexchar2int_covers_exactly_the_hex_digits() {
        for c in 0u8..=255 {
            let want = match c {
                b'0'..=b'9' => c_int::from(c - b'0'),
                b'a'..=b'f' => c_int::from(c - b'a') + 10,
                b'A'..=b'F' => c_int::from(c - b'A') + 10,
                _ => -1,
            };
            assert_eq!(
                OPENSSL_hexchar2int(c),
                want,
                "OPENSSL_hexchar2int({c:#04x})"
            );
        }
    }

    #[test]
    fn hexstr2buf_round_trips_and_reports_its_errors() {
        let Ok(text) = CString::new("01:ab:CD") else {
            unreachable!("the literal has no interior NUL");
        };
        let mut len: c_long = -1;
        // SAFETY: `text` is NUL-terminated and `len` is writable.
        let p = unsafe { OPENSSL_hexstr2buf(text.as_ptr(), &mut len) };
        assert!(!p.is_null());
        assert_eq!(len, 3);
        // SAFETY: the decoder allocated 3 bytes and returned them.
        let decoded = unsafe { core::slice::from_raw_parts(p, 3) };
        assert_eq!(decoded, [1u8, 0xab, 0xcd]);
        // SAFETY: `p` came from `CRYPTO_malloc`.
        unsafe { CRYPTO_free(p.cast::<c_void>(), core::ptr::null(), 0) };

        // One byte is too short to be a hex string.
        let Ok(short) = CString::new("a") else {
            unreachable!("the literal has no interior NUL");
        };
        // SAFETY: `short` is NUL-terminated.
        assert!(unsafe { OPENSSL_hexstr2buf(short.as_ptr(), core::ptr::null_mut()) }.is_null());

        // An odd number of digits raises rather than silently dropping one.
        let Ok(odd) = CString::new("abc") else {
            unreachable!("the literal has no interior NUL");
        };
        // SAFETY: `odd` is NUL-terminated.
        assert!(unsafe { OPENSSL_hexstr2buf(odd.as_ptr(), core::ptr::null_mut()) }.is_null());

        // A too-small buffer is reported through the bounded form.
        let mut out = [0u8; 2];
        let mut got = 0usize;
        // SAFETY: `out` is writable for 2 bytes, `got` is writable, and `text`
        // is NUL-terminated; the bounded decoder writes at most `out.len()`.
        let rc = unsafe {
            OPENSSL_hexstr2buf_ex(
                out.as_mut_ptr(),
                out.len(),
                &mut got,
                text.as_ptr(),
                b':' as c_char,
            )
        };
        assert_eq!(rc, 0);
    }

    #[test]
    fn buf2hexstr_uses_upper_case_and_a_colon_separator() {
        let input = [0x01u8, 0xab, 0xcd];
        // SAFETY: `input` is readable for its own length.
        let p = unsafe { OPENSSL_buf2hexstr(input.as_ptr(), input.len() as c_long) };
        assert!(!p.is_null());
        // SAFETY: the encoder returned a NUL-terminated string.
        let raw = unsafe { std::ffi::CStr::from_ptr(p) };
        let Ok(got) = raw.to_str() else {
            unreachable!("the encoder emits ASCII only");
        };
        assert_eq!(got, "01:AB:CD");
        // SAFETY: `p` came from `CRYPTO_malloc`.
        unsafe { CRYPTO_free(p.cast::<c_void>(), core::ptr::null(), 0) };

        // An empty buffer is the empty string, not NULL.
        // SAFETY: a zero length is explicitly accepted.
        let empty = unsafe { OPENSSL_buf2hexstr(input.as_ptr(), 0) };
        assert!(!empty.is_null());
        // SAFETY: the encoder returned a NUL-terminated string.
        assert_eq!(unsafe { *empty }, 0);

        // A NULL output pointer measures.
        let mut need = 0usize;
        // SAFETY: `need` is writable; a NULL `str` is the measuring form.
        let rc = unsafe {
            OPENSSL_buf2hexstr_ex(
                core::ptr::null_mut(),
                0,
                &mut need,
                input.as_ptr(),
                input.len(),
                b':' as c_char,
            )
        };
        assert_eq!(rc, 1);
        assert_eq!(need, 9, "3 bytes as 8 digits plus 2 separators plus NUL");
    }

    #[test]
    fn strtoul_rejects_a_negative_sign_and_leftover_input() {
        let Ok(good) = CString::new("42") else {
            unreachable!("the literal has no interior NUL");
        };
        let mut num: c_ulong = 0;
        // SAFETY: both out-parameters are writable and the input is terminated.
        let rc = unsafe { OPENSSL_strtoul(good.as_ptr(), core::ptr::null_mut(), 10, &mut num) };
        assert_eq!(rc, 1);
        assert_eq!(num, 42);

        // Without an `endptr`, trailing bytes are a failure.
        let Ok(trailing) = CString::new("42x") else {
            unreachable!("the literal has no interior NUL");
        };
        // SAFETY: as above.
        let rc = unsafe { OPENSSL_strtoul(trailing.as_ptr(), core::ptr::null_mut(), 10, &mut num) };
        assert_eq!(rc, 0);

        // A leading minus is rejected before `strtoul` ever runs.
        let Ok(negative) = CString::new("-1") else {
            unreachable!("the literal has no interior NUL");
        };
        // SAFETY: as above.
        let rc = unsafe { OPENSSL_strtoul(negative.as_ptr(), core::ptr::null_mut(), 10, &mut num) };
        assert_eq!(rc, 0);
        assert_eq!(
            num, 42,
            "the output is untouched when the input is rejected"
        );
    }
}
