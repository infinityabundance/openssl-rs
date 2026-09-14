//! Phase 4 — `BIO_dump*` and `BIO_hex_string`.
//!
//! The canonical OpenSSL hex dump. Its exact shape is a contract because tools
//! parse it and users diff it: a four-hex-digit offset, ` - `, sixteen hex bytes
//! with a `-` after the eighth, two spaces, then the printable-ASCII column with
//! `.` for non-printables, then a newline.
//!
//! Two details are easy to get wrong and are reproduced deliberately:
//!
//! * the per-row width shrinks with `indent`
//!   (`16 - ((indent - min(indent, 6) + 3) / 4)`), so an indented dump has fewer
//!   bytes per row rather than a longer line;
//! * every write is bounded by a 288-byte scratch buffer, and the truncation
//!   checks are *strict* (`sizeof(buf) - pos > n`), which is what makes the
//!   output truncate rather than overflow for pathological `indent`/`len`.
//!
//! The callback form is the primitive: `BIO_dump` is `BIO_dump_cb` writing into a
//! BIO and `BIO_dump_fp` is the same writing into a `FILE *`.

use core::ffi::{c_char, c_int, c_void};
use core::ptr;

use crate::ffi::guard_ffi;

use super::sys::FILE;

/// `DUMP_WIDTH` — the width of a full-width row.
const DUMP_WIDTH: c_int = 16;
/// The size of the authority's scratch line buffer.
const BUF_LEN: usize = 288;

/// `DUMP_WIDTH_LESS_INDENT(i)`.
fn dump_width_less_indent(indent: c_int) -> c_int {
    DUMP_WIDTH - ((indent - if indent > 6 { 6 } else { indent } + 3) / 4)
}

/// The authority's `SPACE(buf, pos, n)` macro: `sizeof(buf) - pos > n`.
#[inline]
fn space(pos: usize, n: usize) -> bool {
    BUF_LEN + 1 - pos > n
}

/// The callback type every dump entry point funnels through.
pub type DumpCb = unsafe extern "C" fn(*const c_void, usize, *mut c_void) -> c_int;

/// `int BIO_dump_indent_cb(int (*cb)(const void *, size_t, void *), void *u,
/// const void *s, int len, int indent)`
///
/// The formatter. `indent` is clamped to `0..=64`; the row count is
/// `ceil(len / dump_width)`; each row's bytes are written into a bounded buffer
/// and handed to `cb`, whose negative result aborts and whose positive results
/// accumulate into the return value.
#[no_mangle]
pub unsafe extern "C" fn BIO_dump_indent_cb(
    cb: Option<DumpCb>,
    u: *mut c_void,
    v: *const c_void,
    len: c_int,
    indent: c_int,
) -> c_int {
    guard_ffi(0, || {
        let Some(cb) = cb else {
            return -1;
        };
        let s = v.cast::<u8>();
        let indent = indent.clamp(0, 64);
        let dump_width = dump_width_less_indent(indent);
        let mut rows = len / dump_width;
        if rows * dump_width < len {
            rows += 1;
        }
        let mut ret: c_int = 0;
        let mut buf = [0u8; BUF_LEN + 1];
        for i in 0..rows {
            let mut n: usize = 0;
            // `%*s%04x - `: indent spaces, then the row's byte offset.
            for _ in 0..indent {
                if !space(n, 1) {
                    break;
                }
                buf[n] = b' ';
                n += 1;
            }
            let off = (i * dump_width) as u32;
            let off_text = format_hex4(off);
            for b in off_text {
                if space(n, 1) {
                    buf[n] = b;
                    n += 1;
                }
            }
            for b in *b" - " {
                if space(n, 1) {
                    buf[n] = b;
                    n += 1;
                }
            }
            for j in 0..dump_width {
                if !space(n, 3) {
                    continue;
                }
                let at = i * dump_width + j;
                if at >= len {
                    for b in *b"   " {
                        buf[n] = b;
                        n += 1;
                    }
                } else {
                    // SAFETY: `at < len` and the caller vouches for `len` bytes
                    // at `s`.
                    let ch = unsafe { *s.add(at as usize) };
                    let two = format_hex2(ch);
                    buf[n] = two[0];
                    buf[n + 1] = two[1];
                    buf[n + 2] = if j == 7 { b'-' } else { b' ' };
                    n += 3;
                }
            }
            if space(n, 2) {
                buf[n] = b' ';
                buf[n + 1] = b' ';
                n += 2;
            }
            for j in 0..dump_width {
                let at = i * dump_width + j;
                if at >= len {
                    break;
                }
                if space(n, 1) {
                    // SAFETY: `at < len`; see above.
                    let ch = unsafe { *s.add(at as usize) };
                    buf[n] = if (b' '..=b'~').contains(&ch) {
                        ch
                    } else {
                        b'.'
                    };
                    n += 1;
                }
            }
            if space(n, 1) {
                buf[n] = b'\n';
                n += 1;
            }
            // SAFETY: `cb` is the caller's callback; `buf` holds `n` valid bytes
            // and `u` is the caller's opaque pointer.
            let res = unsafe { cb(buf.as_ptr().cast(), n, u) };
            if res < 0 {
                return res;
            }
            ret += res;
        }
        ret
    })
}

/// `int BIO_dump_cb(int (*cb)(const void *, size_t, void *), void *u,
/// const void *s, int len)`
#[no_mangle]
pub unsafe extern "C" fn BIO_dump_cb(
    cb: Option<DumpCb>,
    u: *mut c_void,
    s: *const c_void,
    len: c_int,
) -> c_int {
    guard_ffi(0, || {
        // SAFETY: forwarded; `s` is valid for `len` bytes per the caller.
        unsafe { BIO_dump_indent_cb(cb, u, s, len, 0) }
    })
}

/// `static int write_bio(const void *data, size_t len, void *bp)`
///
/// # Safety
/// `bp` must be a live BIO.
unsafe extern "C" fn write_bio(data: *const c_void, len: usize, bp: *mut c_void) -> c_int {
    if len > c_int::MAX as usize {
        return -1;
    }
    // SAFETY: `bp` is a live BIO and `data` is valid for `len` bytes.
    unsafe { super::BIO_write(bp.cast(), data, len as c_int) }
}

/// `static int write_fp(const void *data, size_t len, void *fp)`
///
/// # Safety
/// `fp` must be a live `FILE *`.
unsafe extern "C" fn write_fp(data: *const c_void, len: usize, fp: *mut c_void) -> c_int {
    // SAFETY: `fp` is a live `FILE *` and `data` is valid for `len` bytes.
    unsafe { super::sys::fwrite(data, len, 1, fp.cast::<FILE>()) as c_int }
}

/// `int BIO_dump(BIO *b, const void *bytes, int len)`
#[no_mangle]
pub unsafe extern "C" fn BIO_dump(bp: *mut super::Bio, s: *const c_void, len: c_int) -> c_int {
    guard_ffi(0, || {
        // SAFETY: forwarded; `bp` is a live BIO.
        unsafe { BIO_dump_cb(Some(write_bio), bp.cast(), s, len) }
    })
}

/// `int BIO_dump_indent(BIO *b, const void *bytes, int len, int indent)`
#[no_mangle]
pub unsafe extern "C" fn BIO_dump_indent(
    bp: *mut super::Bio,
    s: *const c_void,
    len: c_int,
    indent: c_int,
) -> c_int {
    guard_ffi(0, || {
        // SAFETY: forwarded; `bp` is a live BIO.
        unsafe { BIO_dump_indent_cb(Some(write_bio), bp.cast(), s, len, indent) }
    })
}

/// `int BIO_dump_fp(FILE *fp, const void *s, int len)`
#[no_mangle]
pub unsafe extern "C" fn BIO_dump_fp(fp: *mut FILE, s: *const c_void, len: c_int) -> c_int {
    guard_ffi(0, || {
        // SAFETY: forwarded; `fp` is a live `FILE *`.
        unsafe { BIO_dump_cb(Some(write_fp), fp.cast(), s, len) }
    })
}

/// `int BIO_dump_indent_fp(FILE *fp, const void *s, int len, int indent)`
#[no_mangle]
pub unsafe extern "C" fn BIO_dump_indent_fp(
    fp: *mut FILE,
    s: *const c_void,
    len: c_int,
    indent: c_int,
) -> c_int {
    guard_ffi(0, || {
        // SAFETY: forwarded; `fp` is a live `FILE *`.
        unsafe { BIO_dump_indent_cb(Some(write_fp), fp.cast(), s, len, indent) }
    })
}

/// `int BIO_hex_string(BIO *out, int indent, int width, const void *data,
/// int datalen)`
///
/// Colon-separated upper-case hex, wrapped at `width` bytes per line with
/// `indent` spaces. `datalen < 1` is success without output, and the final byte
/// is emitted without a trailing colon — the two asymmetries the authority has.
#[no_mangle]
pub unsafe extern "C" fn BIO_hex_string(
    out: *mut super::Bio,
    indent: c_int,
    width: c_int,
    data: *const c_void,
    datalen: c_int,
) -> c_int {
    guard_ffi(0, || {
        let d = data.cast::<u8>();
        if datalen < 1 {
            return 1;
        }
        let mut j: c_int = 0;
        let mut i: c_int = 0;
        while i < datalen - 1 {
            if i != 0 && j == 0 {
                // SAFETY: `out` is a live BIO.
                unsafe { super::print::BIO_printf(out, c"%*s".as_ptr(), indent, c"".as_ptr()) };
            }
            // SAFETY: `i < datalen`; `out` is live.
            unsafe {
                let ch = *d.add(i as usize);
                super::print::BIO_printf(out, c"%02X:".as_ptr(), ch as c_int);
            }
            j += 1;
            if j >= width {
                j = 0;
                // SAFETY: `out` is live.
                unsafe { super::print::BIO_printf(out, c"\n".as_ptr()) };
            }
            i += 1;
        }
        if i != 0 && j == 0 {
            // SAFETY: `out` is live.
            unsafe { super::print::BIO_printf(out, c"%*s".as_ptr(), indent, c"".as_ptr()) };
        }
        // SAFETY: `datalen >= 1`, so the last byte is in range; `out` is live.
        unsafe {
            let last = *d.add((datalen - 1) as usize);
            super::print::BIO_printf(out, c"%02X".as_ptr(), last as c_int);
        }
        1
    })
}

/// Four lower-case hex digits, as `%04x` produces for a row offset.
fn format_hex4(v: u32) -> [u8; 4] {
    let digits = b"0123456789abcdef";
    [
        digits[((v >> 12) & 0xf) as usize],
        digits[((v >> 8) & 0xf) as usize],
        digits[((v >> 4) & 0xf) as usize],
        digits[(v & 0xf) as usize],
    ]
}

/// Two lower-case hex digits, as `%02x` produces for one byte.
fn format_hex2(v: u8) -> [u8; 2] {
    let digits = b"0123456789abcdef";
    [digits[(v >> 4) as usize], digits[(v & 0xf) as usize]]
}

/// `NULL` need not be spelled for the C string literals above.
const _: *const c_char = ptr::null();
