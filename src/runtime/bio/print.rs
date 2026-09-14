//! Phase 4 — the BIO printf surface.
//!
//! `BIO_printf`, `BIO_vprintf`, `BIO_snprintf` and `BIO_vsnprintf` are
//! C-variadic, and stable Rust cannot **define** a C-variadic function. The
//! definitions therefore live in `src/runtime/bio/bio_variadic.c`, which formats
//! the arguments and calls back into this crate's `BIO_write`; no formatting or
//! BIO behaviour lives in the C.
//!
//! This module also implements the one non-variadic member of the family,
//! `BIO_indent`, whose control flow is observable: it writes **one byte at a
//! time** through `BIO_puts` and stops at the first `BIO_puts` that does not
//! report exactly 1, so a partially-failing sink produces fewer spaces than were
//! asked for and a 0 return.

use core::ffi::{c_char, c_int};

use crate::ffi::guard_ffi;

use super::Bio;

extern "C" {
    /// `int BIO_printf(BIO *bio, const char *format, ...)` — defined in
    /// `bio_variadic.c`.
    pub fn BIO_printf(bio: *mut Bio, format: *const c_char, ...) -> c_int;
    /// `int BIO_snprintf(char *buf, size_t n, const char *format, ...)` — defined
    /// in `bio_variadic.c`.
    pub fn BIO_snprintf(buf: *mut c_char, n: usize, format: *const c_char, ...) -> c_int;
}

/// `int BIO_indent(BIO *b, int indent, int max)`
///
/// `indent` is clamped to `0..=max`, and each space is a separate `BIO_puts`
/// whose result must be exactly 1. A sink that returns a short count therefore
/// truncates the indentation and makes this return 0, which is the authority's
/// behaviour and is measured by the RT-BIO probe through a custom method.
#[no_mangle]
pub unsafe extern "C" fn BIO_indent(bio: *mut Bio, indent: c_int, max: c_int) -> c_int {
    guard_ffi(0, || {
        let mut indent = if indent < 0 { 0 } else { indent };
        if indent > max {
            indent = max;
        }
        while indent > 0 {
            // SAFETY: `bio` is a live BIO; the string is a static NUL-terminated
            // literal.
            if unsafe { super::BIO_puts(bio, c" ".as_ptr()) } != 1 {
                return 0;
            }
            indent -= 1;
        }
        1
    })
}
