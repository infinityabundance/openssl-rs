//! `crypto/trace.c` — the `OSSL_TRACE_*` facility, as this profile builds it.
//!
//! ## The build profile decides almost all of this module
//!
//! The pinned profile is configured `no-trace`, so `OPENSSL_NO_TRACE` is defined
//! (measured in the court, not inferred from the configure line) and the bodies of
//! every *channel-setting* function in `crypto/trace.c` are compiled out. What is
//! left is not a no-op implementation on this side — it is the authority's own
//! behaviour, and it is exact:
//!
//! | export | authority's answer under `OPENSSL_NO_TRACE` |
//! |---|---|
//! | `OSSL_trace_set_channel` | `0` for every category, valid ones included |
//! | `OSSL_trace_set_callback` | `0` |
//! | `OSSL_trace_set_prefix` | `0` |
//! | `OSSL_trace_set_suffix` | `0` |
//! | `OSSL_trace_enabled` | `0` |
//! | `OSSL_trace_begin` | `NULL` |
//! | `OSSL_trace_end` | returns without touching the channel |
//!
//! Read from `crypto/trace.c` at `openssl-3.6.4`: each body is
//! `#ifndef OPENSSL_NO_TRACE ... #endif` followed by a fall-through `return 0;` or
//! `return NULL;`, and the *initialisers* (`int ret = 0;`,
//! `BIO *channel = NULL;`) sit outside the guard — so the fall-through value is
//! the answer rather than an uninitialised one. `OSSL_trace_set_channel` and
//! friends therefore do **not** validate their category on this profile: the range
//! check is inside the guard too.
//!
//! ## Three of the ten are live, and they are the ones a caller can see
//!
//! `OSSL_trace_get_category_name` and `OSSL_trace_get_category_num` are declared
//! *above* the first `#ifndef` in the file, and `OSSL_trace_string` is outside
//! every guard. So a program that traces nothing can still ask the library what
//! the categories are called, and can still format a byte string through
//! `OSSL_trace_string`.
//!
//! `OSSL_TRACE_CATEGORY_NUM` is **21** and the name table is order-dependent:
//! `trace.c` builds it with `TRACE_CATEGORY_(name)` in declaration order and
//! carries a `KEEP THIS LIST IN SYNC` comment against `trace.h`'s defines. Both
//! sides were read and the table here is the join of them, because a
//! desynchronised pair is exactly what that comment warns about — and it is what
//! `OSSL_trace_get_category_name`'s `ossl_assert` pair exists to detect.
//!
//! ## One recorded divergence
//!
//! `OSSL_trace_string` has a `buf[81]` local and assigns `len = (int)size`
//! whenever `full` is non-zero **or** `size <= 80`. A caller passing `full != 0`
//! with `size > 80` therefore makes the authority read `len` bytes from a buffer
//! that only ever holds 81 — a stack over-read, and with `text == 0` a stack
//! overflow writing `buf[i]`. That is a memory fault, not a contract: recorded in
//! `docs/SECURITY_DIVERGENCE_POLICY.md` and deliberately **not** reproduced. A
//! caller inside the documented use sees byte-identical output, because the clamp
//! only engages above `OSSL_TRACE_STRING_MAX`.

use core::ffi::{c_char, c_int, c_void};

use crate::runtime::bio::print::BIO_printf;
use crate::runtime::bio::Bio;
use crate::runtime::str::OPENSSL_strcasecmp;

/// `OSSL_TRACE_CATEGORY_NUM`, from `trace.h`.
const OSSL_TRACE_CATEGORY_NUM: usize = 21;

/// `OSSL_TRACE_STRING_MAX`, from `trace.h`.
const OSSL_TRACE_STRING_MAX: usize = 80;

/// `OSSL_trace_cb`, from `trace.h`: `size_t (*)(const char *, size_t, int, int,
/// void *)`. Spelled as the atlas records the typedef, so `ABI-PROTOTYPE`'s
/// canonical form matches on both sides.
pub type OsslTraceCb =
    unsafe extern "C" fn(*const c_char, usize, c_int, c_int, *mut c_void) -> usize;

/// The names as NUL-terminated `*const c_char`, so `OSSL_trace_get_category_name`
/// can hand back a pointer stable for the life of the program — which is what the
/// authority's static table does, and a caller may rely on.
struct NamePtrs([*const c_char; OSSL_TRACE_CATEGORY_NUM]);

// SAFETY: every entry points at a `'static` NUL-terminated string literal, so the
// array is immutable for the life of the program and may be shared across threads.
unsafe impl Sync for NamePtrs {}

static NAME_PTRS: NamePtrs = NamePtrs([
    c"ALL".as_ptr(),
    c"TRACE".as_ptr(),
    c"INIT".as_ptr(),
    c"TLS".as_ptr(),
    c"TLS_CIPHER".as_ptr(),
    c"CONF".as_ptr(),
    c"ENGINE_TABLE".as_ptr(),
    c"ENGINE_REF_COUNT".as_ptr(),
    c"PKCS5V2".as_ptr(),
    c"PKCS12_KEYGEN".as_ptr(),
    c"PKCS12_DECRYPT".as_ptr(),
    c"X509V3_POLICY".as_ptr(),
    c"BN_CTX".as_ptr(),
    c"CMP".as_ptr(),
    c"STORE".as_ptr(),
    c"DECODER".as_ptr(),
    c"ENCODER".as_ptr(),
    c"REF_COUNT".as_ptr(),
    c"HTTP".as_ptr(),
    c"PROVIDER".as_ptr(),
    c"QUERY".as_ptr(),
]);

/// `ossl_iscntrl(c)` for one byte, with OpenSSL's own table semantics.
///
/// `ossl_ctype_check(c, mask)` is
///
/// ```c
/// return a >= 0 && a < max && (ctype_char_map[a] & mask) != 0;
/// ```
///
/// with `max == 128`. So a byte at or above 128 is **not** a control character:
/// the predicate is false for anything outside the table rather than falling back
/// to a mask test. The first version of this function assumed a `CTYPE_MASK_ascii`
/// fallback and masked bytes >= 128 into spaces; the RT-RUNTIME-EXT court found it
/// by passing 0x80 through `OSSL_trace_string`, which the authority passes through
/// unchanged.
const fn ossl_iscntrl(byte: u8) -> bool {
    byte < 0x20 || byte == 0x7f
}

/// `const char *OSSL_trace_get_category_name(int num)`
///
/// Answers the category's name, or NULL when `num` is outside
/// `[0, OSSL_TRACE_CATEGORY_NUM)`. The authority's two `ossl_assert`s check that
/// the name table and `trace.h`'s numbers have not drifted apart; both conditions
/// hold by construction here, so the range check is the only NULL path.
#[no_mangle]
pub extern "C" fn OSSL_trace_get_category_name(num: c_int) -> *const c_char {
    if num < 0 || (num as usize) >= OSSL_TRACE_CATEGORY_NUM {
        return core::ptr::null();
    }
    NAME_PTRS.0[num as usize]
}

/// `int OSSL_trace_get_category_num(const char *name)`
///
/// The reverse lookup, case-insensitively, answering `-1` for NULL and for an
/// unknown name. `-1` rather than an error code: callers compare against it
/// directly.
///
/// # Safety
/// `name` must be NULL or a NUL-terminated C string.
#[no_mangle]
pub unsafe extern "C" fn OSSL_trace_get_category_num(name: *const c_char) -> c_int {
    if name.is_null() {
        return -1;
    }
    for (i, candidate) in NAME_PTRS.0.iter().enumerate() {
        // SAFETY: `name` is NUL-terminated per the caller's contract and
        // `candidate` is a pointer to a static literal, so both are readable.
        if unsafe { OPENSSL_strcasecmp(name, *candidate) } == 0 {
            return i as c_int;
        }
    }
    -1
}

/// `int OSSL_trace_set_channel(int category, BIO *channel)`
///
/// `0`, unconditionally under `OPENSSL_NO_TRACE`.
#[no_mangle]
pub extern "C" fn OSSL_trace_set_channel(_category: c_int, _channel: *mut Bio) -> c_int {
    0
}

/// `int OSSL_trace_set_callback(int category, OSSL_trace_cb callback, void *data)`
///
/// `0`, unconditionally under `OPENSSL_NO_TRACE`.
#[no_mangle]
pub extern "C" fn OSSL_trace_set_callback(
    _category: c_int,
    _callback: Option<OsslTraceCb>,
    _data: *mut c_void,
) -> c_int {
    0
}

/// `int OSSL_trace_set_prefix(int category, const char *prefix)`
///
/// `0`, unconditionally under `OPENSSL_NO_TRACE`.
#[no_mangle]
pub extern "C" fn OSSL_trace_set_prefix(_category: c_int, _prefix: *const c_char) -> c_int {
    0
}

/// `int OSSL_trace_set_suffix(int category, const char *suffix)`
///
/// `0`, unconditionally under `OPENSSL_NO_TRACE`.
#[no_mangle]
pub extern "C" fn OSSL_trace_set_suffix(_category: c_int, _suffix: *const c_char) -> c_int {
    0
}

/// `int OSSL_trace_enabled(int category)`
///
/// `0` under `OPENSSL_NO_TRACE`: `ret` is initialised outside the guard and
/// nothing inside it runs.
#[no_mangle]
pub extern "C" fn OSSL_trace_enabled(_category: c_int) -> c_int {
    0
}

/// `BIO *OSSL_trace_begin(int category)`
///
/// `NULL` under `OPENSSL_NO_TRACE`. This is what the `OSSL_TRACE_BEGIN` macro
/// calls, so under this profile `OSSL_TRACE_BEGIN` writes nothing anywhere.
#[no_mangle]
pub extern "C" fn OSSL_trace_begin(_category: c_int) -> *mut Bio {
    core::ptr::null_mut()
}

/// `void OSSL_trace_end(int category, BIO *channel)`
///
/// Under `OPENSSL_NO_TRACE` the body is empty: no flush, and none of the
/// `ossl_assert(channel == current_channel)` the full build performs. The channel
/// a caller passes is not touched.
#[no_mangle]
pub extern "C" fn OSSL_trace_end(_category: c_int, _channel: *mut Bio) {}

/// `int OSSL_trace_string(BIO *out, int text, int full, const unsigned char *data,
/// size_t size)`
///
/// Formats up to `OSSL_TRACE_STRING_MAX` bytes to `out` and returns what
/// `BIO_printf` returned. This function is **not** inside a `#ifndef`, so it is
/// fully live in this profile, and its three documented behaviours are all
/// observable:
///
/// * `full == 0` and `size > 80` writes a `[len N limited to 80]: ` prefix first;
/// * `text == 0` masks control characters to spaces **while preserving newlines**,
///   and appends a newline unless the last byte read already was one;
/// * the result goes out through `%.*s`, so a NUL byte inside the range does not
///   terminate it.
///
/// The clamp described in this module's header engages only when `full != 0` and
/// `size > 80`.
///
/// # Safety
/// `out` must be NULL or a live `BIO`. `data` must point to at least `size`
/// readable bytes when `size != 0`.
#[no_mangle]
pub unsafe extern "C" fn OSSL_trace_string(
    out: *mut Bio,
    text: c_int,
    full: c_int,
    data: *const u8,
    size: usize,
) -> c_int {
    let mut buf = [0u8; OSSL_TRACE_STRING_MAX + 1];
    let limited = full == 0 && size > OSSL_TRACE_STRING_MAX;
    let len = if limited {
        OSSL_TRACE_STRING_MAX
    } else {
        size.min(OSSL_TRACE_STRING_MAX)
    };
    if limited {
        // SAFETY: `out` is the caller's BIO, and the format is a literal whose one
        // `size_t` and one `int` conversion match the arguments passed.
        unsafe {
            BIO_printf(
                out,
                c"[len %zu limited to %d]: ".as_ptr(),
                size,
                OSSL_TRACE_STRING_MAX as c_int,
            );
        }
    }

    let (src, out_len) = if text == 0 {
        for (i, slot) in buf.iter_mut().enumerate().take(len) {
            // SAFETY: the caller's contract says `data` holds at least `size`
            // bytes, and `i < len <= size`.
            let byte = unsafe { *data.add(i) };
            *slot = if byte != b'\n' && ossl_iscntrl(byte) {
                b' '
            } else {
                byte
            };
        }
        // The authority's `data[-1]` after its `data++` loop is the last byte it
        // read, so this is "the input did not end in a newline".
        // SAFETY: as above, with `len - 1 < size`.
        let last_is_newline = len > 0 && unsafe { *data.add(len - 1) } == b'\n';
        let out_len = if len == 0 || !last_is_newline {
            buf[len] = b'\n';
            len + 1
        } else {
            len
        };
        (buf.as_ptr(), out_len)
    } else {
        (data, len)
    };

    // SAFETY: `out` is the caller's BIO; `src` is either the caller's buffer, with
    // at least `size >= out_len` readable bytes, or `buf`, which is 81 bytes with
    // `out_len - 1 <= 80` written.
    unsafe { BIO_printf(out, c"%.*s".as_ptr(), out_len as c_int, src) }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CString;

    /// `trace_categories[].name`, in index order, exactly as `crypto/trace.c`'s
    /// `TRACE_CATEGORY_(...)` list writes them. The index *is* the category number,
    /// which is what `OSSL_trace_get_category_name` returns and what
    /// `OSSL_trace_get_category_num` searches for.
    ///
    /// Held here rather than beside `NAME_PTRS` so that the test below compares the
    /// table the *build* uses against the list read out of `trace.c`, instead of
    /// against a second copy of itself: an unused `const` beside the static would be
    /// a list nobody checks.
    const TRACE_CATEGORY_NAMES: [&str; OSSL_TRACE_CATEGORY_NUM] = [
        "ALL",
        "TRACE",
        "INIT",
        "TLS",
        "TLS_CIPHER",
        "CONF",
        "ENGINE_TABLE",
        "ENGINE_REF_COUNT",
        "PKCS5V2",
        "PKCS12_KEYGEN",
        "PKCS12_DECRYPT",
        "X509V3_POLICY",
        "BN_CTX",
        "CMP",
        "STORE",
        "DECODER",
        "ENCODER",
        "REF_COUNT",
        "HTTP",
        "PROVIDER",
        "QUERY",
    ];

    #[test]
    fn names_and_numbers_round_trip() {
        for (i, name) in TRACE_CATEGORY_NAMES.iter().enumerate() {
            let ptr = OSSL_trace_get_category_name(i as c_int);
            assert!(!ptr.is_null(), "category {i} has a name");
            // SAFETY: the returned pointer is a static NUL-terminated literal.
            let got = unsafe { std::ffi::CStr::from_ptr(ptr) };
            assert_eq!(got.to_str(), Ok(*name));
            let Ok(text) = CString::new(*name) else {
                unreachable!("the literal has no interior NUL")
            };
            // SAFETY: `text` is NUL-terminated.
            // SAFETY: `text` is a live NUL-terminated `CString`.
            let num = unsafe { OSSL_trace_get_category_num(text.as_ptr()) };
            assert_eq!(num, i as c_int);
        }
    }

    #[test]
    fn the_range_is_exclusive_and_the_lookup_is_case_insensitive() {
        assert!(OSSL_trace_get_category_name(-1).is_null());
        assert!(OSSL_trace_get_category_name(21).is_null());
        // SAFETY: NULL is an explicitly supported argument for this function, which
        // is what the assertion is about.
        let null_answer = unsafe { OSSL_trace_get_category_num(core::ptr::null()) };
        assert_eq!(null_answer, -1);
        let Ok(lower) = CString::new("tls_cipher") else {
            unreachable!()
        };
        let Ok(upper) = CString::new("X509v3_Policy") else {
            unreachable!()
        };
        let Ok(unknown) = CString::new("NOT_A_CATEGORY") else {
            unreachable!()
        };
        // SAFETY: each `CString` is a live NUL-terminated string.
        let (lower_num, upper_num, unknown_num) = unsafe {
            (
                OSSL_trace_get_category_num(lower.as_ptr()),
                OSSL_trace_get_category_num(upper.as_ptr()),
                OSSL_trace_get_category_num(unknown.as_ptr()),
            )
        };
        assert_eq!(lower_num, 4);
        assert_eq!(upper_num, 11);
        assert_eq!(unknown_num, -1);
    }

    #[test]
    fn the_profile_answers_zero_and_null_everywhere_it_should() {
        for category in [-1, 0, 5, 20, 21] {
            assert_eq!(OSSL_trace_set_channel(category, core::ptr::null_mut()), 0);
            assert_eq!(OSSL_trace_set_prefix(category, core::ptr::null()), 0);
            assert_eq!(OSSL_trace_set_suffix(category, core::ptr::null()), 0);
            assert_eq!(
                OSSL_trace_set_callback(category, None, core::ptr::null_mut()),
                0
            );
            assert_eq!(OSSL_trace_enabled(category), 0);
            assert!(OSSL_trace_begin(category).is_null());
            OSSL_trace_end(category, core::ptr::null_mut());
        }
    }

    #[test]
    fn control_bytes_are_masked_and_newlines_are_not() {
        // The predicate itself, which is what the masking depends on.
        assert!(ossl_iscntrl(0x00));
        assert!(ossl_iscntrl(0x1f));
        assert!(!ossl_iscntrl(b' '));
        assert!(!ossl_iscntrl(b'~'));
        assert!(ossl_iscntrl(0x7f));
        // Outside `ctype_char_map`, so not a control character -- see the note on
        // `ossl_iscntrl`. `OSSL_trace_string` passes these through unchanged.
        assert!(!ossl_iscntrl(0x80));
        assert!(!ossl_iscntrl(0xff));
    }
}
