//! `crypto/punycode.c` — the RFC 3492 Punycode decoder and the A-label→U-label
//! conversion `crypto/x509/v3_ncons.c` needs. Landed whole.
//!
//! The authority unit is 316 lines (`include/crypto/punycode.h` is its only header) and
//! defines exactly **two** external names:
//!
//! * `ossl_punycode_decode` (`:119-200`) — decode an `xn--`-stripped A-label into code
//!   points, refusing anything that would overflow a `unsigned int` or the output buffer.
//! * `ossl_a2ulabel` (`:252-316`) — the A-label→U-label walk: split the domain on `.`,
//!   copy `xn--`-free labels through unchanged, and decode `xn--` labels to UTF-8.
//!
//! It also defines four `static` helpers — `adapt` (`:44-58`), `is_basic` (`:60-63`),
//! `digit_decoded` (`:72-84`) and `codepoint2utf8` (`:207-243`) — which are private Rust
//! functions here. There is **no** `ossl_punycode_encode` in this file, despite the
//! dependency brief naming one: neither `crypto/punycode.c` nor `include/crypto/punycode.h`
//! declares or defines an encoder, and no other unit defines one either.
//!
//! ## ABI
//!
//! Both external names are non-`static` C symbols, so each is `#[no_mangle] pub unsafe
//! extern "C" fn`; the four helpers are `static` in the authority and carry no
//! `#[no_mangle]`. Neither external name appears in `util/libcrypto.num` (the DSO export
//! list) — they are internal `ossl_*` symbols reached by Rust path from
//! `crate::punycode::ossl_a2ulabel`, which is the single name `v3_ncons.c` needs.
//!
//! ## The two contracts that are easy to lose
//!
//! * The digit and basic checks are done on the **C `char`**, not on a `u8`: the authority
//!   compares `pEncoded[loop] == delimiter` and passes `pEncoded[loop]` to `is_basic`'s
//!   `unsigned int` parameter, so a byte with the high bit set sign-extends to a value
//!   `>= 0x80` and is rejected. The transcription casts through `c_char` to keep that.
//! * Every arithmetic step is `unsigned int` and checked *before* it can wrap:
//!   `digit > (maxint - i) / w`, `w > maxint / (base - t)`, and `i / (written_out + 1) >
//!   maxint - n` each return 0 rather than let an overflow through, and the final
//!   `memmove` is the Rust `ptr::copy` (`memmove` semantics) over a range the preceding
//!   bound check has proved in-bounds.
//!
//! SPDX-License-Identifier: Apache-2.0

#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]

use core::ffi::{c_char, c_int, c_uchar, c_uint, c_ulong};

use crate::packet::{
    WPACKET_cleanup, WPACKET_init_static_len, WPACKET_memcpy, WPACKET_put_bytes_u8, Wpacket,
};
use crate::runtime::bio::sys::{strchr, strlen, strncmp};

// ---------------------------------------------------------------------------
// The Punycode constants and the four `static` helpers
// ---------------------------------------------------------------------------

/// `static const unsigned int base = 36;` — `crypto/punycode.c:17`.
const base: c_uint = 36;
/// `static const unsigned int tmin = 1;` — `crypto/punycode.c:18`.
const tmin: c_uint = 1;
/// `static const unsigned int tmax = 26;` — `crypto/punycode.c:19`.
const tmax: c_uint = 26;
/// `static const unsigned int skew = 38;` — `crypto/punycode.c:20`.
const skew: c_uint = 38;
/// `static const unsigned int damp = 700;` — `crypto/punycode.c:21`.
const damp: c_uint = 700;
/// `static const unsigned int initial_bias = 72;` — `crypto/punycode.c:22`.
const initial_bias: c_uint = 72;
/// `static const unsigned int initial_n = 0x80;` — `crypto/punycode.c:23`.
const initial_n: c_uint = 0x80;
/// `static const unsigned int maxint = 0xFFFFFFFF;` — `crypto/punycode.c:24`.
const maxint: c_uint = 0xFFFFFFFF;
/// `static const char delimiter = '-';` — `crypto/punycode.c:25`.
const delimiter: c_char = b'-' as c_char;

/// `#define LABEL_BUF_SIZE 512` — `crypto/punycode.c:27`. The size of `ossl_a2ulabel`'s
/// stack code-point buffer, and the initial `pout_length` it passes to the decoder.
const LABEL_BUF_SIZE: usize = 512;

/// `static int adapt(unsigned int delta, unsigned int numpoints, unsigned int firsttime)`
/// — `crypto/punycode.c:44-58`.
///
/// `firsttime` is the authority's `unsigned int` truthiness value; `oldi == 0` is its only
/// caller-side source, so a `bool` carries the same information.
fn adapt(delta: c_uint, numpoints: c_uint, firsttime: bool) -> c_int {
    let mut k: c_uint = 0;
    let mut delta = if firsttime { delta / damp } else { delta / 2 };

    delta += delta / numpoints;

    while delta > ((base - tmin) * tmax) / 2 {
        delta /= base - tmin;
        k += base;
    }

    (k + (((base - tmin + 1) * delta) / (delta + skew))) as c_int
}

/// `static ossl_inline int is_basic(unsigned int a)` — `crypto/punycode.c:60-63`:
/// `return (a < 0x80) ? 1 : 0;`. Returned as a `bool`, its only use.
fn is_basic(a: c_uint) -> bool {
    a < 0x80
}

/// `static ossl_inline int digit_decoded(const unsigned char a)` — `crypto/punycode.c:72-84`.
///
/// `A-Z`/`a-z`/`0-9` map to `0..25`/`0..25`/`26..35`; anything else is `-1`.
fn digit_decoded(a: c_uchar) -> c_int {
    if (0x41..=0x5A).contains(&a) {
        return c_int::from(a - 0x41);
    }

    if (0x61..=0x7A).contains(&a) {
        return c_int::from(a - 0x61);
    }

    if (0x30..=0x39).contains(&a) {
        return c_int::from(a - 0x30) + 26;
    }

    -1
}

/// `static int codepoint2utf8(unsigned char *out, unsigned long utf)` — `crypto/punycode.c:207-243`.
///
/// Encodes one code point as UTF-8 and answers the number of bytes written, leaving a NUL
/// one past them; a code point above `U+10FFFF` writes the three-byte replacement character
/// and answers 0. `out` must be at least 5 bytes (the four-byte arm writes four bytes plus
/// the terminator), which is why the caller's `seed` is `[u8; 6]`.
///
/// # Safety
///
/// `out` must be writable for at least 5 bytes.
unsafe fn codepoint2utf8(out: *mut c_uchar, utf: c_ulong) -> c_int {
    if utf <= 0x7F {
        // SAFETY: `out` is writable for at least 5 bytes per the contract.
        unsafe { *out = utf as c_uchar };
        // SAFETY: index 1 is in bounds.
        unsafe { *out.add(1) = 0 };
        1
    } else if utf <= 0x07FF {
        // SAFETY: indices 0..=2 are in bounds.
        unsafe {
            *out = (((utf >> 6) & 0x1F) | 0xC0) as c_uchar;
            *out.add(1) = ((utf & 0x3F) | 0x80) as c_uchar;
            *out.add(2) = 0;
        }
        2
    } else if utf <= 0xFFFF {
        // SAFETY: indices 0..=3 are in bounds.
        unsafe {
            *out = (((utf >> 12) & 0x0F) | 0xE0) as c_uchar;
            *out.add(1) = (((utf >> 6) & 0x3F) | 0x80) as c_uchar;
            *out.add(2) = ((utf & 0x3F) | 0x80) as c_uchar;
            *out.add(3) = 0;
        }
        3
    } else if utf <= 0x10FFFF {
        // SAFETY: indices 0..=4 are in bounds.
        unsafe {
            *out = (((utf >> 18) & 0x07) | 0xF0) as c_uchar;
            *out.add(1) = (((utf >> 12) & 0x3F) | 0x80) as c_uchar;
            *out.add(2) = (((utf >> 6) & 0x3F) | 0x80) as c_uchar;
            *out.add(3) = ((utf & 0x3F) | 0x80) as c_uchar;
            *out.add(4) = 0;
        }
        4
    } else {
        // SAFETY: indices 0..=3 are in bounds.
        unsafe {
            *out = 0xEF;
            *out.add(1) = 0xBF;
            *out.add(2) = 0xBD;
            *out.add(3) = 0;
        }
        0
    }
}

// ---------------------------------------------------------------------------
// The two external names
// ---------------------------------------------------------------------------

/// `int ossl_punycode_decode(const char *pEncoded, const size_t enc_len, unsigned int *pDecoded,
/// unsigned int *pout_length)` — `crypto/punycode.c:119-200`.
///
/// Decodes `enc_len` bytes of an `xn--`-stripped A-label into `p_decoded`, whose capacity in
/// code points arrives in `*pout_length` and is rewritten with the number written. Answers 1
/// on success, 0 on any refusal (non-basic copy range, bad digit, or an overflow the
/// pre-checks catch).
///
/// # Safety
///
/// `p_encoded` must be readable for `enc_len` bytes; `p_decoded` must be writable for at
/// least `*pout_length` `unsigned int`s; `pout_length` must point at a live, writable
/// `unsigned int`.
#[no_mangle]
pub unsafe extern "C" fn ossl_punycode_decode(
    p_encoded: *const c_char,
    enc_len: usize,
    p_decoded: *mut c_uint,
    pout_length: *mut c_uint,
) -> c_int {
    let mut n: c_uint = initial_n;
    let mut i: c_uint = 0;
    let mut bias: c_uint = initial_bias;
    let mut processed_in: c_uint = 0;
    let mut written_out: c_uint = 0;
    // SAFETY: `pout_length` is a live, writable `unsigned int` per the contract.
    let max_out: c_uint = unsafe { *pout_length };
    let mut basic_count: c_uint = 0;

    if enc_len >= c_uint::MAX as usize {
        return 0;
    }
    // The last delimiter splits the basic prefix from the encoded tail; the loop keeps
    // the *last* index at which the delimiter occurs, so it overwrites any earlier one.
    let mut loop_: c_uint = 0;
    while loop_ < enc_len as c_uint {
        // SAFETY: `loop_ < enc_len`, so the read is inside the caller's buffer.
        if unsafe { *p_encoded.add(loop_ as usize) } == delimiter {
            basic_count = loop_;
        }
        loop_ += 1;
    }

    if basic_count > 0 {
        if basic_count > max_out {
            return 0;
        }

        loop_ = 0;
        while loop_ < basic_count {
            // SAFETY: `loop_ < basic_count < enc_len`, inside the input buffer.
            if !is_basic(unsafe { *p_encoded.add(loop_ as usize) } as c_uint) {
                return 0;
            }

            // SAFETY: `loop_ < basic_count <= max_out`, so the write is inside `p_decoded`.
            unsafe { *p_decoded.add(loop_ as usize) = *p_encoded.add(loop_ as usize) as c_uint };
            written_out += 1;
            loop_ += 1;
        }
        processed_in = basic_count + 1;
    }

    loop_ = processed_in;
    while loop_ < enc_len as c_uint {
        let oldi = i;
        let mut w: c_uint = 1;
        let mut k: c_uint = base;

        loop {
            if loop_ >= enc_len as c_uint {
                return 0;
            }

            // SAFETY: `loop_ < enc_len`, inside the input buffer.
            let digit = digit_decoded(unsafe { *p_encoded.add(loop_ as usize) } as c_uchar);
            loop_ += 1;

            if digit < 0 {
                return 0;
            }
            if digit as c_uint > (maxint - i) / w {
                return 0;
            }

            i += digit as c_uint * w;
            let t = if k <= bias {
                tmin
            } else if k >= bias + tmax {
                tmax
            } else {
                k - bias
            };

            if (digit as c_uint) < t {
                break;
            }

            if w > maxint / (base - t) {
                return 0;
            }
            w *= base - t;
            k += base;
        }

        bias = adapt(i - oldi, written_out + 1, oldi == 0) as c_uint;
        if i / (written_out + 1) > maxint - n {
            return 0;
        }
        n += i / (written_out + 1);
        i %= written_out + 1;

        if written_out >= max_out {
            return 0;
        }

        // `memmove(pDecoded + i + 1, pDecoded + i, (written_out - i) * sizeof(*pDecoded))`.
        //
        // SAFETY: `i <= written_out` (it was just reduced modulo `written_out + 1`) and
        // `written_out < max_out` (checked directly above), so both the source range
        // `[i, written_out)` and the one-past destination are inside the caller's buffer of
        // at least `max_out` elements. `ptr::copy` is `memmove`, so the overlap is defined.
        unsafe {
            core::ptr::copy(
                p_decoded.add(i as usize),
                p_decoded.add(i as usize + 1),
                (written_out - i) as usize,
            );
        }
        // SAFETY: `i <= written_out < max_out` bounds the write inside `p_decoded`.
        unsafe { *p_decoded.add(i as usize) = n };
        i += 1;
        written_out += 1;
    }

    // SAFETY: `pout_length` is a live, writable `unsigned int` per the contract.
    unsafe { *pout_length = written_out };
    1
}

/// `HAS_PREFIX(str, pre)` — `include/internal/common.h:59`:
/// `strncmp(str, pre "", sizeof(pre) - 1) == 0`. For the `"xn--"` test `ossl_a2ulabel` makes.
///
/// # Safety
///
/// `s` must be NUL-terminated, so `strncmp` stops at its terminator rather than reading past it.
unsafe fn has_prefix(s: *const c_char, pre: &[u8]) -> bool {
    // SAFETY: `s` is NUL-terminated per the contract; `pre` is a static byte slice.
    unsafe { strncmp(s, pre.as_ptr().cast::<c_char>(), pre.len()) == 0 }
}

/// `int ossl_a2ulabel(const char *in, char *out, size_t outlen)` — `crypto/punycode.c:252-316`.
///
/// Walks `in` one dot-separated label at a time. A label shorter than the `xn--` prefix — or
/// not starting with it — is copied through unchanged; an `xn--` label is decoded to code
/// points and re-encoded as UTF-8. Answers 1 on success, 0 when the output buffer was too
/// short, and -1 on a malformed input or a failed internal setup.
///
/// # Safety
///
/// `in_` must be NUL-terminated; `out` must be writable for `outlen` bytes.
#[no_mangle]
pub unsafe extern "C" fn ossl_a2ulabel(
    in_: *const c_char,
    out: *mut c_char,
    outlen: usize,
) -> c_int {
    let mut inptr = in_;
    let mut result: c_int = 1;
    let mut buf = [0 as c_uint; LABEL_BUF_SIZE];
    // SAFETY: `Wpacket` is initialised by `WPACKET_init_static_len` below before it is read.
    let mut pkt = unsafe { core::mem::zeroed::<Wpacket>() };

    /* Internal API, so should not fail. */
    if ossl_assert(!out.is_null()) == 0 {
        return -1;
    }

    // SAFETY: `out` is writable for `outlen` bytes per the caller's contract.
    if unsafe { WPACKET_init_static_len(&mut pkt, out.cast::<c_uchar>(), outlen, 0) } == 0 {
        return -1;
    }

    'end: {
        loop {
            // SAFETY: `inptr` is NUL-terminated, so `strchr` stops at the terminator.
            let tmpptr = unsafe { strchr(inptr, c_int::from(b'.')) }.cast_const();
            let delta = if tmpptr.is_null() {
                // SAFETY: `inptr` is NUL-terminated per the contract.
                unsafe { strlen(inptr) }
            } else {
                // SAFETY: `tmpptr` points into the same NUL-terminated string after `inptr`.
                unsafe { tmpptr.offset_from(inptr) as usize }
            };

            // SAFETY: `inptr` is NUL-terminated, so `has_prefix`'s `strncmp` stops at it.
            if !unsafe { has_prefix(inptr, b"xn--") } {
                // SAFETY: `inptr` is readable for `delta` bytes (up to the terminator or the
                // dot found above).
                if unsafe { WPACKET_memcpy(&mut pkt, inptr.cast(), delta) } == 0 {
                    result = 0;
                }
            } else {
                let mut bufsize: c_uint = LABEL_BUF_SIZE as c_uint;

                // SAFETY: the `"xn--"` prefix is present, so `inptr + 4` is inside the label
                // and `delta - 4` (with `delta >= 4`) is its remaining length.
                if unsafe {
                    ossl_punycode_decode(inptr.add(4), delta - 4, buf.as_mut_ptr(), &mut bufsize)
                } <= 0
                {
                    result = -1;
                    break 'end;
                }

                for item in buf.iter().take(bufsize as usize) {
                    let mut seed = [0u8; 6];

                    // SAFETY: `seed` has 6 bytes, at least the 5 `codepoint2utf8` may write.
                    let utfsize = unsafe { codepoint2utf8(seed.as_mut_ptr(), *item as c_ulong) };
                    if utfsize == 0 {
                        result = -1;
                        break 'end;
                    }

                    // SAFETY: `seed` is readable for `utfsize` bytes.
                    if unsafe { WPACKET_memcpy(&mut pkt, seed.as_ptr().cast(), utfsize as usize) }
                        == 0
                    {
                        result = 0;
                    }
                }
            }

            if tmpptr.is_null() {
                break;
            }

            // SAFETY: `pkt` is live.
            if unsafe { WPACKET_put_bytes_u8(&mut pkt, b'.') } == 0 {
                result = 0;
            }

            // SAFETY: `tmpptr` points at a '.', so `tmpptr + 1` is inside the string.
            inptr = unsafe { tmpptr.add(1) };
        }

        // SAFETY: `pkt` is live; the trailing NUL is the output's terminator.
        if unsafe { WPACKET_put_bytes_u8(&mut pkt, 0) } == 0 {
            result = 0;
        }
    }

    // SAFETY: `pkt` was initialised above and is cleaned up exactly once.
    unsafe { WPACKET_cleanup(&mut pkt) };
    result
}

/// The authority's `ossl_assert` under `-DNDEBUG`, which this profile sets: a plain check
/// that returns its argument, not the `OPENSSL_die` form. `src/x509/x_pubkey.rs` carries
/// the same helper.
#[inline]
fn ossl_assert(expr: bool) -> c_int {
    c_int::from(expr)
}
