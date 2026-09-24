//! Phase 8 — `crypto/quic_vlint.c`: the QUIC variable-length integer codec.
//!
//! This unit has no stratum's plan row and is transcribed here because `crypto/packet.c`'s
//! QUIC half calls it: `put_quic_value` and `WPACKET_quic_write_vlint` are reached by
//! `WPACKET_start_quic_sub_packet*`, and `OPENSSL_NO_QUIC` is **absent** from the admitted
//! `configuration.h`, so those functions are compiled and their callee is not optional. The
//! unit is `include/internal/quic_vlint.h`'s and its four exports are all internal.
//!
//! **Transcribed whole** (D327's rule): the two functions that are external symbols in the
//! authority's object ([`ossl_quic_vlint_encode_n`], [`ossl_quic_vlint_encode`],
//! [`ossl_quic_vlint_decode_unchecked`], [`ossl_quic_vlint_decode`]) *and* the two the header
//! defines `static ossl_inline` ([`ossl_quic_vlint_encode_len`], [`ossl_quic_vlint_decode_len`]),
//! which the authority's object does not carry but every caller in `packet.c` and this file
//! reads. The `#ifndef OPENSSL_NO_QUIC` guard is the authority's own and this profile takes the
//! defined arm.
//!
//! The `encode_n`/`decode_unchecked` arms write and read `uint8_t`s at a `c_uchar *`, exactly as
//! the authority does; the two length helpers are the header's bit tests.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_int, c_uchar};

/// `uint64_t` — the decoded value.
type U64 = u64;

/// `#define OSSL_QUIC_VLINT_2B_MIN 64` — the smallest value needing two bytes.
pub(crate) const OSSL_QUIC_VLINT_2B_MIN: U64 = 64;
/// `#define OSSL_QUIC_VLINT_4B_MIN 16384` — the smallest value needing four bytes.
pub(crate) const OSSL_QUIC_VLINT_4B_MIN: U64 = 16384;
/// `#define OSSL_QUIC_VLINT_8B_MIN 1073741824` — the smallest value needing eight bytes.
pub(crate) const OSSL_QUIC_VLINT_8B_MIN: U64 = 1073741824;
/// `#define OSSL_QUIC_VLINT_8B_MAX (((uint64_t)1 << 62) - 1)` — the largest encodable value.
pub(crate) const OSSL_QUIC_VLINT_8B_MAX: U64 = (1u64 << 62) - 1;

/// `size_t ossl_quic_vlint_encode_len(uint64_t v)` — `internal/quic_vlint.h:39-54`.
///
/// The number of bytes the minimal encoding of `v` needs, or 0 when `v` is above
/// [`OSSL_QUIC_VLINT_8B_MAX`]. The header's two `if`s are a range test, so the arms are the
/// constants' own comparisons rather than arithmetic on the exponent.
pub(crate) fn ossl_quic_vlint_encode_len(v: U64) -> usize {
    if v < OSSL_QUIC_VLINT_2B_MIN {
        return 1;
    }
    if v < OSSL_QUIC_VLINT_4B_MIN {
        return 2;
    }
    if v < OSSL_QUIC_VLINT_8B_MIN {
        return 4;
    }
    if v <= OSSL_QUIC_VLINT_8B_MAX {
        return 8;
    }
    0
}

/// `size_t ossl_quic_vlint_decode_len(uint8_t first_byte)` — `internal/quic_vlint.h:97-100`.
///
/// The length is `1 << (top two bits)`, so the four legal values are 1, 2, 4 and 8.
#[allow(dead_code)] // transcribed whole; the DER path reads none of the QUIC decode side (D342)
pub(crate) fn ossl_quic_vlint_decode_len(first_byte: u8) -> usize {
    1usize << ((first_byte & 0xC0) >> 6)
}

/// `void ossl_quic_vlint_encode_n(unsigned char *buf, uint64_t v, int n)` —
/// `crypto/quic_vlint.c:6-28`.
///
/// The caller has already established `n` is one of 1, 2, 4 or 8 and that `v` fits; the final
/// `else` is the eight-byte arm, which is the authority's own fall-through. The first byte
/// carries the two length bits in its top half and the value's high bits below them.
///
/// # Safety
///
/// `buf` is writable for `n` bytes, `n` is one of 1, 2, 4 or 8, and `v` fits the chosen width.
pub(crate) unsafe fn ossl_quic_vlint_encode_n(buf: *mut c_uchar, v: U64, n: c_int) {
    // SAFETY: `buf` is writable for `n` bytes per the contract.
    unsafe {
        if n == 1 {
            *buf = v as u8;
        } else if n == 2 {
            *buf = 0x40 | ((v >> 8) as u8 & 0x3F);
            *buf.add(1) = v as u8;
        } else if n == 4 {
            *buf = 0x80 | ((v >> 24) as u8 & 0x3F);
            *buf.add(1) = (v >> 16) as u8;
            *buf.add(2) = (v >> 8) as u8;
            *buf.add(3) = v as u8;
        } else {
            *buf = 0xC0 | ((v >> 56) as u8 & 0x3F);
            *buf.add(1) = (v >> 48) as u8;
            *buf.add(2) = (v >> 40) as u8;
            *buf.add(3) = (v >> 32) as u8;
            *buf.add(4) = (v >> 24) as u8;
            *buf.add(5) = (v >> 16) as u8;
            *buf.add(6) = (v >> 8) as u8;
            *buf.add(7) = v as u8;
        }
    }
}

/// `void ossl_quic_vlint_encode(unsigned char *buf, uint64_t v)` — `crypto/quic_vlint.c:30-33`.
///
/// The minimal encoding: the width is [`ossl_quic_vlint_encode_len`]'s answer and the body is
/// [`ossl_quic_vlint_encode_n`]'s.
///
/// # Safety
///
/// `buf` is writable for `ossl_quic_vlint_encode_len(v)` bytes and `v` is at most
/// [`OSSL_QUIC_VLINT_8B_MAX`].
#[allow(dead_code)] // transcribed whole; the DER path writes no QUIC value (D342)
pub(crate) unsafe fn ossl_quic_vlint_encode(buf: *mut c_uchar, v: U64) {
    // SAFETY: the contract gives `buf` room for the minimal encoding and `v` fits it.
    unsafe { ossl_quic_vlint_encode_n(buf, v, ossl_quic_vlint_encode_len(v) as c_int) }
}

/// `uint64_t ossl_quic_vlint_decode_unchecked(const unsigned char *buf)` —
/// `crypto/quic_vlint.c:35-61`.
///
/// The caller has checked the first byte is readable and that the buffer holds
/// [`ossl_quic_vlint_decode_len`] bytes. The value is the low six bits of each length arm's
/// first byte followed by the byte's own big-endian payload.
///
/// # Safety
///
/// `buf` is readable for `ossl_quic_vlint_decode_len(*buf)` bytes.
#[allow(dead_code)] // transcribed whole; the DER path reads none of the QUIC decode side (D342)
pub(crate) unsafe fn ossl_quic_vlint_decode_unchecked(buf: *const c_uchar) -> U64 {
    // SAFETY: the first byte is readable per the contract.
    let first_byte = unsafe { *buf };
    let sz = ossl_quic_vlint_decode_len(first_byte);

    if sz == 1 {
        return (first_byte & 0x3F) as U64;
    }
    if sz == 2 {
        // SAFETY: the contract gives the buffer `sz == 2` readable bytes.
        return (((first_byte & 0x3F) as U64) << 8) | unsafe { *buf.add(1) } as U64;
    }
    if sz == 4 {
        // SAFETY: the contract gives the buffer `sz == 4` readable bytes.
        return (((first_byte & 0x3F) as U64) << 24)
            | ((unsafe { *buf.add(1) } as U64) << 16)
            | ((unsafe { *buf.add(2) } as U64) << 8)
            | unsafe { *buf.add(3) } as U64;
    }
    // SAFETY: the contract gives the buffer `sz == 8` readable bytes.
    (((first_byte & 0x3F) as U64) << 56)
        | ((unsafe { *buf.add(1) } as U64) << 48)
        | ((unsafe { *buf.add(2) } as U64) << 40)
        | ((unsafe { *buf.add(3) } as U64) << 32)
        | ((unsafe { *buf.add(4) } as U64) << 24)
        | ((unsafe { *buf.add(5) } as U64) << 16)
        | ((unsafe { *buf.add(6) } as U64) << 8)
        | unsafe { *buf.add(7) } as U64
}

/// `int ossl_quic_vlint_decode(const unsigned char *buf, size_t buf_len, uint64_t *v)` —
/// `crypto/quic_vlint.c:63-79`.
///
/// Returns the number of bytes consumed, or 0 on a truncated buffer. `v` is written only on
/// success, which is why the caller's value is untouched by a refusal.
///
/// # Safety
///
/// `buf` is readable for `buf_len` bytes; `v` is NULL or writable.
#[allow(dead_code)] // transcribed whole; the DER path reads none of the QUIC decode side (D342)
pub(crate) unsafe fn ossl_quic_vlint_decode(
    buf: *const c_uchar,
    buf_len: usize,
    v: *mut U64,
) -> c_int {
    if buf_len < 1 {
        return 0;
    }
    // SAFETY: `buf_len >= 1`, so the first byte is readable.
    let dec_len = ossl_quic_vlint_decode_len(unsafe { *buf });
    if buf_len < dec_len {
        return 0;
    }

    // SAFETY: `buf_len >= dec_len`, so `decode_unchecked`'s contract holds.
    let x = unsafe { ossl_quic_vlint_decode_unchecked(buf) };

    // SAFETY: `v` is writable or NULL per the contract; the authority dereferences it without a
    // NULL test, so the caller's contract is the guard.
    unsafe { *v = x };
    dec_len as c_int
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_width_boundaries_are_the_headers_own() {
        assert_eq!(ossl_quic_vlint_encode_len(0), 1);
        assert_eq!(ossl_quic_vlint_encode_len(63), 1);
        assert_eq!(ossl_quic_vlint_encode_len(64), 2);
        assert_eq!(ossl_quic_vlint_encode_len(16383), 2);
        assert_eq!(ossl_quic_vlint_encode_len(16384), 4);
        assert_eq!(ossl_quic_vlint_encode_len(1073741823), 4);
        assert_eq!(ossl_quic_vlint_encode_len(1073741824), 8);
        assert_eq!(ossl_quic_vlint_encode_len(OSSL_QUIC_VLINT_8B_MAX), 8);
        assert_eq!(ossl_quic_vlint_encode_len(OSSL_QUIC_VLINT_8B_MAX + 1), 0);
    }

    #[test]
    fn a_round_trip_is_the_identity_at_every_width() {
        let mut buf = [0u8; 8];
        for v in [
            0u64,
            63,
            64,
            16383,
            16384,
            1073741823,
            1073741824,
            OSSL_QUIC_VLINT_8B_MAX,
        ] {
            let n = ossl_quic_vlint_encode_len(v);
            // SAFETY: `buf` owns eight bytes, which is every width, and `v` fits its width.
            unsafe { ossl_quic_vlint_encode(buf.as_mut_ptr(), v) };
            assert_eq!(ossl_quic_vlint_decode_len(buf[0]), n);
            let mut out = 0u64;
            // SAFETY: `buf` holds `n` written bytes and `out` is a live local.
            let consumed = unsafe { ossl_quic_vlint_decode(buf.as_ptr(), n, &mut out) };
            assert_eq!(consumed, n as c_int);
            assert_eq!(out, v);
        }
    }
}
