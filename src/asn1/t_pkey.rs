//! Phase 5 — `crypto/asn1/t_pkey.c`: the two number-printing helpers.
//!
//! `ASN1_buf_print` writes a byte buffer as colon-separated hexadecimal, fifteen
//! octets to a line, each line indented by `BIO_indent`. `ASN1_bn_print` is the
//! `BIGNUM` form and has three shapes, chosen by the *value* rather than by the
//! caller:
//!
//! * a null number is a success with no output at all — not a failure, and not an
//!   empty line;
//! * zero is printed by value, `"<name> 0\n"`;
//! * a number that fits in one limb is printed as a decimal and a hexadecimal,
//!   `"<name> <neg><dec> (<neg>0x<hex>)\n"`, with the sign repeated inside the
//!   parentheses;
//! * anything wider is printed by magnitude in hexadecimal, prefixed with
//!   `" (Negative)"` when it is negative, and the magnitude is prefixed with a
//!   zero octet when the top bit of the first significant octet is set so that the
//!   printed form reads as an unsigned magnitude.
//!
//! That last point is what the `buf[1] & 0x80` test is for, and it is why the
//! output buffer is one byte longer than the magnitude and why `tmp` starts one
//! byte in when it does not: `BN_bn2bin` writes exactly `BN_num_bytes` bytes and
//! cannot be told to prepend anything.
//!
//! `ASN1_buf_print` is a separate export because a caller with a raw buffer needs
//! exactly its format, and because `ASN1_bn_print`'s own indentation of the digits
//! is four columns deeper than its own.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_char, c_int, c_uchar, c_ulong};

use crate::bn::bignum::{BN_bn2bin, BN_is_negative, BN_is_zero, BigNum};
use crate::bn::limbs;
use crate::ffi::guard_ffi;
use crate::runtime::bio::iolib::{BIO_puts, BIO_write};
use crate::runtime::bio::print::{BIO_indent, BIO_printf};
use crate::runtime::bio::Bio;
use crate::runtime::mem::{CRYPTO_clear_free, CRYPTO_malloc};

/// The authority translation unit for the two printers.
pub(crate) const FILE: &core::ffi::CStr = c"crypto/asn1/t_pkey.c";
/// The authority passes `__LINE__`, inert under `OPENSSL_NO_CRYPTO_MDEBUG`.
pub(crate) const LINE: c_int = 0;

/// `ASN1_BUF_PRINT_WIDTH` — octets per line.
const ASN1_BUF_PRINT_WIDTH: usize = 15;
/// `ASN1_PRINT_MAX_INDENT` — the most columns `BIO_indent` will write.
///
/// It is **128**, not 80. The first version of this module had 80 here, taken from
/// the ASCII line width rather than from the header, and RT-ASN1-STR found it: with
/// an indent of 81 the authority writes 81 spaces and 80 is a visible truncation of
/// two octets over two lines. A constant read out of `t_pkey.c` rather than
/// recalled would have been right the first time.
const ASN1_PRINT_MAX_INDENT: c_int = 128;
/// The authority's indentation for the digits of a wide number.
const NEG_INDENT: c_int = 4;

/// `int ASN1_buf_print(BIO *bp, const unsigned char *buf, size_t buflen,
/// int indent)`
///
/// The first line is not preceded by a newline; every later one is, and every line
/// is indented. A failing indent or write stops the whole print with 0, so a
/// partially-written buffer is possible and is the caller's to interpret.
///
/// # Safety
///
/// `bp` must be a live BIO; `buf` must be readable for `buflen` bytes.
#[no_mangle]
pub unsafe extern "C" fn ASN1_buf_print(
    bp: *mut Bio,
    buf: *const c_uchar,
    buflen: usize,
    indent: c_int,
) -> c_int {
    guard_ffi(0, || {
        for i in 0..buflen {
            if i % ASN1_BUF_PRINT_WIDTH == 0 {
                if i > 0 {
                    // SAFETY: `bp` is a live BIO.
                    if unsafe { BIO_puts(bp, c"\n".as_ptr()) } <= 0 {
                        return 0;
                    }
                }
                // SAFETY: `bp` is a live BIO.
                if unsafe { BIO_indent(bp, indent, ASN1_PRINT_MAX_INDENT) } == 0 {
                    return 0;
                }
            }
            // SAFETY: `buf` is readable for `buflen` bytes and `i < buflen`.
            let octet = unsafe { *buf.add(i) };
            // SAFETY: `bp` is a live BIO and the format matches the arguments.
            let n = unsafe {
                BIO_printf(
                    bp,
                    c"%02x%s".as_ptr(),
                    c_int::from(octet),
                    if i == buflen - 1 {
                        c"".as_ptr()
                    } else {
                        c":".as_ptr()
                    },
                )
            };
            if n <= 0 {
                return 0;
            }
        }
        // SAFETY: `bp` is a live BIO.
        if unsafe { BIO_write(bp, c"\n".as_ptr().cast(), 1) } <= 0 {
            return 0;
        }
        1
    })
}

/// `int ASN1_bn_print(BIO *bp, const char *number, const BIGNUM *num,
/// unsigned char *ign, int indent)`
///
/// `ign` is the authority's third parameter and is never read — it is the caller's
/// scratch buffer that an earlier version used, and it is kept in the signature
/// because it is part of the contract.
///
/// # Safety
///
/// `bp` must be a live BIO; `number` must be a NUL-terminated string; `num` must be
/// null or a live `BIGNUM`.
#[no_mangle]
pub unsafe extern "C" fn ASN1_bn_print(
    bp: *mut Bio,
    number: *const c_char,
    num: *const BigNum,
    ign: *mut c_uchar,
    indent: c_int,
) -> c_int {
    guard_ffi(0, || {
        let _ = ign;
        if num.is_null() {
            return 1;
        }
        // SAFETY: the caller's contract makes `num` a live `BIGNUM`.
        let neg: &core::ffi::CStr = if unsafe { BN_is_negative(num) } != 0 {
            c"-"
        } else {
            c""
        };
        // SAFETY: `bp` is a live BIO.
        if unsafe { BIO_indent(bp, indent, ASN1_PRINT_MAX_INDENT) } == 0 {
            return 0;
        }
        // SAFETY: `num` is live.
        if unsafe { BN_is_zero(num) } != 0 {
            // SAFETY: `bp` is a live BIO, `number` is NUL-terminated.
            if unsafe { BIO_printf(bp, c"%s 0\n".as_ptr(), number) } <= 0 {
                return 0;
            }
            return 1;
        }

        // SAFETY: `num` is live, so `d` is a live limb vector.
        let nbytes = (limbs::bit_len(unsafe { &(*num).d }).div_ceil(8)) as c_int;
        if nbytes <= core::mem::size_of::<c_ulong>() as c_int {
            // SAFETY: the value fits in one limb, so the first limb is the value.
            let word = unsafe { (*num).d.first().copied().unwrap_or(0) };
            // SAFETY: `bp` is a live BIO and the format matches the arguments.
            if unsafe {
                BIO_printf(
                    bp,
                    c"%s %s%lu (%s0x%lx)\n".as_ptr(),
                    number,
                    neg.as_ptr(),
                    word,
                    neg.as_ptr(),
                    word,
                )
            } <= 0
            {
                return 0;
            }
            return 1;
        }

        let buflen = nbytes as usize + 1;
        // SAFETY: `CRYPTO_malloc` answers null or `buflen` bytes.
        let buf = CRYPTO_malloc(buflen, FILE.as_ptr(), LINE).cast::<c_uchar>();
        if buf.is_null() {
            return 0;
        }
        // SAFETY: `buf` owns `buflen` bytes and `buflen >= 2`.
        unsafe { *buf = 0 };
        // SAFETY: `bp` is a live BIO, `number` is NUL-terminated.
        let header = unsafe {
            BIO_printf(
                bp,
                c"%s%s\n".as_ptr(),
                number,
                if !neg.is_empty() {
                    c" (Negative)".as_ptr()
                } else {
                    c"".as_ptr()
                },
            )
        };
        if header <= 0 {
            // SAFETY: `buf` came from this allocator and is not owned elsewhere.
            unsafe { CRYPTO_clear_free(buf.cast(), buflen, FILE.as_ptr(), LINE) };
            return 0;
        }
        // SAFETY: `buf` owns `buflen` and the caller's contract makes `num` live;
        // `BN_bn2bin` writes exactly `nbytes` bytes at `buf + 1`.
        let n = unsafe { BN_bn2bin(num, buf.add(1)) };

        // The magnitude's first octet is significant only from here on. When its
        // top bit is set the leading zero is what keeps the printed form unsigned,
        // so it stays in the count; otherwise the leading zero is skipped.
        // SAFETY: `buf` has `buflen = nbytes + 1` bytes and `n <= nbytes`.
        let (tmp, n) = if unsafe { *buf.add(1) } & 0x80 != 0 {
            (buf, n + 1)
        } else {
            // SAFETY: one byte past the start of an allocation of at least two bytes.
            (unsafe { buf.add(1) }, n)
        };

        // SAFETY: `tmp` holds `n` bytes and `bp` is a live BIO.
        let rv = unsafe { ASN1_buf_print(bp, tmp, n as usize, indent + NEG_INDENT) };
        // SAFETY: `buf` came from this allocator, is not owned elsewhere, and is
        // `buflen` bytes long; the secret-clearing free is the authority's.
        unsafe { CRYPTO_clear_free(buf.cast(), buflen, FILE.as_ptr(), LINE) };
        if rv == 0 {
            0
        } else {
            1
        }
    })
}
