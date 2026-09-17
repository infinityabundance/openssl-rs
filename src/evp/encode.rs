//! Phase 7.5 — `crypto/evp/encode.c`: base64 over caller buffers, and nothing else.
//!
//! Twelve exports and two internals, and no dependency on any other stratum: this is the one
//! part of 7.5's row whose buildability was never in question. It is also the part the rest of
//! the row stands on — `crypto/pem/pem_lib.c`'s reader and writer are both written against
//! `EVP_ENCODE_CTX`, and `crypto/evp/bio_b64.c` is a `BIO` filter over it — so what this file
//! gets wrong is not local.
//!
//! ## The context is opaque, so its layout is the authority's and not the header's
//!
//! `evp.h` forward-declares `typedef struct evp_Encode_Ctx_st EVP_ENCODE_CTX;` and never defines
//! it; the definition is `crypto/evp/evp_local.h:278-292`, and it is five fields:
//!
//! ```text
//! int num;                    /* number saved in a partial encode/decode */
//! int length;                 /* output line length in input bytes, or the shortest ok input line */
//! unsigned char enc_data[80]; /* the partial block */
//! int line_num;               /* number read on current line */
//! unsigned int flags;
//! ```
//!
//! The field *order* is not ABI — nothing outside the library can see it — but `EVP_ENCODE_CTX_copy`
//! is a `memcpy` of `sizeof(EVP_ENCODE_CTX)`, so the order decides what a copy means, and the
//! `80` decides what an over-long `length` can reach. Both are transcribed rather than chosen.
//!
//! ## The decoder's table is not the encoder's, and one test reads both
//!
//! `data_bin2ascii` maps six bits to a character; `data_ascii2bin` maps a byte to six bits or to
//! one of four sentinels — `0xE0` whitespace, `0xF0` line feed, `0xF1` carriage return, `0xF2`
//! `'-'` (end of content) — with `0xFF` for "invalid". The predicates over those sentinels are
//! arithmetic rather than comparisons, and they do not say what their names suggest:
//!
//! ```text
//! B64_NOT_BASE64(a)  ((a) | 0x13) == 0xF3
//! B64_BASE64(a)      !B64_NOT_BASE64(a)
//! ```
//!
//! `0xE0 | 0x13`, `0xF0 | 0x13`, `0xF1 | 0x13` and `0xF2 | 0x13` are all `0xF3`, so those four are
//! "not base64"; **`0xFF` is not one of them** — `0xFF | 0x13` is `0xFF` — so an invalid byte counts
//! as base64 to `B64_BASE64` and is rejected instead by the `(a | b | c | d) & 0x80` test inside the
//! block decoder, or by the `v == B64_ERROR` test that precedes the store. A transcription that
//! replaced the mask with a range test would agree on every valid input and differ on a byte with
//! the high bit set, which is exactly what `EVP_DecodeUpdate`'s error arm is for.
//!
//! ## What `EVP_DecodeUpdate` answers, and the four things its comment says
//!
//! `-1` error, `0` last line, `1` full line. The authority's own comment
//! (`crypto/evp/encode.c:273-292`) records that the "last line" answer no longer has anything to
//! do with line length and is now:
//!
//! * `0` when padding or `B64_EOF` was seen **and** the outstanding block is complete;
//! * `0` for a zero-length input — the legacy "empty chunk means end of input" signal;
//! * `-1` for an invalid character, for data after padding, for more than two `'='`, for `B64_EOF`
//!   in the middle of a block, and for a partial group;
//! * and the context **does not remember** that it answered `0`, so a caller that keeps feeding it
//!   is accepted. "Therefore the caller is responsible for checking and rejecting a 0 return value
//!   in the middle of content."
//!
//! The three state variables that decide it — `eof` (padding seen so far), `seof` (`'-'` seen) and
//! `n` (`ctx->num`, the base64 characters held back) — are seeded from the *previous* call's
//! buffer (`d[n-1] == '='`, and `d[n-2]` for the second), which is what makes a `'='` split across
//! two calls behave like one in a single call.
//!
//! ## Two `OPENSSL_assert`s, and they are reached by nothing
//!
//! `EVP_EncodeUpdate`'s `OPENSSL_assert(ctx->length <= (int)sizeof(ctx->enc_data))` and
//! `EVP_DecodeUpdate`'s `OPENSSL_assert(n < (int)sizeof(ctx->enc_data))` are both
//! `include/openssl/crypto.h`'s macro, which expands to `OPENSSL_die` and is **not**
//! `NDEBUG`-gated. Neither can be reached through this surface: `length` is 48 from
//! `EVP_EncodeInit` and 0 from `EVP_DecodeInit` and nothing else writes it, and `n` is refused at
//! 64 before the store. They are written as refusals — the disposition `D-RCU-3` records for the
//! same shape — with the coordinate named at the site.
//!
//! ## `evp_encode_ctx_set_flags` lands with no caller in this stratum
//!
//! `include/crypto/evp.h:893` declares it and `crypto/srp/srp_vfy.c:83` and `:144` are its only
//! callers; SRP is Phase 12's. The prerequisite gate owes it the moment this unit has a module —
//! an internal function of a unit the crate transcribes, mentioned by neither the unit's module nor
//! the defining one — so it is defined here, `pub(crate)`, and the `SRP` alphabet tables it selects
//! are written with it. The flag cannot be set through the public surface, so the two tables are
//! unreachable from a probe and are nevertheless transcribed: they are what the branch *is*.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_char, c_int, c_uchar, c_uint};
use core::ptr;

use crate::runtime::mem::{CRYPTO_free, CRYPTO_zalloc};

/// `OPENSSL_FILE` at the three allocation sites in `crypto/evp/encode.c`.
const FILE_ENCODE: *const c_char = c"../../src/openssl-3.6.4/crypto/evp/encode.c".as_ptr();
/// `OPENSSL_LINE` of `EVP_ENCODE_CTX_new`'s `OPENSSL_zalloc` — `crypto/evp/encode.c:120`.
const LINE_ZALLOC_CTX: c_int = 120;
/// `OPENSSL_LINE` of `EVP_ENCODE_CTX_free`'s `OPENSSL_free` — `crypto/evp/encode.c:125`.
const LINE_FREE_CTX: c_int = 125;

/// `EVP_ENCODE_CTX_NO_NEWLINES` — `include/crypto/evp.h:897`.
const EVP_ENCODE_CTX_NO_NEWLINES: c_uint = 1;
/// `EVP_ENCODE_CTX_USE_SRP_ALPHABET` — `include/crypto/evp.h:899`.
const EVP_ENCODE_CTX_USE_SRP_ALPHABET: c_uint = 2;

/// `BIN_PER_LINE` — `crypto/evp/encode.c:44`. Declared and never read: the `48` in
/// `EVP_EncodeInit` is what decides the line length, and the two are equal by construction.
#[allow(dead_code)] // the authority declares it and reads it nowhere; kept for the derivation
const BIN_PER_LINE: c_int = 64 / 4 * 3;
/// `EVP_ENCODE_LENGTH(l)`'s `48` divisor — `include/openssl/evp.h:677`'s `((l) / 48 + 1) * 2`.
pub(crate) const ENCODE_LINE_LENGTH: c_int = 48;

/// `B64_EOLN` — `crypto/evp/encode.c:61`.
const B64_EOLN: c_uchar = 0xF0;
/// `B64_CR` — `crypto/evp/encode.c:62`.
const B64_CR: c_uchar = 0xF1;
/// `B64_EOF` — `crypto/evp/encode.c:63`.
const B64_EOF: c_uchar = 0xF2;
/// `B64_WS` — `crypto/evp/encode.c:64`.
const B64_WS: c_uchar = 0xE0;
/// `B64_ERROR` — `crypto/evp/encode.c:65`.
const B64_ERROR: c_uchar = 0xFF;

/// `B64_NOT_BASE64(a)` — `crypto/evp/encode.c:66`: `((a) | 0x13) == 0xF3`.
///
/// Note `0xFF` is **not** "not base64" under this test; see the module doc.
#[inline]
const fn b64_not_base64(a: c_uchar) -> bool {
    (a | 0x13) == 0xF3
}

/// `B64_BASE64(a)` — `crypto/evp/encode.c:67`.
#[inline]
const fn b64_base64(a: c_uchar) -> bool {
    !b64_not_base64(a)
}

/// `data_bin2ascii[65]` — `crypto/evp/encode.c:48`. The sixty-fifth byte is the terminator the
/// authority's initialiser leaves; only `[a & 0x3f]` is ever read.
static DATA_BIN2ASCII: [c_uchar; 65] =
    *b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/\0";

/// `srpdata_bin2ascii[65]` — `crypto/evp/encode.c:51`.
static SRPDATA_BIN2ASCII: [c_uchar; 65] =
    *b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz./\0";

/// `data_ascii2bin[128]` — `crypto/evp/encode.c:69-83`, transcribed byte for byte.
static DATA_ASCII2BIN: [c_uchar; 128] = [
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xE0, 0xF0, 0xFF, 0xFF, 0xF1, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xE0, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x3E, 0xFF, 0xF2, 0xFF, 0x3F,
    0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0xFF, 0xFF, 0xFF, 0x00, 0xFF, 0xFF,
    0xFF, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
    0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28,
    0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F, 0x30, 0x31, 0x32, 0x33, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
];

/// `srpdata_ascii2bin[128]` — `crypto/evp/encode.c:85-99`, transcribed byte for byte.
static SRPDATA_ASCII2BIN: [c_uchar; 128] = [
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xE0, 0xF0, 0xFF, 0xFF, 0xF1, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xE0, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xF2, 0x3E, 0x3F,
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0xFF, 0xFF, 0xFF, 0x00, 0xFF, 0xFF,
    0xFF, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
    0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20, 0x21, 0x22, 0x23, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F, 0x30, 0x31, 0x32,
    0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
];

// The four sentinels, at the offsets the authority's initialisers put them. Asserted rather than
// described because a transcription that reordered them would shift every character after it.
const _: () = {
    assert!(DATA_ASCII2BIN[9] == B64_WS);
    assert!(DATA_ASCII2BIN[10] == B64_EOLN);
    assert!(DATA_ASCII2BIN[13] == B64_CR);
    assert!(DATA_ASCII2BIN[45] == B64_EOF);
    assert!(DATA_ASCII2BIN[43] == 0x3E); // '+'
    assert!(DATA_ASCII2BIN[47] == 0x3F); // '/'
    assert!(DATA_ASCII2BIN[61] == 0x00); // '='
    assert!(SRPDATA_ASCII2BIN[9] == B64_WS);
    assert!(SRPDATA_ASCII2BIN[10] == B64_EOLN);
    assert!(SRPDATA_ASCII2BIN[13] == B64_CR);
    assert!(SRPDATA_ASCII2BIN[45] == B64_EOF);
    assert!(SRPDATA_ASCII2BIN[61] == 0x00); // '='
};

/// `EVP_ENCODE_CTX` — `crypto/evp/evp_local.h:278-292`'s `struct evp_Encode_Ctx_st`.
///
/// Opaque in `evp.h`, so the layout is not ABI; it is the authority's because
/// `EVP_ENCODE_CTX_copy` copies it whole.
#[repr(C)]
pub struct EvpEncodeCtx {
    /// `int num` — base64 characters held back between calls.
    pub num: c_int,
    /// `int length` — the output line length in input bytes (48), or 0 for a decoder.
    pub length: c_int,
    /// `unsigned char enc_data[80]` — the partial block.
    pub enc_data: [c_uchar; 80],
    /// `int line_num` — written by `EVP_EncodeInit` and read by nothing.
    pub line_num: c_int,
    /// `unsigned int flags` — `EVP_ENCODE_CTX_NO_NEWLINES` / `_USE_SRP_ALPHABET`.
    pub flags: c_uint,
}

const _: () = {
    assert!(core::mem::offset_of!(EvpEncodeCtx, num) == 0);
    assert!(core::mem::offset_of!(EvpEncodeCtx, length) == 4);
    assert!(core::mem::offset_of!(EvpEncodeCtx, enc_data) == 8);
    assert!(core::mem::offset_of!(EvpEncodeCtx, line_num) == 88);
    assert!(core::mem::offset_of!(EvpEncodeCtx, flags) == 92);
    assert!(core::mem::size_of::<EvpEncodeCtx>() == 96);
};

/// `conv_ascii2bin(a, table)` — `crypto/evp/encode.c:102-107`.
///
/// The `CHARSET_EBCDIC` arm is absent from this profile, so the byte is tested and indexed
/// directly. The `a & 0x80` test is what keeps the index inside the 128-byte table.
#[inline]
fn conv_ascii2bin(a: c_uchar, table: &[c_uchar; 128]) -> c_uchar {
    if a & 0x80 != 0 {
        return B64_ERROR;
    }
    table[a as usize]
}

/// `conv_bin2ascii(a, table)` — `crypto/evp/encode.c:25`.
#[inline]
fn conv_bin2ascii(a: u64, table: &[c_uchar; 65]) -> c_uchar {
    table[(a & 0x3f) as usize]
}

/// `void evp_encode_ctx_set_flags(EVP_ENCODE_CTX *ctx, unsigned int flags)`
///
/// `include/crypto/evp.h:893` declares it; `crypto/srp/srp_vfy.c:83` and `:144` are the only
/// callers in the authority, and both are Phase 12's. It carries no `#[no_mangle]` for the reason
/// D192 records for `crypto/asn1/p5_scrypt.c`'s internals: the authority's version script keeps
/// `crypto/evp/`'s non-exported names local, so no symbol of this name exists in `libcrypto.so`.
///
/// # Safety
/// `ctx` must be a live context, or NULL, in which case the authority dereferences it and this
/// does too.
#[allow(dead_code)] // the landing caller is `crypto/srp/srp_vfy.c:83`, Phase 12's
pub(crate) unsafe fn evp_encode_ctx_set_flags(ctx: *mut EvpEncodeCtx, flags: c_uint) {
    // SAFETY: the caller's contract.
    unsafe { (*ctx).flags = flags };
}

/// `EVP_ENCODE_CTX *EVP_ENCODE_CTX_new(void)`
#[no_mangle]
pub extern "C" fn EVP_ENCODE_CTX_new() -> *mut EvpEncodeCtx {
    CRYPTO_zalloc(
        core::mem::size_of::<EvpEncodeCtx>(),
        FILE_ENCODE,
        LINE_ZALLOC_CTX,
    )
    .cast::<EvpEncodeCtx>()
}

/// `void EVP_ENCODE_CTX_free(EVP_ENCODE_CTX *ctx)`
///
/// # Safety
/// `ctx` must be NULL or a pointer from [`EVP_ENCODE_CTX_new`], not already freed.
#[no_mangle]
pub unsafe extern "C" fn EVP_ENCODE_CTX_free(ctx: *mut EvpEncodeCtx) {
    // SAFETY: the caller's contract; `CRYPTO_free` accepts NULL.
    unsafe { CRYPTO_free(ctx.cast(), FILE_ENCODE, LINE_FREE_CTX) };
}

/// `int EVP_ENCODE_CTX_copy(EVP_ENCODE_CTX *dctx, const EVP_ENCODE_CTX *sctx)`
///
/// The authority's answer is a constant `1`: the copy cannot fail. It is the whole reason the
/// layout above has to be the authority's.
///
/// # Safety
/// `dctx` must be a live writable context and `sctx` a live readable one. The authority does not
/// test either and neither does this.
#[no_mangle]
pub unsafe extern "C" fn EVP_ENCODE_CTX_copy(
    dctx: *mut EvpEncodeCtx,
    sctx: *const EvpEncodeCtx,
) -> c_int {
    // SAFETY: the caller's contract; the two regions are the caller's and are assumed distinct.
    unsafe { ptr::copy_nonoverlapping(sctx, dctx, 1) };
    1
}

/// `int EVP_ENCODE_CTX_num(EVP_ENCODE_CTX *ctx)`
///
/// # Safety
/// `ctx` must be a live context, or NULL, in which case the authority dereferences it.
#[no_mangle]
pub unsafe extern "C" fn EVP_ENCODE_CTX_num(ctx: *mut EvpEncodeCtx) -> c_int {
    // SAFETY: the caller's contract.
    unsafe { (*ctx).num }
}

/// `void EVP_EncodeInit(EVP_ENCODE_CTX *ctx)`
///
/// `length` is `48` — the literal in the authority, and [`ENCODE_LINE_LENGTH`] here because that
/// number is also the divisor in `evp.h`'s `EVP_ENCODE_LENGTH` macro. `line_num` is written and
/// never read — `EVP_DecodeInit` writes it too, which is why it is not dead.
///
/// # Safety
/// `ctx` must be a live context, or NULL, in which case the authority dereferences it.
#[no_mangle]
pub unsafe extern "C" fn EVP_EncodeInit(ctx: *mut EvpEncodeCtx) {
    // SAFETY: the caller's contract.
    unsafe {
        (*ctx).length = ENCODE_LINE_LENGTH;
        (*ctx).num = 0;
        (*ctx).line_num = 0;
        (*ctx).flags = 0;
    }
}

/// `int EVP_EncodeUpdate(EVP_ENCODE_CTX *ctx, unsigned char *out, int *outl, const unsigned char *in, int inl)`
///
/// Three arms, in this order: a non-positive `inl` answers **0 with `*outl` untouched** (the
/// caller sees whatever it passed); a short input is buffered and answers 1 with `*outl == 0`; a
/// full line is emitted with its trailing newline unless `EVP_ENCODE_CTX_NO_NEWLINES` is set, and
/// the leftovers are buffered for the next call.
///
/// # Safety
/// `ctx` must be a live context; `out` must be writable for the encoded form of `inl` bytes plus
/// the line breaks and a terminator; `in` must be readable for `inl` bytes.
#[no_mangle]
pub unsafe extern "C" fn EVP_EncodeUpdate(
    ctx: *mut EvpEncodeCtx,
    out: *mut c_uchar,
    outl: *mut c_int,
    in_: *const c_uchar,
    inl: c_int,
) -> c_int {
    let mut out = out;
    let mut in_ = in_;
    let mut inl = inl;
    let mut total: usize = 0;

    // SAFETY: `outl` is the caller's out-parameter.
    unsafe { *outl = 0 };
    if inl <= 0 {
        return 0;
    }
    // The authority's `OPENSSL_assert(ctx->length <= (int)sizeof(ctx->enc_data))`
    // (`crypto/evp/encode.c:162`) is an `OPENSSL_die` and not `NDEBUG`-gated. Nothing on this
    // surface can set `length` above 80 — `EVP_EncodeInit` writes 48 and `EVP_DecodeInit` writes
    // 0 — so the arm is unreachable and is written as the refusal `D-RCU-3` records rather than as
    // a fault.
    // SAFETY: `ctx` is live per the contract.
    if unsafe { (*ctx).length } > 80 {
        return 0;
    }
    // SAFETY: `ctx` is live.
    if unsafe { (*ctx).length - (*ctx).num } > inl {
        // SAFETY: `ctx->num` is below `ctx->length` here, and `inl` bytes of the caller's input
        // are copied into the 80-byte buffer at that offset.
        unsafe {
            ptr::copy_nonoverlapping(
                in_,
                (*ctx).enc_data.as_mut_ptr().add((*ctx).num as usize),
                inl as usize,
            );
            (*ctx).num += inl;
        }
        return 1;
    }
    // SAFETY: `ctx` is live.
    if unsafe { (*ctx).num } != 0 {
        // SAFETY: `ctx` is live.
        let i = unsafe { (*ctx).length - (*ctx).num };
        // SAFETY: `i` bytes fill the buffer to `ctx->length`; `in_` is readable for `inl >= i`.
        unsafe {
            ptr::copy_nonoverlapping(
                in_,
                (*ctx).enc_data.as_mut_ptr().add((*ctx).num as usize),
                i as usize,
            );
        }
        // SAFETY: the pointer is live per the caller's contract.
        in_ = unsafe { in_.add(i as usize) };
        inl -= i;
        // SAFETY: `ctx` is live; `out` is the caller's room for one full line.
        let j = unsafe { evp_encodeblock_int(ctx, out, (*ctx).enc_data.as_ptr(), (*ctx).length) };
        // SAFETY: `ctx` is live.
        unsafe { (*ctx).num = 0 };
        // SAFETY: the pointer is live per the caller's contract.
        out = unsafe { out.add(j as usize) };
        total = j as usize;
        // SAFETY: `ctx` is live and `out` is inside the caller's buffer.
        if unsafe { (*ctx).flags } & EVP_ENCODE_CTX_NO_NEWLINES == 0 {
            // SAFETY: the pointer is live per the caller's contract.
            unsafe {
                *out = b'\n';
                out = out.add(1);
            }
            total += 1;
        }
        // SAFETY: `out` is inside the caller's buffer.
        unsafe { *out = 0 };
    }
    // SAFETY: `ctx` is live.
    while inl >= unsafe { (*ctx).length } && total <= c_int::MAX as usize {
        // SAFETY: `ctx` is live; the input has at least a full line left.
        let j = unsafe { evp_encodeblock_int(ctx, out, in_, (*ctx).length) };
        // SAFETY: `inl >= ctx->length`, so the advance stays inside the caller's buffer.
        in_ = unsafe { in_.add((*ctx).length as usize) };
        // SAFETY: the pointer is live per the caller's contract.
        inl -= unsafe { (*ctx).length };
        // SAFETY: the pointer is live per the caller's contract.
        out = unsafe { out.add(j as usize) };
        total += j as usize;
        // SAFETY: `ctx` is live and `out` is inside the caller's buffer.
        if unsafe { (*ctx).flags } & EVP_ENCODE_CTX_NO_NEWLINES == 0 {
            // SAFETY: the pointer is live per the caller's contract.
            unsafe {
                *out = b'\n';
                out = out.add(1);
            }
            total += 1;
        }
        // SAFETY: `out` is inside the caller's buffer.
        unsafe { *out = 0 };
    }
    if total > c_int::MAX as usize {
        // Too much output data.
        // SAFETY: `outl` is the caller's out-parameter.
        unsafe { *outl = 0 };
        return 0;
    }
    if inl != 0 {
        // SAFETY: `inl` is below `ctx->length`, so this fills the 80-byte buffer without
        // overflowing it; `in_` is readable for `inl` bytes.
        unsafe { ptr::copy_nonoverlapping(in_, (*ctx).enc_data.as_mut_ptr(), inl as usize) };
    }
    // SAFETY: `ctx` is live.
    unsafe {
        (*ctx).num = inl;
        *outl = total as c_int;
    }
    1
}

/// `void EVP_EncodeFinal(EVP_ENCODE_CTX *ctx, unsigned char *out, int *outl)`
///
/// A short tail is emitted with its newline — the newline is written even when the block itself
/// encoded to nothing, which cannot happen, and it is `out[ret++]` and not a separate call.
///
/// # Safety
/// `ctx` must be a live context; `out` must be writable for one encoded line.
#[no_mangle]
pub unsafe extern "C" fn EVP_EncodeFinal(
    ctx: *mut EvpEncodeCtx,
    out: *mut c_uchar,
    outl: *mut c_int,
) {
    let mut ret: c_uint = 0;
    // SAFETY: `ctx` is live.
    if unsafe { (*ctx).num } != 0 {
        // SAFETY: `ctx` is live; `ctx->num` is at most 47 here, so the block is one line.
        ret = unsafe {
            evp_encodeblock_int(ctx, out, (*ctx).enc_data.as_ptr(), (*ctx).num) as c_uint
        };
        // SAFETY: `ctx` is live.
        if unsafe { (*ctx).flags } & EVP_ENCODE_CTX_NO_NEWLINES == 0 {
            // SAFETY: `out + ret` is one past the encoded block, inside the caller's line.
            unsafe {
                *out.add(ret as usize) = b'\n';
            }
            ret += 1;
        }
        // SAFETY: `out + ret` is the terminator slot of the caller's line.
        unsafe { *out.add(ret as usize) = 0 };
        // SAFETY: `ctx` is live.
        unsafe { (*ctx).num = 0 };
    }
    // SAFETY: `outl` is the caller's out-parameter.
    unsafe { *outl = ret as c_int };
}

/// `static int evp_encodeblock_int(EVP_ENCODE_CTX *ctx, unsigned char *t, const unsigned char *f, int dlen)`
///
/// The only writer of the encoded bytes. `ctx` is NULL for [`EVP_EncodeBlock`], which is why the
/// `SRP` table test is two conjuncts and not a dereference.
///
/// # Safety
/// `t` must be writable for `4 * ceil(dlen / 3) + 1` bytes; `f` readable for `dlen` bytes; `ctx`
/// NULL or live.
unsafe fn evp_encodeblock_int(
    ctx: *mut EvpEncodeCtx,
    t: *mut c_uchar,
    f: *const c_uchar,
    dlen: c_int,
) -> c_int {
    let mut t = t;
    let mut f = f;
    let mut ret: c_int = 0;
    let table: &[c_uchar; 65] = if !ctx.is_null()
        // SAFETY: the caller's contract makes a non-NULL `ctx` live.
        && unsafe { (*ctx).flags } & EVP_ENCODE_CTX_USE_SRP_ALPHABET != 0
    {
        &SRPDATA_BIN2ASCII
    } else {
        &DATA_BIN2ASCII
    };

    let mut i = dlen;
    while i > 0 {
        if i >= 3 {
            // SAFETY: `i >= 3` of the caller's `dlen` bytes remain at `f`.
            let l = (u64::from(unsafe { *f }) << 16)
                | (u64::from(unsafe { *f.add(1) }) << 8)
                | u64::from(unsafe { *f.add(2) });
            // SAFETY: `t` is writable for the whole encoded block.
            unsafe {
                *t = conv_bin2ascii(l >> 18, table);
                *t.add(1) = conv_bin2ascii(l >> 12, table);
                *t.add(2) = conv_bin2ascii(l >> 6, table);
                *t.add(3) = conv_bin2ascii(l, table);
                t = t.add(4);
            }
        } else {
            // SAFETY: `i` is 1 or 2 here, so `f[0]` is the caller's and `f[1]` is read only for 2.
            let mut l = u64::from(unsafe { *f }) << 16;
            if i == 2 {
                // SAFETY: the pointer is live per the caller's contract.
                l |= u64::from(unsafe { *f.add(1) }) << 8;
            }
            // SAFETY: `t` is writable for the whole (padded) encoded block.
            unsafe {
                *t = conv_bin2ascii(l >> 18, table);
                *t.add(1) = conv_bin2ascii(l >> 12, table);
                *t.add(2) = if i == 1 {
                    b'='
                } else {
                    conv_bin2ascii(l >> 6, table)
                };
                *t.add(3) = b'=';
                t = t.add(4);
            }
        }
        ret += 4;
        // The authority advances `f` by three unconditionally, which for a one- or two-byte tail
        // forms a pointer past the end of a buffer it never reads through again. This advances by
        // what was consumed instead, so the pointer stays inside the caller's region; no read
        // differs, because the loop ends on the next test either way.
        // SAFETY: `i` bytes were consumed above and `i <= 3`, so the advance is in bounds.
        f = unsafe { f.add(i.min(3) as usize) };
        i -= 3;
    }

    // SAFETY: the caller's room includes the terminator.
    unsafe { *t = 0 };
    ret
}

/// `int EVP_EncodeBlock(unsigned char *t, const unsigned char *f, int dlen)`
///
/// # Safety
/// `t` as [`evp_encodeblock_int`]; `f` readable for `dlen` bytes.
#[no_mangle]
pub unsafe extern "C" fn EVP_EncodeBlock(t: *mut c_uchar, f: *const c_uchar, dlen: c_int) -> c_int {
    // SAFETY: the caller's contract; `ctx` NULL selects the standard alphabet.
    unsafe { evp_encodeblock_int(ptr::null_mut(), t, f, dlen) }
}

/// `void EVP_DecodeInit(EVP_ENCODE_CTX *ctx)`
///
/// "Only `ctx->num` and `ctx->flags` are used during decoding" — and `length` and `line_num` are
/// nevertheless zeroed, which is what makes a context used as an encoder and then as a decoder
/// start from a defined state.
///
/// # Safety
/// `ctx` must be a live context, or NULL, in which case the authority dereferences it.
#[no_mangle]
pub unsafe extern "C" fn EVP_DecodeInit(ctx: *mut EvpEncodeCtx) {
    // SAFETY: the caller's contract.
    unsafe {
        (*ctx).num = 0;
        (*ctx).length = 0;
        (*ctx).line_num = 0;
        (*ctx).flags = 0;
    }
}

/// `int EVP_DecodeUpdate(EVP_ENCODE_CTX *ctx, unsigned char *out, int *outl, const unsigned char *in, int inl)`
///
/// The state machine the module doc describes. Two details a rewrite loses: `*outl` is set to the
/// **partial** count on every error path — the comment at `crypto/evp/encode.c:397` says so in as
/// many words — and `ctx->num` is set to the surviving `n` even when the answer is `-1`.
///
/// # Safety
/// `ctx` must be a live context; `out` writable for `3 * (inl / 4) + 3` bytes; `in` readable for
/// `inl` bytes.
#[no_mangle]
pub unsafe extern "C" fn EVP_DecodeUpdate(
    ctx: *mut EvpEncodeCtx,
    out: *mut c_uchar,
    outl: *mut c_int,
    in_: *const c_uchar,
    inl: c_int,
) -> c_int {
    let mut seof = 0;
    let mut eof = 0;
    // The authority initialises `rv = -1` in the declaration and every arm below assigns before
    // the epilogue reads it, so the initialiser is dead to Rust and kept for correspondence.
    #[allow(unused_assignments)]
    let mut rv: c_int = -1;
    let mut ret: c_int = 0;
    let mut out = out;

    // SAFETY: `ctx` is live.
    let d = unsafe { (*ctx).enc_data.as_mut_ptr() };
    // SAFETY: `ctx` is live.
    let mut n = unsafe { (*ctx).num };

    // SAFETY: the pointer is live per the caller's contract.
    if n > 0 && unsafe { *d.add(n as usize - 1) } == b'=' {
        eof += 1;
        // SAFETY: the pointer is live per the caller's contract.
        if n > 1 && unsafe { *d.add(n as usize - 2) } == b'=' {
            eof += 1;
        }
    }

    // The authority's `tail:` label and its eight `goto end` sites are two different destinations
    // -- `goto tail` enters the epilogue, `goto end` skips it -- so the loop is its own labelled
    // block inside `'end`, and `break 'outer` is the one arm that reaches the epilogue with the
    // loop abandoned.
    'end: {
        // Legacy behaviour: an empty input chunk signals end of input.
        if inl == 0 {
            rv = 0;
            break 'end;
        }

        let table: &[c_uchar; 128] =
            // SAFETY: the pointer is live per the caller's contract.
            if unsafe { (*ctx).flags } & EVP_ENCODE_CTX_USE_SRP_ALPHABET != 0 {
                &SRPDATA_ASCII2BIN
            } else {
                &DATA_ASCII2BIN
            };

        'outer: {
            let mut i = 0;
            while i < inl {
                // SAFETY: `i < inl`, so the byte is the caller's.
                let tmp = unsafe { *in_.add(i as usize) };
                let v = conv_ascii2bin(tmp, table);
                if v == B64_ERROR {
                    rv = -1;
                    break 'end;
                }

                if tmp == b'=' {
                    eof += 1;
                } else if eof > 0 && b64_base64(v) {
                    // More data after padding.
                    rv = -1;
                    break 'end;
                }

                if eof > 2 {
                    rv = -1;
                    break 'end;
                }

                if v == B64_EOF {
                    seof = 1;
                    break 'outer;
                }

                // Only save valid base64 characters.
                if b64_base64(v) {
                    if n >= 64 {
                        // We increment n once per loop, and empty the buffer as soon as we reach
                        // 64 characters, so this can only happen if someone's manually messed with
                        // the ctx. Refuse to write any more data.
                        rv = -1;
                        break 'end;
                    }
                    // The authority's `OPENSSL_assert(n < (int)sizeof(ctx->enc_data))` is
                    // unreachable: `n >= 64` was refused immediately above and the buffer is 80
                    // bytes.
                    // SAFETY: `ctx` is live and `n < 80`.
                    unsafe { *d.add(n as usize) = tmp };
                    n += 1;
                }

                if n == 64 {
                    // SAFETY: `out` is writable for the decoded block; `d` holds 64 base64
                    // characters.
                    let decoded_len = unsafe { evp_decodeblock_int(ctx, out, d, n, eof) };
                    n = 0;
                    if decoded_len < 0 || (decoded_len == 0 && eof > 0) {
                        rv = -1;
                        break 'end;
                    }
                    ret += decoded_len;
                    // SAFETY: the pointer is live per the caller's contract.
                    out = unsafe { out.add(decoded_len as usize) };
                }
                i += 1;
            }
        }

        // `tail:` -- Legacy behaviour: if the current line is a full base64 block (0 mod 4 base64
        // characters), it is processed immediately. Applications may not be calling
        // `EVP_DecodeFinal` properly, so the behaviour is kept.
        if n > 0 {
            if n & 3 == 0 {
                // SAFETY: `out` is writable for the decoded block; `d` holds `n` characters.
                let decoded_len = unsafe { evp_decodeblock_int(ctx, out, d, n, eof) };
                n = 0;
                if decoded_len < 0 || (decoded_len == 0 && eof > 0) {
                    rv = -1;
                    break 'end;
                }
                ret += decoded_len;
            } else if seof != 0 {
                // EOF in the middle of a base64 block.
                rv = -1;
                break 'end;
            }
        }

        rv = if seof != 0 || (n == 0 && eof != 0) {
            0
        } else {
            1
        };
    }

    // Legacy behaviour. This should probably rather be zeroed on error.
    // SAFETY: `outl` and `ctx` are the caller's.
    unsafe {
        *outl = ret;
        (*ctx).num = n;
    }
    rv
}

/// `static int evp_decodeblock_int(EVP_ENCODE_CTX *ctx, unsigned char *t, const unsigned char *f, int n, int eof)`
///
/// The last block is the only one that may carry padding, and `eof == -1` — the value
/// [`EVP_DecodeFinal`] passes — makes the function *derive* the padding from the `'='` characters
/// instead of being told. `0` means "nothing to decode" and is not an error; `-1` is.
///
/// # Safety
/// `t` must be writable for `3 * (n / 4)` bytes; `f` readable for `n` bytes; `ctx` NULL or live.
unsafe fn evp_decodeblock_int(
    ctx: *mut EvpEncodeCtx,
    t: *mut c_uchar,
    f: *const c_uchar,
    n: c_int,
    eof: c_int,
) -> c_int {
    let mut t = t;
    let mut f = f;
    let mut n = n;
    let mut eof = eof;
    let mut ret: c_int = 0;

    if !(-1..=2).contains(&eof) {
        return -1;
    }

    let table: &[c_uchar; 128] = if !ctx.is_null()
        // SAFETY: the caller's contract makes a non-NULL `ctx` live.
        && unsafe { (*ctx).flags } & EVP_ENCODE_CTX_USE_SRP_ALPHABET != 0
    {
        &SRPDATA_ASCII2BIN
    } else {
        &DATA_ASCII2BIN
    };

    // Trim whitespace from the start of the line.
    // SAFETY: `n > 0` on entry to the body, so `f` is the caller's byte.
    while n > 0 && conv_ascii2bin(unsafe { *f }, table) == B64_WS {
        // SAFETY: the pointer is live per the caller's contract.
        f = unsafe { f.add(1) };
        n -= 1;
    }

    // Strip off stuff at the end of the line with ascii2bin values B64_WS, B64_EOLN, B64_CR and
    // B64_EOF.
    // SAFETY: `n > 3` on entry to the body, so `f[n-1]` is the caller's byte.
    while n > 3 && b64_not_base64(conv_ascii2bin(unsafe { *f.add(n as usize - 1) }, table)) {
        n -= 1;
    }

    if n % 4 != 0 {
        return -1;
    }
    if n == 0 {
        return 0;
    }

    // All 4-byte blocks except the last one do not have padding.
    let mut i = 0;
    while i < n - 4 {
        // SAFETY: four bytes remain before the last block, so all four are the caller's.
        let (a, b, c, d) = unsafe {
            (
                conv_ascii2bin(*f, table),
                conv_ascii2bin(*f.add(1), table),
                conv_ascii2bin(*f.add(2), table),
                conv_ascii2bin(*f.add(3), table),
            )
        };
        if (a | b | c | d) & 0x80 != 0 {
            return -1;
        }
        let l = (u64::from(a) << 18) | (u64::from(b) << 12) | (u64::from(c) << 6) | u64::from(d);
        // SAFETY: `t` is writable for three bytes per four-byte block.
        unsafe {
            *t = ((l >> 16) & 0xff) as c_uchar;
            *t.add(1) = ((l >> 8) & 0xff) as c_uchar;
            *t.add(2) = (l & 0xff) as c_uchar;
        }
        ret += 3;
        // SAFETY: the pointer is live per the caller's contract.
        f = unsafe { f.add(4) };
        // SAFETY: the pointer is live per the caller's contract.
        t = unsafe { t.add(3) };
        i += 4;
    }

    // Process the last block that may have padding.
    // SAFETY: `n % 4 == 0` and `n >= 4` here, so four bytes are the caller's.
    let (a, b, c, d) = unsafe {
        (
            conv_ascii2bin(*f, table),
            conv_ascii2bin(*f.add(1), table),
            conv_ascii2bin(*f.add(2), table),
            conv_ascii2bin(*f.add(3), table),
        )
    };
    if (a | b | c | d) & 0x80 != 0 {
        return -1;
    }
    let l = (u64::from(a) << 18) | (u64::from(b) << 12) | (u64::from(c) << 6) | u64::from(d);

    if eof == -1 {
        // `'='` is `0x3D`, which is its own table value: the padding is visible in the *output* of
        // `conv_ascii2bin` here and not as a sentinel.
        eof = c_int::from(c == 0x3D) + c_int::from(d == 0x3D);
    }

    // SAFETY: `t` is writable for at least one more byte for each arm; the `case 0` arm writes
    // three and the buffer has room because a full four-character block decodes to three.
    match eof {
        // SAFETY: the pointer is live per the caller's contract.
        2 => unsafe {
            *t = ((l >> 16) & 0xff) as c_uchar;
        },
        // SAFETY: the pointer is live per the caller's contract.
        1 => unsafe {
            *t = ((l >> 16) & 0xff) as c_uchar;
            *t.add(1) = ((l >> 8) & 0xff) as c_uchar;
        },
        // SAFETY: the pointer is live per the caller's contract.
        _ => unsafe {
            *t = ((l >> 16) & 0xff) as c_uchar;
            *t.add(1) = ((l >> 8) & 0xff) as c_uchar;
            *t.add(2) = (l & 0xff) as c_uchar;
        },
    }
    ret += 3 - eof;

    ret
}

/// `int EVP_DecodeBlock(unsigned char *t, const unsigned char *f, int n)`
///
/// `eof == 0`, so padding is still derived inside the last block when it is present but the
/// `3 - eof` arithmetic is applied to that derived count. `ctx` is NULL, so the standard alphabet.
///
/// # Safety
/// `t` writable for `3 * (n / 4)` bytes; `f` readable for `n` bytes.
#[no_mangle]
pub unsafe extern "C" fn EVP_DecodeBlock(t: *mut c_uchar, f: *const c_uchar, n: c_int) -> c_int {
    // SAFETY: the caller's contract.
    unsafe { evp_decodeblock_int(ptr::null_mut(), t, f, n, 0) }
}

/// `int EVP_DecodeFinal(EVP_ENCODE_CTX *ctx, unsigned char *out, int *outl)`
///
/// `-1` when the held-back group is not decodable, `1` otherwise — including when there is
/// nothing to do, which is why a caller must look at `*outl` and not at the return code alone.
///
/// # Safety
/// `ctx` must be a live context; `out` writable for the held-back group's decoded form.
#[no_mangle]
pub unsafe extern "C" fn EVP_DecodeFinal(
    ctx: *mut EvpEncodeCtx,
    out: *mut c_uchar,
    outl: *mut c_int,
) -> c_int {
    // SAFETY: `outl` is the caller's out-parameter.
    unsafe { *outl = 0 };
    // SAFETY: `ctx` is live.
    if unsafe { (*ctx).num } != 0 {
        // SAFETY: `ctx` is live; `ctx->num` characters are in the buffer and `out` has room for
        // the decoded form.
        let i = unsafe { evp_decodeblock_int(ctx, out, (*ctx).enc_data.as_ptr(), (*ctx).num, -1) };
        if i < 0 {
            return -1;
        }
        // SAFETY: `ctx` and `outl` are the caller's.
        unsafe {
            (*ctx).num = 0;
            *outl = i;
        }
        1
    } else {
        1
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The encoder's line length is forty-eight input bytes, which is four 4-character blocks of
    /// three bytes each; the two constants that say so must agree because `EVP_EncodeUpdate`
    /// compares `ctx->length` and `evp_encodeblock_int` walks `dlen` in threes.
    #[test]
    fn line_length_is_forty_eight_and_a_multiple_of_three() {
        assert_eq!(BIN_PER_LINE, 48);
        assert_eq!(ENCODE_LINE_LENGTH, 48);
        // SAFETY: a fresh context is live unless the allocator failed.
        let ctx = EVP_ENCODE_CTX_new();
        assert!(!ctx.is_null());
        // SAFETY: `ctx` came from the constructor above.
        unsafe {
            EVP_EncodeInit(ctx);
            assert_eq!((*ctx).length, ENCODE_LINE_LENGTH);
            assert_eq!((*ctx).num, 0);
            assert_eq!((*ctx).flags, 0);
            EVP_ENCODE_CTX_free(ctx);
        }
    }

    /// `EVP_EncodeBlock` is the standard alphabet, three bytes in and four characters out, with
    /// `=` for a one- or two-byte tail and a NUL terminator the return value does not count.
    #[test]
    fn encode_block_pads_the_tail() {
        let mut out = [0u8; 16];
        // SAFETY: `out` is writable and the input is this test's own four bytes.
        let n = unsafe { EVP_EncodeBlock(out.as_mut_ptr(), b"abcd".as_ptr(), 4) };
        assert_eq!(n, 8);
        assert_eq!(&out[..8], b"YWJjZA==");
        assert_eq!(out[8], 0);

        // SAFETY: as above.
        let n = unsafe { EVP_EncodeBlock(out.as_mut_ptr(), b"ab".as_ptr(), 2) };
        assert_eq!(n, 4);
        assert_eq!(&out[..4], b"YWI=");

        // SAFETY: as above.
        let n = unsafe { EVP_EncodeBlock(out.as_mut_ptr(), b"a".as_ptr(), 1) };
        assert_eq!(n, 4);
        assert_eq!(&out[..4], b"YQ==");
    }

    /// The round trip the court drives for every arm: encode with the streaming API and decode
    /// with the streaming API, and the decoder's answer for a complete group is `0` ("last line")
    /// once padding has been seen.
    #[test]
    fn streaming_round_trip_answers_zero_at_the_end() {
        let plain = b"the quick brown fox jumps over the lazy dog";
        // SAFETY: both contexts are live; the buffers are sized for this input.
        unsafe {
            let enc = EVP_ENCODE_CTX_new();
            let mut encoded = [0u8; 256];
            let mut outl = 0;
            EVP_EncodeInit(enc);
            assert_eq!(
                EVP_EncodeUpdate(enc, encoded.as_mut_ptr(), &mut outl, plain.as_ptr(), 43),
                1
            );
            let mut n = outl;
            EVP_EncodeFinal(enc, encoded.as_mut_ptr().add(n as usize), &mut outl);
            n += outl;

            let dec = EVP_ENCODE_CTX_new();
            let mut decoded = [0u8; 256];
            EVP_DecodeInit(dec);
            let rv = EVP_DecodeUpdate(dec, decoded.as_mut_ptr(), &mut outl, encoded.as_ptr(), n);
            assert_eq!(rv, 0, "padding seen and the group is complete");
            let mut dn = outl;
            assert_eq!(
                EVP_DecodeFinal(dec, decoded.as_mut_ptr().add(dn as usize), &mut outl),
                1
            );
            dn += outl;
            assert_eq!(&decoded[..dn as usize], &plain[..]);

            EVP_ENCODE_CTX_free(enc);
            EVP_ENCODE_CTX_free(dec);
        }
    }

    /// A decoder fed only a partial group holds it back and answers `1`; the group is refused
    /// once a `'-'` (end of content) arrives, which is the `seof` arm of the `tail:` label.
    #[test]
    fn partial_group_is_held_back_and_then_refused_with_the_eof_marker() {
        // SAFETY: `ctx` is live and the buffers are this test's own.
        unsafe {
            let ctx = EVP_ENCODE_CTX_new();
            let mut out = [0u8; 16];
            let mut outl = 0;
            EVP_DecodeInit(ctx);
            let rv = EVP_DecodeUpdate(ctx, out.as_mut_ptr(), &mut outl, b"YWJ".as_ptr(), 3);
            assert_eq!(rv, 1);
            assert_eq!(outl, 0);
            assert_eq!((*ctx).num, 3, "the three characters are held back");
            let rv = EVP_DecodeUpdate(ctx, out.as_mut_ptr(), &mut outl, b"-".as_ptr(), 1);
            assert_eq!(rv, -1, "EOF in the middle of a base64 block");
            EVP_ENCODE_CTX_free(ctx);
        }
    }

    /// The four sentinels are `B64_NOT_BASE64` and `0xFF` is not — the arithmetic the module doc
    /// describes. Asserted rather than described, because a rewrite to a range test would agree
    /// on every valid byte.
    #[test]
    fn the_not_base64_mask_covers_four_sentinels_and_not_the_error_code() {
        for a in [B64_EOLN, B64_CR, B64_EOF, B64_WS] {
            assert!(b64_not_base64(a), "{a:#04x} is not base64");
            assert!(!b64_base64(a));
        }
        assert!(
            !b64_not_base64(B64_ERROR),
            "0xFF counts as base64 to this test"
        );
        assert!(b64_base64(B64_ERROR));
        for a in 0u8..0x3F {
            assert!(b64_base64(a));
        }
    }
}
