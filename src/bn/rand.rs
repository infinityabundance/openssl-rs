//! Phase 5 — the `BN_*` random family of `crypto/bn/bn_rand.c`.
//!
//! ## Landed in D314
//!
//! Every public entry point below reaches `RAND_bytes_ex` / `RAND_priv_bytes_ex`, which
//! landed in D313 as `crate::rand::rand_lib`, and `ossl_bn_get_libctx`
//! (`crypto/bn/bn_ctx.c:243`), which landed with them in `crate::bn::ctx`. The module
//! compiles unchanged from the transcription: not one call was watered down to make it
//! link, because a version that stubbed the RNG would be a different observable
//! contract rather than a smaller one.
//!
//! ## Callees, all present
//!
//! * `crate::rand::rand_lib::RAND_bytes_ex` / `RAND_priv_bytes_ex` — the authority's
//!   signatures, from `include/openssl/rand.h`:
//!   `int RAND_bytes_ex(OSSL_LIB_CTX *libctx, unsigned char *buf, size_t num,
//!   unsigned int strength)` and the `_priv_` twin.
//! * `crate::bn::ctx::ossl_bn_get_libctx` — an internal declared in
//!   `include/crypto/bn.h:126`. It reads the `libctx` field `BN_CTX_new_ex` stores,
//!   which is the field that function used to accept and discard; the half of
//!   `OBL-BN-CTX-LIBCTX-SELECTION` that remains is *using* the context to select a
//!   provider, which is Phase 6's.
//!
//! Every other callee — `BN_zero_ex`, `BN_bin2bn`, `BN_num_bits`, `BN_is_zero`,
//! `BN_is_bit_set`, `BN_cmp`, `BN_sub`, `BN_set_flags`, `CRYPTO_malloc`
//! and `CRYPTO_clear_free` — was already in the crate with the authority's
//! signature. (`BN_set_flags` is used only by the out-of-scope tail, below.)
//!
//! ## Scope: lines 19–239, and what is deliberately left
//!
//! The authority file is 412 lines. Transcribed here are the public random family
//! and its two static helpers, `crypto/bn/bn_rand.c:19-239`: the `BNRAND_FLAG`
//! enum, `bnrand`, `BN_rand_ex`/`BN_rand`/`BN_bntest_rand`,
//! `BN_priv_rand_ex`/`BN_priv_rand`, `bnrand_range`, the four `_range` entry points
//! and the two deprecated `BN_pseudo_*` forwards.
//!
//! The file continues past line 239 with `ossl_bn_priv_rand_range_fixed_top`
//! (`:241-283`), `ossl_bn_gen_dsa_nonce_fixed_top` (`:293-395`) and
//! `BN_generate_dsa_nonce` (`:397-412`). Those are **not** transcribed here: the
//! first needs `ossl_bn_mask_bits_fixed_top` and the fixed-top representation in
//! `bn_lib.c`, and the other two need the EVP digest front and `SHA512`
//! (Phase 6/7), so `BN_generate_dsa_nonce` is the one name of Phase 9's twelve
//! `src/bn/rand.rs` obligations that this module does **not** discharge. Their error
//! sites are already generated (`BN_RAND_248`, `_253`, `_271`, `_332`, `_338`,
//! `_385` in `src/runtime/err_sites.rs`), so the later slice lands on arranged ground
//! rather than guessing coordinates.
//!
//! ## Macro spellings, checked rather than assumed
//!
//! The brief expected `BN_priv_rand` to be a macro in the header. On this authority
//! it is not: every name in the family is a real function in
//! `include/openssl/bn.h:216-232`, and `grep -n "BN_priv_rand" include/openssl/bn.h`
//! answers a prototype rather than a `#define`. The two names this file does meet
//! that the header spells as macros are handled the way the crate already handles
//! its kind:
//!
//! * `BN_zero`, which the authority's `bnrand`/`bnrand_range` call, is
//!   `#define BN_zero(a) BN_zero_ex(a)` (`bn.h:201`), so it is transcribed as the
//!   function behind it, `BN_zero_ex` — exactly as `src/bn/bignum.rs` documents.
//! * `BN_num_bytes` is `((BN_num_bits(a) + 7) / 8)`; this file does not use it.
//!
//! `BN_pseudo_rand` and `BN_pseudo_rand_range` are functions behind
//! `#ifndef OPENSSL_NO_DEPRECATED_3_0`, and this profile defines no
//! `OPENSSL_NO_DEPRECATED_*` (D172), so both are compiled by the authority and both
//! are transcribed.
//!
//! SPDX-License-Identifier: Apache-2.0

#![deny(unsafe_op_in_unsafe_fn)]
#![deny(missing_docs)]

use core::ffi::{c_int, c_uchar, c_uint, c_void};

use crate::bn::arith::{BN_cmp, BN_sub};
use crate::bn::bignum::{
    as_ref, BN_bin2bn, BN_is_bit_set, BN_is_zero, BN_num_bits, BN_zero_ex, BigNum,
};
use crate::bn::ctx::BnCtx;
use crate::ffi::guard_ffi;
use crate::rand::rand_lib::{RAND_bytes_ex, RAND_priv_bytes_ex};
use crate::runtime::err::err_sites::{
    BN_RAND_140, BN_RAND_145, BN_RAND_180, BN_RAND_193, BN_RAND_98,
};
use crate::runtime::err::raise_site;
use crate::runtime::mem::{CRYPTO_clear_free, CRYPTO_malloc};

/// The authority translation unit, for the `CRYPTO_malloc`/`CRYPTO_clear_free`
/// records `bnrand` makes.
const FILE: &core::ffi::CStr = c"crypto/bn/bn_rand.c";
/// The authority passes `__LINE__`, inert under `OPENSSL_NO_CRYPTO_MDEBUG`.
const LINE: c_int = 0;

/// `BN_RAND_TOP_ANY` — `include/openssl/bn.h:80`.
pub(crate) const BN_RAND_TOP_ANY: c_int = -1;
/// `BN_RAND_TOP_ONE` — `include/openssl/bn.h:81`.
///
/// Nothing in this file reads it; `bn_prime.c:563`, `bn_x931p.c:234` and
/// `bn_gf2m.c:1042` do, and none of those is transcribed yet.
#[allow(dead_code)] // read by the prime-generation callers, not yet in this crate
pub(crate) const BN_RAND_TOP_ONE: c_int = 0;
/// `BN_RAND_TOP_TWO` — `include/openssl/bn.h:82`.
///
/// Nothing in this file reads it; `bn_prime.c:496` and `bn_x931p.c:178` do, and
/// neither is transcribed yet.
#[allow(dead_code)] // read by the prime-generation callers, not yet in this crate
pub(crate) const BN_RAND_TOP_TWO: c_int = 1;
/// `BN_RAND_BOTTOM_ANY` — `include/openssl/bn.h:85`.
pub(crate) const BN_RAND_BOTTOM_ANY: c_int = 0;
/// `BN_RAND_BOTTOM_ODD` — `include/openssl/bn.h:86`.
///
/// Nothing in this file reads it; `bn_prime.c:496` and `bn_rsa_fips186_4.c:215` do,
/// and neither is transcribed yet.
#[allow(dead_code)] // read by the prime-generation callers, not yet in this crate
pub(crate) const BN_RAND_BOTTOM_ODD: c_int = 1;

/// The authority's `BNRAND_FLAG` (`crypto/bn/bn_rand.c:19-23`): which RNG a draw
/// comes from, and whether the bug-hunting patterner runs.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum BnrandFlag {
    /// `NORMAL` — `RAND_bytes_ex`.
    Normal,
    /// `TESTING` — `RAND_priv_bytes_ex` for the fill, then `RAND_bytes_ex` per byte
    /// for the patterner. That asymmetry is the authority's and is kept.
    Testing,
    /// `PRIVATE` — `RAND_priv_bytes_ex`.
    Private,
}

/// `static int bnrand(BNRAND_FLAG flag, BIGNUM *rnd, int bits, int top, int bottom,
/// unsigned int strength, BN_CTX *ctx)` — `crypto/bn/bn_rand.c:25-100`.
///
/// The temporary buffer is the authority's `OPENSSL_malloc(bytes)` released with
/// `OPENSSL_clear_free`, so it is allocated and released through this crate's
/// `CRYPTO_malloc`/`CRYPTO_clear_free` and a program that installs memory hooks
/// sees it exactly as it sees the authority's. It is the *only* allocation here:
/// `BN_bin2bn` owns the result.
///
/// `bn_check_top(rnd)` at the authority's `err` label is a `BN_DEBUG`-only
/// assertion, so it is a no-op on this profile and is not written.
///
/// # Safety
///
/// `rnd` must be null or a live, uniquely-owned `BIGNUM`; `ctx` must be null or a
/// live `BN_CTX`.
pub(crate) unsafe fn bnrand(
    flag: BnrandFlag,
    rnd: *mut BigNum,
    bits: c_int,
    top: c_int,
    bottom: c_int,
    strength: c_uint,
    ctx: *mut BnCtx,
) -> c_int {
    if bits == 0 {
        if top != BN_RAND_TOP_ANY || bottom != BN_RAND_BOTTOM_ANY {
            // The authority's `goto toosmall`.
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&BN_RAND_98) };
            return 0;
        }
        // SAFETY: `rnd` is null-or-live per this function's `# Safety` section. The
        // authority writes the `BN_zero` macro here; this is its body.
        unsafe { BN_zero_ex(rnd) };
        return 1;
    }
    if bits < 0 || (bits == 1 && top > 0) {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&BN_RAND_98) };
        return 0;
    }

    // `(bits + 7) / 8` in the authority. `bits` is a caller-supplied `int`, so the
    // authority's own addition can overflow; `wrapping_add` gives the same low
    // result for every `bits` a caller can actually allocate and, unlike `+`, cannot
    // panic a debug build.
    let bytes = bits.wrapping_add(7) / 8;
    let bit = (bits - 1) % 8;
    // `mask = 0xff << (bit + 1)` is the authority's `int`, but only its low eight
    // bits survive `buf[0] &= ~mask`, so the complement is taken in a `u8` and the
    // two agree byte for byte.
    let mask: u8 = (0xffu32 << (bit as u32 + 1)) as u8;

    // The authority reads the context's library context here, through
    // `ossl_bn_get_libctx` (`crypto/bn/bn_ctx.c:243`).
    // SAFETY: `ctx` is null-or-live per this function's `# Safety` section.
    let libctx: *mut c_void = unsafe { crate::bn::ctx::ossl_bn_get_libctx(ctx) };

    // SAFETY: `CRYPTO_malloc` needs no caller pointer and answers null on failure.
    let buf = CRYPTO_malloc(bytes as usize, FILE.as_ptr(), LINE).cast::<u8>();
    if buf.is_null() {
        // The authority's `goto err` with `ret == 0`; the buffer is null, so the
        // clearing free has nothing to release.
        return 0;
    }

    let ret = (|| -> c_int {
        // SAFETY: `buf` came from the `CRYPTO_malloc` above and has not been
        // released; `bytes >= 1` because `bits >= 1`, so it is writable for `bytes`
        // bytes and is not aliased.
        let buf = unsafe { core::slice::from_raw_parts_mut(buf, bytes as usize) };

        // `libctx` is the caller's context (null when `ctx` is null, which the RAND
        // front accepts) and `buf` is writable for `buf.len()` bytes per the block above.
        let b = if flag == BnrandFlag::Normal {
            // SAFETY: `libctx` is null or live and `buf` is writable for `buf.len()`
            // bytes; `RAND_bytes_ex` is the landed Phase-9 front.
            unsafe {
                RAND_bytes_ex(
                    libctx,
                    buf.as_mut_ptr().cast::<c_uchar>(),
                    buf.len(),
                    strength,
                )
            }
        } else {
            // SAFETY: as the public arm above; the `_priv_` spelling takes the private
            // secondary DRBG.
            unsafe {
                RAND_priv_bytes_ex(
                    libctx,
                    buf.as_mut_ptr().cast::<c_uchar>(),
                    buf.len(),
                    strength,
                )
            }
        };
        if b <= 0 {
            return 0;
        }

        if flag == BnrandFlag::Testing {
            /*
             * generate patterns that are more likely to trigger BN library bugs
             */
            let mut i = 0usize;
            while i < buf.len() {
                let mut c: u8 = 0;
                // SAFETY: `c` is this frame's own byte and the RAND front writes
                // exactly one byte; `libctx` is as above.
                let r = unsafe {
                    RAND_bytes_ex(libctx, (&mut c as *mut u8).cast::<c_uchar>(), 1, strength)
                };
                if r <= 0 {
                    return 0;
                }
                if c >= 128 && i > 0 {
                    buf[i] = buf[i - 1];
                } else if c < 42 {
                    buf[i] = 0;
                } else if c < 84 {
                    buf[i] = 255;
                }
                i += 1;
            }
        }

        if top >= 0 {
            if top != 0 {
                if bit == 0 {
                    // `bits == 1 && top > 0` was refused above, so an odd-byte
                    // `bits` with a set `top` here has `bits >= 9` and `buf[1]`
                    // exists. Zeroing `buf[0]` first is the authority's assignment.
                    buf[0] = 1;
                    buf[1] |= 0x80;
                } else {
                    buf[0] |= 3u8 << ((bit - 1) as u32);
                }
            } else {
                buf[0] |= 1u8 << (bit as u32);
            }
        }
        buf[0] &= !mask;
        if bottom != 0 {
            /* set bottom bit if requested */
            buf[buf.len() - 1] |= 1;
        }
        // SAFETY: `buf` is readable for `bytes` bytes and `rnd` is null-or-live; a
        // null `rnd` makes `BN_bin2bn` allocate and answer non-null, which is the
        // authority's behaviour too.
        if unsafe { BN_bin2bn(buf.as_ptr(), bytes, rnd) }.is_null() {
            return 0;
        }
        1
    })();

    // `OPENSSL_clear_free(buf, bytes)` — the authority's clearing free.
    // SAFETY: `buf` came from the `CRYPTO_malloc` above and has not been released.
    unsafe { CRYPTO_clear_free(buf.cast(), bytes as usize, FILE.as_ptr(), LINE) };
    ret
}

/// `int BN_rand_ex(BIGNUM *rnd, int bits, int top, int bottom,
/// unsigned int strength, BN_CTX *ctx)` — `crypto/bn/bn_rand.c:102-106`.
///
/// # Safety
///
/// As [`bnrand`].
#[no_mangle]
pub unsafe extern "C" fn BN_rand_ex(
    rnd: *mut BigNum,
    bits: c_int,
    top: c_int,
    bottom: c_int,
    strength: c_uint,
    ctx: *mut BnCtx,
) -> c_int {
    guard_ffi(0, || {
        // SAFETY: the caller's contract is this function's `# Safety` section.
        unsafe { bnrand(BnrandFlag::Normal, rnd, bits, top, bottom, strength, ctx) }
    })
}

/// `int BN_rand(BIGNUM *rnd, int bits, int top, int bottom)` —
/// `crypto/bn/bn_rand.c:108-111`, behind `#ifndef FIPS_MODULE`.
///
/// # Safety
///
/// As [`bnrand`].
#[no_mangle]
pub unsafe extern "C" fn BN_rand(
    rnd: *mut BigNum,
    bits: c_int,
    top: c_int,
    bottom: c_int,
) -> c_int {
    guard_ffi(0, || {
        // SAFETY: as `BN_rand_ex`, with the authority's zero strength and null
        // context.
        unsafe {
            bnrand(
                BnrandFlag::Normal,
                rnd,
                bits,
                top,
                bottom,
                0,
                core::ptr::null_mut(),
            )
        }
    })
}

/// `int BN_bntest_rand(BIGNUM *rnd, int bits, int top, int bottom)` —
/// `crypto/bn/bn_rand.c:113-116`, behind `#ifndef FIPS_MODULE` and declared in
/// `include/openssl/bn.h:583`.
///
/// The test-only generator: it picks a random fill and then biases bytes toward
/// repetition, all-zero and all-one, which is the input distribution that finds
/// carry and normalisation bugs.
///
/// # Safety
///
/// As [`bnrand`].
#[no_mangle]
pub unsafe extern "C" fn BN_bntest_rand(
    rnd: *mut BigNum,
    bits: c_int,
    top: c_int,
    bottom: c_int,
) -> c_int {
    guard_ffi(0, || {
        // SAFETY: as `BN_rand`, with the authority's `TESTING` flag.
        unsafe {
            bnrand(
                BnrandFlag::Testing,
                rnd,
                bits,
                top,
                bottom,
                0,
                core::ptr::null_mut(),
            )
        }
    })
}

/// `int BN_priv_rand_ex(BIGNUM *rnd, int bits, int top, int bottom,
/// unsigned int strength, BN_CTX *ctx)` — `crypto/bn/bn_rand.c:119-123`.
///
/// # Safety
///
/// As [`bnrand`].
#[no_mangle]
pub unsafe extern "C" fn BN_priv_rand_ex(
    rnd: *mut BigNum,
    bits: c_int,
    top: c_int,
    bottom: c_int,
    strength: c_uint,
    ctx: *mut BnCtx,
) -> c_int {
    guard_ffi(0, || {
        // SAFETY: the caller's contract is this function's `# Safety` section.
        unsafe { bnrand(BnrandFlag::Private, rnd, bits, top, bottom, strength, ctx) }
    })
}

/// `int BN_priv_rand(BIGNUM *rnd, int bits, int top, int bottom)` —
/// `crypto/bn/bn_rand.c:126-129`, behind `#ifndef FIPS_MODULE`.
///
/// The header declares this as a function on this authority
/// (`include/openssl/bn.h:221`), not as the macro the brief expected.
///
/// # Safety
///
/// As [`bnrand`].
#[no_mangle]
pub unsafe extern "C" fn BN_priv_rand(
    rnd: *mut BigNum,
    bits: c_int,
    top: c_int,
    bottom: c_int,
) -> c_int {
    guard_ffi(0, || {
        // SAFETY: as `BN_priv_rand_ex`, with the authority's zero strength and null
        // context.
        unsafe {
            bnrand(
                BnrandFlag::Private,
                rnd,
                bits,
                top,
                bottom,
                0,
                core::ptr::null_mut(),
            )
        }
    })
}

/// `static int bnrand_range(BNRAND_FLAG flag, BIGNUM *r, const BIGNUM *range,
/// unsigned int strength, BN_CTX *ctx)` — `crypto/bn/bn_rand.c:133-201`.
///
/// Drawn into `[0, range)`. The two iteration arms are the authority's: when
/// `range` is `100..._2` the draw is taken one bit wide and reduced up to twice, and
/// otherwise the draw is `n` bits wide and rejected. The 100-iteration ceiling and
/// both raise coordinates are kept.
///
/// One deliberate reading difference: the authority dereferences `range->neg`
/// **before** any null test, so a null `range` is a null dereference there. This
/// module follows the crate's `as_ref` convention, under which a null `BIGNUM *`
/// reads as zero, and therefore refuses it with `BN_R_INVALID_RANGE`. That is a
/// graceful extension, not a claim about the authority's crash.
///
/// `bn_check_top(r)` at the authority's return is `BN_DEBUG`-only and is not
/// written.
///
/// # Safety
///
/// `r` must be null or a live, uniquely-owned `BIGNUM`; `range` must be null or
/// live; `ctx` must be null or a live `BN_CTX`.
pub(crate) unsafe fn bnrand_range(
    flag: BnrandFlag,
    r: *mut BigNum,
    range: *const BigNum,
    strength: c_uint,
    ctx: *mut BnCtx,
) -> c_int {
    let mut count = 100;

    if r.is_null() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&BN_RAND_140) };
        return 0;
    }

    // See the note on null `range` in this function's documentation.
    // SAFETY: `range` is null or live per this function's `# Safety` section.
    let range_neg = match unsafe { as_ref(range) } {
        Some(b) => b.neg,
        None => 0,
    };
    // SAFETY: `range` is null or live, and `as_ref` reads a null object as zero.
    if range_neg != 0 || unsafe { BN_is_zero(range) } != 0 {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&BN_RAND_145) };
        return 0;
    }

    // SAFETY: `range` is null or live; `as_ref` inside reads a null object as zero, so
    // the answer is 0 rather than a read of a null pointer.
    let n = unsafe { BN_num_bits(range) }; /* n > 0 */
    if n == 1 {
        // `range` is one, so the only value in `[0, range)` is zero.
        // SAFETY: `r` is non-null and live, checked above.
        unsafe { BN_zero_ex(r) };
    } else if
    // SAFETY: `range` is null or live; both reads are of the same live object.
    unsafe { BN_is_bit_set(range, n - 2) } == 0
        // SAFETY: as the read above.
        && unsafe { BN_is_bit_set(range, n - 3) } == 0
    {
        /*
         * range = 100..._2, so 3*range (= 11..._2) is exactly one bit longer
         * than range
         */
        loop {
            // SAFETY: `flag` and `strength` are values, `r`/`range`/`ctx` are null or
            // live per this function's `# Safety` section. `n + 1` cannot be reached
            // with `n == c_int::MAX` for a `BIGNUM` this process can hold, and
            // `wrapping_add` keeps a debug build from panicking if it were.
            if unsafe {
                bnrand(
                    flag,
                    r,
                    n.wrapping_add(1),
                    BN_RAND_TOP_ANY,
                    BN_RAND_BOTTOM_ANY,
                    strength,
                    ctx,
                )
            } == 0
            {
                return 0;
            }

            /*
             * If r < 3*range, use r := r MOD range (which is either r, r -
             * range, or r - 2*range). Otherwise, iterate once more. Since
             * 3*range = 11..._2, each iteration succeeds with probability >=
             * .75.
             */
            // SAFETY: `r` and `range` are live per this function's `# Safety` section.
            if unsafe { BN_cmp(r, range) } >= 0 {
                // SAFETY: all three are live and `r` aliases `r`, which `BN_sub`
                // permits.
                if unsafe { BN_sub(r, r.cast_const(), range) } == 0 {
                    return 0;
                }
                // SAFETY: as the comparison above.
                if unsafe { BN_cmp(r, range) } >= 0 {
                    // SAFETY: as the subtraction above.
                    if unsafe { BN_sub(r, r.cast_const(), range) } == 0 {
                        return 0;
                    }
                }
            }

            count -= 1;
            if count == 0 {
                // SAFETY: a compile-time-constant site.
                unsafe { raise_site(&BN_RAND_180) };
                return 0;
            }

            // SAFETY: `r` and `range` are live per this function's `# Safety` section.
            if unsafe { BN_cmp(r, range) } < 0 {
                break;
            }
        }
    } else {
        loop {
            /* range = 11..._2  or  range = 101..._2 */
            // SAFETY: as the first arm's draw.
            if unsafe {
                bnrand(
                    flag,
                    r,
                    n,
                    BN_RAND_TOP_ANY,
                    BN_RAND_BOTTOM_ANY,
                    strength,
                    ctx,
                )
            } == 0
            {
                return 0;
            }

            count -= 1;
            if count == 0 {
                // SAFETY: a compile-time-constant site.
                unsafe { raise_site(&BN_RAND_193) };
                return 0;
            }

            // SAFETY: `r` and `range` are live per this function's `# Safety` section.
            if unsafe { BN_cmp(r, range) } < 0 {
                break;
            }
        }
    }

    1
}

/// `int BN_rand_range_ex(BIGNUM *r, const BIGNUM *range, unsigned int strength,
/// BN_CTX *ctx)` — `crypto/bn/bn_rand.c:203-207`.
///
/// # Safety
///
/// As [`bnrand_range`].
#[no_mangle]
pub unsafe extern "C" fn BN_rand_range_ex(
    r: *mut BigNum,
    range: *const BigNum,
    strength: c_uint,
    ctx: *mut BnCtx,
) -> c_int {
    guard_ffi(0, || {
        // SAFETY: the caller's contract is this function's `# Safety` section.
        unsafe { bnrand_range(BnrandFlag::Normal, r, range, strength, ctx) }
    })
}

/// `int BN_rand_range(BIGNUM *rnd, const BIGNUM *range)` —
/// `crypto/bn/bn_rand.c:210-213`, behind `#ifndef FIPS_MODULE`.
///
/// # Safety
///
/// As [`bnrand_range`].
#[no_mangle]
pub unsafe extern "C" fn BN_rand_range(rnd: *mut BigNum, range: *const BigNum) -> c_int {
    guard_ffi(0, || {
        // SAFETY: as `BN_rand_range_ex`, with the authority's zero strength and null
        // context.
        unsafe { bnrand_range(BnrandFlag::Normal, rnd, range, 0, core::ptr::null_mut()) }
    })
}

/// `int BN_priv_rand_range_ex(BIGNUM *r, const BIGNUM *range,
/// unsigned int strength, BN_CTX *ctx)` — `crypto/bn/bn_rand.c:216-220`.
///
/// # Safety
///
/// As [`bnrand_range`].
#[no_mangle]
pub unsafe extern "C" fn BN_priv_rand_range_ex(
    r: *mut BigNum,
    range: *const BigNum,
    strength: c_uint,
    ctx: *mut BnCtx,
) -> c_int {
    guard_ffi(0, || {
        // SAFETY: the caller's contract is this function's `# Safety` section.
        unsafe { bnrand_range(BnrandFlag::Private, r, range, strength, ctx) }
    })
}

/// `int BN_priv_rand_range(BIGNUM *rnd, const BIGNUM *range)` —
/// `crypto/bn/bn_rand.c:223-226`, behind `#ifndef FIPS_MODULE`.
///
/// # Safety
///
/// As [`bnrand_range`].
#[no_mangle]
pub unsafe extern "C" fn BN_priv_rand_range(rnd: *mut BigNum, range: *const BigNum) -> c_int {
    guard_ffi(0, || {
        // SAFETY: as `BN_priv_rand_range_ex`, with the authority's zero strength and
        // null context.
        unsafe { bnrand_range(BnrandFlag::Private, rnd, range, 0, core::ptr::null_mut()) }
    })
}

/// `int BN_pseudo_rand(BIGNUM *rnd, int bits, int top, int bottom)` —
/// `crypto/bn/bn_rand.c:229-232`, the deprecated spelling behind
/// `#ifndef OPENSSL_NO_DEPRECATED_3_0`.
///
/// The authority's body is literally `return BN_rand(rnd, bits, top, bottom);`.
///
/// # Safety
///
/// `BN_rand`'s contract is this function's contract.
#[no_mangle]
pub unsafe extern "C" fn BN_pseudo_rand(
    rnd: *mut BigNum,
    bits: c_int,
    top: c_int,
    bottom: c_int,
) -> c_int {
    // SAFETY: `BN_rand`'s contract is this function's contract.
    unsafe { BN_rand(rnd, bits, top, bottom) }
}

/// `int BN_pseudo_rand_range(BIGNUM *r, const BIGNUM *range)` —
/// `crypto/bn/bn_rand.c:234-237`, the deprecated spelling behind
/// `#ifndef OPENSSL_NO_DEPRECATED_3_0`.
///
/// The authority's body is literally `return BN_rand_range(r, range);`.
///
/// # Safety
///
/// `BN_rand_range`'s contract is this function's contract.
#[no_mangle]
pub unsafe extern "C" fn BN_pseudo_rand_range(rnd: *mut BigNum, range: *const BigNum) -> c_int {
    // SAFETY: `BN_rand_range`'s contract is this function's contract.
    unsafe { BN_rand_range(rnd, range) }
}

// =============================================================================================
// Tests — the arms that do not draw randomness.
//
// Every test below stops before `bnrand` reaches `RAND_bytes_ex`: a zero-bit request
// with a pinned `top`/`bottom`, a negative or one-bit `top` request, and the range
// validation and `n == 1` pre-draw guards. The drawing arms are the differential
// court's, not this module's, so no expectation here depends on a random byte.
// =============================================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bn::bignum::{BN_free, BN_new, BN_set_negative, BN_set_word};
    use crate::runtime::err::{err_sites, ERR_clear_error, ERR_peek_error};

    /// The packed code `ERR_peek_error` reports for a recorded site:
    /// `(lib & 0xff) << 23 | (reason & 0x7fffff)`, read from the generated table
    /// rather than typed, so a wrong expectation here cannot disagree with the
    /// coordinates the authority actually uses.
    fn packed(site: &err_sites::ErrSite) -> core::ffi::c_ulong {
        (((site.lib as core::ffi::c_ulong) & 0xff) << 23)
            | ((site.reason as core::ffi::c_ulong) & 0x7f_ffff)
    }

    /// `bits == 0` with `TOP_ANY`/`BOTTOM_ANY` is the one successful `bnrand` arm
    /// that needs no randomness: the authority answers a zero `BIGNUM`.
    #[test]
    fn zero_bits_with_any_top_and_bottom_is_zero() {
        ERR_clear_error();
        // SAFETY: `rnd` is allocated here and live for the test.
        let rnd = unsafe { BN_new() };
        // SAFETY: `rnd` is live.
        unsafe { BN_set_word(rnd, 0xdead) };

        assert_eq!(
            // SAFETY: `rnd` is live and the three values are constants.
            unsafe { BN_rand(rnd, 0, BN_RAND_TOP_ANY, BN_RAND_BOTTOM_ANY) },
            1
        );
        assert_eq!(
            // SAFETY: `rnd` is live.
            unsafe { BN_is_zero(rnd) },
            1,
            "the value was cleared to zero"
        );
        assert_eq!(ERR_peek_error(), 0, "and nothing was raised");

        // SAFETY: `rnd` was allocated by this test.
        unsafe { BN_free(rnd) };
    }

    /// A zero-bit request with a pinned `top` or `bottom` is `toosmall` at the
    /// authority's own coordinate.
    #[test]
    fn zero_bits_with_a_pinned_top_or_bottom_is_too_small() {
        // SAFETY: `rnd` is allocated here and live for the test.
        let rnd = unsafe { BN_new() };
        for (top, bottom) in [
            (BN_RAND_TOP_ONE, BN_RAND_BOTTOM_ANY),
            (BN_RAND_TOP_ANY, BN_RAND_BOTTOM_ODD),
            (2, BN_RAND_BOTTOM_ANY),
        ] {
            ERR_clear_error();
            assert_eq!(
                // SAFETY: `rnd` is live and `top`/`bottom` are plain values.
                unsafe { BN_rand(rnd, 0, top, bottom) },
                0,
                "top={top} bottom={bottom}"
            );
            assert_eq!(
                ERR_peek_error(),
                packed(&BN_RAND_98),
                "top={top} bottom={bottom}"
            );
        }
        // SAFETY: `rnd` was allocated by this test.
        unsafe { BN_free(rnd) };
    }

    /// A negative bit count, and one bit with any positive `top`, are refused
    /// before the buffer is allocated.
    #[test]
    fn a_negative_or_topped_one_bit_request_is_too_small() {
        // SAFETY: `rnd` is allocated here and live for the test.
        let rnd = unsafe { BN_new() };

        for bits in [-1, c_int::MIN] {
            ERR_clear_error();
            assert_eq!(
                // SAFETY: `rnd` is live and the three values are constants.
                unsafe { BN_rand(rnd, bits, BN_RAND_TOP_ANY, BN_RAND_BOTTOM_ANY) },
                0
            );
            assert_eq!(ERR_peek_error(), packed(&BN_RAND_98), "bits={bits}");
        }

        // `top > 0` with a single bit is the authority's second `toosmall` arm. The
        // values above `BN_RAND_TOP_TWO` are not defined by the header, but the
        // guard is `top > 0`, so they take the same path.
        for top in [BN_RAND_TOP_TWO, 2, c_int::MAX] {
            ERR_clear_error();
            // SAFETY: `rnd` is live and `top` is a plain value.
            assert_eq!(unsafe { BN_rand(rnd, 1, top, BN_RAND_BOTTOM_ANY) }, 0);
            assert_eq!(ERR_peek_error(), packed(&BN_RAND_98), "top={top}");
        }

        // SAFETY: `rnd` was allocated by this test.
        unsafe { BN_free(rnd) };
    }

    /// The two deprecated forwards reach the same guard.
    #[test]
    fn the_pseudo_spellings_share_the_guard() {
        // SAFETY: `rnd` is allocated here and live for the test.
        let rnd = unsafe { BN_new() };

        ERR_clear_error();
        assert_eq!(
            // SAFETY: `rnd` is live and the three values are constants.
            unsafe { BN_pseudo_rand(rnd, -1, BN_RAND_TOP_ANY, BN_RAND_BOTTOM_ANY) },
            0
        );
        assert_eq!(ERR_peek_error(), packed(&BN_RAND_98));

        // SAFETY: `rnd` was allocated by this test.
        unsafe { BN_free(rnd) };
    }

    /// A null output is refused at `bnrand_range`'s first line, before `range` is
    /// read at all.
    #[test]
    fn a_null_output_is_refused_before_the_range_is_read() {
        // SAFETY: `range` is allocated here and live for the test.
        let range = unsafe { BN_new() };
        // SAFETY: `range` is live.
        unsafe { BN_set_word(range, 7) };

        ERR_clear_error();
        // SAFETY: the output is null on purpose and `range` is live.
        assert_eq!(unsafe { BN_rand_range(core::ptr::null_mut(), range) }, 0);
        assert_eq!(ERR_peek_error(), packed(&BN_RAND_140));

        // SAFETY: `range` was allocated by this test.
        unsafe { BN_free(range) };
    }

    /// A zero range, a negative range and a null range are all
    /// `BN_R_INVALID_RANGE`. (The authority's null-range behaviour is a null
    /// dereference; this crate reads a null object as zero, as the module note
    /// says.)
    #[test]
    fn a_zero_negative_or_null_range_is_invalid() {
        // SAFETY: `r` is allocated here and live for the test.
        let r = unsafe { BN_new() };
        // SAFETY: `zero` is allocated here and live for the test.
        let zero = unsafe { BN_new() };
        // SAFETY: `negative` is allocated here and live for the test.
        let negative = unsafe { BN_new() };
        // SAFETY: `negative` is live.
        unsafe {
            BN_set_word(negative, 5);
            BN_set_negative(negative, 1);
        }

        let cases: [*const BigNum; 3] = [zero, negative, core::ptr::null()];
        for range in cases {
            ERR_clear_error();
            // SAFETY: `r` is live and each `range` is a case under test.
            assert_eq!(unsafe { BN_rand_range(r, range) }, 0);
            assert_eq!(ERR_peek_error(), packed(&BN_RAND_145));
        }

        // SAFETY: all three were allocated by this test.
        unsafe {
            BN_free(r);
            BN_free(zero);
            BN_free(negative);
        }
    }

    /// `range == 1` takes the `n == 1` arm, which is a `BN_zero` and no draw. Both
    /// public spellings are checked, since the flag does not change the arm.
    #[test]
    fn a_range_of_one_answers_zero_without_drawing() {
        // SAFETY: `r` is allocated here and live for the test.
        let r = unsafe { BN_new() };
        // SAFETY: `one` is allocated here and live for the test.
        let one = unsafe { BN_new() };
        // SAFETY: `one` is live.
        unsafe { BN_set_word(one, 1) };

        ERR_clear_error();
        // SAFETY: `r` and `one` are live.
        assert_eq!(unsafe { BN_rand_range(r, one) }, 1);
        // SAFETY: `r` is live.
        assert_eq!(unsafe { BN_is_zero(r) }, 1);
        assert_eq!(ERR_peek_error(), 0);

        // SAFETY: `r` is live.
        unsafe { BN_set_word(r, 9) }; // make the next answer observable
                                      // SAFETY: `r` and `one` are live.
        assert_eq!(unsafe { BN_priv_rand_range(r, one) }, 1);
        // SAFETY: `r` is live.
        assert_eq!(
            // SAFETY: `r` is live.
            unsafe { BN_is_zero(r) },
            1,
            "the private spelling takes it too"
        );
        assert_eq!(ERR_peek_error(), 0);

        // SAFETY: both were allocated by this test.
        unsafe {
            BN_free(r);
            BN_free(one);
        }
    }
}
