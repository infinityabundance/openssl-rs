//! Phase 9 — `crypto/rand/rand_uniform.c`: the optimal draw of an integer below a bound.
//!
//! The authority is 109 lines and exports **nothing**. `ossl_rand_uniform_uint32` and
//! `ossl_rand_range_uint32` are declared in `include/crypto/rand.h` (`:148-156`) but are
//! internal to the RAND stratum: reached only by `rand_lib.c`'s nonce/range consumers and by
//! `OSSL_HPKE_get_grease_value`. They are transcribed here as `pub(crate) unsafe fn` with **no**
//! `#[no_mangle]`, and this file therefore adds no C ABI. (The authority carries no `_uint64`
//! variant; the two functions below are the whole translation unit.)
//!
//! # The algorithm
//!
//! A fixed-point number on `[0, 1)` is generated one 32-bit word at a time and multiplied by
//! `upper`. The high word of the product is the integral part `i`, the low word `f` is the
//! fractional part. If `f` is bounded by `1 + ~upper` — algebraically `upper.wrapping_neg()`, the
//! gap between `upper` and the next power of two — then no carry out of any lower word can reach
//! the integral part and `i` is final. Otherwise at most `max_followup_iterations` (10) further
//! words are drawn; each returns `i + 1` on a carry, `i` as soon as `f` is not all ones, and
//! continues only while `f == 0xffff_ffff`. The probability of falling off the end is below
//! `2^-(32*10)`, a residual bias the authority accepts at `rand_uniform.c:93-97`.
//!
//! # Arithmetic
//!
//! The crate builds with `overflow-checks = true`. The authority's `f += f2`, `i + 1`, and
//! `1 + ~upper` are defined unsigned wraparounds in C and become `wrapping_add` /
//! `wrapping_neg` here so that a defined wraparound cannot turn into a panic. `upper * rand` is
//! widened to `uint64_t` before the multiply, so it cannot overflow; `wrapping_mul` is used only
//! to keep every arithmetic step uniform. The C spells the bound `1 + ~upper` (with a comment
//! that compilers warn about it); the equivalent `upper.wrapping_neg()` is transcribed.
//!
//! # `OSSL_LIB_CTX`
//!
//! The authority's `OSSL_LIB_CTX *ctx` is `*mut c_void` at this crate's RAND boundary, the same
//! opaque spelling the crate's `RAND_bytes_ex` already takes; the pointer is only forwarded.
//!
//! # MISSING (before this unit can be integrated)
//!
//! * `crate::rand::rand_lib::RAND_bytes_ex` — `crypto/rand/rand_lib.c`, 9.2 and not landed
//!   (`src/rand/mod.rs:10` lists it as unstarted). Called with the crate's signature
//!   `(ctx: *mut c_void, buf: *mut c_uchar, num: usize, strength: c_uint) -> c_int`; its return
//!   gates on `<= 0`, exactly as the authority's `RAND_bytes_ex(...) <= 0`.
//! * `ossl_assert(bool) -> c_int` — no shared crate helper exists. Its only copy is the private,
//!   `-DNDEBUG`-form `fn ossl_assert` at `src/mac/ssl3_cbc.rs:74`, which this unit needs in
//!   scope. The profile's Makefile sets `-DNDEBUG`, so the call is the non-dying `(x) != 0`,
//!   which is what the `== 0` arms below assume.
//!
//! `ossl_likely` / `ossl_unlikely` (`include/internal/common.h:22-27`) are compiler branch hints
//! with no semantic content; their three authority uses are transcribed as the bare conditions
//! and are deliberately **not** listed as needed.
//!
//! SPDX-License-Identifier: Apache-2.0

#![allow(dead_code)] // reached only from `rand_lib.c`'s nonce draws and HPKE, none landed yet

use core::ffi::{c_int, c_uchar, c_void};
use core::mem::size_of;
use core::ptr;

use crate::rand::rand_lib::RAND_bytes_ex;

/// `ossl_assert` — `include/internal/common.h:41`, which under this profile is
/// `ossl_likely((x) != 0)`: a plain check, **not** the `OPENSSL_die` form (`:52` is the
/// `NDEBUG`-less arm and the build tree carries `-DNDEBUG`). `src/mac/ssl3_cbc.rs`,
/// `src/provider/seed_src.rs` and this unit each carry their own, for the reason those modules
/// give: the authority's is a macro every translation unit includes.
#[inline]
fn ossl_assert(expr: bool) -> c_int {
    c_int::from(expr)
}

/// `const int max_followup_iterations = 10` — `rand_uniform.c:30`.
///
/// The number of extra 32-bit words the range draw is willing to consume before settling for the
/// current integral part; falling off the end leaves a bias below `2^-(32*10)`.
const MAX_FOLLOWUP_ITERATIONS: c_int = 10;

/// `uint32_t ossl_rand_uniform_uint32(OSSL_LIB_CTX *ctx, uint32_t upper, int *err)`
/// — `rand_uniform.c:25-99`.
///
/// An optimal uniform integer in `[0, upper)`. The first word gives the integral part `i` and the
/// fractional part `f`; when `f <= upper.wrapping_neg()` the draw is final. Otherwise up to
/// [`MAX_FOLLOWUP_ITERATIONS`] more words are drawn, and the loop returns `i + 1` on a carry,
/// `i` when `f` is not all ones, and otherwise carries `f`'s low word forward.
///
/// `upper == 0` fails the authority's assertion: `*err` is set to 0 and the answer is 0 — the
/// only path that writes 0 to `*err`. `upper == 1` answers 0 **without touching** `*err`. Any
/// entropy failure sets `*err` to 1 and answers 0.
///
/// # Safety
/// `err` is non-null and writable. `ctx` is NULL or a live library context for
/// [`RAND_bytes_ex`].
pub(crate) unsafe fn ossl_rand_uniform_uint32(
    ctx: *mut c_void,
    upper: u32,
    err: *mut c_int,
) -> u32 {
    // SAFETY: `err` is writable and `ctx` is forwarded under this function's contract; `err` is
    // only ever written, never read. The entropy buffer passed to `RAND_bytes_ex` is a live local.
    unsafe {
        if ossl_assert(upper > 0) == 0 {
            *err = 0;
            return 0;
        }
        // `ossl_unlikely(upper == 1)`: the hint is inert and has been dropped.
        if upper == 1 {
            return 0;
        }

        /* Get 32 bits of entropy */
        let mut rand: u32 = 0;
        // SAFETY: `ctx` is NULL or live per the contract; `&mut rand` is a live local of exactly
        // `size_of::<u32>()` bytes, writable throughout the call.
        if RAND_bytes_ex(
            ctx,
            ptr::addr_of_mut!(rand).cast::<c_uchar>(),
            size_of::<u32>(),
            0,
        ) <= 0
        {
            *err = 1;
            return 0;
        }

        /*
         * We are generating a fixed point number on the interval [0, 1). Multiplying this by the
         * range gives us a number on [0, upper). The high word of the multiplication result
         * represents the integral part we want; the lower word is the fractional part.
         */
        let mut prod: u64 = (upper as u64).wrapping_mul(rand as u64);
        let i: u32 = (prod >> 32) as u32;
        let mut f: u32 = (prod & 0xffff_ffff) as u32;
        // The authority's `f <= 1 + ~upper`; `1 + ~upper` is `upper.wrapping_neg()`.
        // `ossl_likely` is inert and has been dropped.
        if f <= upper.wrapping_neg() {
            return i;
        }

        for _ in 0..MAX_FOLLOWUP_ITERATIONS {
            // SAFETY: as the first draw above.
            if RAND_bytes_ex(
                ctx,
                ptr::addr_of_mut!(rand).cast::<c_uchar>(),
                size_of::<u32>(),
                0,
            ) <= 0
            {
                *err = 1;
                return 0;
            }
            prod = (upper as u64).wrapping_mul(rand as u64);
            let f2: u32 = (prod >> 32) as u32;
            f = f.wrapping_add(f2);
            /* On overflow, add the carry to our result */
            if f < f2 {
                return i.wrapping_add(1);
            }
            /* For not all 1 bits, there is no carry so return the result */
            if f != 0xffff_ffff {
                return i;
            }
            /* setup for the next word of randomness */
            f = (prod & 0xffff_ffff) as u32;
        }
        /*
         * If we get here, we've consumed 32 * max_followup_iterations + 32 bits with no firm
         * decision, which gives a bias with probability < 2^-(32*n).
         */
        i
    }
}

/// `uint32_t ossl_rand_range_uint32(OSSL_LIB_CTX *ctx, uint32_t lower, uint32_t upper,
/// int *err)` — `rand_uniform.c:101-109`.
///
/// A uniform integer in `[lower, upper)`: `lower` plus a uniform draw below `upper - lower`. The
/// assertion is `lower < upper`; on failure `*err` is set to 1 and the answer is 0.
///
/// # Safety
/// `err` is non-null and writable. `ctx` is NULL or a live library context for
/// [`ossl_rand_uniform_uint32`].
pub(crate) unsafe fn ossl_rand_range_uint32(
    ctx: *mut c_void,
    lower: u32,
    upper: u32,
    err: *mut c_int,
) -> u32 {
    // SAFETY: `err` is writable and `ctx` is forwarded unchanged under this function's contract.
    unsafe {
        if ossl_assert(lower < upper) == 0 {
            *err = 1;
            return 0;
        }
        // `upper - lower` is positive because of the assertion and is transcribed as
        // `wrapping_sub`; the sum is strictly below `upper`, so `wrapping_add` is defensive only.
        lower.wrapping_add(ossl_rand_uniform_uint32(
            ctx,
            upper.wrapping_sub(lower),
            err,
        ))
    }
}

#[cfg(test)]
mod tests {
    //! The range helper with no caller yet, tested against the properties the authority's own
    //! code states: the `upper == 0` assertion that clears `*err`, the `upper == 1` edge that
    //! leaves `*err` untouched, the `lower < upper` refusal in `ossl_rand_range_uint32`, the
    //! wrapping form of the early-exit bound `1 + ~upper`, and the interval invariant that holds
    //! across repeated draws (the `MAX_FOLLOWUP_ITERATIONS` loop included).
    //!
    //! The draws that need entropy require the landed `RAND_bytes_ex`; until then the crate does
    //! not compile this unit, as the module's MISSING note records.

    use super::*;

    /// `upper == 0` fails the authority's assertion: `*err` is written 0 and the answer is 0,
    /// with no entropy drawn.
    #[test]
    fn uniform_rejects_zero_upper_and_clears_err() {
        let mut err: c_int = 7;
        // SAFETY: `err` is a live local; `upper == 0` returns before `RAND_bytes_ex`.
        let v = unsafe { ossl_rand_uniform_uint32(ptr::null_mut(), 0, ptr::addr_of_mut!(err)) };
        assert_eq!(v, 0);
        assert_eq!(err, 0);
    }

    /// `upper == 1` is the one in-range bound with a single outcome: 0, and `*err` is left
    /// untouched because the authority returns before any `*err` write.
    #[test]
    fn uniform_one_answers_zero_without_touching_err() {
        let mut err: c_int = 7;
        // SAFETY: `err` is a live local; `upper == 1` returns before `RAND_bytes_ex`.
        let v = unsafe { ossl_rand_uniform_uint32(ptr::null_mut(), 1, ptr::addr_of_mut!(err)) };
        assert_eq!(v, 0);
        assert_eq!(err, 7, "upper == 1 returns before touching err");
    }

    /// `lower >= upper` fails the authority's assertion: `*err` is set to 1 and the answer is 0.
    #[test]
    fn range_refuses_an_empty_or_inverted_interval() {
        let mut err: c_int = 0;
        // SAFETY: `err` is a live local; the assertion failure returns before any draw.
        let empty =
            unsafe { ossl_rand_range_uint32(ptr::null_mut(), 5, 5, ptr::addr_of_mut!(err)) };
        assert_eq!(empty, 0);
        assert_eq!(err, 1);

        err = 0;
        // SAFETY: as above.
        let inverted =
            unsafe { ossl_rand_range_uint32(ptr::null_mut(), 6, 5, ptr::addr_of_mut!(err)) };
        assert_eq!(inverted, 0);
        assert_eq!(err, 1);
    }

    /// The early-exit bound `f <= 1 + ~upper` is `f <= upper.wrapping_neg()`: at both ends of the
    /// `u32` range the C's `1 + ~upper` is a defined wrap, which must not panic under
    /// `overflow-checks = true`.
    #[test]
    fn the_early_exit_bound_is_the_negation_of_upper() {
        assert_eq!(1u32.wrapping_add(!1u32), 1u32.wrapping_neg());
        assert_eq!(1u32.wrapping_add(!u32::MAX), u32::MAX.wrapping_neg());
        assert_eq!(1u32.wrapping_neg(), u32::MAX);
        assert_eq!(u32::MAX.wrapping_neg(), 1);
    }

    /// Repeated draws stay inside the authority's half-open interval `[lower, upper)` and leave
    /// `*err` clear; the `MAX_FOLLOWUP_ITERATIONS` follow-up path must not escape it either.
    ///
    /// This is the draw that needs the landed `RAND_bytes_ex`; the interval invariant is the
    /// property the authority's own comments state for both the early exit and the follow-up loop.
    #[test]
    fn repeated_range_calls_stay_inside_the_half_open_interval() {
        let mut err: c_int = 0;
        for _ in 0..256 {
            // SAFETY: `err` is a live local; `ctx` is NULL, which `RAND_bytes_ex` resolves to the
            // default library context.
            let v =
                unsafe { ossl_rand_range_uint32(ptr::null_mut(), 3, 10, ptr::addr_of_mut!(err)) };
            assert!(
                (3..10).contains(&v),
                "the authority's contract is [lower, upper)"
            );
            assert_eq!(err, 0);
        }
    }
}
