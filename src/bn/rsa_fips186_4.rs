//! Phase 5 — `crypto/bn/bn_rsa_fips186_4.c`: the probable-prime generators RSA key
//! generation is built on.
//!
//! The unit is four static helpers, two functions and one data symbol, and it is
//! Phase 5's by its declaring header — `include/crypto/bn.h` — even though its only
//! callers are in `crypto/rsa`. D324's ownership-transition row records that
//! assignment explicitly: the owner of a shared internal is the earliest stratum that
//! *calls* it, and the only authority callers of these names are
//! `crypto/rsa/rsa_sp800_56b_gen.c`, which is Phase 8's. The module therefore
//! declares Phase 5, matching [`crate::bn::primes`], and Phase 8 reaches it as a
//! prerequisite rather than owning it.
//!
//! ## What the file is
//!
//! FIPS 186-4 B.3.6 — with FIPS 186-5's updated tables — generates an RSA prime `p`
//! from two auxiliary probable primes `p1`/`p2` and a random `X`, by the Chinese
//! Remainder Theorem: [`ossl_bn_rsa_fips186_4_derive_prime`] computes
//! `R = ((r2^-1 mod 2r1)*r2) - ((2r1^-1 mod r2)*2r1)`, then walks `Y = R + k*2r1r2`
//! until `gcd(Y-1, e) = 1` and `Y` is probably prime.
//!
//! Two things about the transcription are worth naming before the bodies:
//!
//! * **The profile's constants are FIPS 186-5's, not 186-4's.** The authority's four
//!   table functions carry the 186-5 Table A.1/B.1 entries, including the `>= 4096`
//!   arm 186-4 did not have, and they are what the file's own header comment
//!   describes.
//! * **`ossl_bn_inv_sqrt_2` is the crate's static-`BIGNUM` idiom, not a `static`.**
//!   The authority declares a `const BIGNUM` with `BN_FLG_STATIC_DATA`; this crate's
//!   `BIGNUM` owns a heap `Vec` and has no C layout to place in `.rodata`, so the
//!   constant is a lazily built cached object returned by reference, exactly as
//!   [`crate::bn::primes`]'s `BN_get0_nist_prime_*` family represents *its* static
//!   `BIGNUM`s. The value is the authority's own `inv_sqrt_2_val[]`, and the module
//!   test re-derives it from `ceil(2^256 / sqrt(2))`, so the limbs are checked rather
//!   than trusted.

use core::ffi::c_int;
use core::sync::atomic::{AtomicPtr, Ordering};

use crate::bn::arith::{
    BN_add, BN_add_word, BN_are_coprime, BN_lshift, BN_lshift1, BN_mod_inverse, BN_mod_sub, BN_mul,
    BN_sub, BN_sub_word,
};
use crate::bn::bignum::{
    new_owned, BN_clear, BN_copy, BN_free, BN_is_negative, BN_num_bits, BN_set_flags, BN_value_one,
    BigNum,
};
use crate::bn::ctx::{BN_CTX_end, BN_CTX_get, BN_CTX_start, BN_GENCB_call, BnCtx, BnGencb};
use crate::bn::primes::ossl_bn_check_generated_prime;
use crate::bn::rand::{
    BN_priv_rand_ex, BN_priv_rand_range_ex, BN_RAND_BOTTOM_ODD, BN_RAND_TOP_ONE,
};
use crate::runtime::err::err_sites::BN_RSA_FIPS186_4_391;
use crate::runtime::err::raise_site;

/// `BN_FLG_CONSTTIME` — `include/openssl/bn.h:67`.
const BN_FLG_CONSTTIME: c_int = 0x04;

/// `inv_sqrt_2_val[]` — `crypto/bn/bn_rsa_fips186_4.c:38-41`, little-endian limbs.
///
/// `BN_DEF(lo, hi)` is `(BN_ULONG)hi << 32 | lo` on this `BN_BITS2 == 64` profile, so
/// each source row becomes one 64-bit limb and the rows are already in `d[0]`-first
/// order. The test below is what keeps that reading honest.
const INV_SQRT_2_LIMBS: [u64; 4] = [
    0xED17_AC85_8333_9916,
    0x1D6F_60BA_893B_A84C,
    0x597D_89B3_754A_BE9F,
    0xB504_F333_F9DE_6484,
];

/// The cached object for [`ossl_bn_inv_sqrt_2`].
///
/// The authority's is a `static const BIGNUM` and two reads answer the same address; a
/// caller may compare them (nothing does, but the object is shared static storage by
/// contract). Building it lazily and caching it reproduces that: a caller that leaks
/// the pointer — it must not free it — leaks exactly one.
static INV_SQRT_2: AtomicPtr<BigNum> = AtomicPtr::new(core::ptr::null_mut());

/// `extern const BIGNUM ossl_bn_inv_sqrt_2` — `crypto/bn/bn_rsa_fips186_4.c:43-49`.
///
/// `1 / sqrt(2) * 2^256`, rounded up. The name is kept because two authority bodies
/// read the symbol by name, and the crate's static-`BIGNUM` representation is a
/// function answering a pointer to shared, lazily built storage.
///
/// # Safety
///
/// Takes no pointers. The result is shared storage and must not be modified or freed.
pub(crate) unsafe fn ossl_bn_inv_sqrt_2() -> *const BigNum {
    let existing = INV_SQRT_2.load(Ordering::Acquire);
    if !existing.is_null() {
        return existing;
    }
    let fresh = new_owned(INV_SQRT_2_LIMBS.to_vec(), 0);
    match INV_SQRT_2.compare_exchange(
        core::ptr::null_mut(),
        fresh,
        Ordering::AcqRel,
        Ordering::Acquire,
    ) {
        Ok(_) => fresh,
        Err(winner) => {
            // SAFETY: `fresh` is the object this call allocated and has not been
            // published, so releasing it here leaves the cached one alone.
            unsafe { BN_free(fresh) };
            winner
        }
    }
}

/// `static int bn_rsa_fips186_5_aux_prime_MR_rounds(int nbits)` —
/// `crypto/bn/bn_rsa_fips186_4.c:55-64`.
///
/// FIPS 186-5 Table B.1's minimum Miller-Rabin rounds for the *auxiliary* primes.
/// `0` is the error answer for an unsupported width, and the caller turns it into a
/// refusal rather than a smaller round count.
fn bn_rsa_fips186_5_aux_prime_mr_rounds(nbits: c_int) -> c_int {
    if nbits >= 4096 {
        44
    } else if nbits >= 3072 {
        41
    } else if nbits >= 2048 {
        38
    } else {
        0
    }
}

/// `static int bn_rsa_fips186_5_prime_MR_rounds(int nbits)` —
/// `crypto/bn/bn_rsa_fips186_4.c:70-77`.
///
/// The same table's rounds for the RSA primes `p` and `q` themselves, a much smaller
/// number than the auxiliary primes' because each candidate is only reached after
/// `gcd(Y-1, e) = 1`.
fn bn_rsa_fips186_5_prime_mr_rounds(nbits: c_int) -> c_int {
    if nbits >= 3072 {
        4
    } else if nbits >= 2048 {
        5
    } else {
        0
    }
}

/// `static int bn_rsa_fips186_5_aux_prime_min_size(int nbits)` —
/// `crypto/bn/bn_rsa_fips186_4.c:88-97`.
///
/// FIPS 186-5 Table A.1's minimum auxiliary-prime length.
fn bn_rsa_fips186_5_aux_prime_min_size(nbits: c_int) -> c_int {
    if nbits >= 4096 {
        201
    } else if nbits >= 3072 {
        171
    } else if nbits >= 2048 {
        141
    } else {
        0
    }
}

/// `static int bn_rsa_fips186_5_aux_prime_max_sum_size_for_prob_primes(int nbits)` —
/// `crypto/bn/bn_rsa_fips186_4.c:108-117`.
///
/// Table A.1's ceiling on `len(p1) + len(p2)`. A pair drawn a little long is a
/// refusal, not a retry.
fn bn_rsa_fips186_5_aux_prime_max_sum_size_for_prob_primes(nbits: c_int) -> c_int {
    if nbits >= 4096 {
        2030
    } else if nbits >= 3072 {
        1518
    } else if nbits >= 2048 {
        1007
    } else {
        0
    }
}

/// `static int bn_rsa_fips186_4_find_aux_prob_prime(const BIGNUM *Xp1, BIGNUM *p1,`
/// `BN_CTX *ctx, int rounds, BN_GENCB *cb)` — `crypto/bn/bn_rsa_fips186_4.c:132-163`.
///
/// The first **odd** integer at or above the seed that is probably prime. The
/// `BN_add_word(p1, 2)` is what makes it odd rather than the seed's own parity: the
/// seed is drawn odd already, but this is also the CAVS entry point and a caller may
/// hand in anything.
///
/// [`ossl_bn_check_generated_prime`] is the un-clamped trial-division-plus-Miller-Rabin
/// the file uses for key generation, and its `-1` is the authority's `goto err`.
///
/// # Safety
///
/// `xp1` must be live; `p1` must be live and writable; `ctx` must be a live `BN_CTX`;
/// `cb` must be NULL or a live `BN_GENCB` whose callback is safe to call.
unsafe fn bn_rsa_fips186_4_find_aux_prob_prime(
    xp1: *const BigNum,
    p1: *mut BigNum,
    ctx: *mut BnCtx,
    rounds: c_int,
    cb: *mut BnGencb,
) -> c_int {
    // SAFETY: `p1` is live and writable and `xp1` is live per this function's
    // `# Safety` section.
    if unsafe { BN_copy(p1, xp1) }.is_null() {
        return 0;
    }
    // SAFETY: `p1` is live.
    unsafe { BN_set_flags(p1, BN_FLG_CONSTTIME) };

    /* Find the first odd number >= Xp1 that is probably prime */
    let mut i: c_int = 0;
    loop {
        i += 1;
        // SAFETY: `cb` is NULL or live.
        unsafe { BN_GENCB_call(cb, 0, i) };
        /* MR test with trial division */
        // SAFETY: `p1` and `ctx` are live; `cb` is NULL or live.
        let tmp = unsafe { ossl_bn_check_generated_prime(p1, rounds, ctx, cb) };
        if tmp > 0 {
            break;
        }
        if tmp < 0 {
            return 0;
        }
        /* Get next odd number */
        // SAFETY: `p1` is live.
        if unsafe { BN_add_word(p1, 2) } == 0 {
            return 0;
        }
    }
    // SAFETY: `cb` is NULL or live.
    unsafe { BN_GENCB_call(cb, 2, i) };
    1
}

/// `int ossl_bn_rsa_fips186_4_gen_prob_primes(BIGNUM *p, BIGNUM *Xpout, BIGNUM *p1,`
/// `BIGNUM *p2, const BIGNUM *Xp, const BIGNUM *Xp1, const BIGNUM *Xp2, int nlen,`
/// `const BIGNUM *e, BN_CTX *ctx, BN_GENCB *cb)` —
/// `crypto/bn/bn_rsa_fips186_4.c:184-251`.
///
/// Two auxiliary primes and then the prime itself. **Each of the six middle arguments
/// is "returned if non-NULL, drawn if NULL"**, and the `p1 == NULL` tests in the
/// cleanup are the two directions of that contract: an internally drawn auxiliary
/// prime is zeroized on the way out, and a caller's buffer is not.
///
/// # Safety
///
/// `p` and `xpout` must be live and writable; `p1`/`p2` must be NULL or live and
/// writable; `xp`/`xp1`/`xp2` must be NULL or live; `e` must be live; `ctx` must be a
/// live `BN_CTX`; `cb` must be NULL or a live `BN_GENCB` whose callback is safe to
/// call.
#[allow(clippy::too_many_arguments)] // mirrors the authority's signature exactly
pub(crate) unsafe fn ossl_bn_rsa_fips186_4_gen_prob_primes(
    p: *mut BigNum,
    xpout: *mut BigNum,
    p1: *mut BigNum,
    p2: *mut BigNum,
    xp: *const BigNum,
    xp1: *const BigNum,
    xp2: *const BigNum,
    nlen: c_int,
    e: *const BigNum,
    ctx: *mut BnCtx,
    cb: *mut BnGencb,
) -> c_int {
    if p.is_null() || xpout.is_null() {
        return 0;
    }

    // SAFETY: `ctx` is live per this function's `# Safety` section.
    unsafe { BN_CTX_start(ctx) };

    // SAFETY: `ctx` is live; each `BN_CTX_get` answers a pool slot or NULL.
    let (p1i, p2i, xp1i, xp2i) = unsafe {
        (
            if !p1.is_null() { p1 } else { BN_CTX_get(ctx) },
            if !p2.is_null() { p2 } else { BN_CTX_get(ctx) },
            if !xp1.is_null() {
                xp1.cast_mut()
            } else {
                BN_CTX_get(ctx)
            },
            if !xp2.is_null() {
                xp2.cast_mut()
            } else {
                BN_CTX_get(ctx)
            },
        )
    };

    let ok = if p1i.is_null() || p2i.is_null() || xp1i.is_null() || xp2i.is_null() {
        false
    } else {
        let bitlen = bn_rsa_fips186_5_aux_prime_min_size(nlen);
        if bitlen == 0 {
            false
        } else {
            let rounds = bn_rsa_fips186_5_aux_prime_mr_rounds(nlen);
            // SAFETY: every pointer below is live per this function's `# Safety`
            // section or a pool slot `BN_CTX_get` just answered, and `ctx` is live.
            unsafe {
                /* (Steps 4.1/5.1): Randomly generate Xp1 if it is not passed in */
                let drew_x1 = xp1.is_null()
                    && BN_priv_rand_ex(xp1i, bitlen, BN_RAND_TOP_ONE, BN_RAND_BOTTOM_ODD, 0, ctx)
                        == 0;
                /* (Steps 4.1/5.1): Randomly generate Xp2 if it is not passed in */
                let drew_x2 = xp2.is_null()
                    && BN_priv_rand_ex(xp2i, bitlen, BN_RAND_TOP_ONE, BN_RAND_BOTTOM_ODD, 0, ctx)
                        == 0;

                if drew_x1 || drew_x2 {
                    false
                } else {
                    /* (Steps 4.2/5.2) - find first auxiliary probable primes */
                    let found = bn_rsa_fips186_4_find_aux_prob_prime(xp1i, p1i, ctx, rounds, cb)
                        != 0
                        && bn_rsa_fips186_4_find_aux_prob_prime(xp2i, p2i, ctx, rounds, cb) != 0;
                    /* (FIPS 186-5 Table A.1) auxiliary prime Max length check */
                    let fits = found
                        && BN_num_bits(p1i) + BN_num_bits(p2i)
                            <= bn_rsa_fips186_5_aux_prime_max_sum_size_for_prob_primes(nlen);
                    /* (Steps 4.3/5.3) - generate prime */
                    fits && ossl_bn_rsa_fips186_4_derive_prime(
                        p, xpout, xp, p1i, p2i, nlen, e, ctx, cb,
                    ) != 0
                }
            }
        }
    };

    /* The authority's `err:` label. `p1 == NULL` and `p2 == NULL` are the "internally
     * drawn auxiliary primes are zeroized, a caller's are not" half of the contract;
     * `xp1`/`xp2` hold only a caller's values. */
    // SAFETY: each pointer is NULL or live per this function's contract and `BN_clear`
    // accepts NULL and a pool slot alike; `ctx` is live.
    unsafe {
        if p1.is_null() {
            BN_clear(p1i);
        }
        if p2.is_null() {
            BN_clear(p2i);
        }
        if xp1.is_null() {
            BN_clear(xp1i);
        }
        if xp2.is_null() {
            BN_clear(xp2i);
        }
        BN_CTX_end(ctx);
    }

    c_int::from(ok)
}

/// `int ossl_bn_rsa_fips186_4_derive_prime(BIGNUM *Y, BIGNUM *X, const BIGNUM *Xin,`
/// `const BIGNUM *r1, const BIGNUM *r2, int nlen, const BIGNUM *e,`
/// `BN_CTX *ctx, BN_GENCB *cb)` — `crypto/bn/bn_rsa_fips186_4.c:274-405`.
///
/// The CRT construction of one RSA prime from two auxiliary primes.
///
/// Three details are the algorithm rather than the shape:
///
/// * **`R` is made positive by one addition of the modulus**, because
///   `BN_sub(R, R, tmp)` can go negative when the second product is larger, and
///   `BN_mod_sub` below is only correct for a non-negative `R`.
/// * **The inner loop is `Y = Y + 2r1r2` until the width exceeds `bits`.** With an
///   internally drawn `X` that is a `break` back to step 3; with a caller's `Xin` it
///   is a hard error, because a fixed `X` can never fit a wider `Y`.
/// * **`imax` is `20 * bits`, not FIPS 186-4's `5 * nlen/2`.** The authority's comment
///   cites Roginsky's analysis and FIPS 186-5 Appendix B.9.
///
/// # Safety
///
/// `y` and `x` must be live and writable; `xin`, `r1`, `r2` and `e` must be live;
/// `ctx` must be a live `BN_CTX`; `cb` must be NULL or a live `BN_GENCB` whose
/// callback is safe to call.
#[allow(clippy::too_many_arguments)] // mirrors the authority's signature exactly
pub(crate) unsafe fn ossl_bn_rsa_fips186_4_derive_prime(
    y: *mut BigNum,
    x: *mut BigNum,
    xin: *const BigNum,
    r1: *const BigNum,
    r2: *const BigNum,
    nlen: c_int,
    e: *const BigNum,
    ctx: *mut BnCtx,
    cb: *mut BnGencb,
) -> c_int {
    let bits = nlen >> 1;

    // SAFETY: `ctx` is live per this function's `# Safety` section.
    unsafe { BN_CTX_start(ctx) };

    // SAFETY: `ctx` is live; each allocation is a pool slot or NULL.
    let (base, range, r, tmp, r1r2x2, y1, r1x2) = unsafe {
        (
            BN_CTX_get(ctx),
            BN_CTX_get(ctx),
            BN_CTX_get(ctx),
            BN_CTX_get(ctx),
            BN_CTX_get(ctx),
            BN_CTX_get(ctx),
            BN_CTX_get(ctx),
        )
    };

    let mut ret: c_int = 0;
    if !r1x2.is_null() {
        // SAFETY: every pointer below is live per this function's `# Safety` section
        // or a pool slot `BN_CTX_get` just answered, and `ctx` is live.
        unsafe {
            'body: {
                if !xin.is_null() && BN_copy(x, xin).is_null() {
                    break 'body;
                }

                /*
                 * We need to generate a random number X in the range
                 * 1/sqrt(2) * 2^(nlen/2) <= X < 2^(nlen/2).
                 * We can rewrite that as:
                 * base = 1/sqrt(2) * 2^(nlen/2)
                 * range = ((2^(nlen/2))) - (1/sqrt(2) * 2^(nlen/2))
                 * X = base + random(range)
                 * We only have the first 256 bit of 1/sqrt(2)
                 */
                if xin.is_null() {
                    let inv = ossl_bn_inv_sqrt_2();
                    if bits < BN_num_bits(inv)
                        || BN_lshift(base, inv, bits - BN_num_bits(inv)) == 0
                        || BN_lshift(range, BN_value_one(), bits) == 0
                        || BN_sub(range, range, base) == 0
                    {
                        break 'body;
                    }
                }

                /*
                 * (Step 1) GCD(2r1, r2) = 1.
                 * [the authority's note that the gcd test was folded into the inversions]
                 */
                if !(BN_lshift1(r1x2, r1) != 0
                    && !BN_mod_inverse(tmp, r1x2, r2, ctx).is_null()
                    /* (Step 2) R = ((r2^-1 mod 2r1) * r2) - ((2r1^-1 mod r2)*2r1) */
                    && !BN_mod_inverse(r, r2, r1x2, ctx).is_null()
                    && BN_mul(r, r, r2, ctx) != 0 /* R = (r2^-1 mod 2r1) * r2 */
                    && BN_mul(tmp, tmp, r1x2, ctx) != 0 /* tmp = (2r1^-1 mod r2)*2r1 */
                    && BN_sub(r, r, tmp) != 0
                    /* Calculate 2r1r2 */
                    && BN_mul(r1r2x2, r1x2, r2, ctx) != 0)
                {
                    break 'body;
                }
                /* Make positive by adding the modulus */
                if BN_is_negative(r) != 0 && BN_add(r, r, r1r2x2) == 0 {
                    break 'body;
                }

                let rounds = bn_rsa_fips186_5_prime_mr_rounds(nlen);
                let imax = 20 * bits; /* max = 20/2 * nbits */
                loop {
                    if xin.is_null() {
                        /*
                         * (Step 3) Choose Random X such that
                         * sqrt(2) * 2^(nlen/2-1) <= Random X <= (2^(nlen/2)) - 1.
                         */
                        if BN_priv_rand_range_ex(x, range, 0, ctx) == 0 || BN_add(x, x, base) == 0 {
                            break 'body;
                        }
                    }
                    /* (Step 4) Y = X + ((R - X) mod 2r1r2) */
                    if BN_mod_sub(y, r, x, r1r2x2, ctx) == 0 || BN_add(y, y, x) == 0 {
                        break 'body;
                    }
                    /* (Step 5) */
                    let mut i: c_int = 0;
                    loop {
                        /* (Step 6) */
                        if BN_num_bits(y) > bits {
                            if xin.is_null() {
                                break; /* Randomly Generated X so Go back to Step 3 */
                            } else {
                                break 'body; /* X is not random so it will always fail */
                            }
                        }
                        BN_GENCB_call(cb, 0, 2);

                        /* (Step 7) If GCD(Y-1) == 1 & Y is probably prime then return Y */
                        if BN_copy(y1, y).is_null() || BN_sub_word(y1, 1) == 0 {
                            break 'body;
                        }

                        if BN_are_coprime(y1, e, ctx) != 0 {
                            let rv = ossl_bn_check_generated_prime(y, rounds, ctx, cb);
                            if rv > 0 {
                                ret = 1;
                                BN_GENCB_call(cb, 3, 0);
                                break 'body;
                            }
                            if rv < 0 {
                                break 'body;
                            }
                        }
                        /* (Step 8-10) */
                        i += 1;
                        if i >= imax {
                            raise_site(&BN_RSA_FIPS186_4_391);
                            break 'body;
                        }
                        if BN_add(y, y, r1r2x2) == 0 {
                            break 'body;
                        }
                    }
                }
            }
        }
    }

    // SAFETY: `y1` is a pool slot or NULL, and `BN_clear` accepts both; `ctx` is live
    // and this call unwinds the frame started above.
    unsafe {
        BN_clear(y1);
        BN_CTX_end(ctx);
    }

    ret
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bn::arith::{BN_cmp, BN_div, BN_gcd, BN_mod_word};
    use crate::bn::bignum::{BN_is_odd, BN_is_one, BN_new, BN_set_bit, BN_set_word};
    use crate::bn::ctx::{BN_CTX_free, BN_CTX_new};
    use crate::bn::primes::BN_check_prime;

    /// `#define BN_DEF(lo, hi)` — the `BN_BITS2 == 64` arm this profile compiles, so
    /// the test reads the source's own literals through the source's own macro rather
    /// than re-typing the combined 64-bit values.
    fn bn_def(lo: u32, hi: u32) -> u64 {
        ((hi as u64) << 32) | lo as u64
    }

    /// The 256-bit schoolbook square of a four-limb value, as eight little-endian
    /// limbs. The product of two 256-bit values is below `2^512`, so no carry escapes
    /// limb seven and the comparison against `2^511` is that limb's top bit.
    fn square(a: &[u64; 4]) -> [u64; 8] {
        let mut out = [0u64; 8];
        for i in 0..4 {
            let mut carry: u128 = 0;
            for j in 0..4 {
                let t = out[i + j] as u128 + (a[i] as u128) * (a[j] as u128) + carry;
                out[i + j] = t as u64;
                carry = t >> 64;
            }
            let mut k = i + 4;
            while carry != 0 && k < 8 {
                let t = out[k] as u128 + carry;
                out[k] = t as u64;
                carry = t >> 64;
                k += 1;
            }
        }
        out
    }

    /// **The static constant is `ceil(2^256 / sqrt(2))`.** The authority's four limbs
    /// are transcribed with its own `BN_DEF(lo, hi)` grouping, and this test
    /// re-derives the value from the definition: `v^2 >= 2^511` and
    /// `(v-1)^2 < 2^511` is what "the ceiling of `2^256/sqrt(2)`" means, and `v` must
    /// also be exactly 256 bits wide for the shifts in [`ossl_bn_rsa_fips186_4_derive_prime`]
    /// to line up.
    #[test]
    fn the_inv_sqrt_2_constant_is_the_ceiling_of_2_to_256_over_root_2() {
        let source = [
            bn_def(0x8333_9916, 0xED17_AC85),
            bn_def(0x893B_A84C, 0x1D6F_60BA),
            bn_def(0x754A_BE9F, 0x597D_89B3),
            bn_def(0xF9DE_6484, 0xB504_F333),
        ];
        assert_eq!(source, INV_SQRT_2_LIMBS);

        // SAFETY: the constant is shared static storage.
        let v = unsafe { ossl_bn_inv_sqrt_2() };
        assert!(!v.is_null());
        // SAFETY: `v` is live.
        assert_eq!(unsafe { BN_num_bits(v) }, 256);
        // SAFETY: two reads of shared storage are one object.
        assert_eq!(v, unsafe { ossl_bn_inv_sqrt_2() });

        let top_of_2_511 = 1u64 << 63;
        assert!(square(&INV_SQRT_2_LIMBS)[7] >= top_of_2_511, "v^2 < 2^511");
        let vm1 = [
            INV_SQRT_2_LIMBS[0] - 1,
            INV_SQRT_2_LIMBS[1],
            INV_SQRT_2_LIMBS[2],
            INV_SQRT_2_LIMBS[3],
        ];
        assert!(square(&vm1)[7] < top_of_2_511, "(v-1)^2 >= 2^511");
    }

    /// **The four FIPS 186-5 tables are the published ladder.** Each answers `0` below
    /// 2048 bits, which is what makes `gen_prob_primes` refuse a 1024-bit request
    /// before drawing anything.
    #[test]
    fn the_fips_186_5_tables_are_the_published_ladder() {
        assert_eq!(bn_rsa_fips186_5_aux_prime_min_size(2047), 0);
        assert_eq!(bn_rsa_fips186_5_aux_prime_min_size(2048), 141);
        assert_eq!(bn_rsa_fips186_5_aux_prime_min_size(3072), 171);
        assert_eq!(bn_rsa_fips186_5_aux_prime_min_size(4096), 201);

        assert_eq!(bn_rsa_fips186_5_aux_prime_mr_rounds(2047), 0);
        assert_eq!(bn_rsa_fips186_5_aux_prime_mr_rounds(2048), 38);
        assert_eq!(bn_rsa_fips186_5_aux_prime_mr_rounds(3072), 41);
        assert_eq!(bn_rsa_fips186_5_aux_prime_mr_rounds(4096), 44);

        assert_eq!(bn_rsa_fips186_5_prime_mr_rounds(2047), 0);
        assert_eq!(bn_rsa_fips186_5_prime_mr_rounds(2048), 5);
        assert_eq!(bn_rsa_fips186_5_prime_mr_rounds(3072), 4);
        assert_eq!(bn_rsa_fips186_5_prime_mr_rounds(4096), 4);

        assert_eq!(
            bn_rsa_fips186_5_aux_prime_max_sum_size_for_prob_primes(2047),
            0
        );
        assert_eq!(
            bn_rsa_fips186_5_aux_prime_max_sum_size_for_prob_primes(2048),
            1007
        );
        assert_eq!(
            bn_rsa_fips186_5_aux_prime_max_sum_size_for_prob_primes(3072),
            1518
        );
        assert_eq!(
            bn_rsa_fips186_5_aux_prime_max_sum_size_for_prob_primes(4096),
            2030
        );
    }

    /// **A `bits` too small to have a ladder entry is refused before any draw.** The
    /// 1024-bit request is the one a caller moving an old key generator meets, and it
    /// answers 0 here rather than at the first random call.
    #[test]
    fn the_generator_refuses_a_null_output_and_a_short_key() {
        // SAFETY: every pointer is a fresh object this test owns or the null the
        // contract names; `ctx` is live.
        unsafe {
            let ctx = BN_CTX_new();
            assert!(!ctx.is_null());
            let p = BN_new();
            let xp = BN_new();
            let e = BN_new();
            assert!(!p.is_null() && !xp.is_null() && !e.is_null());
            assert_eq!(BN_set_word(e, 65537), 1);

            /* `p == NULL`. */
            assert_eq!(
                ossl_bn_rsa_fips186_4_gen_prob_primes(
                    core::ptr::null_mut(),
                    xp,
                    core::ptr::null_mut(),
                    core::ptr::null_mut(),
                    core::ptr::null(),
                    core::ptr::null(),
                    core::ptr::null(),
                    2048,
                    e,
                    ctx,
                    core::ptr::null_mut(),
                ),
                0
            );
            /* `Xpout == NULL`. */
            assert_eq!(
                ossl_bn_rsa_fips186_4_gen_prob_primes(
                    p,
                    core::ptr::null_mut(),
                    core::ptr::null_mut(),
                    core::ptr::null_mut(),
                    core::ptr::null(),
                    core::ptr::null(),
                    core::ptr::null(),
                    2048,
                    e,
                    ctx,
                    core::ptr::null_mut(),
                ),
                0
            );
            /* 1024 bits has no FIPS 186-5 auxiliary-prime entry. */
            assert_eq!(
                ossl_bn_rsa_fips186_4_gen_prob_primes(
                    p,
                    xp,
                    core::ptr::null_mut(),
                    core::ptr::null_mut(),
                    core::ptr::null(),
                    core::ptr::null(),
                    core::ptr::null(),
                    1024,
                    e,
                    ctx,
                    core::ptr::null_mut(),
                ),
                0
            );

            BN_free(p);
            BN_free(xp);
            BN_free(e);
            BN_CTX_free(ctx);
        }
    }

    /// An odd `bits`-wide value: its top and bottom bits set, plus `addend`.
    ///
    /// # Safety
    /// Takes no pointers; the returned object is owned by the caller.
    unsafe fn seeded(bits: c_int, addend: u64) -> *mut BigNum {
        // SAFETY: `BN_new` takes no pointers and answers a fresh object or NULL.
        let b = unsafe { BN_new() };
        assert!(!b.is_null());
        // SAFETY: `b` is fresh and live; `BN_set_bit`/`BN_add_word` take it and the
        // values asserted are non-zero.
        unsafe {
            assert_eq!(BN_set_bit(b, bits - 1), 1);
            assert_eq!(BN_set_bit(b, 0), 1);
            if addend != 0 {
                assert_eq!(BN_add_word(b, addend), 1);
            }
        }
        b
    }

    /// **A fixed `Xp1`/`Xp2`/`Xp` makes the whole derivation a pure function of the
    /// inputs, and the prime it builds satisfies every relation the algorithm
    /// promises.** This is the deterministic half of the unit's behaviour: nothing
    /// here reads a random byte, so `p1`, `p2`, `p` and the congruences are values
    /// both the authority and the crate must compute identically.
    ///
    /// The two seeds are millions apart on purpose: `find_aux_prob_prime` answers the
    /// first odd prime at or above each seed, and primes near `2^140` are a few
    /// hundred apart, so two seeds a handful apart can round to the *same* prime and
    /// make `gcd(2r1, r2) != 1`.
    #[test]
    fn a_fixed_derivation_builds_a_prime_with_the_186_4_congruences() {
        // SAFETY: every pointer is a fresh allocation this test owns; the BN calls are
        // the contract of their own `# Safety` sections.
        unsafe {
            let ctx = BN_CTX_new();
            assert!(!ctx.is_null());
            let e = BN_new();
            assert!(!e.is_null());
            assert_eq!(BN_set_word(e, 65537), 1);

            /* A 2048-bit modulus wants 141-bit auxiliary primes and a 1024-bit `p`. */
            let xp1 = seeded(141, 0);
            let xp2 = seeded(141, 0);
            assert_eq!(BN_add_word(xp2, 30_000_000), 1);

            /* The caller's `X`: the authority copies it and does not range-check it,
             * so any width is legal; a 1024-bit value keeps `Y` at 1024 bits. */
            let xp = seeded(1024, 0x5a5a);
            assert_eq!(crate::bn::bignum::BN_num_bits(xp), 1024);

            let p = BN_new();
            let xout = BN_new();
            let p1 = BN_new();
            let p2 = BN_new();
            assert!(!p.is_null() && !xout.is_null() && !p1.is_null() && !p2.is_null());

            assert_eq!(
                ossl_bn_rsa_fips186_4_gen_prob_primes(
                    p,
                    xout,
                    p1,
                    p2,
                    xp,
                    xp1,
                    xp2,
                    2048,
                    e,
                    ctx,
                    core::ptr::null_mut()
                ),
                1
            );

            /* The prime and its two auxiliary primes. */
            assert_eq!(BN_check_prime(p, ctx, core::ptr::null_mut()), 1);
            assert_eq!(BN_check_prime(p1, ctx, core::ptr::null_mut()), 1);
            assert_eq!(BN_check_prime(p2, ctx, core::ptr::null_mut()), 1);
            assert_eq!(BN_is_odd(p), 1);
            assert_eq!(BN_is_odd(p1), 1);
            assert_eq!(BN_is_odd(p2), 1);
            assert_eq!(crate::bn::bignum::BN_num_bits(p), 1024);
            /* The auxiliary primes are the seeds' successors. */
            assert!(BN_cmp(p1, xp1) >= 0 && BN_cmp(p2, xp2) >= 0);
            assert_ne!(BN_cmp(p1, p2), 0);
            /* The caller's `X` is copied through unchanged. */
            assert_eq!(BN_cmp(xout, xp), 0);

            /* `p = 1 (mod p1)` and `p = -1 (mod p2)`: the two residue classes `R`
             * factors into. The second is the one a first reading gets backwards. */
            let r = BN_new();
            let pm1 = BN_new();
            let gcd = BN_new();
            assert!(!r.is_null() && !pm1.is_null() && !gcd.is_null());
            assert_eq!(BN_div(core::ptr::null_mut(), r, p, p1, ctx), 1);
            assert_eq!(BN_is_one(r), 1);
            assert_eq!(BN_sub(pm1, p2, BN_value_one()), 1);
            assert_eq!(BN_div(core::ptr::null_mut(), r, p, p2, ctx), 1);
            assert_eq!(BN_cmp(r, pm1), 0);

            /* `gcd(p-1, e) = 1`, the step the walk tests before Miller-Rabin. */
            assert_eq!(BN_sub(pm1, p, BN_value_one()), 1);
            assert_eq!(BN_gcd(gcd, pm1, e, ctx), 1);
            assert_eq!(BN_is_one(gcd), 1);

            /* `2 p1 p2` is even and is the modulus the walk advances by. */
            let r1x2 = BN_new();
            let modulus = BN_new();
            assert!(!r1x2.is_null() && !modulus.is_null());
            assert_eq!(BN_lshift1(r1x2, p1), 1);
            assert_eq!(BN_mul(modulus, r1x2, p2, ctx), 1);
            assert_eq!(BN_mod_word(modulus, 2), 0);

            BN_free(p);
            BN_free(xout);
            BN_free(p1);
            BN_free(p2);
            BN_free(r);
            BN_free(pm1);
            BN_free(gcd);
            BN_free(r1x2);
            BN_free(modulus);
            BN_free(xp);
            BN_free(xp1);
            BN_free(xp2);
            BN_free(e);
            BN_CTX_free(ctx);
        }
    }

    /// **The width-driven refusal inside the walk.** A caller-supplied `X` wider than
    /// `nlen/2` makes `BN_num_bits(Y) > bits` a hard error -- a fixed `X` cannot be
    /// retried the way a drawn one can -- so the derivation answers 0 rather than
    /// looping to `imax`.
    #[test]
    fn a_caller_supplied_x_wider_than_half_the_modulus_is_refused() {
        // SAFETY: every pointer is a fresh allocation this test owns.
        unsafe {
            let ctx = BN_CTX_new();
            assert!(!ctx.is_null());
            let e = BN_new();
            assert_eq!(BN_set_word(e, 65537), 1);

            let r1 = BN_new();
            let r2 = BN_new();
            assert_eq!(BN_set_word(r1, 3), 1);
            assert_eq!(BN_set_word(r2, 5), 1);
            /* A 600-bit `X` against a 32-bit modulus: `Y` is far wider than `bits`. */
            let xin = BN_new();
            assert_eq!(BN_set_bit(xin, 599), 1);

            let y = BN_new();
            let x = BN_new();
            assert!(!y.is_null() && !x.is_null());
            assert_eq!(
                ossl_bn_rsa_fips186_4_derive_prime(
                    y,
                    x,
                    xin,
                    r1,
                    r2,
                    32,
                    e,
                    ctx,
                    core::ptr::null_mut(),
                ),
                0
            );

            BN_free(y);
            BN_free(x);
            BN_free(xin);
            BN_free(r1);
            BN_free(r2);
            BN_free(e);
            BN_CTX_free(ctx);
        }
    }
}
