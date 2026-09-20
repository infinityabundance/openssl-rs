//! Phase 8 — `crypto/rsa/rsa_sp800_56b_gen.c`, the SP800-56B RSA key generator.
//!
//! This module is Phase 8.4's. The unit is five internals and one static, and it is
//! the half of 8.4's slice E that D326 measured the three `RSA_generate_*` labels to
//! be blocked on: `rsa_gen.c`'s static `rsa_keygen` sends the ordinary
//! `primes == 2 && bits >= 2048 && BN_num_bits(e) > 16` case here rather than to
//! `rsa_multiprime_keygen`, so this file is on the path of every 2048-bit
//! `RSA_generate_key_ex(rsa, 2048, e = 65537, cb)`.
//!
//! **The three `rsa_sp800_56b_check.c` helpers the generator reaches live here too,
//! and the reason is the prerequisite gate rather than convenience.** The generate
//! path reaches exactly three of that unit's ten functions —
//! [`ossl_rsa_check_public_exponent`], [`ossl_rsa_check_pminusq_diff`] and
//! [`ossl_rsa_get_lcm`] — and the other seven are reachable only from
//! `ossl_rsa_sp800_56b_check_keypair` and the provider's public-key validation, which
//! no 8.4 body calls. Giving `rsa_sp800_56b_check.c` its own module would make those
//! seven names *countable* to the gate, which would then report them as unbuilt
//! internals of an in-progress stratum's unit; D326's own rule is that an unreachable
//! transcription is dead code rather than a landing. So the file's dominant unit here
//! is `rsa_sp800_56b_gen.c` (five symbols against three), and the three helpers are
//! written beside the generator that calls them. `src/rsa/mod.rs` and
//! `src/rsa/object.rs` are the same pattern from the other side: a module's
//! definitions are allowed to be spread across units, and what the map records is the
//! dominant one.
//!
//! **The `RSA_ACVP_TEST` machinery is `void` on this profile.** `include/crypto/rsa.h`
//! defines the type only under `FIPS_MODULE && !OPENSSL_NO_ACVP_TESTS` and spells it
//! `#define RSA_ACVP_TEST void` otherwise, so the `test`/`info` parameter below is
//! `*mut c_void` and the CAVS-only arms are not compiled here. That is the same
//! profile choice `src/rsa/object.rs` makes about the object's own `acvp_test` member,
//! which this crate's `Rsa` does not have.

use core::ffi::{c_int, c_void};

use crate::bn::arith::{
    BN_cmp, BN_div, BN_gcd, BN_mod_exp, BN_mod_inverse, BN_mul, BN_sub, BN_sub_word,
};
use crate::bn::bignum::{
    BN_clear, BN_clear_free, BN_dup, BN_free, BN_is_odd, BN_is_zero, BN_new, BN_num_bits,
    BN_secure_new, BN_set_flags, BN_set_negative, BN_set_word, BN_value_one, BigNum,
};
use crate::bn::ctx::{
    BN_CTX_end, BN_CTX_free, BN_CTX_get, BN_CTX_new_ex, BN_CTX_start, BnCtx, BnGencb,
};
use crate::rsa::object::ossl_ifc_ffc_compute_security_bits;
use crate::rsa::Rsa;
use crate::runtime::err::err_sites::{
    RSA_SP800_56B_GEN_185, RSA_SP800_56B_GEN_454, RSA_SP800_56B_GEN_89, RSA_SP800_56B_GEN_94,
};
use crate::runtime::err::raise_site;

/// `RSA_FIPS1864_MIN_KEYGEN_KEYSIZE` — `crypto/rsa/rsa_sp800_56b_gen.c:20`.
const RSA_FIPS1864_MIN_KEYGEN_KEYSIZE: c_int = 2048;

/// `BN_FLG_CONSTTIME` — `include/openssl/bn.h:67`.
const BN_FLG_CONSTTIME: c_int = 0x04;

/// `int ossl_rsa_check_public_exponent(const BIGNUM *e)` —
/// `crypto/rsa/rsa_sp800_56b_check.c:226-237`.
///
/// The profile's `#else` arm: "Allow small exponents larger than 1 for legacy
/// purposes". The FIPS arm's `[17..256]` bit-length window is not this build's, and
/// neither is the bound it would place on `rsa_multiprime_keygen`'s `e`.
///
/// # Safety
///
/// `e` must be NULL or a live `BIGNUM`.
pub(crate) unsafe fn ossl_rsa_check_public_exponent(e: *const BigNum) -> c_int {
    // SAFETY: `e` is NULL or live per this function's `# Safety` section, and
    // `BN_is_odd`/`BN_cmp`/`BN_value_one` accept those.
    unsafe { c_int::from(BN_is_odd(e) != 0 && BN_cmp(e, BN_value_one()) > 0) }
}

/// `int ossl_rsa_check_pminusq_diff(BIGNUM *diff, const BIGNUM *p, const BIGNUM *q,`
/// `int nbits)` — `crypto/rsa/rsa_sp800_56b_check.c:243-258`.
///
/// `|p - q| > 2^(nbits/2 - 100)`, with `-1` for "the subtraction failed" and `0` for
/// "not far enough apart". The `BN_set_negative(diff, 0)` is the absolute value, and
/// the `BN_sub_word(diff, 1)` before the width test makes the comparison strict:
/// `num_bits(p - q - 1) > bitlen` is the authority's spelling of
/// `p - q > 2^bitlen`.
///
/// # Safety
///
/// `diff` must be live and writable; `p` and `q` must be live.
pub(crate) unsafe fn ossl_rsa_check_pminusq_diff(
    diff: *mut BigNum,
    p: *const BigNum,
    q: *const BigNum,
    nbits: c_int,
) -> c_int {
    let bitlen = (nbits >> 1) - 100;

    // SAFETY: `diff`, `p` and `q` are live per this function's `# Safety` section.
    unsafe {
        if BN_sub(diff, p, q) == 0 {
            return -1;
        }
        BN_set_negative(diff, 0);
        if BN_is_zero(diff) != 0 {
            return 0;
        }
        if BN_sub_word(diff, 1) == 0 {
            return -1;
        }
        c_int::from(BN_num_bits(diff) > bitlen)
    }
}

/// `int ossl_rsa_get_lcm(BN_CTX *ctx, const BIGNUM *p, const BIGNUM *q, BIGNUM *lcm,`
/// `BIGNUM *gcd, BIGNUM *p1, BIGNUM *q1, BIGNUM *p1q1)` —
/// `crypto/rsa/rsa_sp800_56b_check.c:266-275`.
///
/// `LCM(p-1, q-1)` as `(p-1)(q-1) / gcd(p-1, q-1)`. The caller owns every temporary
/// and must have marked them `BN_FLG_CONSTTIME`; this function only consumes them.
///
/// # Safety
///
/// Every pointer is live; `ctx` is a live `BN_CTX`.
#[allow(clippy::too_many_arguments)] // mirrors the authority's signature exactly
pub(crate) unsafe fn ossl_rsa_get_lcm(
    ctx: *mut BnCtx,
    p: *const BigNum,
    q: *const BigNum,
    lcm: *mut BigNum,
    gcd: *mut BigNum,
    p1: *mut BigNum,
    q1: *mut BigNum,
    p1q1: *mut BigNum,
) -> c_int {
    // SAFETY: every pointer is live per this function's `# Safety` section.
    unsafe {
        c_int::from(
            BN_sub(p1, p, BN_value_one()) != 0 /* p-1 */
                && BN_sub(q1, q, BN_value_one()) != 0 /* q-1 */
                && BN_mul(p1q1, p1, q1, ctx) != 0 /* (p-1)(q-1) */
                && BN_gcd(gcd, p1, q1, ctx) != 0
                && BN_div(lcm, core::ptr::null_mut(), p1q1, gcd, ctx) != 0,
        )
    }
}

/// `int ossl_rsa_fips186_4_gen_prob_primes(RSA *rsa, RSA_ACVP_TEST *test, int nbits,`
/// `const BIGNUM *e, BN_CTX *ctx, BN_GENCB *cb)` — `rsa_sp800_56b_gen.c:55-162`.
///
/// Generates `rsa->p` and `rsa->q` and checks the two `|p - q|` separations, drawing a
/// fresh `q` until both hold. The `p1`/`p2`/`Xp*`/`q1`/`q2`/`Xq*` locals are the
/// CAVS-only in/out parameters and are NULL on this profile, so the whole body is the
/// two calls into [`crate::bn::rsa_fips186_4`] plus the separation loop.
///
/// # Safety
///
/// `rsa` must be a live object whose `libctx` is the context the key is being made in;
/// `e` must be live; `ctx` must be a live `BN_CTX`; `cb` must be NULL or a live
/// `BN_GENCB` whose callback is safe to call; `_test` is unused on this profile.
#[allow(clippy::too_many_arguments)] // mirrors the authority's signature exactly
pub(crate) unsafe fn ossl_rsa_fips186_4_gen_prob_primes(
    rsa: *mut Rsa,
    _test: *mut c_void,
    nbits: c_int,
    e: *const BigNum,
    ctx: *mut BnCtx,
    cb: *mut BnGencb,
) -> c_int {
    /* (Step 1) Check key length */
    if nbits < RSA_FIPS1864_MIN_KEYGEN_KEYSIZE {
        // SAFETY: the site is a constant and `raise_site` takes its address.
        unsafe { raise_site(&RSA_SP800_56B_GEN_89) };
        return 0;
    }

    // SAFETY: `e` is live per this function's `# Safety` section.
    if unsafe { ossl_rsa_check_public_exponent(e) } == 0 {
        // SAFETY: as above.
        unsafe { raise_site(&RSA_SP800_56B_GEN_94) };
        return 0;
    }

    // SAFETY: `ctx` is live per this function's `# Safety` section.
    unsafe { BN_CTX_start(ctx) };

    // SAFETY: `ctx` is live; each allocation is a pool slot or NULL.
    let (tmp, xpo, xqo) = unsafe { (BN_CTX_get(ctx), BN_CTX_get(ctx), BN_CTX_get(ctx)) };

    let mut ret: c_int = 0;
    if !(tmp.is_null() || xpo.is_null() || xqo.is_null()) {
        // SAFETY: `xpo` and `xqo` are live pool slots.
        unsafe {
            BN_set_flags(xpo, BN_FLG_CONSTTIME);
            BN_set_flags(xqo, BN_FLG_CONSTTIME);
        }

        let ok = 'body: {
            // SAFETY: `rsa` is live per this function's `# Safety` section; `rsa->p`
            // and `rsa->q` are each NULL or the object's own `BIGNUM`, and both are
            // established non-NULL before the generators below read them. Every other
            // pointer is a live pool slot.
            unsafe {
                if (*rsa).p.is_null() {
                    (*rsa).p = BN_secure_new();
                }
                if (*rsa).q.is_null() {
                    (*rsa).q = BN_secure_new();
                }
                if (*rsa).p.is_null() || (*rsa).q.is_null() {
                    break 'body false;
                }
                BN_set_flags((*rsa).p, BN_FLG_CONSTTIME);
                BN_set_flags((*rsa).q, BN_FLG_CONSTTIME);

                /* (Step 4) Generate p, Xp */
                if crate::bn::rsa_fips186_4::ossl_bn_rsa_fips186_4_gen_prob_primes(
                    (*rsa).p,
                    xpo,
                    core::ptr::null_mut(),
                    core::ptr::null_mut(),
                    core::ptr::null(),
                    core::ptr::null(),
                    core::ptr::null(),
                    nbits,
                    e,
                    ctx,
                    cb,
                ) == 0
                {
                    break 'body false;
                }
                loop {
                    /* (Step 5) Generate q, Xq */
                    if crate::bn::rsa_fips186_4::ossl_bn_rsa_fips186_4_gen_prob_primes(
                        (*rsa).q,
                        xqo,
                        core::ptr::null_mut(),
                        core::ptr::null_mut(),
                        core::ptr::null(),
                        core::ptr::null(),
                        core::ptr::null(),
                        nbits,
                        e,
                        ctx,
                        cb,
                    ) == 0
                    {
                        break 'body false;
                    }

                    /* (Step 6) |Xp - Xq| > 2^(nbitlen/2 - 100) */
                    let separate_x = ossl_rsa_check_pminusq_diff(tmp, xpo, xqo, nbits);
                    if separate_x < 0 {
                        break 'body false;
                    }
                    if separate_x == 0 {
                        continue;
                    }

                    /* (Step 6) |p - q| > 2^(nbitlen/2 - 100) */
                    let separate_pq = ossl_rsa_check_pminusq_diff(tmp, (*rsa).p, (*rsa).q, nbits);
                    if separate_pq < 0 {
                        break 'body false;
                    }
                    if separate_pq == 0 {
                        continue;
                    }
                    break; /* successfully finished */
                }
                (*rsa).dirty_cnt = (*rsa).dirty_cnt.wrapping_add(1);
            }
            true
        };
        if ok {
            ret = 1;
        }
    }

    /* The authority's `err:` label. */
    // SAFETY: each pool slot is NULL or live and `BN_clear` accepts both; `rsa` is
    // live and its `p`/`q` are each NULL or the object's own `BIGNUM`.
    unsafe {
        BN_clear(xpo);
        BN_clear(xqo);
        BN_clear(tmp);
        if ret != 1 {
            BN_clear_free((*rsa).p);
            (*rsa).p = core::ptr::null_mut();
            BN_clear_free((*rsa).q);
            (*rsa).q = core::ptr::null_mut();
        }
        BN_CTX_end(ctx);
    }
    ret
}

/// `int ossl_rsa_sp800_56b_validate_strength(int nbits, int strength)` —
/// `rsa_sp800_56b_gen.c:174-189`.
///
/// -1 means "the target strength is unknown" and is the value the generator passes; a
/// caller that *does* state a strength gets the equality test. The `#ifdef FIPS_MODULE`
/// floor below the computation is not this profile's.
///
/// # Safety
///
/// Takes no pointers. It is `unsafe` only because its caller is.
pub(crate) unsafe fn ossl_rsa_sp800_56b_validate_strength(nbits: c_int, strength: c_int) -> c_int {
    let s = c_int::from(ossl_ifc_ffc_compute_security_bits(nbits));

    if strength != -1 && s != strength {
        // SAFETY: the site is a constant and `raise_site` takes its address.
        unsafe { raise_site(&RSA_SP800_56B_GEN_185) };
        return 0;
    }
    1
}

/// `static int rsa_validate_rng_strength(EVP_RAND_CTX *rng, int nbits)` —
/// `rsa_sp800_56b_gen.c:195-211`.
///
/// The profile's `#else` arm is the `rng == NULL` refusal and nothing else; the
/// strength comparison below it is inside `#ifdef FIPS_MODULE`, which is why `nbits`
/// is unread here.
fn rsa_validate_rng_strength(rng: *mut c_void, _nbits: c_int) -> c_int {
    if rng.is_null() {
        0
    } else {
        1
    }
}

/// `int ossl_rsa_sp800_56b_derive_params_from_pq(RSA *rsa, int nbits,`
/// `const BIGNUM *e, BN_CTX *ctx)` — `rsa_sp800_56b_gen.c:237-345`.
///
/// Fills in `n`, `d`, `dmp1`, `dmq1` and `iqmp` from `p` and `q`.
///
/// **The three-valued answer is the contract**: `-1` is an error, `0` is "the computed
/// `d` is too small" and sends [`ossl_rsa_sp800_56b_generate_key`]'s loop round again
/// with fresh primes, and `1` is success. The `err:` label releases *everything it
/// derived* on any non-success, so a round that finds `d` too small leaves the object
/// as it found it and the loop can retry.
///
/// **`e == NULL` skips the first block entirely**, the "`e`, `n` and `d` are already
/// set and do not need recalculating" arm; only the CRT parameters are refreshed.
///
/// **The `err:` label runs even when `gcd` is NULL**, which is the authority's own
/// shape: the `BN_CTX_get` failure jumps to it directly and it releases whatever the
/// object already held. Transcribed rather than folded into the `gcd` guard.
///
/// # Safety
///
/// `rsa` must be a live object whose `p` and `q` are live; `e` must be NULL or live;
/// `ctx` must be a live `BN_CTX`.
pub(crate) unsafe fn ossl_rsa_sp800_56b_derive_params_from_pq(
    rsa: *mut Rsa,
    nbits: c_int,
    e: *const BigNum,
    ctx: *mut BnCtx,
) -> c_int {
    let mut ret: c_int = -1;

    // SAFETY: `ctx` is live per this function's `# Safety` section.
    unsafe { BN_CTX_start(ctx) };

    // SAFETY: `ctx` is live; each allocation is a pool slot or NULL.
    let (p1, q1, lcm, p1q1, gcd) = unsafe {
        (
            BN_CTX_get(ctx),
            BN_CTX_get(ctx),
            BN_CTX_get(ctx),
            BN_CTX_get(ctx),
            BN_CTX_get(ctx),
        )
    };

    if !gcd.is_null() {
        // SAFETY: each is a live pool slot.
        unsafe {
            BN_set_flags(p1, BN_FLG_CONSTTIME);
            BN_set_flags(q1, BN_FLG_CONSTTIME);
            BN_set_flags(lcm, BN_FLG_CONSTTIME);
            BN_set_flags(p1q1, BN_FLG_CONSTTIME);
            BN_set_flags(gcd, BN_FLG_CONSTTIME);
        }

        // SAFETY: `rsa` is live and its `p`/`q` are live per this function's
        // `# Safety` section; `ctx` and the five pool slots are live.
        unsafe {
            /* LCM((p-1, q-1)) */
            if ossl_rsa_get_lcm(ctx, (*rsa).p, (*rsa).q, lcm, gcd, p1, q1, p1q1) != 1 {
                ret = -1;
            } else {
                let mut ok = true;

                /*
                 * if e is provided as a parameter, don't recompute e, d or n
                 */
                if !e.is_null() {
                    /* copy e */
                    BN_free((*rsa).e);
                    (*rsa).e = BN_dup(e);
                    if (*rsa).e.is_null() {
                        ok = false;
                    } else {
                        BN_clear_free((*rsa).d);
                        /* (Step 3) d = (e^-1) mod (LCM(p-1, q-1)) */
                        (*rsa).d = BN_secure_new();
                        if (*rsa).d.is_null() {
                            ok = false;
                        } else {
                            BN_set_flags((*rsa).d, BN_FLG_CONSTTIME);
                            if BN_mod_inverse((*rsa).d, e, lcm, ctx).is_null() {
                                ok = false;
                            } else if BN_num_bits((*rsa).d) <= (nbits >> 1) {
                                /* (Step 3) return an error if d is too small */
                                ret = 0;
                                ok = false;
                            } else {
                                /* (Step 4) n = pq */
                                if (*rsa).n.is_null() {
                                    (*rsa).n = BN_new();
                                }
                                if (*rsa).n.is_null()
                                    || BN_mul((*rsa).n, (*rsa).p, (*rsa).q, ctx) == 0
                                {
                                    ok = false;
                                }
                            }
                        }
                    }
                }

                if ok {
                    /* (Step 5a) dP = d mod (p-1). `BN_mod(r, m, d, ctx)` is the
                     * header's `BN_div(NULL, r, m, d, ctx)`. */
                    if (*rsa).dmp1.is_null() {
                        (*rsa).dmp1 = BN_secure_new();
                    }
                    let mut good = !(*rsa).dmp1.is_null();
                    if good {
                        BN_set_flags((*rsa).dmp1, BN_FLG_CONSTTIME);
                        good = BN_div(core::ptr::null_mut(), (*rsa).dmp1, (*rsa).d, p1, ctx) != 0;
                    }

                    /* (Step 5b) dQ = d mod (q-1) */
                    if good {
                        if (*rsa).dmq1.is_null() {
                            (*rsa).dmq1 = BN_secure_new();
                        }
                        good = !(*rsa).dmq1.is_null();
                        if good {
                            BN_set_flags((*rsa).dmq1, BN_FLG_CONSTTIME);
                            good =
                                BN_div(core::ptr::null_mut(), (*rsa).dmq1, (*rsa).d, q1, ctx) != 0;
                        }
                    }

                    /* (Step 5c) qInv = (inverse of q) mod p */
                    if good {
                        BN_free((*rsa).iqmp);
                        (*rsa).iqmp = BN_secure_new();
                        good = !(*rsa).iqmp.is_null();
                        if good {
                            BN_set_flags((*rsa).iqmp, BN_FLG_CONSTTIME);
                            good = !BN_mod_inverse((*rsa).iqmp, (*rsa).q, (*rsa).p, ctx).is_null();
                        }
                    }

                    if good {
                        (*rsa).dirty_cnt = (*rsa).dirty_cnt.wrapping_add(1);
                        ret = 1;
                    } else {
                        ret = -1;
                    }
                }
            }
        }
    }

    /* The authority's `err:` label. */
    // SAFETY: `rsa` is live and each of its six components is NULL or the object's own
    // `BIGNUM`; every `BN_free` accepts NULL.
    unsafe {
        if ret != 1 {
            BN_free((*rsa).e);
            (*rsa).e = core::ptr::null_mut();
            BN_free((*rsa).d);
            (*rsa).d = core::ptr::null_mut();
            BN_free((*rsa).n);
            (*rsa).n = core::ptr::null_mut();
            BN_free((*rsa).iqmp);
            (*rsa).iqmp = core::ptr::null_mut();
            BN_free((*rsa).dmq1);
            (*rsa).dmq1 = core::ptr::null_mut();
            BN_free((*rsa).dmp1);
            (*rsa).dmp1 = core::ptr::null_mut();
        }
        /* Each pool slot is NULL or live and `BN_clear` accepts both. */
        BN_clear(p1);
        BN_clear(q1);
        BN_clear(lcm);
        BN_clear(p1q1);
        BN_clear(gcd);
        BN_CTX_end(ctx);
    }
    ret
}

/// `int ossl_rsa_sp800_56b_generate_key(RSA *rsa, int nbits, const BIGNUM *efixed,`
/// `BN_GENCB *cb)` — `rsa_sp800_56b_gen.c:365-429`.
///
/// The whole generator: validate the strength, check the RNG, then loop
/// [`ossl_rsa_fips186_4_gen_prob_primes`] and
/// [`ossl_rsa_sp800_56b_derive_params_from_pq`] until the latter accepts the pair, and
/// finish with the pairwise test.
///
/// **`efixed == NULL` means the default exponent, and it also means "I allocated it,
/// so I free it"** — which is why the release is guarded on the parameter rather than
/// on the local.
///
/// # Safety
///
/// `rsa` must be a live object whose `libctx` is the context the key is being made in;
/// `efixed` must be NULL or live; `cb` must be NULL or a live `BN_GENCB` whose
/// callback is safe to call.
pub(crate) unsafe fn ossl_rsa_sp800_56b_generate_key(
    rsa: *mut Rsa,
    nbits: c_int,
    efixed: *const BigNum,
    cb: *mut BnGencb,
) -> c_int {
    /* (Steps 1a-1b) : Currently ignores the strength check */
    // SAFETY: `ossl_rsa_sp800_56b_validate_strength` takes no pointers.
    if unsafe { ossl_rsa_sp800_56b_validate_strength(nbits, -1) } == 0 {
        return 0;
    }

    /* Check that the RNG is capable of generating a key this large */
    // SAFETY: `rsa` is live per this function's `# Safety` section; `RAND_get0_private`
    // accepts a NULL or live `OSSL_LIB_CTX`.
    let rng = unsafe { crate::rand::rand_lib::RAND_get0_private((*rsa).libctx) };
    if rsa_validate_rng_strength(rng.cast(), nbits) == 0 {
        return 0;
    }

    // SAFETY: `rsa` is live and `libctx` is the context the object belongs to;
    // `BN_CTX_new_ex` accepts a NULL or live `OSSL_LIB_CTX`.
    let ctx = unsafe { BN_CTX_new_ex((*rsa).libctx) };
    if ctx.is_null() {
        return 0;
    }

    let mut ret: c_int = 0;
    // `RSA_ACVP_TEST` is `void` on this profile, so the CAVS object is always NULL and
    // the `info == NULL` swap below always runs.
    let info: *mut c_void = core::ptr::null_mut();

    // SAFETY: `rsa` is live; `e` is either the caller's or a fresh object; `ctx` is
    // live. Every pointer is valid for the whole block.
    unsafe {
        let mut own_e = false;
        /* Set default if e is not passed in */
        let e: *mut BigNum = if efixed.is_null() {
            own_e = true;
            BN_new()
        } else {
            efixed.cast_mut()
        };
        let ok = 'body: {
            if own_e && (e.is_null() || BN_set_word(e, 65537) == 0) {
                break 'body false;
            }
            /* (Step 1c) fixed exponent is checked later .*/

            loop {
                /* (Step 2) Generate prime factors */
                if ossl_rsa_fips186_4_gen_prob_primes(rsa, info, nbits, e, ctx, cb) == 0 {
                    break 'body false;
                }

                /* p>q check and skipping in case of acvp test */
                if info.is_null() && BN_cmp((*rsa).p, (*rsa).q) < 0 {
                    core::mem::swap(&mut (*rsa).p, &mut (*rsa).q);
                }

                /* (Steps 3-5) Compute params d, n, dP, dQ, qInv */
                let derived = ossl_rsa_sp800_56b_derive_params_from_pq(rsa, nbits, e, ctx);
                if derived < 0 {
                    break 'body false;
                }
                if derived > 0 {
                    break;
                }
                /* Gets here if computed d is too small - so try again */
            }

            /* (Step 6) Do pairwise test - optional validity test has been omitted */
            ret = ossl_rsa_sp800_56b_pairwise_test(rsa, ctx);
            true
        };
        if !ok {
            ret = 0;
        }
        /* The authority's `err:` label frees `e` only when it allocated it. */
        if own_e {
            BN_free(e);
        }
    }

    // SAFETY: `ctx` is live.
    unsafe { BN_CTX_free(ctx) };
    ret
}

/// `int ossl_rsa_sp800_56b_pairwise_test(RSA *rsa, BN_CTX *ctx)` —
/// `rsa_sp800_56b_gen.c:437-458`.
///
/// `k = (k^e)^d mod n` for `k = 2`. The one place in the generator that raises
/// `RSA_R_PAIRWISE_TEST_FAILURE`, and the reason [`ossl_rsa_sp800_56b_generate_key`]
/// cannot answer 1 without an actual exponentiation having succeeded.
///
/// **A NULL `k` answers 0 without raising**: it is the authority's `goto err`, which
/// skips the `RSA_R_PAIRWISE_TEST_FAILURE` line.
///
/// # Safety
///
/// `rsa` must be a live object with live `e`, `d` and `n`; `ctx` must be a live
/// `BN_CTX`.
pub(crate) unsafe fn ossl_rsa_sp800_56b_pairwise_test(rsa: *mut Rsa, ctx: *mut BnCtx) -> c_int {
    // SAFETY: `ctx` is live per this function's `# Safety` section.
    unsafe { BN_CTX_start(ctx) };

    // SAFETY: `ctx` is live; each allocation is a pool slot or NULL.
    let (tmp, k) = unsafe { (BN_CTX_get(ctx), BN_CTX_get(ctx)) };

    let mut ret: c_int = 0;
    if !k.is_null() {
        // SAFETY: `rsa` is live with live `e`, `d` and `n`; `tmp` and `k` are live pool
        // slots and `ctx` is live.
        unsafe {
            BN_set_flags(k, BN_FLG_CONSTTIME);
            ret = c_int::from(
                BN_set_word(k, 2) != 0
                    && BN_mod_exp(tmp, k, (*rsa).e, (*rsa).n, ctx) != 0
                    && BN_mod_exp(tmp, tmp, (*rsa).d, (*rsa).n, ctx) != 0
                    && BN_cmp(k, tmp) == 0,
            );
        }
        if ret == 0 {
            // SAFETY: the site is a constant and `raise_site` takes its address.
            unsafe { raise_site(&RSA_SP800_56B_GEN_454) };
        }
    }

    // SAFETY: `ctx` is live; this call unwinds the frame started above.
    unsafe { BN_CTX_end(ctx) };
    ret
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bn::bignum::{BN_is_one, BN_set_word};

    /// **The profile's public-exponent rule is the legacy arm**: an odd exponent
    /// greater than 1 is accepted, and everything else — even values, 1, 0 — is not.
    /// The FIPS arm's bit-length window is a different function, and a test that
    /// asserted it here would be asserting a branch this build does not compile.
    #[test]
    fn the_public_exponent_check_is_the_legacy_arm() {
        // SAFETY: each `e` is a fresh object this test owns and `BN_set_word` writes a
        // live one.
        unsafe {
            for (word, want) in [
                (65537u64, 1),
                (3, 1),
                (17, 1),
                (1, 0),
                (0, 0),
                (2, 0),
                (4, 0),
            ] {
                let e = BN_new();
                assert!(!e.is_null());
                assert_eq!(BN_set_word(e, word), 1);
                assert_eq!(
                    ossl_rsa_check_public_exponent(e),
                    want,
                    "ossl_rsa_check_public_exponent({word})"
                );
                BN_free(e);
            }
        }
    }

    /// **`|p - q| > 2^(nbits/2 - 100)` and its three answers.** A 1023-bit `p` against
    /// `q = 3` is far enough apart at 2048 bits; equal factors answer `0`, and a pair
    /// one apart also answers `0` because the `BN_sub_word(diff, 1)` makes the test
    /// strict.
    #[test]
    fn the_pminusq_check_measures_the_gap() {
        // SAFETY: every pointer is a fresh object this test owns.
        unsafe {
            let p = BN_new();
            let q = BN_new();
            let diff = BN_new();
            assert!(!p.is_null() && !q.is_null() && !diff.is_null());

            assert_eq!(crate::bn::bignum::BN_set_bit(p, 1023), 1);
            assert_eq!(BN_set_word(q, 3), 1);
            assert_eq!(ossl_rsa_check_pminusq_diff(diff, p, q, 2048), 1);

            /* `p == q`: zero difference. */
            assert_eq!(ossl_rsa_check_pminusq_diff(diff, p, p, 2048), 0);

            /* One apart: `diff - 1 == 0`, so the width test is not satisfied. */
            let q2 = BN_new();
            assert!(!q2.is_null());
            assert_eq!(BN_set_word(q2, 4), 1);
            let p2 = BN_new();
            assert!(!p2.is_null());
            assert_eq!(BN_set_word(p2, 5), 1);
            assert_eq!(ossl_rsa_check_pminusq_diff(diff, p2, q2, 2048), 0);

            BN_free(p);
            BN_free(q);
            BN_free(q2);
            BN_free(p2);
            BN_free(diff);
        }
    }

    /// **The lcm helper is `LCM(p-1, q-1)`, not `(p-1)(q-1)`.** With `p = 61` and
    /// `q = 53` the factors are 60 and 52, whose gcd is 4, so the lcm is 780 — and the
    /// product identity `(p-1)(q-1) = gcd * lcm` is the independent statement that does
    /// not restate the two `BN_div` arguments.
    #[test]
    fn the_lcm_helper_is_the_least_common_multiple() {
        // SAFETY: every pointer is a fresh object this test owns or a live pool slot.
        unsafe {
            let ctx = BN_CTX_new_ex(core::ptr::null_mut());
            assert!(!ctx.is_null());
            BN_CTX_start(ctx);
            let p = BN_new();
            let q = BN_new();
            assert!(!p.is_null() && !q.is_null());
            assert_eq!(BN_set_word(p, 61), 1);
            assert_eq!(BN_set_word(q, 53), 1);

            let (p1, q1, lcm, p1q1, gcd) = (
                BN_CTX_get(ctx),
                BN_CTX_get(ctx),
                BN_CTX_get(ctx),
                BN_CTX_get(ctx),
                BN_CTX_get(ctx),
            );
            assert!(!gcd.is_null());
            assert_eq!(ossl_rsa_get_lcm(ctx, p, q, lcm, gcd, p1, q1, p1q1), 1);

            let want = BN_new();
            assert!(!want.is_null());
            assert_eq!(BN_set_word(want, 780), 1);
            assert_eq!(BN_cmp(lcm, want), 0);

            /* `(p-1)(q-1) == gcd * lcm`. */
            let prod = BN_new();
            assert!(!prod.is_null());
            assert_eq!(BN_mul(prod, gcd, lcm, ctx), 1);
            assert_eq!(BN_cmp(prod, p1q1), 0);
            assert_eq!(BN_is_one(gcd), 0);

            BN_free(want);
            BN_free(prod);
            BN_free(p);
            BN_free(q);
            BN_CTX_end(ctx);
            BN_CTX_free(ctx);
        }
    }

    /// **The strength check is the equality test with `-1` meaning "unknown".** The
    /// generator always passes `-1`; a caller that states a strength gets `1` for the
    /// matching value, `0` after a raise for a wrong one, and `1` for `-1` whatever the
    /// modulus.
    #[test]
    fn the_strength_check_compares_only_when_a_strength_is_stated() {
        // SAFETY: the function takes no pointers.
        unsafe {
            assert_eq!(ossl_rsa_sp800_56b_validate_strength(2048, -1), 1);
            assert_eq!(ossl_rsa_sp800_56b_validate_strength(3072, -1), 1);
            /* `ossl_ifc_ffc_compute_security_bits(2048) == 112`. */
            assert_eq!(ossl_rsa_sp800_56b_validate_strength(2048, 112), 1);
            assert_eq!(ossl_rsa_sp800_56b_validate_strength(2048, 100), 0);
            assert_eq!(ossl_rsa_sp800_56b_validate_strength(3072, 112), 0);
        }
    }
}
