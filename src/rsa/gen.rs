//! Phase 8 — `crypto/rsa/rsa_gen.c`, the RSA key generator and its dispatchers, plus the
//! one deprecated constructor `crypto/rsa/rsa_depr.c` exposes.
//!
//! This module is Phase 8.4's, and it is the last piece of slice E. The three exports
//! [`RSA_generate_key_ex`], [`RSA_generate_multi_prime_key`] and [`RSA_generate_key`]
//! were the names D326 could not land: their ordinary 2048-bit path goes through
//! `rsa_keygen` -> [`crate::rsa::sp800`] -> [`crate::bn::rsa_fips186_4`], which did not
//! exist. It does now, so the whole dispatcher chain lands here.
//!
//! **Three translation units, one module, and the dominant one is `rsa_gen.c`.** The
//! file is `rsa_gen.c`'s static `rsa_multiprime_keygen`, the static `rsa_keygen` above
//! it, the two public dispatchers, and `ossl_rsa_multiprime_derive`; on top of that
//! sits `rsa_depr.c`'s only body, `RSA_generate_key` — the 1.1.1-era constructor that
//! builds a `BN_GENCB` and a `BIGNUM` exponent and forwards to
//! [`RSA_generate_key_ex`]. `rsa_gen.c` defines three of the symbols and `rsa_depr.c`
//! one, so the module maps to `rsa_gen.c`; a module's definitions are allowed to be
//! spread across units and the map records the dominant one (the same shape
//! `src/rsa/mod.rs` and `src/rsa/object.rs` already have).
//!
//! **There is no `FILE` constant and that is a measurement.** Every allocation these
//! bodies make is a `BN_CTX` or a `BIGNUM`, and this crate's `BnCtx`/`BigNum` are
//! Rust-native structures that never route through `CRYPTO_set_mem_functions` (D321
//! records that plane), so `rsa_gen.c` has no `OPENSSL_zalloc`/`OPENSSL_malloc` call
//! for a `file` string to attribute.
//!
//! **The two multiplies that are `BN_mod`'s remainder slot** are written as the
//! header's own macro expansion (`BN_div(NULL, r, m, d, ctx)`), because this crate
//! deliberately does not export a `BN_mod` (it is a macro in the authority's `bn.h`).
//! That is the same substitution D326 recorded for the X9.31 generator's lcm.

use core::ffi::{c_char, c_int, c_uchar, c_ulong, c_void};

use crate::bn::arith::{BN_cmp, BN_div, BN_mod_inverse, BN_mul, BN_rshift, BN_sub};
use crate::bn::bignum::{
    BN_clear_free, BN_copy, BN_dup, BN_free, BN_get_word, BN_new, BN_num_bits, BN_secure_new,
    BN_set_bit, BN_set_flags, BN_value_one, BigNum,
};
use crate::bn::ctx::{
    BN_CTX_end, BN_CTX_free, BN_CTX_get, BN_CTX_new_ex, BN_CTX_start, BN_GENCB_call, BN_GENCB_free,
    BN_GENCB_new, BN_GENCB_set_old, BnCtx, BnGencb,
};
use crate::bn::primes::BN_generate_prime_ex2;
use crate::rsa::mp::{
    multip_info_free_thunk, ossl_rsa_multip_cap, ossl_rsa_multip_info_new, RSA_MAX_PRIME_NUM,
};
use crate::rsa::object::{
    RSA_private_decrypt, RSA_public_encrypt, RSA_size, RSA_ASN1_VERSION_MULTI,
};
use crate::rsa::sp800::{ossl_rsa_check_public_exponent, ossl_rsa_sp800_56b_generate_key};
use crate::rsa::{Rsa, RsaPrimeInfo};
use crate::runtime::err::err_sites::{
    RSA_GEN_282, RSA_GEN_286, RSA_GEN_291, RSA_GEN_296, RSA_GEN_602,
};
use crate::runtime::err::{
    peek_last_lib, peek_last_reason, raise_site, ERR_pop_to_mark, ERR_set_mark,
};
use crate::runtime::mem::{CRYPTO_calloc, CRYPTO_free};
use crate::runtime::stack::{
    OPENSSL_sk_delete, OPENSSL_sk_free, OPENSSL_sk_insert, OPENSSL_sk_new_null,
    OPENSSL_sk_new_reserve, OPENSSL_sk_num, OPENSSL_sk_pop_free, OPENSSL_sk_push, OPENSSL_sk_value,
    OpenSslStack,
};
use crate::selftest::{
    OSSL_SELF_TEST_free, OSSL_SELF_TEST_get_callback, OSSL_SELF_TEST_new, OSSL_SELF_TEST_onbegin,
    OSSL_SELF_TEST_oncorrupt_byte, OSSL_SELF_TEST_onend, OsslCallback,
};

/// `RSA_DEFAULT_PRIME_NUM` — `include/openssl/rsa.h:62`. The two-prime default
/// [`RSA_generate_key_ex`] forwards.
const RSA_DEFAULT_PRIME_NUM: c_int = 2;

/// `RSA_MIN_MODULUS_BITS` — `include/crypto/rsa.h:18`. The floor
/// [`rsa_multiprime_keygen`] refuses below.
const RSA_MIN_MODULUS_BITS: c_int = 512;

/// `BN_FLG_CONSTTIME` — `include/openssl/bn.h:67`.
const BN_FLG_CONSTTIME: c_int = 0x04;

/// `ERR_LIB_BN` — `include/openssl/err.h`, the library an `ERR_GET_LIB` test compares.
const ERR_LIB_BN: c_int = 3;
/// `BN_R_NO_INVERSE` — `include/openssl/bnerr.h`.
const BN_R_NO_INVERSE: c_int = 106;

/// `__FILE__` at `rsa_keygen_pairwise_test`'s `OPENSSL_calloc`/`OPENSSL_free`.
///
/// `crypto/rsa/rsa_gen.c` is a **source-tree** file, so the compiler's path carries
/// the `../../src/openssl-3.6.4/` prefix — measured with `strings` on
/// `forensics/authorities/build/openssl-3.6.4-production/crypto/rsa/libcrypto-lib-rsa_gen.o`,
/// the same check D279 and D280 applied to the cipher units. The allocation is
/// unreachable on this profile (`pairwise_test` is always 0 outside `FIPS_MODULE`),
/// but the constant is the one the authority's own call site would report.
const FILE_RSA_GEN: *const c_char = c"../../src/openssl-3.6.4/crypto/rsa/rsa_gen.c".as_ptr();

/// `__LINE__`, inert under `OPENSSL_NO_CRYPTO_MDEBUG`.
const LINE: c_int = 0;

/// `##__VA_ARGS__`-free `OPENSSL_FILE`/`OPENSSL_LINE` for the two `OPENSSL_free`
/// calls the pairwise test makes; the authority's `OPENSSL_free` is
/// `CRYPTO_free(ptr, OPENSSL_FILE, OPENSSL_LINE)`.
const OSSL_SELF_TEST_TYPE_PCT: &core::ffi::CStr = c"Conditional_PCT";
/// `OSSL_SELF_TEST_DESC_PCT_RSA` — `include/openssl/self_test.h:50`.
const OSSL_SELF_TEST_DESC_PCT_RSA: &core::ffi::CStr = c"RSA";

/// The `OPENSSL_sk_freefunc` adapter for `BN_free`, which the authority's generated
/// `sk_BIGNUM_pop_free(pplist, BN_free)` installs.
///
/// # Safety
/// `bn` must be NULL or a live `BIGNUM` this call owns.
unsafe extern "C" fn bn_free_thunk(bn: *mut c_void) {
    // SAFETY: the caller's contract is this function's, and `BN_free` accepts NULL.
    unsafe { BN_free(bn.cast::<BigNum>()) };
}

/// The `OPENSSL_sk_freefunc` adapter for `BN_clear_free`, which the authority's
/// `sk_BIGNUM_pop_free(factors, BN_clear_free)` installs on the "re-generate all
/// primes" path.
///
/// # Safety
/// `bn` must be NULL or a live `BIGNUM` this call owns.
unsafe extern "C" fn bn_clear_free_thunk(bn: *mut c_void) {
    // SAFETY: the caller's contract is this function's, and `BN_clear_free` accepts
    // NULL.
    unsafe { BN_clear_free(bn.cast::<BigNum>()) };
}

/// `int RSA_generate_key_ex(RSA *rsa, int bits, BIGNUM *e_value, BN_GENCB *cb)` —
/// `rsa_gen.c:41-48`.
///
/// The method dispatch the authority's own comment explains is kept *here*, in the
/// generator's file, "so that we don't introduce a new linker dependency". An
/// `rsa->meth->rsa_keygen` that exists wins; the default table leaves it NULL, so the
/// ordinary call reaches [`RSA_generate_multi_prime_key`].
///
/// # Safety
/// `rsa` is a live object with a live method table; `cb` is NULL or a live callback.
#[no_mangle]
pub unsafe extern "C" fn RSA_generate_key_ex(
    rsa: *mut Rsa,
    bits: c_int,
    e_value: *mut BigNum,
    cb: *mut BnGencb,
) -> c_int {
    // SAFETY: `rsa` is live per the contract and `meth` is the object's own table.
    let keygen = unsafe { (*(*rsa).meth).rsa_keygen };
    if let Some(f) = keygen {
        // SAFETY: `f` is the method's own entry point and the arguments are the
        // caller's under this function's contract.
        return unsafe { f(rsa, bits, e_value, cb) };
    }

    // SAFETY: the same contract, with the authority's `RSA_DEFAULT_PRIME_NUM`.
    unsafe { RSA_generate_multi_prime_key(rsa, bits, RSA_DEFAULT_PRIME_NUM, e_value, cb) }
}

/// `int RSA_generate_multi_prime_key(RSA *rsa, int bits, int primes,`
/// `BIGNUM *e_value, BN_GENCB *cb)` — `rsa_gen.c:50-72`.
///
/// The two method arms are the authority's: a `rsa_multi_prime_keygen` wins outright
/// and a bare `rsa_keygen` is honoured only for `primes == 2` (the comment's own
/// reason is that an external generator "wouldn't know what to do with multi-prime key
/// generated by builtin subroutine"). Both are NULL on the authority's tables, so the
/// builtin `rsa_keygen` below is the answer here, with `pairwise_test = 0`.
///
/// # Safety
/// `rsa` is a live object with a live method table; `e_value` is NULL or live; `cb` is
/// NULL or a live callback.
#[no_mangle]
pub unsafe extern "C" fn RSA_generate_multi_prime_key(
    rsa: *mut Rsa,
    bits: c_int,
    primes: c_int,
    e_value: *mut BigNum,
    cb: *mut BnGencb,
) -> c_int {
    // SAFETY: `rsa` is live per the contract and `meth` is the object's own table.
    let meth = unsafe { &*(*rsa).meth };

    if let Some(f) = meth.rsa_multi_prime_keygen {
        // SAFETY: `f` is the method's own entry point and the arguments are the
        // caller's under this function's contract.
        return unsafe { f(rsa, bits, primes, e_value, cb) };
    } else if let Some(f) = meth.rsa_keygen {
        if primes == RSA_DEFAULT_PRIME_NUM {
            // SAFETY: as above.
            return unsafe { f(rsa, bits, e_value, cb) };
        } else {
            return 0;
        }
    }

    // SAFETY: the object's `libctx` is the context it belongs to; the remaining
    // arguments are the caller's under this function's contract.
    unsafe { rsa_keygen((*rsa).libctx, rsa, bits, primes, e_value, cb, 0) }
}

/// `int ossl_rsa_multiprime_derive(RSA *rsa, int bits, int primes, BIGNUM *e_value,`
/// `STACK_OF(BIGNUM) *factors, STACK_OF(BIGNUM) *exps, STACK_OF(BIGNUM) *coeffs)` —
/// `rsa_gen.c:82-263`.
///
/// Given `n`, `d` and the prime list, derive each extra prime's exponent and
/// coefficient and push them onto the caller's three stacks.
///
/// **The `BN_mod` calls are the header's remainder spelling.** `BN_mod(dmp1, rsa->d,
/// r1, ctx)` is `BN_div(NULL, dmp1, rsa->d, r1, ctx)`, which is how the authority's
/// own `bn.h` defines it and what this crate writes.
///
/// **The two element stacks the caller owns are different objects from the two this
/// body builds.** `pplist` and `pdlist` are internal — partial products and the
/// relative `d` values — and are `pop_free`d with `BN_free` at the release label;
/// `factors`/`exps`/`coeffs` are the caller's and are only appended to.
///
/// # Safety
/// `rsa` is live with live `n`, `d` and `e`; the three stacks are live and owned by
/// the caller.
#[allow(clippy::too_many_arguments)] // mirrors the authority's signature exactly
pub(crate) unsafe fn ossl_rsa_multiprime_derive(
    rsa: *mut Rsa,
    _bits: c_int,
    _primes: c_int,
    _e_value: *mut BigNum,
    factors: *mut OpenSslStack,
    exps: *mut OpenSslStack,
    coeffs: *mut OpenSslStack,
) -> c_int {
    let mut ret: c_int = 0;
    let mut pplist: *mut OpenSslStack = core::ptr::null_mut();
    let mut pdlist: *mut OpenSslStack = core::ptr::null_mut();
    let mut tmp: *mut BigNum = core::ptr::null_mut();
    let mut dval: *mut BigNum = core::ptr::null_mut();
    let mut newexp: *mut BigNum = core::ptr::null_mut();
    let mut newcoeff: *mut BigNum = core::ptr::null_mut();
    let mut dmp1: *mut BigNum = core::ptr::null_mut();
    let mut dmq1: *mut BigNum = core::ptr::null_mut();
    let mut iqmp: *mut BigNum = core::ptr::null_mut();

    // SAFETY: `rsa` is live per this function's `# Safety` section.
    let libctx = unsafe { (*rsa).libctx };
    // SAFETY: `BN_CTX_new_ex` accepts a NULL or live `OSSL_LIB_CTX`.
    let ctx = unsafe { BN_CTX_new_ex(libctx) };

    if !ctx.is_null() {
        // SAFETY: `ctx` is live.
        unsafe { BN_CTX_start(ctx) };
        pplist = OPENSSL_sk_new_null();
        pdlist = if pplist.is_null() {
            core::ptr::null_mut()
        } else {
            OPENSSL_sk_new_null()
        };

        // SAFETY: `ctx` is live; each allocation is a pool slot or NULL.
        let (r0, r1, r2) = unsafe { (BN_CTX_get(ctx), BN_CTX_get(ctx), BN_CTX_get(ctx)) };

        if !pplist.is_null() && !pdlist.is_null() && !r2.is_null() {
            // SAFETY: `r0`, `r1`, `r2` are live pool slots.
            unsafe {
                BN_set_flags(r0, BN_FLG_CONSTTIME);
                BN_set_flags(r1, BN_FLG_CONSTTIME);
                BN_set_flags(r2, BN_FLG_CONSTTIME);
            }

            let built = 'body: {
                // SAFETY: `rsa` is live with a live `n`; `r1` is a live pool slot.
                unsafe {
                    if BN_copy(r1, (*rsa).n).is_null() {
                        break 'body false;
                    }
                }

                // SAFETY: `factors` is the caller's live stack and holds at least the
                // two primes the generator pushed; the elements are `BIGNUM`s.
                let p = unsafe { OPENSSL_sk_value(factors, 0).cast::<BigNum>() };
                // SAFETY: as above, for index 1.
                let q = unsafe { OPENSSL_sk_value(factors, 1).cast::<BigNum>() };

                /* Build list of partial products of primes */
                // SAFETY: `factors` is a live stack; `OPENSSL_sk_num` accepts any.
                let nfactors = unsafe { OPENSSL_sk_num(factors) };
                let mut i: c_int = 0;
                let mut ok = true;
                while i < nfactors {
                    // SAFETY: every pointer below is live per this function's
                    // `# Safety` section or a pool slot; `i` is in the factors stack.
                    unsafe {
                        match i {
                            0 => {
                                /* our first prime, p */
                                if BN_sub(r2, p, BN_value_one()) == 0 {
                                    ok = false;
                                } else {
                                    BN_set_flags(r2, BN_FLG_CONSTTIME);
                                    if BN_mod_inverse(r1, r2, (*rsa).e, ctx).is_null() {
                                        ok = false;
                                    }
                                }
                            }
                            1 => {
                                /* second prime q */
                                if BN_mul(r1, p, q, ctx) == 0 {
                                    ok = false;
                                } else {
                                    tmp = BN_dup(r1);
                                    if tmp.is_null()
                                        || OPENSSL_sk_insert(
                                            pplist,
                                            tmp.cast(),
                                            OPENSSL_sk_num(pplist),
                                        ) == 0
                                    {
                                        ok = false;
                                    } else {
                                        tmp = core::ptr::null_mut();
                                    }
                                }
                            }
                            _ => {
                                let factor = OPENSSL_sk_value(factors, i).cast::<BigNum>();
                                if BN_mul(r1, r1, factor, ctx) == 0 {
                                    ok = false;
                                } else {
                                    tmp = BN_dup(r1);
                                    if tmp.is_null()
                                        || OPENSSL_sk_insert(
                                            pplist,
                                            tmp.cast(),
                                            OPENSSL_sk_num(pplist),
                                        ) == 0
                                    {
                                        ok = false;
                                    } else {
                                        tmp = core::ptr::null_mut();
                                    }
                                }
                            }
                        }
                    }
                    if !ok {
                        break 'body false;
                    }
                    i += 1;
                }

                /* build list of relative d values */
                /* p - 1 */
                // SAFETY: all pointers live per the contract or pool slots.
                unsafe {
                    if BN_sub(r1, p, BN_value_one()) == 0
                        || BN_sub(r2, q, BN_value_one()) == 0
                        || BN_mul(r0, r1, r2, ctx) == 0
                    {
                        break 'body false;
                    }
                    let mut j: c_int = 2;
                    while j < OPENSSL_sk_num(factors) {
                        let factor = OPENSSL_sk_value(factors, j).cast::<BigNum>();
                        dval = BN_new();
                        if dval.is_null() {
                            break 'body false;
                        }
                        BN_set_flags(dval, BN_FLG_CONSTTIME);
                        if BN_sub(dval, factor, BN_value_one()) == 0
                            || BN_mul(r0, r0, dval, ctx) == 0
                            || OPENSSL_sk_insert(pdlist, dval.cast(), OPENSSL_sk_num(pdlist)) == 0
                        {
                            break 'body false;
                        }
                        dval = core::ptr::null_mut();
                        j += 1;
                    }

                    /* Calculate dmp1, dmq1 and additional exponents */
                    dmp1 = BN_secure_new();
                    dmq1 = BN_secure_new();
                    if dmp1.is_null() || dmq1.is_null() {
                        break 'body false;
                    }

                    /* The authority spells this `BN_mod(dmp1, rsa->d, r1, ctx)`, the
                     * header's macro over `BN_div(NULL, dmp1, rsa->d, r1, ctx)`. */
                    if BN_div(core::ptr::null_mut(), dmp1, (*rsa).d, r1, ctx) == 0
                        || OPENSSL_sk_insert(exps, dmp1.cast(), OPENSSL_sk_num(exps)) == 0
                    {
                        break 'body false;
                    }
                    dmp1 = core::ptr::null_mut();

                    if BN_div(core::ptr::null_mut(), dmq1, (*rsa).d, r2, ctx) == 0
                        || OPENSSL_sk_insert(exps, dmq1.cast(), OPENSSL_sk_num(exps)) == 0
                    {
                        break 'body false;
                    }
                    dmq1 = core::ptr::null_mut();

                    let mut j: c_int = 2;
                    while j < OPENSSL_sk_num(factors) {
                        let newpd = OPENSSL_sk_value(pdlist, j - 2).cast::<BigNum>();
                        newexp = BN_new();
                        if newexp.is_null() {
                            break 'body false;
                        }
                        if BN_div(core::ptr::null_mut(), newexp, (*rsa).d, newpd, ctx) == 0
                            || OPENSSL_sk_insert(exps, newexp.cast(), OPENSSL_sk_num(exps)) == 0
                        {
                            break 'body false;
                        }
                        newexp = core::ptr::null_mut();
                        j += 1;
                    }

                    /* Calculate iqmp and additional coefficients */
                    iqmp = BN_new();
                    if iqmp.is_null() {
                        break 'body false;
                    }
                    if BN_mod_inverse(
                        iqmp,
                        OPENSSL_sk_value(factors, 1).cast::<BigNum>(),
                        OPENSSL_sk_value(factors, 0).cast::<BigNum>(),
                        ctx,
                    )
                    .is_null()
                        || OPENSSL_sk_insert(coeffs, iqmp.cast(), OPENSSL_sk_num(coeffs)) == 0
                    {
                        break 'body false;
                    }
                    iqmp = core::ptr::null_mut();

                    let mut j: c_int = 2;
                    while j < OPENSSL_sk_num(factors) {
                        let newpp = OPENSSL_sk_value(pplist, j - 2).cast::<BigNum>();
                        newcoeff = BN_new();
                        if newcoeff.is_null() {
                            break 'body false;
                        }
                        if BN_mod_inverse(
                            newcoeff,
                            newpp,
                            OPENSSL_sk_value(factors, j).cast::<BigNum>(),
                            ctx,
                        )
                        .is_null()
                            || OPENSSL_sk_insert(coeffs, newcoeff.cast(), OPENSSL_sk_num(coeffs))
                                == 0
                        {
                            break 'body false;
                        }
                        newcoeff = core::ptr::null_mut();
                        j += 1;
                    }
                }
                true
            };
            if built {
                ret = 1;
            }
        }
    }

    /* The authority's `err:` label. */
    // SAFETY: each pointer is NULL or an object this call owns; `BN_free` accepts
    // NULL; `OPENSSL_sk_pop_free` accepts a NULL stack.
    unsafe {
        BN_free(newcoeff);
        BN_free(newexp);
        BN_free(dval);
        BN_free(tmp);
        OPENSSL_sk_pop_free(pplist, Some(bn_free_thunk));
        OPENSSL_sk_pop_free(pdlist, Some(bn_free_thunk));
        BN_CTX_end(ctx);
        BN_CTX_free(ctx);
        BN_clear_free(dmp1);
        BN_clear_free(dmq1);
        BN_clear_free(iqmp);
    }
    ret
}

/// `static int rsa_multiprime_keygen(RSA *rsa, int bits, int primes,`
/// `BIGNUM *e_value, BN_GENCB *cb)` — `rsa_gen.c:265-608`.
///
/// The arbitrary-prime generator: below 2048 bits, with `BN_num_bits(e) <= 16`, or
/// with more than two primes. It splits the modulus width evenly across `primes`,
/// draws each prime with `BN_generate_prime_ex2`, checks the running product's top
/// four bits and re-draws or widens the last factor until they are in `[0x9, 0xF]`,
/// then derives `d` modulo `lcm` and the extra components through
/// [`ossl_rsa_multiprime_derive`].
///
/// **`ok` is three-valued and starts at `-1`.** `-1` means "the body failed without
/// saying why", and the release label turns exactly that into `ERR_R_BN_LIB` and a
/// `0`; `1` is success. A function that returned `0` from its early guards never
/// touches the stacks or the context, which is why those guards `return` rather than
/// jump to the label.
///
/// **The `err:` label frees the three stacks without their elements.** That is the
/// authority's own shape (`sk_BIGNUM_free`, not `_pop_free`), and it is transcribed
/// rather than corrected: the only path that would leak is a mid-generation failure,
/// and "fixing" it here would be a behaviour this crate claims and the authority does
/// not have. The one place the authority *does* free elements is the four-prime
/// restart, which is `sk_BIGNUM_pop_free(factors, BN_clear_free)` below.
///
/// # Safety
/// `rsa` is a live object whose `libctx` is the context the key is being made in;
/// `e_value` is NULL or live; `cb` is NULL or a live callback.
unsafe fn rsa_multiprime_keygen(
    rsa: *mut Rsa,
    bits: c_int,
    primes: c_int,
    e_value: *mut BigNum,
    cb: *mut BnGencb,
) -> c_int {
    let mut bitsr = [0 as c_int; RSA_MAX_PRIME_NUM as usize];
    let mut n: c_int = 0;
    let mut bitse: c_int = 0;
    let mut ok: c_int = -1;
    let mut ctx: *mut BnCtx = core::ptr::null_mut();

    /* The four guards, each with its own raise and a plain `return 0`. */
    if bits < RSA_MIN_MODULUS_BITS {
        // SAFETY: the site is a constant.
        unsafe { raise_site(&RSA_GEN_282) };
        return 0;
    }
    if e_value.is_null() {
        // SAFETY: as above.
        unsafe { raise_site(&RSA_GEN_286) };
        return 0;
    }
    /* A bad value for e can cause infinite loops */
    // SAFETY: `e_value` is live per the guard above.
    if unsafe { ossl_rsa_check_public_exponent(e_value) } == 0 {
        // SAFETY: as above.
        unsafe { raise_site(&RSA_GEN_291) };
        return 0;
    }
    if primes < RSA_DEFAULT_PRIME_NUM || primes > ossl_rsa_multip_cap(bits) {
        // SAFETY: as above.
        unsafe { raise_site(&RSA_GEN_296) };
        return 0;
    }

    let mut factors = OPENSSL_sk_new_null();
    if factors.is_null() {
        return 0;
    }
    let exps = OPENSSL_sk_new_null();
    let coeffs = if exps.is_null() {
        core::ptr::null_mut()
    } else {
        OPENSSL_sk_new_null()
    };

    let ran = 'body: {
        if coeffs.is_null() {
            break 'body false;
        }
        // SAFETY: `rsa` is live per this function's `# Safety` section.
        ctx = unsafe { BN_CTX_new_ex((*rsa).libctx) };
        if ctx.is_null() {
            break 'body false;
        }
        // SAFETY: `ctx` is live.
        unsafe { BN_CTX_start(ctx) };
        // SAFETY: `ctx` is live; each allocation is a pool slot or NULL.
        let (r0, r1, r2) = unsafe { (BN_CTX_get(ctx), BN_CTX_get(ctx), BN_CTX_get(ctx)) };
        if r2.is_null() {
            break 'body false;
        }

        /* divide bits into 'primes' pieces evenly */
        let quo = bits / primes;
        let rmd = bits % primes;
        for (i, slot) in bitsr.iter_mut().take(primes as usize).enumerate() {
            *slot = if (i as c_int) < rmd { quo + 1 } else { quo };
        }

        // SAFETY: `rsa` is live; each `BN_new`/`BN_secure_new` answers a fresh object
        // or NULL, and the `BN_set_flags` calls take a live object.
        unsafe {
            (*rsa).dirty_cnt = (*rsa).dirty_cnt.wrapping_add(1);

            /* We need the RSA components non-NULL */
            if (*rsa).n.is_null() {
                (*rsa).n = BN_new();
            }
            if (*rsa).n.is_null() {
                break 'body false;
            }
            if (*rsa).d.is_null() {
                (*rsa).d = BN_secure_new();
            }
            if (*rsa).d.is_null() {
                break 'body false;
            }
            BN_set_flags((*rsa).d, BN_FLG_CONSTTIME);
            if (*rsa).e.is_null() {
                (*rsa).e = BN_new();
            }
            if (*rsa).e.is_null() {
                break 'body false;
            }
            if (*rsa).p.is_null() {
                (*rsa).p = BN_secure_new();
            }
            if (*rsa).p.is_null() {
                break 'body false;
            }
            BN_set_flags((*rsa).p, BN_FLG_CONSTTIME);
            if (*rsa).q.is_null() {
                (*rsa).q = BN_secure_new();
            }
            if (*rsa).q.is_null() {
                break 'body false;
            }
            BN_set_flags((*rsa).q, BN_FLG_CONSTTIME);

            /* initialize multi-prime components */
            if primes > RSA_DEFAULT_PRIME_NUM {
                (*rsa).version = RSA_ASN1_VERSION_MULTI;
                let prime_infos = OPENSSL_sk_new_reserve(None, primes - 2);
                if prime_infos.is_null() {
                    break 'body false;
                }
                if !(*rsa).prime_infos.is_null() {
                    /* could this happen? */
                    OPENSSL_sk_pop_free((*rsa).prime_infos, Some(multip_info_free_thunk));
                }
                (*rsa).prime_infos = prime_infos;

                /* prime_info from 2 to |primes| -1 */
                let mut i: c_int = 2;
                while i < primes {
                    let pinfo = ossl_rsa_multip_info_new();
                    if pinfo.is_null() {
                        break 'body false;
                    }
                    /* The authority discards this result. */
                    OPENSSL_sk_push(prime_infos, pinfo.cast());
                    i += 1;
                }
            }

            if BN_copy((*rsa).e, e_value).is_null() {
                break 'body false;
            }
        }

        /* generate p, q and other primes (if any) */
        let mut i: c_int = 0;
        let generated = {
            'next_i: while i < primes {
                let mut adj: c_int = 0;
                let mut retries: c_int = 0;

                // SAFETY: `rsa` is live with a live `prime_infos` when `i > 1`; every
                // element of that stack is a live `RSA_PRIME_INFO`.
                let prime: *mut BigNum = unsafe {
                    if i == 0 {
                        (*rsa).p
                    } else if i == 1 {
                        (*rsa).q
                    } else {
                        let pinfo =
                            OPENSSL_sk_value((*rsa).prime_infos, i - 2).cast::<RsaPrimeInfo>();
                        (*pinfo).r
                    }
                };
                // SAFETY: `prime` is a live `BIGNUM`.
                unsafe { BN_set_flags(prime, BN_FLG_CONSTTIME) };

                let mut bitst: c_ulong;
                're_do: loop {
                    /* The `for (;;)` loop, then the top-four-bits check that could
                     * `goto redo` from *outside* it. Keeping both in one label is how
                     * that jump is written without a `goto`. */
                    // Every pointer below is live per this function's `# Safety`
                    // section, and `ctx` is live.
                    'find_inverse: loop {
                        // SAFETY: `prime` is live and `ctx` is live; the null `add`
                        // and `rem` are the authority's own.
                        if unsafe {
                            BN_generate_prime_ex2(
                                prime,
                                bitsr[i as usize] + adj,
                                0,
                                core::ptr::null(),
                                core::ptr::null(),
                                cb,
                                ctx,
                            )
                        } == 0
                        {
                            break 'body false;
                        }

                        /* prime should not be equal to p, q, r_3... */
                        {
                            let mut j: c_int = 0;
                            let mut same = false;
                            while j < i {
                                // SAFETY: `rsa`/`prime_infos` are live per the
                                // contract and `j < i`.
                                let prev = unsafe {
                                    if j == 0 {
                                        (*rsa).p
                                    } else if j == 1 {
                                        (*rsa).q
                                    } else {
                                        let pinfo = OPENSSL_sk_value((*rsa).prime_infos, j - 2)
                                            .cast::<RsaPrimeInfo>();
                                        (*pinfo).r
                                    }
                                };
                                // SAFETY: both are live `BIGNUM`s.
                                if unsafe { BN_cmp(prime, prev) } == 0 {
                                    same = true;
                                    break;
                                }
                                j += 1;
                            }
                            if same {
                                continue 'find_inverse; /* goto redo */
                            }
                        }

                        // SAFETY: `prime` and `r2` are live; `rsa->e` is live.
                        unsafe {
                            if BN_sub(r2, prime, BN_value_one()) == 0 {
                                break 'body false;
                            }
                            ERR_set_mark();
                            BN_set_flags(r2, BN_FLG_CONSTTIME);
                            if !BN_mod_inverse(r1, r2, (*rsa).e, ctx).is_null() {
                                break 'find_inverse;
                            }
                            if peek_last_lib() == ERR_LIB_BN as c_ulong
                                && peek_last_reason() == BN_R_NO_INVERSE as c_ulong
                            {
                                ERR_pop_to_mark();
                            } else {
                                break 'body false;
                            }
                            if BN_GENCB_call(cb, 2, n) == 0 {
                                break 'body false;
                            }
                            n += 1;
                        }
                    }

                    bitse += bitsr[i as usize];

                    /* calculate n immediately to see if it's sufficient */
                    if i == 1 {
                        /* we get at least 2 primes */
                        // SAFETY: `rsa->p`/`rsa->q`/`r1` are live, `ctx` is live.
                        if unsafe { BN_mul(r1, (*rsa).p, (*rsa).q, ctx) } == 0 {
                            break 'body false;
                        }
                    } else if i != 0 {
                        /* modulus n = p * q * r_3 * r_4 ... */
                        // SAFETY: as above with `rsa->n`.
                        if unsafe { BN_mul(r1, (*rsa).n, prime, ctx) } == 0 {
                            break 'body false;
                        }
                    } else {
                        /* i == 0, do nothing */
                        // SAFETY: `cb` is NULL or live.
                        if unsafe { BN_GENCB_call(cb, 3, i) } == 0 {
                            break 'body false;
                        }
                        // SAFETY: `prime` is live; the stack is this call's.
                        unsafe {
                            let tmp = BN_dup(prime);
                            if tmp.is_null()
                                || OPENSSL_sk_insert(factors, tmp.cast(), OPENSSL_sk_num(factors))
                                    == 0
                            {
                                break 'body false;
                            }
                        }
                        i += 1;
                        continue 'next_i;
                    }

                    /*
                     * if |r1|, product of factors so far, is not as long as expected
                     * (by checking the first 4 bits are less than 0x9 or greater than
                     * 0xF).
                     */
                    // SAFETY: `r1`/`r2` are live and `ctx` is live.
                    unsafe {
                        if BN_rshift(r2, r1, bitse - 4) == 0 {
                            break 'body false;
                        }
                        bitst = BN_get_word(r2);
                    }

                    if !(0x9..=0xF).contains(&bitst) {
                        bitse -= bitsr[i as usize];
                        // SAFETY: `cb` is NULL or live.
                        if unsafe { BN_GENCB_call(cb, 2, n) } == 0 {
                            break 'body false;
                        }
                        n += 1;
                        if primes > 4 {
                            if bitst < 0x9 {
                                adj += 1;
                            } else {
                                adj -= 1;
                            }
                        } else if retries == 4 {
                            /*
                             * re-generate all primes from scratch, mainly used
                             * in 4 prime case to avoid long loop.
                             */
                            i = -1;
                            bitse = 0;
                            // SAFETY: `factors` is this call's stack and every element is
                            // a `BIGNUM` this call owns.
                            unsafe { OPENSSL_sk_pop_free(factors, Some(bn_clear_free_thunk)) };
                            factors = OPENSSL_sk_new_null();
                            if factors.is_null() {
                                break 'body false;
                            }
                            i += 1;
                            continue 'next_i;
                        }
                        retries += 1;
                        continue 're_do; /* goto redo */
                    }
                    break 're_do;
                }

                /* save product of primes for further use, for multi-prime only */
                // SAFETY: `i > 1` here, so `pinfo` names a live record; the pointers are
                // live per the contract.
                unsafe {
                    if i > 1 {
                        let pinfo =
                            OPENSSL_sk_value((*rsa).prime_infos, i - 2).cast::<RsaPrimeInfo>();
                        if BN_copy((*pinfo).pp, (*rsa).n).is_null() {
                            break 'body false;
                        }
                    }
                    if BN_copy((*rsa).n, r1).is_null() {
                        break 'body false;
                    }
                    if BN_GENCB_call(cb, 3, i) == 0 {
                        break 'body false;
                    }
                    let tmp = BN_dup(prime);
                    if tmp.is_null()
                        || OPENSSL_sk_insert(factors, tmp.cast(), OPENSSL_sk_num(factors)) == 0
                    {
                        break 'body false;
                    }
                }
                i += 1;
            }
            true
        };
        if !generated {
            break 'body false;
        }

        // SAFETY: `rsa->p`/`rsa->q` are live and the stack is this call's.
        unsafe {
            if BN_cmp((*rsa).p, (*rsa).q) < 0 {
                core::mem::swap(&mut (*rsa).p, &mut (*rsa).q);
                /* mirror this in our factor stack */
                let first = OPENSSL_sk_delete(factors, 0);
                if OPENSSL_sk_insert(factors, first, 1) == 0 {
                    break 'body false;
                }
            }

            /* calculate d */

            /* p - 1 */
            if BN_sub(r1, (*rsa).p, BN_value_one()) == 0 {
                break 'body false;
            }
            /* q - 1 */
            if BN_sub(r2, (*rsa).q, BN_value_one()) == 0 {
                break 'body false;
            }
            /* (p - 1)(q - 1) */
            if BN_mul(r0, r1, r2, ctx) == 0 {
                break 'body false;
            }
            /* multi-prime */
            let mut j: c_int = 2;
            while j < primes {
                let pinfo = OPENSSL_sk_value((*rsa).prime_infos, j - 2).cast::<RsaPrimeInfo>();
                /* save r_i - 1 to pinfo->d temporarily */
                if BN_sub((*pinfo).d, (*pinfo).r, BN_value_one()) == 0
                    || BN_mul(r0, r0, (*pinfo).d, ctx) == 0
                {
                    break 'body false;
                }
                j += 1;
            }

            BN_set_flags(r0, BN_FLG_CONSTTIME);
            if BN_mod_inverse((*rsa).d, (*rsa).e, r0, ctx).is_null() {
                break 'body false; /* d */
            }

            /* derive any missing exponents and coefficients */
            if ossl_rsa_multiprime_derive(rsa, bits, primes, e_value, factors, exps, coeffs) == 0 {
                break 'body false;
            }

            /*
             * first 2 factors/exps are already tracked in p/q/dmq1/dmp1 and the
             * first coeff is in iqmp, so pop those off the stack.
             */
            BN_clear_free(OPENSSL_sk_delete(factors, 0).cast::<BigNum>());
            BN_clear_free(OPENSSL_sk_delete(factors, 0).cast::<BigNum>());
            (*rsa).dmp1 = OPENSSL_sk_delete(exps, 0).cast::<BigNum>();
            (*rsa).dmq1 = OPENSSL_sk_delete(exps, 0).cast::<BigNum>();
            (*rsa).iqmp = OPENSSL_sk_delete(coeffs, 0).cast::<BigNum>();
            let mut j: c_int = 2;
            while j < primes {
                let pinfo = OPENSSL_sk_value((*rsa).prime_infos, j - 2).cast::<RsaPrimeInfo>();
                let mut tmp = OPENSSL_sk_delete(factors, 0).cast::<BigNum>();
                BN_copy((*pinfo).r, tmp);
                BN_clear_free(tmp);
                tmp = OPENSSL_sk_delete(exps, 0).cast::<BigNum>();
                let tmp2 = BN_copy((*pinfo).d, tmp);
                BN_clear_free(tmp);
                if tmp2.is_null() {
                    break 'body false;
                }
                tmp = OPENSSL_sk_delete(coeffs, 0).cast::<BigNum>();
                let tmp2 = BN_copy((*pinfo).t, tmp);
                BN_clear_free(tmp);
                if tmp2.is_null() {
                    break 'body false;
                }
                j += 1;
            }
        }
        ok = 1;
        true
    };

    if !ran {
        ok = -1;
    }

    /* The authority's `err:` label. */
    // SAFETY: each stack is NULL or one this call owns; `OPENSSL_sk_free` accepts
    // NULL; `ctx` is NULL or live.
    unsafe {
        OPENSSL_sk_free(factors);
        OPENSSL_sk_free(exps);
        OPENSSL_sk_free(coeffs);
        if ok == -1 {
            raise_site(&RSA_GEN_602);
            ok = 0;
        }
        BN_CTX_end(ctx);
        BN_CTX_free(ctx);
    }
    ok
}

/// `static int rsa_keygen(OSSL_LIB_CTX *libctx, RSA *rsa, int bits, int primes,`
/// `BIGNUM *e_value, BN_GENCB *cb, int pairwise_test)` — `rsa_gen.c:611-655`.
///
/// The choice D326 measured: `primes == 2 && bits >= 2048 && (e_value == NULL ||
/// BN_num_bits(e_value) > 16)` goes to [`ossl_rsa_sp800_56b_generate_key`], and
/// everything else — a key below 2048 bits, an exponent of 16 bits or fewer, or more
/// than two primes — goes to [`rsa_multiprime_keygen`].
///
/// **`pairwise_test` is never set on this profile.** Only the `FIPS_MODULE` arm forces
/// it to 1, and [`RSA_generate_multi_prime_key`] passes it 0; the body is transcribed
/// anyway because the reference is what makes [`rsa_keygen_pairwise_test`] a reachable
/// function rather than dead code.
///
/// `libctx` is read only by the FIPS arm's `OSSL_SELF_TEST_get_callback` and is unused
/// here, which is why the parameter is `_libctx`.
///
/// # Safety
/// `rsa` is a live object; `e_value` is NULL or live; `cb` is NULL or a live callback.
#[allow(clippy::too_many_arguments)] // mirrors the authority's signature exactly
unsafe fn rsa_keygen(
    libctx: *mut c_void,
    rsa: *mut Rsa,
    bits: c_int,
    primes: c_int,
    e_value: *mut BigNum,
    cb: *mut BnGencb,
    pairwise_test: c_int,
) -> c_int {
    let mut ok: c_int;

    /*
     * Only multi-prime keys or insecure keys with a small key length or a public
     * exponent <= 2^16 will use the older rsa_multiprime_keygen().
     */
    let e_bits = if e_value.is_null() {
        0
    } else {
        // SAFETY: `e_value` is non-NULL here.
        unsafe { BN_num_bits(e_value) }
    };
    if primes == RSA_DEFAULT_PRIME_NUM && bits >= 2048 && (e_value.is_null() || e_bits > 16) {
        // SAFETY: `rsa`, `e_value` and `cb` are the caller's under this function's
        // contract.
        ok = unsafe { ossl_rsa_sp800_56b_generate_key(rsa, bits, e_value, cb) };
    } else {
        // SAFETY: as above.
        ok = unsafe { rsa_multiprime_keygen(rsa, bits, primes, e_value, cb) };
    }

    if pairwise_test != 0 && ok > 0 {
        let mut stcb: Option<OsslCallback> = None;
        let mut stcbarg: *mut c_void = core::ptr::null_mut();

        // SAFETY: `libctx` is the caller's and the two out-parameters are this
        // frame's slots.
        unsafe { OSSL_SELF_TEST_get_callback(libctx, &mut stcb, &mut stcbarg) };
        // SAFETY: `rsa` is live and the self-test callback is the caller's.
        ok = unsafe { rsa_keygen_pairwise_test(rsa, stcb, stcbarg) };
        if ok == 0 {
            /* Clear intermediate results */
            // SAFETY: each component is NULL or the object's own `BIGNUM`.
            unsafe {
                BN_clear_free((*rsa).d);
                BN_clear_free((*rsa).p);
                BN_clear_free((*rsa).q);
                BN_clear_free((*rsa).dmp1);
                BN_clear_free((*rsa).dmq1);
                BN_clear_free((*rsa).iqmp);
                (*rsa).d = core::ptr::null_mut();
                (*rsa).p = core::ptr::null_mut();
                (*rsa).q = core::ptr::null_mut();
                (*rsa).dmp1 = core::ptr::null_mut();
                (*rsa).dmq1 = core::ptr::null_mut();
                (*rsa).iqmp = core::ptr::null_mut();
            }
        }
    }
    ok
}

/// `static int rsa_keygen_pairwise_test(RSA *rsa, OSSL_CALLBACK *cb, void *cbarg)` —
/// `rsa_gen.c:683-737`.
///
/// The FIPS 140-3 AS10.35 pairwise consistency test, option 3: encrypt a plaintext with
/// `RSA_NO_PADDING` and decrypt it again, then compare. The comment block above the
/// authority's body is the standard's own text and is not reproduced line by line; the
/// code is.
///
/// **`plaintxt[plaintxt_len - 1] = 2`** is SP 800-56Br2 §6.4.1.1's "plaintext is
/// greater than 1", written as a single trailing octet because the buffer is
/// `RSA_size` octets of zero otherwise.
///
/// # Safety
/// `rsa` is a live object with a live `n`; `cb` is NULL or a live self-test callback.
unsafe fn rsa_keygen_pairwise_test(
    rsa: *mut Rsa,
    cb: Option<OsslCallback>,
    cbarg: *mut c_void,
) -> c_int {
    let mut ret: c_int = 0;
    const PADDING: c_int = 3; /* RSA_NO_PADDING */
    let mut plaintxt: *mut c_uchar = core::ptr::null_mut();

    // SAFETY: `OSSL_SELF_TEST_new` takes no caller pointers and answers a fresh
    // object or NULL.
    let st = OSSL_SELF_TEST_new(cb, cbarg);
    if st.is_null() {
        return 0;
    }
    // SAFETY: `st` is live; the two strings are static.
    unsafe {
        OSSL_SELF_TEST_onbegin(
            st,
            OSSL_SELF_TEST_TYPE_PCT.as_ptr(),
            OSSL_SELF_TEST_DESC_PCT_RSA.as_ptr(),
        );
    }

    /*
     * For RSA_NO_PADDING, RSA_public_encrypt() and RSA_private_decrypt() require the
     * 'to' and 'from' parameters to have equal length and a maximum of RSA_size().
     */
    // SAFETY: `rsa` is live with a live `n`.
    let plaintxt_len = unsafe { RSA_size(rsa) };
    // `OPENSSL_calloc(plaintxt_len, 3)`.
    let block = CRYPTO_calloc(plaintxt_len as usize, 3, FILE_RSA_GEN, LINE).cast::<c_uchar>();

    'body: {
        if block.is_null() {
            break 'body;
        }
        plaintxt = block;
        // SAFETY: `block` was allocated this call for `3 * plaintxt_len` octets, so
        // both offsets are in bounds.
        let ciphertxt = unsafe { plaintxt.add(plaintxt_len as usize) };
        // SAFETY: as above, one block further in.
        let decoded = unsafe { ciphertxt.add(plaintxt_len as usize) };

        /* SP 800-56Br2 Section 6.4.1.1 requires that plaintext is greater than 1 */
        // SAFETY: the block is `3 * plaintxt_len` octets, so this index is in bounds
        // for a positive `plaintxt_len`.
        unsafe { *plaintxt.add(plaintxt_len as usize - 1) = 2 };

        // SAFETY: `plaintxt` is a readable `plaintxt_len`-octet buffer, `ciphertxt` is
        // the next one, `rsa` is live, and the padding is the authority's own.
        let ciphertxt_len =
            unsafe { RSA_public_encrypt(plaintxt_len, plaintxt, ciphertxt, rsa, PADDING) };
        if ciphertxt_len <= 0 {
            break 'body;
        }

        // SAFETY: `st` is live and `ciphertxt` points into the block this call owns.
        unsafe { OSSL_SELF_TEST_oncorrupt_byte(st, ciphertxt) };

        // SAFETY: `ciphertxt` is readable for `ciphertxt_len` octets, `decoded` is the
        // third block, `rsa` is live.
        let decoded_len =
            unsafe { RSA_private_decrypt(ciphertxt_len, ciphertxt, decoded, rsa, PADDING) };
        if decoded_len != plaintxt_len
            // SAFETY: `decoded` and `plaintxt` are the first and third
            // `plaintxt_len`-octet blocks of one allocation, and the short-circuit
            // above means this is reached only when `decoded_len == plaintxt_len`, a
            // positive value.
            || unsafe {
                core::slice::from_raw_parts(decoded, decoded_len as usize)
                    != core::slice::from_raw_parts(plaintxt, decoded_len as usize)
            }
        {
            break 'body;
        }

        ret = 1;
    }

    // SAFETY: `st` is live or NULL; `plaintxt` is the block this call allocated or
    // NULL.
    unsafe {
        OSSL_SELF_TEST_onend(st, ret);
        OSSL_SELF_TEST_free(st);
        if !plaintxt.is_null() {
            CRYPTO_free(plaintxt.cast(), FILE_RSA_GEN, LINE);
        }
    }

    ret
}

/// `RSA *RSA_generate_key(int bits, unsigned long e_value,`
/// `void (*callback)(int, int, void *), void *cb_arg)` — `rsa_depr.c:29-62`.
///
/// The deprecated constructor: a `BN_GENCB` wrapped around the caller's old-style
/// callback, a `BIGNUM` exponent assembled **bit by bit** from the `unsigned long`
/// (the comment's own reason is that `unsigned long` can be wider than a `BN_ULONG`),
/// and then [`RSA_generate_key_ex`].
///
/// **A failure frees all three objects.** `cb`, `rsa` and `e` are all created before
/// the first possible failure, so the release label is correct at any prefix, and the
/// successful path releases only `e` and `cb` -- the `RSA` is the return value.
///
/// # Safety
/// `callback` is NULL or a function safe to call with `(int, int, *mut c_void)`.
#[no_mangle]
pub unsafe extern "C" fn RSA_generate_key(
    bits: c_int,
    e_value: c_ulong,
    callback: Option<unsafe extern "C" fn(c_int, c_int, *mut c_void)>,
    cb_arg: *mut c_void,
) -> *mut Rsa {
    // SAFETY: every allocation below takes no caller pointer; the loop's
    // `BN_set_bit` takes a live object.
    unsafe {
        let cb = BN_GENCB_new();
        let rsa = crate::rsa::object::RSA_new();
        let e = BN_new();

        if cb.is_null() || rsa.is_null() || e.is_null() {
            BN_free(e);
            crate::rsa::object::RSA_free(rsa);
            BN_GENCB_free(cb);
            return core::ptr::null_mut();
        }

        /*
         * The problem is when building with 8, 16, or 32 BN_ULONG, unsigned long
         * can be larger
         */
        let mut i: c_int = 0;
        while i < (core::mem::size_of::<c_ulong>() * 8) as c_int {
            if e_value & (1u64 << i) != 0 && BN_set_bit(e, i) == 0 {
                BN_free(e);
                crate::rsa::object::RSA_free(rsa);
                BN_GENCB_free(cb);
                return core::ptr::null_mut();
            }
            i += 1;
        }

        BN_GENCB_set_old(cb, callback, cb_arg);

        if RSA_generate_key_ex(rsa, bits, e, cb) != 0 {
            BN_free(e);
            BN_GENCB_free(cb);
            return rsa;
        }

        BN_free(e);
        crate::rsa::object::RSA_free(rsa);
        BN_GENCB_free(cb);
        core::ptr::null_mut()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bn::bignum::{BN_free, BN_is_one, BN_set_word};
    use crate::bn::ctx::{BN_CTX_free, BN_CTX_new};
    use crate::bn::primes::BN_check_prime;
    use crate::rsa::object::{
        RSA_bits, RSA_free, RSA_get0_crt_params, RSA_get0_factors, RSA_get0_key,
        RSA_get0_multi_prime_factors, RSA_get_multi_prime_extra_count, RSA_get_version, RSA_new,
        RSA_size,
    };

    /// A fresh `65537` exponent, or a different word when asked.
    ///
    /// # Safety
    /// Takes no pointers; the returned object is owned by the caller.
    unsafe fn exponent(word: c_ulong) -> *mut BigNum {
        // SAFETY: `BN_new` takes no pointers.
        let e = unsafe { BN_new() };
        assert!(!e.is_null());
        // SAFETY: `e` is fresh and live.
        assert_eq!(unsafe { BN_set_word(e, word) }, 1);
        e
    }

    /// **The ordinary 2048-bit call takes the SP800-56B path and produces a key whose
    /// components satisfy every relation and whose own public/private operations
    /// recover a plaintext.** The prime values are drawn, so nothing here compares a
    /// `BIGNUM` against a constant; what is assertable is `RSA_bits`/`RSA_size`, the
    /// primality of the two factors, `n = p*q`, `e*d = 1` modulo the factors, and the
    /// round trip -- which is one observation of [`RSA_generate_key_ex`],
    /// [`crate::rsa::object::RSA_public_encrypt`] and
    /// [`crate::rsa::object::RSA_private_decrypt`] at once.
    #[test]
    fn the_sp800_path_builds_a_2048_bit_key_that_round_trips() {
        use crate::rsa::object::{RSA_private_decrypt, RSA_public_encrypt};

        // SAFETY: every pointer is a fresh object this test owns and every length is
        // the buffer's own.
        unsafe {
            let e = exponent(65537);
            let rsa = RSA_new();
            assert!(!rsa.is_null());

            assert_eq!(RSA_generate_key_ex(rsa, 2048, e, core::ptr::null_mut()), 1);
            assert_eq!(RSA_bits(rsa), 2048);
            assert_eq!(RSA_size(rsa), 256);
            assert_eq!(RSA_get_version(rsa), 0);
            assert_eq!(RSA_get_multi_prime_extra_count(rsa), 0);

            let mut n: *const BigNum = core::ptr::null();
            let mut ep: *const BigNum = core::ptr::null();
            let mut d: *const BigNum = core::ptr::null();
            RSA_get0_key(rsa, &mut n, &mut ep, &mut d);
            let mut p: *const BigNum = core::ptr::null();
            let mut q: *const BigNum = core::ptr::null();
            RSA_get0_factors(rsa, &mut p, &mut q);
            let mut dmp1: *const BigNum = core::ptr::null();
            let mut dmq1: *const BigNum = core::ptr::null();
            let mut iqmp: *const BigNum = core::ptr::null();
            RSA_get0_crt_params(rsa, &mut dmp1, &mut dmq1, &mut iqmp);
            assert!(!n.is_null() && !ep.is_null() && !d.is_null());
            assert!(!p.is_null() && !q.is_null());
            assert!(!dmp1.is_null() && !dmq1.is_null() && !iqmp.is_null());

            let ctx = BN_CTX_new();
            assert!(!ctx.is_null());
            assert_eq!(BN_check_prime(p, ctx, core::ptr::null_mut()), 1);
            assert_eq!(BN_check_prime(q, ctx, core::ptr::null_mut()), 1);

            let prod = BN_new();
            let pm1 = BN_new();
            let qm1 = BN_new();
            let t = BN_new();
            let ed = BN_new();
            assert!(!prod.is_null() && !pm1.is_null() && !qm1.is_null());
            assert!(!t.is_null() && !ed.is_null());
            assert_eq!(BN_mul(prod, p, q, ctx), 1);
            assert_eq!(BN_cmp(prod, n), 0);

            /* `e*d = 1 (mod p-1)` and `(mod q-1)`: `d` is the inverse modulo the
             * lcm, which divides both. */
            assert_eq!(BN_sub(pm1, p, BN_value_one()), 1);
            assert_eq!(BN_sub(qm1, q, BN_value_one()), 1);
            assert_eq!(BN_mul(ed, ep, d, ctx), 1);
            assert_eq!(BN_div(core::ptr::null_mut(), t, ed, pm1, ctx), 1);
            assert_eq!(BN_is_one(t), 1);
            assert_eq!(BN_div(core::ptr::null_mut(), t, ed, qm1, ctx), 1);
            assert_eq!(BN_is_one(t), 1);

            /* The PKCS#1 v1.5 round trip. */
            let msg = [0xa0u8, 0xa1, 0xa2, 0xa3, 0xa4];
            let mut ct = [0u8; 256];
            let mut out = [0u8; 256];
            let enc = RSA_public_encrypt(5, msg.as_ptr(), ct.as_mut_ptr(), rsa, 1);
            assert_eq!(enc, 256);
            let dec = RSA_private_decrypt(enc, ct.as_ptr(), out.as_mut_ptr(), rsa, 1);
            assert_eq!(dec, 5);
            assert_eq!(&out[..5], &msg[..]);

            BN_free(prod);
            BN_free(pm1);
            BN_free(qm1);
            BN_free(t);
            BN_free(ed);
            BN_CTX_free(ctx);
            BN_free(e);
            RSA_free(rsa);
        }
    }

    /// **The multi-prime path is a different generator and it says so in the object.**
    /// A three-prime 1024-bit key sets `version` to `RSA_ASN1_VERSION_MULTI`, reports
    /// one extra prime through `RSA_get_multi_prime_extra_count`, and the extra prime
    /// is a factor of `n`. That is the observable difference between the two paths,
    /// and it is what the three-prime arm is for.
    #[test]
    fn the_multi_prime_path_reports_its_extra_prime() {
        // SAFETY: every pointer is a fresh object this test owns.
        unsafe {
            let e = exponent(65537);
            let rsa = RSA_new();
            assert!(!rsa.is_null());

            assert_eq!(
                RSA_generate_multi_prime_key(rsa, 1024, 3, e, core::ptr::null_mut()),
                1
            );
            assert_eq!(RSA_bits(rsa), 1024);
            assert_eq!(RSA_get_version(rsa), RSA_ASN1_VERSION_MULTI);
            assert_eq!(RSA_get_multi_prime_extra_count(rsa), 1);

            let mut n: *const BigNum = core::ptr::null();
            RSA_get0_key(rsa, &mut n, core::ptr::null_mut(), core::ptr::null_mut());
            let mut p: *const BigNum = core::ptr::null();
            let mut q: *const BigNum = core::ptr::null();
            RSA_get0_factors(rsa, &mut p, &mut q);
            /* The extra primes come back in a caller-sized array, one per extra prime. */
            let mut extra: [*const BigNum; 1] = [core::ptr::null()];
            assert_eq!(RSA_get0_multi_prime_factors(rsa, extra.as_mut_ptr()), 1);
            let r = extra[0];
            assert!(!n.is_null() && !p.is_null() && !q.is_null() && !r.is_null());

            let ctx = BN_CTX_new();
            assert!(!ctx.is_null());
            assert_eq!(BN_check_prime(p, ctx, core::ptr::null_mut()), 1);
            assert_eq!(BN_check_prime(q, ctx, core::ptr::null_mut()), 1);
            assert_eq!(BN_check_prime(r, ctx, core::ptr::null_mut()), 1);
            /* `n = p*q*r`. */
            let prod = BN_new();
            assert!(!prod.is_null());
            assert_eq!(BN_mul(prod, p, q, ctx), 1);
            assert_eq!(BN_mul(prod, prod, r, ctx), 1);
            assert_eq!(BN_cmp(prod, n), 0);

            BN_free(prod);
            BN_CTX_free(ctx);
            BN_free(e);
            RSA_free(rsa);
        }
    }

    /// **A public exponent of 16 or fewer bits stays on the multi-prime generator even
    /// at 2048 bits.** That is `rsa_keygen`'s own condition, and the observable is the
    /// two-prime default `version` plus a key whose width is what was asked for.
    #[test]
    fn a_small_exponent_takes_the_multiprime_path_at_full_width() {
        // SAFETY: every pointer is a fresh object this test owns.
        unsafe {
            let e = exponent(17);
            let rsa = RSA_new();
            assert!(!rsa.is_null());
            assert_eq!(RSA_generate_key_ex(rsa, 2048, e, core::ptr::null_mut()), 1);
            assert_eq!(RSA_bits(rsa), 2048);
            assert_eq!(RSA_get_version(rsa), 0);
            assert_eq!(RSA_get_multi_prime_extra_count(rsa), 0);
            BN_free(e);
            RSA_free(rsa);
        }
    }

    /// **The dispatchers refuse what the authority refuses, and the errors are on the
    /// queue.** A modulus below `RSA_MIN_MODULUS_BITS`, a `NULL` or even exponent, and a
    /// prime count outside `[2, ossl_rsa_multip_cap(bits)]` each answer `0` after a
    /// raise; the successful shape is asserted beside them so a blanket refusal would
    /// fail.
    #[test]
    fn the_dispatchers_refuse_what_the_authority_refuses() {
        // SAFETY: every pointer is a fresh object this test owns or the null the
        // contract names.
        unsafe {
            let e = exponent(65537);
            let rsa = RSA_new();
            assert!(!rsa.is_null());

            /* `bits < RSA_MIN_MODULUS_BITS` (512). */
            assert_eq!(
                RSA_generate_multi_prime_key(rsa, 511, 2, e, core::ptr::null_mut()),
                0
            );
            /* `e_value == NULL`. */
            assert_eq!(
                RSA_generate_multi_prime_key(
                    rsa,
                    1024,
                    2,
                    core::ptr::null_mut(),
                    core::ptr::null_mut()
                ),
                0
            );
            /* An even exponent is not a public exponent. */
            let even = exponent(65536);
            assert_eq!(
                RSA_generate_multi_prime_key(rsa, 1024, 2, even, core::ptr::null_mut()),
                0
            );
            /* `primes` below 2 and above the 1024-bit cap (3). */
            assert_eq!(
                RSA_generate_multi_prime_key(rsa, 1024, 1, e, core::ptr::null_mut()),
                0
            );
            assert_eq!(
                RSA_generate_multi_prime_key(rsa, 1024, 4, e, core::ptr::null_mut()),
                0
            );

            /* A legal small key still succeeds, so the refusals above are not a
             * blanket `0`. */
            assert_eq!(
                RSA_generate_multi_prime_key(rsa, 1024, 2, e, core::ptr::null_mut()),
                1
            );

            BN_free(even);
            BN_free(e);
            RSA_free(rsa);
        }
    }

    /// **The deprecated constructor is a wrapper and its own refusals are the
    /// exponent's bits.** `e_value` is an `unsigned long`; `2` is a legal exponent and
    /// the key is a real one, and the returned object is the caller's to free.
    #[test]
    fn the_deprecated_constructor_builds_the_default_exponent() {
        // SAFETY: the callback is NULL and the returned object is owned by this test.
        unsafe {
            let rsa = RSA_generate_key(1024, 65537, None, core::ptr::null_mut());
            assert!(!rsa.is_null());
            assert_eq!(RSA_bits(rsa), 1024);
            let mut ep: *const BigNum = core::ptr::null();
            RSA_get0_key(rsa, core::ptr::null_mut(), &mut ep, core::ptr::null_mut());
            assert!(!ep.is_null());
            let ctx = BN_CTX_new();
            assert!(!ctx.is_null());
            let want = exponent(65537);
            assert_eq!(BN_cmp(ep, want), 0);
            BN_free(want);
            BN_CTX_free(ctx);
            RSA_free(rsa);
        }
    }
}
