/*
 * openssl-rs — the differential BN-random probe (RT-BN-RAND).
 *
 * This program is compiled **twice**, once against the admitted authority and once against the
 * candidate distribution shell, and the two `key=value` transcripts are diffed. It decides
 * nothing: a residual is a difference between two executions, so the expectation cannot drift
 * with the crate. `forensics/tools/phase9_courts.py` owns the comparison.
 *
 * What this probe establishes
 * ---------------------------
 * It is the evidence for `crypto/bn/bn_rand.c`'s public family — `BN_rand_ex`, `BN_rand`,
 * `BN_bntest_rand`, `BN_priv_rand_ex`, `BN_priv_rand`, `BN_rand_range_ex`, `BN_rand_range`,
 * `BN_priv_rand_range_ex`, `BN_priv_rand_range`, `BN_pseudo_rand` and `BN_pseudo_rand_range` —
 * and for the `ossl_bn_get_libctx` path they all reach: `bnrand` reads its `BN_CTX`'s library
 * context and hands it to `RAND_bytes_ex`, so every draw here is made with a live `BN_CTX` as
 * well as with none.
 *
 * Why the drawn values cannot be an observation, and what replaces them
 * --------------------------------------------------------------------
 * The authority and the candidate seed their RNGs from different pools, so `BN_rand`'s output
 * differs by construction. Comparing it would compare two machines. What *is* deterministic is
 * the **contract of each arm**, and that is what is printed:
 *
 *   - the return code, always, and the error queue after it;
 *   - `BN_num_bits(rnd) <= bits`, which every successful non-range draw satisfies;
 *   - for `BN_RAND_TOP_ONE` / `BN_RAND_TOP_TWO`, that bit `bits-1` (and `bits-2`) is set;
 *   - for `BN_RAND_BOTTOM_ODD`, that bit 0 is set;
 *   - that the result is not negative;
 *   - for the range family, `BN_cmp(rnd, range) < 0`.
 *
 * `bits = 1` and `bits = 2` are chosen deliberately: there the masks pin the value exactly
 * (`BN_rand(rnd, 2, BN_RAND_TOP_TWO, BN_RAND_BOTTOM_ANY)` is 3 on every RNG, and
 * `BN_rand(rnd, 1, BN_RAND_TOP_ONE, BN_RAND_BOTTOM_ANY)` is 1), so those two arms observe the
 * mask arithmetic itself rather than a property of it.
 *
 * The refusal arms are the other half, because a draw that silently answered 0 where the
 * authority raised would look identical in a success-only transcript: `bits < 0`, `bits == 0`
 * with a pinned `top`/`bottom`, `bits == 1` with `top > 0`, a null output, a zero or negative
 * range, and a strength no DRBG can satisfy.
 *
 * What it deliberately does not observe
 * -------------------------------------
 * `BN_generate_dsa_nonce` and the two `*_fixed_top` internals are out of scope for this
 * module (they need the EVP digest front and the fixed-top representation), so no line here
 * names them.
 *
 * What a difference here means
 * ----------------------------
 * Every observation is a return code, a boolean, a bit index or an `ERR_GET_LIB`/`ERR_GET_REASON`
 * pair drained from the error queue. No address is ever printed and no NULL-dereferencing entry
 * point is called, so a probe that aborts the harness compares nothing rather than noise.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdio.h>
#include <string.h>

#include <openssl/bn.h>
#include <openssl/err.h>

/*
 * The error queue, normalised to the two fields `docs/PARITY_MODEL.md`'s `ERROR_PASS` names as
 * portable: the library and the reason. The file/line/function coordinates are deliberately not
 * printed -- they are transcription-unit properties the error-site courts cover, and printing
 * them here would turn one behavioural residual into a coordinate diff.
 */
static void errs(const char *key)
{
    unsigned long e;
    int i = 0;

    while ((e = ERR_get_error()) != 0)
        printf("%s.%d=lib=%d,reason=%d\n", key, i++, ERR_GET_LIB(e), ERR_GET_REASON(e));
    printf("%s.count=%d\n", key, i);
}

/* Which entry point a draw goes through, so one observation helper covers the family. */
enum which {
    W_RAND = 0,
    W_PRIV = 1,
    W_PSEUDO = 2,
    W_BNTEST = 3,
    W_RAND_EX = 4,
    W_PRIV_EX = 5
};

static int draw(enum which w, BIGNUM *rnd, int bits, int top, int bottom,
                unsigned int strength, BN_CTX *ctx)
{
    switch (w) {
    case W_RAND:      return BN_rand(rnd, bits, top, bottom);
    case W_PRIV:      return BN_priv_rand(rnd, bits, top, bottom);
    case W_PSEUDO:    return BN_pseudo_rand(rnd, bits, top, bottom);
    case W_BNTEST:    return BN_bntest_rand(rnd, bits, top, bottom);
    case W_RAND_EX:   return BN_rand_ex(rnd, bits, top, bottom, strength, ctx);
    case W_PRIV_EX:   return BN_priv_rand_ex(rnd, bits, top, bottom, strength, ctx);
    }
    return -2;
}

static const char *wname(enum which w)
{
    switch (w) {
    case W_RAND:    return "rand";
    case W_PRIV:    return "priv";
    case W_PSEUDO:  return "pseudo";
    case W_BNTEST:  return "bntest";
    case W_RAND_EX: return "rand_ex";
    case W_PRIV_EX: return "priv_ex";
    }
    return "?";
}

/*
 * One draw, observed as its arm's contract: the return code, the error queue, and -- only when
 * the call succeeded -- the properties the arm promises. `bits` is the ceiling the value cannot
 * exceed; the two pinned-bit requests are checked by index.
 */
static void observe(const char *prefix, enum which w, int bits, int top, int bottom,
                    unsigned int strength, BN_CTX *ctx)
{
    char k[128];
    BIGNUM *rnd = BN_new();
    int ret;

    if (rnd == NULL) {
        printf("%s.%s.alloc=0\n", prefix, wname(w));
        return;
    }
    ERR_clear_error();
    ret = draw(w, rnd, bits, top, bottom, strength, ctx);

    snprintf(k, sizeof(k), "%s.%s.ret", prefix, wname(w));
    printf("%s=%d\n", k, ret);
    snprintf(k, sizeof(k), "%s.%s.err", prefix, wname(w));
    errs(k);
    if (ret == 1) {
        snprintf(k, sizeof(k), "%s.%s.bits_le", prefix, wname(w));
        printf("%s=%d\n", k, BN_num_bits(rnd) <= bits);
        snprintf(k, sizeof(k), "%s.%s.negative", prefix, wname(w));
        printf("%s=%d\n", k, BN_is_negative(rnd));
        if (top == BN_RAND_TOP_ONE || top == BN_RAND_TOP_TWO) {
            /* `bits >= 2` for TOP_TWO, so index `bits-1` is the pinned one. */
            snprintf(k, sizeof(k), "%s.%s.top_bit", prefix, wname(w));
            printf("%s=%d\n", k, BN_is_bit_set(rnd, bits - 1));
        }
        if (top == BN_RAND_TOP_TWO && bits >= 2) {
            snprintf(k, sizeof(k), "%s.%s.second_bit", prefix, wname(w));
            printf("%s=%d\n", k, BN_is_bit_set(rnd, bits - 2));
        }
        if (bottom == BN_RAND_BOTTOM_ODD) {
            snprintf(k, sizeof(k), "%s.%s.bottom_bit", prefix, wname(w));
            printf("%s=%d\n", k, BN_is_bit_set(rnd, 0));
        }
        /* The exact-value arms: the masks pin these on every RNG. */
        if (bits == 1 && top == BN_RAND_TOP_ONE) {
            snprintf(k, sizeof(k), "%s.%s.is_one", prefix, wname(w));
            printf("%s=%d\n", k, BN_is_one(rnd));
        }
        if (bits == 2 && top == BN_RAND_TOP_TWO) {
            snprintf(k, sizeof(k), "%s.%s.is_three", prefix, wname(w));
            printf("%s=%d\n", k, BN_is_word(rnd, 3));
        }
    }
    BN_free(rnd);
}

/* The range family: the result must be in `[0, range)`, and the refusals must be refusals. */
static void observe_range(const char *prefix, int which, BIGNUM *rnd, const BIGNUM *range,
                          unsigned int strength, BN_CTX *ctx, const char *label)
{
    char k[160];
    int ret;

    ERR_clear_error();
    switch (which) {
    case 0: ret = BN_rand_range(rnd, range); break;
    case 1: ret = BN_priv_rand_range(rnd, range); break;
    case 2: ret = BN_pseudo_rand_range(rnd, range); break;
    case 3: ret = BN_rand_range_ex(rnd, range, strength, ctx); break;
    default: ret = BN_priv_rand_range_ex(rnd, range, strength, ctx); break;
    }
    snprintf(k, sizeof(k), "%s.%s.ret", prefix, label);
    printf("%s=%d\n", k, ret);
    snprintf(k, sizeof(k), "%s.%s.err", prefix, label);
    errs(k);
    if (ret == 1 && range != NULL) {
        snprintf(k, sizeof(k), "%s.%s.in_range", prefix, label);
        printf("%s=%d\n", k, BN_cmp(rnd, range) < 0);
        snprintf(k, sizeof(k), "%s.%s.negative", prefix, label);
        printf("%s=%d\n", k, BN_is_negative(rnd));
    }
}

int main(void)
{
    BIGNUM *rnd, *range, *zero, *negative;
    BN_CTX *ctx;

    setvbuf(stdout, NULL, _IOLBF, 0);

    rnd = BN_new();
    range = BN_new();
    zero = BN_new();
    negative = BN_new();
    ctx = BN_CTX_new();
    if (rnd == NULL || range == NULL || zero == NULL || negative == NULL || ctx == NULL) {
        printf("alloc.failed=1\n");
        return 1;
    }
    BN_set_word(range, 7);
    BN_set_word(negative, 5);
    BN_set_negative(negative, 1);

    /* ---- 1. The successful arms, with no context ---------------------------------- */

    /* `BN_RAND_TOP_ANY`/`BN_RAND_BOTTOM_ANY`: the ceiling is the only promise. */
    observe("noctx.8.any", W_RAND, 8, BN_RAND_TOP_ANY, BN_RAND_BOTTOM_ANY, 0, NULL);
    observe("noctx.64.any", W_RAND, 64, BN_RAND_TOP_ANY, BN_RAND_BOTTOM_ANY, 0, NULL);
    /* The exact-value masks. */
    observe("noctx.1.topone", W_RAND, 1, BN_RAND_TOP_ONE, BN_RAND_BOTTOM_ANY, 0, NULL);
    observe("noctx.2.toptwo", W_RAND, 2, BN_RAND_TOP_TWO, BN_RAND_BOTTOM_ANY, 0, NULL);
    /* The pinned bits at widths where the value is not pinned. */
    observe("noctx.16.topone", W_RAND, 16, BN_RAND_TOP_ONE, BN_RAND_BOTTOM_ANY, 0, NULL);
    observe("noctx.16.toptwo", W_RAND, 16, BN_RAND_TOP_TWO, BN_RAND_BOTTOM_ANY, 0, NULL);
    observe("noctx.16.bottomodd", W_RAND, 16, BN_RAND_TOP_ANY, BN_RAND_BOTTOM_ODD, 0, NULL);
    observe("noctx.16.both", W_RAND, 16, BN_RAND_TOP_ONE, BN_RAND_BOTTOM_ODD, 0, NULL);

    /* Each of the other entry points through one arm. */
    observe("noctx.16.priv", W_PRIV, 16, BN_RAND_TOP_ANY, BN_RAND_BOTTOM_ANY, 0, NULL);
    observe("noctx.16.pseudo", W_PSEUDO, 16, BN_RAND_TOP_ANY, BN_RAND_BOTTOM_ANY, 0, NULL);
    /*
     * `BN_bntest_rand` is the `TESTING` flag: a private fill and then one `RAND_bytes_ex` per
     * byte for the patterner. Its *pattern* depends on those bytes, so only the ceiling and the
     * pinned bits are observed -- the arm is distinguished by which RNG calls it makes, and
     * that difference is what the candidate has to reproduce.
     */
    observe("noctx.16.bntest", W_BNTEST, 16, BN_RAND_TOP_ANY, BN_RAND_BOTTOM_ANY, 0, NULL);
    observe("noctx.16.bntest_topone", W_BNTEST, 16, BN_RAND_TOP_ONE, BN_RAND_BOTTOM_ANY, 0, NULL);

    /* ---- 2. The same family with a live `BN_CTX`, which is the libctx path ---------- */

    observe("ctx.16.any", W_RAND, 16, BN_RAND_TOP_ANY, BN_RAND_BOTTOM_ANY, 0, ctx);
    observe("ctx.16.ex", W_RAND_EX, 16, BN_RAND_TOP_ONE, BN_RAND_BOTTOM_ANY, 0, ctx);
    observe("ctx.16.priv_ex", W_PRIV_EX, 16, BN_RAND_TOP_ANY, BN_RAND_BOTTOM_ODD, 0, ctx);
    observe("ctx.64.ex", W_RAND_EX, 64, BN_RAND_TOP_TWO, BN_RAND_BOTTOM_ANY, 0, ctx);

    /* ---- 3. The refusal arms ------------------------------------------------------ */

    /* A null output is `BN_R_INVALID_RANGE` at `bnrand_range`'s first line. */
    ERR_clear_error();
    printf("refuse.null_out.ret=%d\n", BN_rand_range(NULL, range));
    errs("refuse.null_out.err");
    ERR_clear_error();
    printf("refuse.null_out.ex.ret=%d\n", BN_rand_range_ex(NULL, range, 0, ctx));
    errs("refuse.null_out.ex.err");

    /*
     * A **null** `range` is deliberately not called. The authority dereferences `range->neg`
     * before any null test (`crypto/bn/bn_rand.c:135`), so it is a null dereference there and
     * the probe would abort the authority side and compare only the prefix it managed to print.
     * The candidate refuses it with `BN_R_INVALID_RANGE` under the crate's `as_ref` convention,
     * which is a recorded divergence (`src/bn/rand.rs`'s module note) rather than something a
     * differential transcript can measure.
     */

    ERR_clear_error();
    printf("refuse.zero_range.ret=%d\n", BN_rand_range(rnd, zero));
    errs("refuse.zero_range.err");

    ERR_clear_error();
    printf("refuse.negative_range.ret=%d\n", BN_rand_range(rnd, negative));
    errs("refuse.negative_range.err");

    /* `bits == 0` with both ends open is the one zero-bit success. */
    ERR_clear_error();
    BN_set_word(rnd, 0xdead);
    printf("zero_bits.any.ret=%d\n", BN_rand(rnd, 0, BN_RAND_TOP_ANY, BN_RAND_BOTTOM_ANY));
    printf("zero_bits.any.zero=%d\n", BN_is_zero(rnd));
    errs("zero_bits.any.err");

    /* The same request with either end pinned is `toosmall`. */
    observe("refuse.0.topone", W_RAND, 0, BN_RAND_TOP_ONE, BN_RAND_BOTTOM_ANY, 0, NULL);
    observe("refuse.0.bottomodd", W_RAND, 0, BN_RAND_TOP_ANY, BN_RAND_BOTTOM_ODD, 0, NULL);
    observe("refuse.0.toptwo", W_RAND, 0, 2, BN_RAND_BOTTOM_ANY, 0, NULL);
    /* A negative ceiling, and one bit with any positive `top`. */
    observe("refuse.neg_bits", W_RAND, -1, BN_RAND_TOP_ANY, BN_RAND_BOTTOM_ANY, 0, NULL);
    observe("refuse.min_bits", W_RAND, -2147483647 - 1, BN_RAND_TOP_ANY,
            BN_RAND_BOTTOM_ANY, 0, NULL);
    observe("refuse.1.toptwo", W_RAND, 1, BN_RAND_TOP_TWO, BN_RAND_BOTTOM_ANY, 0, NULL);
    observe("refuse.1.topmax", W_RAND, 1, 2147483647, BN_RAND_BOTTOM_ANY, 0, NULL);
    /* The deprecated forward reaches the same guard. */
    observe("refuse.pseudo.neg", W_PSEUDO, -1, BN_RAND_TOP_ANY, BN_RAND_BOTTOM_ANY, 0, NULL);

    /*
     * A strength no DRBG can satisfy. This is the arm that proves the `strength` argument is
     * read rather than ignored: the draw fails and the error queue carries the failure.
     */
    observe("refuse.strength", W_RAND_EX, 16, BN_RAND_TOP_ANY, BN_RAND_BOTTOM_ANY, 4096, ctx);

    /* ---- 4. The range family, in and out of range ---------------------------------- */

    observe_range("range", 0, rnd, range, 0, NULL, "rand");
    observe_range("range", 1, rnd, range, 0, NULL, "priv");
    observe_range("range", 2, rnd, range, 0, NULL, "pseudo");
    observe_range("range", 3, rnd, range, 0, ctx, "rand_ex");
    observe_range("range", 4, rnd, range, 0, ctx, "priv_ex");

    /* A power-of-two range takes the `11..._2` arm; a `100..._2` range takes the reduce arm. */
    BN_set_word(range, 8);
    observe_range("pow2", 0, rnd, range, 0, ctx, "rand");
    BN_set_word(range, 4);
    observe_range("pow2", 0, rnd, range, 0, ctx, "rand");
    BN_set_word(range, 12);
    observe_range("reduce", 0, rnd, range, 0, ctx, "rand");
    /* `range == 1` is the `n == 1` arm: a `BN_zero` and no draw at all. */
    BN_set_word(range, 1);
    ERR_clear_error();
    BN_set_word(rnd, 9);
    printf("range.one.ret=%d\n", BN_rand_range(rnd, range));
    printf("range.one.zero=%d\n", BN_is_zero(rnd));
    errs("range.one.err");
    BN_set_word(rnd, 9);
    printf("range.one.priv_ret=%d\n", BN_priv_rand_range(rnd, range));
    printf("range.one.priv_zero=%d\n", BN_is_zero(rnd));
    errs("range.one.priv_err");

    /* A huge draw, to exercise the multi-limb path rather than one word. */
    observe("big.1024", W_RAND, 1024, BN_RAND_TOP_TWO, BN_RAND_BOTTOM_ODD, 0, ctx);
    observe("big.1024.bntest", W_BNTEST, 1024, BN_RAND_TOP_ANY, BN_RAND_BOTTOM_ANY, 0, ctx);

    BN_free(rnd);
    BN_free(range);
    BN_free(zero);
    BN_free(negative);
    BN_CTX_free(ctx);

    printf("done=1\n");
    return 0;
}
