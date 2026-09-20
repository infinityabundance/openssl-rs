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
 * It is also the evidence for the two families `crypto/bn/bn_rand.c`'s callers need, which
 * arrived with it:
 *
 *   - the **blinding** family — `BN_BLINDING_create_param`, `BN_BLINDING_update`,
 *     `BN_BLINDING_convert` and `BN_BLINDING_convert_ex` — observed through the identities it
 *     must satisfy rather than through its factor, which is a draw;
 *   - the **prime** family — `BN_generate_prime`, `BN_generate_prime_ex`,
 *     `BN_generate_prime_ex2`, `BN_check_prime`, `BN_is_prime`, `BN_is_prime_ex`,
 *     `BN_is_prime_fasttest`, `BN_is_prime_fasttest_ex`, `BN_X931_generate_Xpq`,
 *     `BN_X931_generate_prime_ex` and `BN_X931_derive_prime_ex` — observed through answers on
 *     committed inputs, the round counts a `BN_GENCB` callback sees, the refusal codes with
 *     their error queues, and the properties a generated prime must have.
 *
 * Those three are sections 5 and 6 below; the file's earlier sections are the random family.
 *
 * Why section 5's arms are identities and not values
 * -------------------------------------------------
 * `BN_BLINDING_create_param` draws `a` and sets `A = a^e`, `Ai = a^-1`. Neither is comparable
 * across two runs, but their *composition* is exact: a caller that exponentiates by a `d` with
 * `e*d == 1 (mod m-1)` gets its own answer back. That is the shape `rsa_ossl_mod_exp` uses,
 * and it is the only observation of this family that does not print a draw.
 *
 * Why section 6's generated primes are properties and not values
 * -------------------------------------------------------------
 * A generated prime is a draw. What is deterministic is its width, its pinned top and bottom
 * bits, that it is prime, that it satisfies the `add`/`rem` congruence when one was given,
 * and — for X9.31 — that `p == Rp (mod p1*p2)` with `Rp` recomputed here from `p1` and `p2`.
 * The X9.31 **derivation** is checked with every input committed, so even its congruence is a
 * measurement of the construction rather than of a run.
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

/* =============================================================================================
 * 5. The blinding family
 *
 * The blinding factor is a draw, so nothing derived from it may enter the transcript. What may
 * enter is what the *algebra* guarantees for every draw:
 *
 *   `BN_BLINDING_create_param` sets `A = a^e` and `Ai = a^-1` for a freshly drawn `a`, so a
 *   caller that exponentiates by a `d` with `e*d == 1 (mod m-1)` gets its own answer back:
 *   `(n * A)^d * Ai == n^d * a^(e*d-1) == n^d`. That is the round trip below, and it is the
 *   identity RSA's own use of the pair is built on -- `rsa_ossl_mod_exp` converts, exponentiates
 *   by `d`, and inverts.
 *
 * Every observation is therefore a boolean: did the value move, did it come back, how many
 * errors were raised. Two committed values make the round trip exact: the modulus (secp256k1's
 * field prime, so `m - 1` is the multiplicative group's order) and `65537^-1 mod (m - 1)`.
 *
 * The refusals are the other half, and each is a return code plus a drained error queue.
 * ============================================================================================= */

/* secp256k1's field prime: odd, 256 bits, and prime, so a^e and a^-1 are a pair. */
static const char *BLIND_MOD =
    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F";
/* `65537^-1 mod (BLIND_MOD - 1)`, computed rather than drawn. */
static const char *BLIND_D =
    "E8B4174BE8B4174BE8B4174BE8B4174BE8B4174BE8B4174BE8B4174AFFFFFC87";
/* P-256's field prime: a *different* modulus, used to show that `BN_BLINDING_create_param`
 * ignores its `m` argument when it is given a context rather than asked to build one. */
static const char *OTHER_MOD =
    "FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF";

/* A `BIGNUM` from a committed hex string, or NULL. */
static BIGNUM *from_hex(const char *s)
{
    BIGNUM *b = NULL;

    if (BN_hex2bn(&b, s) <= 0)
        return NULL;
    return b;
}

/*
 * One round trip, observed as booleans: the value moved, and after the exponentiation and the
 * inversion it equals `n^d` computed independently here. `expect` must already hold that
 * answer. The error queue is drained either way, because an arm that raises where the other
 * side does not is a difference even when the return codes agree.
 */
static void blind_trip(const char *prefix, BN_BLINDING *b, BIGNUM *n, const BIGNUM *keep,
                       const BIGNUM *expect, const BIGNUM *d, const BIGNUM *m, BN_CTX *ctx)
{
    char k[160];
    BIGNUM *r = BN_new();
    int ok = r != NULL;

    if (!ok) {
        printf("%s.alloc=0\n", prefix);
        return;
    }
    ERR_clear_error();
    if (ok && BN_copy(n, keep) == NULL)
        ok = 0;
    if (ok && BN_BLINDING_convert_ex(n, r, b, ctx) != 1)
        ok = 0;
    snprintf(k, sizeof(k), "%s.moved", prefix);
    printf("%s=%d\n", k, ok && BN_cmp(n, keep) != 0);
    if (ok && BN_mod_exp(n, n, d, m, ctx) != 1)
        ok = 0;
    if (ok && BN_BLINDING_invert_ex(n, r, b, ctx) != 1)
        ok = 0;
    snprintf(k, sizeof(k), "%s.restored", prefix);
    printf("%s=%d\n", k, ok && BN_cmp(n, expect) == 0);
    snprintf(k, sizeof(k), "%s.err", prefix);
    errs(k);
    BN_free(r);
}

/* The context's own inverse, without the `_ex` spelling: `convert` then `invert`. */
static void blind_trip_plain(const char *prefix, BN_BLINDING *b, BIGNUM *n, const BIGNUM *keep,
                             const BIGNUM *expect, const BIGNUM *d, const BIGNUM *m, BN_CTX *ctx)
{
    char k[160];
    int ok = 1;

    ERR_clear_error();
    if (BN_copy(n, keep) == NULL)
        ok = 0;
    if (ok && BN_BLINDING_convert(n, b, ctx) != 1)
        ok = 0;
    snprintf(k, sizeof(k), "%s.moved", prefix);
    printf("%s=%d\n", k, ok && BN_cmp(n, keep) != 0);
    if (ok && BN_mod_exp(n, n, d, m, ctx) != 1)
        ok = 0;
    if (ok && BN_BLINDING_invert(n, b, ctx) != 1)
        ok = 0;
    snprintf(k, sizeof(k), "%s.restored", prefix);
    printf("%s=%d\n", k, ok && BN_cmp(n, expect) == 0);
    snprintf(k, sizeof(k), "%s.err", prefix);
    errs(k);
}

static void blind_arms(BN_CTX *ctx)
{
    BIGNUM *m = from_hex(BLIND_MOD);
    BIGNUM *other = from_hex(OTHER_MOD);
    BIGNUM *d = from_hex(BLIND_D);
    BIGNUM *e = BN_new();
    BIGNUM *n = from_hex("123456789ABCDEF0FEDCBA9876543210");
    BIGNUM *keep = from_hex("123456789ABCDEF0FEDCBA9876543210");
    BIGNUM *expect = BN_new();
    BIGNUM *one = BN_new();
    BIGNUM *r_before = BN_new();
    BIGNUM *r_after = BN_new();
    BN_BLINDING *b, *bm, *bare, *again;
    BN_MONT_CTX *mont;
    int i;

    if (m == NULL || other == NULL || d == NULL || e == NULL || n == NULL || keep == NULL
        || expect == NULL || one == NULL || r_before == NULL || r_after == NULL) {
        printf("blind.alloc=0\n");
        return;
    }
    BN_set_word(e, 65537);
    BN_set_word(one, 1);

    /* `n^d`, the answer every round trip below has to reproduce. */
    if (BN_mod_exp(expect, keep, d, m, ctx) != 1) {
        printf("blind.expect.ret=0\n");
        return;
    }
    /* A self-check on the committed pair, so a wrong `d` fails loudly here rather than as a
     * mysterious "restored=0" further down: `e * d mod (m - 1) == 1`. */
    {
        BIGNUM *m1 = BN_new();
        BIGNUM *prod = BN_new();
        int self = 0;

        if (m1 != NULL && prod != NULL && BN_copy(m1, m) != NULL && BN_sub_word(m1, 1)
            && BN_mod_mul(prod, e, d, m1, ctx) == 1 && BN_is_one(prod))
            self = 1;
        printf("blind.de_pair.selfcheck=%d\n", self);
        BN_free(prod);
        BN_free(m1);
    }

    /* --- 5a. The successful arms ------------------------------------------------------ */

    ERR_clear_error();
    b = BN_BLINDING_create_param(NULL, e, m, ctx, NULL, NULL);
    printf("blind.create.nonnull=%d\n", b != NULL);
    errs("blind.create.err");
    if (b != NULL) {
        /* A fresh context takes the `counter == -1` arm, so the first convert does not
         * update; the second one does, which is the squaring arm. */
        blind_trip("blind.trip1", b, n, keep, expect, d, m, ctx);
        blind_trip("blind.trip2", b, n, keep, expect, d, m, ctx);

        /* An explicit `BN_BLINDING_update` squares the factor on its own. */
        ERR_clear_error();
        printf("blind.update.ret=%d\n", BN_BLINDING_update(b, ctx));
        errs("blind.update.err");
        blind_trip_plain("blind.after_update", b, n, keep, expect, d, m, ctx);

        /* `BN_BLINDING_NO_UPDATE` stops that squaring: the inverse read back after an
         * update is the one from before it. Both values are draws; the *equality* is the
         * observation. */
        ERR_clear_error();
        BN_BLINDING_set_flags(b, BN_BLINDING_NO_UPDATE);
        printf("blind.no_update.flag=%lu\n", BN_BLINDING_get_flags(b));
        if (BN_BLINDING_convert_ex(n, r_before, b, ctx) == 1
            && BN_BLINDING_update(b, ctx) == 1
            && BN_BLINDING_convert_ex(n, r_after, b, ctx) == 1)
            printf("blind.no_update.same=%d\n", BN_cmp(r_before, r_after) == 0);
        else
            printf("blind.no_update.same=ERR\n");
        errs("blind.no_update.err");
        BN_BLINDING_set_flags(b, 0);

        /* The re-creation path: the thirty-second update re-draws the factor through
         * `BN_BLINDING_create_param` (the counter reaching `BN_BLINDING_COUNTER`). The
         * count is deterministic; the values are not, and are not observed. */
        for (i = 0; i < 32; i++)
            if (BN_BLINDING_update(b, ctx) != 1)
                break;
        printf("blind.recreate32.updates_ok=%d\n", i == 32);
        blind_trip_plain("blind.recreate32", b, n, keep, expect, d, m, ctx);

        /* The `m` argument is read only when the context is *built*: given `b`, the pair is
         * made from `b`'s own modulus, so a round trip against `m` still works when the
         * call is handed a different modulus. */
        ERR_clear_error();
        again = BN_BLINDING_create_param(b, e, other, ctx, NULL, NULL);
        printf("blind.same_context.same_ptr=%d\n", again == b);
        errs("blind.same_context.err");
        blind_trip_plain("blind.m_ignored", b, n, keep, expect, d, m, ctx);

        BN_BLINDING_free(b);
    }

    /* The Montgomery arm: the same identity through `BN_mod_mul_montgomery`, which is the
     * other spelling the three multipliers take when `m_ctx` is set. */
    mont = BN_MONT_CTX_new();
    printf("blind.mont_set.ret=%d\n", BN_MONT_CTX_set(mont, m, ctx));
    ERR_clear_error();
    bm = BN_BLINDING_create_param(NULL, e, m, ctx, NULL, mont);
    printf("blind.mont_create.nonnull=%d\n", bm != NULL);
    errs("blind.mont_create.err");
    if (bm != NULL) {
        blind_trip("blind.mont1", bm, n, keep, expect, d, m, ctx);
        blind_trip("blind.mont2", bm, n, keep, expect, d, m, ctx);
        BN_BLINDING_free(bm);
    }
    BN_MONT_CTX_free(mont);

    /* --- 5b. The refusal arms --------------------------------------------------------- */

    /* A context with no factor yet: `BN_BLINDING_new` takes a null `A`/`Ai`, and both
     * readers of them raise `BN_R_NOT_INITIALIZED` at their own coordinate. */
    bare = BN_BLINDING_new(NULL, NULL, m);
    printf("blind.bare.nonnull=%d\n", bare != NULL);
    ERR_clear_error();
    printf("blind.bare.update.ret=%d\n", BN_BLINDING_update(bare, ctx));
    errs("blind.bare.update.err");
    ERR_clear_error();
    printf("blind.bare.convert.ret=%d\n", BN_BLINDING_convert(n, bare, ctx));
    errs("blind.bare.convert.err");
    ERR_clear_error();
    printf("blind.bare.convert_ex.ret=%d\n", BN_BLINDING_convert_ex(n, NULL, bare, ctx));
    errs("blind.bare.convert_ex.err");
    ERR_clear_error();
    printf("blind.bare.invert.ret=%d\n", BN_BLINDING_invert(n, bare, ctx));
    errs("blind.bare.invert.err");
    printf("blind.bare.current_thread=%d\n", BN_BLINDING_is_current_thread(bare));
    BN_BLINDING_free(bare);

    /* No exponent: `ret->e == NULL` is a failure that **raises nothing**, and because `b`
     * was null the half-built context is freed. */
    ERR_clear_error();
    printf("blind.no_e.null=%d\n",
           BN_BLINDING_create_param(NULL, NULL, m, ctx, NULL, NULL) == NULL);
    errs("blind.no_e.err");

    /* No modulus: `BN_BLINDING_new` duplicates it unconditionally, so its `BN_dup(NULL)`
     * is the failure. Also silent. */
    ERR_clear_error();
    printf("blind.no_m.null=%d\n",
           BN_BLINDING_create_param(NULL, e, NULL, ctx, NULL, NULL) == NULL);
    errs("blind.no_m.err");

    /* A modulus of one: every draw is zero and `0` has no inverse, so the retry loop runs
     * to its end -- thirty-three draws -- and raises `BN_R_TOO_MANY_ITERATIONS`. */
    ERR_clear_error();
    printf("blind.mod_one.null=%d\n",
           BN_BLINDING_create_param(NULL, e, one, ctx, NULL, NULL) == NULL);
    errs("blind.mod_one.err");

    BN_free(r_after);
    BN_free(r_before);
    BN_free(one);
    BN_free(expect);
    BN_free(keep);
    BN_free(n);
    BN_free(e);
    BN_free(d);
    BN_free(other);
    BN_free(m);
}

/* =============================================================================================
 * 6. The prime family
 *
 * Generation is random, so a generated value never enters the transcript. What does:
 *
 *   - `BN_check_prime`/`BN_is_prime_ex`/`BN_is_prime` answers on **committed** inputs, which
 *     is where 0, 1, a negative, an even, a small-factor composite, a Carmichael number and a
 *     Fermat number all become exact;
 *   - the refusal return codes and their drained error queues;
 *   - the round counts a `BN_GENCB` callback sees, which is how the 64-round clamp and
 *     `do_trial_division` are observed without a value;
 *   - a generated prime's *properties*: width, pinned bits, primality, the `add`/`rem`
 *     congruence, and -- for X9.31 -- the `Rp` congruence recomputed here from the pair.
 * ============================================================================================= */

struct tally {
    int events;
    int minus_one;
    int max_index;
};

static void tally_add(struct tally *t, int event, int n)
{
    if (t == NULL)
        return;
    t->events++;
    if (event != 1)
        return;
    if (n == -1)
        t->minus_one++;
    else if (n > t->max_index)
        t->max_index = n;
}

static int tally_new_cb(int event, int n, BN_GENCB *cb)
{
    tally_add((struct tally *)BN_GENCB_get_arg(cb), event, n);
    return 1;
}

static void tally_old_cb(int event, int n, void *arg)
{
    tally_add((struct tally *)arg, event, n);
}

/* One committed primality answer, with the error queue. */
static void prime_answer(const char *label, const BIGNUM *w, int want, BN_CTX *ctx)
{
    char k[160];

    ERR_clear_error();
    snprintf(k, sizeof(k), "prime.%s.ret", label);
    printf("%s=%d\n", k, BN_check_prime(w, ctx, NULL));
    snprintf(k, sizeof(k), "prime.%s.want", label);
    printf("%s=%d\n", k, want);
    snprintf(k, sizeof(k), "prime.%s.err", label);
    errs(k);
}

static void prime_answer_arms(BN_CTX *ctx)
{
    /* `(label, hex, expected answer)`. Every one of these is committed: the composites are
     * known composites, and `2^128+1` is Fermat's F_7, whose smallest factor (5964958912749
     * 7217) is far above the trial-division bound, so only Miller-Rabin can reject it. */
    static const struct {
        const char *label;
        const char *hex;
        int want;
    } cases[] = {
        { "zero", "00", 0 },
        { "one", "01", 0 },
        { "two", "02", 1 },
        { "three", "03", 1 },
        { "four", "04", 0 },
        { "six", "06", 0 },
        { "nine", "09", 0 },
        { "twentyfive", "19", 0 },
        { "carmichael561", "231", 0 },
        { "prime97", "61", 1 },
        { "prime307", "133", 1 },
        { "prime311", "137", 1 },
        { "prime313", "139", 1 },
        { "composite_317x331", "199DF", 0 },
        { "carmichael_3fact", "CEC7079", 0 },
        { "mersenne_2_127_minus_1", "7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF", 1 },
        { "fermat_f7", "100000000000000000000000000000001", 0 },
    };
    size_t i;

    for (i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        BIGNUM *w = from_hex(cases[i].hex);

        if (w == NULL) {
            printf("prime.%s.alloc=0\n", cases[i].label);
            continue;
        }
        prime_answer(cases[i].label, w, cases[i].want, ctx);
        BN_free(w);
    }

    /* The signed comparison: a negative value is `<= 1` and therefore composite. */
    {
        BIGNUM *w = BN_new();

        if (w != NULL) {
            BN_set_word(w, 5);
            BN_set_negative(w, 1);
            prime_answer("negative5", w, 0, ctx);
            BN_free(w);
        }
    }
}

static void prime_deprecated_arms(BN_CTX *ctx)
{
    BIGNUM *prime = from_hex("139");  /* 313 */
    BIGNUM *composite = from_hex("CEC7079");
    BIGNUM *w[2];
    int i;

    if (prime == NULL || composite == NULL) {
        printf("prime.deprecated.alloc=0\n");
        return;
    }
    w[0] = prime;
    w[1] = composite;
    for (i = 0; i < 2; i++) {
        const char *which = i == 0 ? "prime" : "composite";
        char k[160];

        ERR_clear_error();
        snprintf(k, sizeof(k), "dep.%s.is_prime_ex", which);
        printf("%s=%d\n", k, BN_is_prime_ex(w[i], 5, ctx, NULL));
        snprintf(k, sizeof(k), "dep.%s.fasttest_ex_no_sieve", which);
        printf("%s=%d\n", k, BN_is_prime_fasttest_ex(w[i], 5, ctx, 0, NULL));
        snprintf(k, sizeof(k), "dep.%s.fasttest_ex_sieve", which);
        printf("%s=%d\n", k, BN_is_prime_fasttest_ex(w[i], 5, ctx, 1, NULL));
        snprintf(k, sizeof(k), "dep.%s.old_style", which);
        printf("%s=%d\n", k, BN_is_prime(w[i], 5, NULL, ctx, NULL));
        snprintf(k, sizeof(k), "dep.%s.old_style_fasttest", which);
        printf("%s=%d\n", k, BN_is_prime_fasttest(w[i], 5, NULL, ctx, NULL, 1));
        snprintf(k, sizeof(k), "dep.%s.err", which);
        errs(k);
    }
    BN_free(composite);
    BN_free(prime);
}

static void prime_callback_arms(BN_CTX *ctx)
{
    BIGNUM *w = from_hex("139");  /* 313: past the sieve, so Miller-Rabin runs */
    BN_GENCB *cb = BN_GENCB_new();
    struct tally t;
    int arm;

    if (w == NULL || cb == NULL) {
        printf("prime.callback.alloc=0\n");
        return;
    }

    for (arm = 0; arm < 3; arm++) {
        int events;

        t.events = 0;
        t.minus_one = 0;
        t.max_index = 0;
        BN_GENCB_set(cb, tally_new_cb, &t);
        ERR_clear_error();
        switch (arm) {
        case 0: events = BN_check_prime(w, ctx, cb); break;
        case 1: events = BN_is_prime_ex(w, 5, ctx, cb); break;
        default: events = BN_is_prime_fasttest_ex(w, 5, ctx, 0, cb); break;
        }
        printf("cb.%s.answered=%d\n",
               arm == 0 ? "check_prime" : arm == 1 ? "is_prime_ex" : "fasttest_no_sieve",
               events);
        printf("cb.%s.events=%d\n",
               arm == 0 ? "check_prime" : arm == 1 ? "is_prime_ex" : "fasttest_no_sieve",
               t.events);
        printf("cb.%s.minus_one=%d\n",
               arm == 0 ? "check_prime" : arm == 1 ? "is_prime_ex" : "fasttest_no_sieve",
               t.minus_one);
        printf("cb.%s.max_index=%d\n",
               arm == 0 ? "check_prime" : arm == 1 ? "is_prime_ex" : "fasttest_no_sieve",
               t.max_index);
        errs(arm == 0 ? "cb.check_prime.err"
                      : arm == 1 ? "cb.is_prime_ex.err" : "cb.fasttest_no_sieve.err");
    }

    /* The `do_trial_division = 1` spelling, whose extra event is the sieve's `(1, -1)`. */
    t.events = 0;
    t.minus_one = 0;
    t.max_index = 0;
    BN_GENCB_set(cb, tally_new_cb, &t);
    printf("cb.fasttest_sieve.answered=%d\n", BN_is_prime_fasttest_ex(w, 5, ctx, 1, cb));
    printf("cb.fasttest_sieve.events=%d\n", t.events);
    printf("cb.fasttest_sieve.minus_one=%d\n", t.minus_one);
    printf("cb.fasttest_sieve.max_index=%d\n", t.max_index);

    /* The deprecated pair reaches the same counts through the `void`-returning callback. */
    for (arm = 0; arm < 2; arm++) {
        t.events = 0;
        t.minus_one = 0;
        t.max_index = 0;
        ERR_clear_error();
        printf("cb.old_%s.answered=%d\n", arm == 0 ? "is_prime" : "fasttest",
               arm == 0 ? BN_is_prime(w, 5, tally_old_cb, ctx, &t)
                        : BN_is_prime_fasttest(w, 5, tally_old_cb, ctx, &t, 1));
        printf("cb.old_%s.events=%d\n", arm == 0 ? "is_prime" : "fasttest", t.events);
        printf("cb.old_%s.minus_one=%d\n", arm == 0 ? "is_prime" : "fasttest", t.minus_one);
        printf("cb.old_%s.max_index=%d\n", arm == 0 ? "is_prime" : "fasttest", t.max_index);
        errs(arm == 0 ? "cb.old_is_prime.err" : "cb.old_fasttest.err");
    }

    /* A NULL old-style callback is not an error: `BN_GENCB_call` answers 1 and invokes
     * nothing. */
    ERR_clear_error();
    printf("cb.null_old.answered=%d\n", BN_is_prime(w, 5, NULL, ctx, NULL));
    errs("cb.null_old.err");

    BN_GENCB_free(cb);
    BN_free(w);
}

static void prime_generation_arms(BN_CTX *ctx)
{
    BIGNUM *out = BN_new();
    BIGNUM *half = BN_new();
    BIGNUM *add = BN_new();
    BIGNUM *rem = BN_new();
    BIGNUM *seen = BN_new();
    BIGNUM *want = BN_new();
    struct tally t;
    char k[160];

    if (out == NULL || half == NULL || add == NULL || rem == NULL || seen == NULL
        || want == NULL) {
        printf("gen.alloc=0\n");
        return;
    }
    BN_set_word(add, 65536);
    BN_set_word(rem, 1);
    BN_set_word(want, 1);

    /* The refusals: `bits < 2`, and the safe-prime band below six bits that is not three. */
    {
        static const struct {
            const char *label;
            int bits;
            int safe;
        } bad[] = { { "bits1", 1, 0 }, { "bits0", 0, 0 }, { "bitsneg", -1, 0 },
                    { "safe2", 2, 1 }, { "safe5", 5, 1 } };
        size_t i;

        for (i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
            ERR_clear_error();
            snprintf(k, sizeof(k), "gen.refuse.%s.ret", bad[i].label);
            printf("%s=%d\n", k,
                   BN_generate_prime_ex2(out, bad[i].bits, bad[i].safe, NULL, NULL, NULL, ctx));
            snprintf(k, sizeof(k), "gen.refuse.%s.err", bad[i].label);
            errs(k);
        }
    }

    /* Two widths where the masks pin the *value*: `BN_RAND_TOP_TWO | BN_RAND_BOTTOM_ODD` at
     * two bits is 0b11 and at three bits is 0b111, and neither is sifted away. The safe arm
     * at three bits is the one width the second refusal does not cover. */
    ERR_clear_error();
    printf("gen.exact2.ret=%d\n", BN_generate_prime_ex2(out, 2, 0, NULL, NULL, NULL, ctx));
    printf("gen.exact2.is_three=%d\n", BN_is_word(out, 3));
    errs("gen.exact2.err");
    ERR_clear_error();
    printf("gen.exact3.ret=%d\n", BN_generate_prime_ex2(out, 3, 0, NULL, NULL, NULL, ctx));
    printf("gen.exact3.is_seven=%d\n", BN_is_word(out, 7));
    errs("gen.exact3.err");
    ERR_clear_error();
    printf("gen.exact3safe.ret=%d\n", BN_generate_prime_ex2(out, 3, 1, NULL, NULL, NULL, ctx));
    printf("gen.exact3safe.is_seven=%d\n", BN_is_word(out, 7));
    errs("gen.exact3safe.err");

    /* The same through the no-context spelling. */
    ERR_clear_error();
    printf("gen.ex_ex.ret=%d\n", BN_generate_prime_ex(out, 2, 0, NULL, NULL, NULL));
    printf("gen.ex_ex.is_three=%d\n", BN_is_word(out, 3));
    errs("gen.ex_ex.err");

    /* --- 6a. The drawn arms, observed as properties ---------------------------------- */

    ERR_clear_error();
    printf("gen.p64.ret=%d\n", BN_generate_prime_ex2(out, 64, 0, NULL, NULL, NULL, ctx));
    printf("gen.p64.width=%d\n", BN_num_bits(out));
    printf("gen.p64.odd=%d\n", BN_is_odd(out));
    printf("gen.p64.top_bit=%d\n", BN_is_bit_set(out, 63));
    printf("gen.p64.prime=%d\n", BN_check_prime(out, ctx, NULL));
    errs("gen.p64.err");

    ERR_clear_error();
    printf("gen.safe32.ret=%d\n", BN_generate_prime_ex2(out, 32, 1, NULL, NULL, NULL, ctx));
    printf("gen.safe32.width=%d\n", BN_num_bits(out));
    printf("gen.safe32.bit1=%d\n", BN_is_bit_set(out, 1));
    printf("gen.safe32.odd=%d\n", BN_is_odd(out));
    printf("gen.safe32.prime=%d\n", BN_check_prime(out, ctx, NULL));
    if (BN_rshift1(half, out) == 1)
        printf("gen.safe32.cofactor_prime=%d\n", BN_check_prime(half, ctx, NULL));
    else
        printf("gen.safe32.cofactor_prime=ERR\n");
    errs("gen.safe32.err");

    /* The `add`/`rem` form: `ret % add == rem` is the whole contract, and the width is a
     * floor rather than a ceiling (the sieve steps by `add` after the initial adjustment). */
    ERR_clear_error();
    printf("gen.dh64.ret=%d\n", BN_generate_prime_ex2(out, 64, 0, add, rem, NULL, ctx));
    printf("gen.dh64.width_ge=%d\n", BN_num_bits(out) >= 64);
    printf("gen.dh64.odd=%d\n", BN_is_odd(out));
    if (BN_div(NULL, seen, out, add, ctx) == 1)
        printf("gen.dh64.residue=%d\n", BN_cmp(seen, rem) == 0);
    else
        printf("gen.dh64.residue=ERR\n");
    printf("gen.dh64.prime=%d\n", BN_check_prime(out, ctx, NULL));
    errs("gen.dh64.err");

    /* The deprecated spelling, whose callback is old-style. At two bits the masks pin the
     * draw and the first candidate is accepted, so exactly one callback fires -- a count, not
     * a value. */
    t.events = 0;
    t.minus_one = 0;
    t.max_index = 0;
    ERR_clear_error();
    {
        BIGNUM *fresh = BN_generate_prime(NULL, 2, 0, NULL, NULL, tally_old_cb, &t);

        printf("gen.deprecated.nonnull=%d\n", fresh != NULL);
        if (fresh != NULL) {
            printf("gen.deprecated.is_three=%d\n", BN_is_word(fresh, 3));
            BN_free(fresh);
        }
        printf("gen.deprecated.events=%d\n", t.events);
        errs("gen.deprecated.err");
    }
    /* A supplied destination is returned unchanged. */
    {
        BIGNUM *got = BN_generate_prime(out, 2, 0, NULL, NULL, NULL, NULL);

        printf("gen.deprecated.dest_same=%d\n", got == out);
        printf("gen.deprecated.dest_is_three=%d\n", BN_is_word(out, 3));
    }

    BN_free(want);
    BN_free(seen);
    BN_free(rem);
    BN_free(add);
    BN_free(half);
    BN_free(out);
}

/* The X9.31 `Rp` for a pair of derived primes, recomputed here: the derived `p` satisfies
 * `p == Rp (mod p1*p2)` -- **not** `p == Xp`, which only chooses the first candidate. */
static void x931_rp(BIGNUM *rp, const BIGNUM *p1, const BIGNUM *p2, const BIGNUM *p1p2,
                    BN_CTX *ctx)
{
    BIGNUM *x = BN_new();
    BIGNUM *y = BN_new();

    if (x == NULL || y == NULL) {
        printf("x931.rp.alloc=0\n");
        BN_free(x);
        BN_free(y);
        return;
    }
    if (BN_mod_inverse(x, p2, p1, ctx) != NULL && BN_mul(x, x, p2, ctx) == 1
        && BN_mod_inverse(y, p1, p2, ctx) != NULL && BN_mul(y, y, p1, ctx) == 1)
        printf("x931.rp.computed=%d\n", BN_mod_sub(rp, x, y, p1p2, ctx));
    else
        printf("x931.rp.computed=ERR\n");
    BN_free(y);
    BN_free(x);
}

/* One derived prime checked against its construction, as booleans. */
static void x931_check(const char *prefix, BIGNUM *p, BIGNUM *p1, BIGNUM *p2, const BIGNUM *xp,
                       BN_CTX *ctx)
{
    BIGNUM *p1p2 = BN_new();
    BIGNUM *rp = BN_new();
    BIGNUM *seen = BN_new();
    char k[160];

    if (p1p2 == NULL || rp == NULL || seen == NULL) {
        printf("%s.alloc=0\n", prefix);
        return;
    }
    snprintf(k, sizeof(k), "%s.p_prime", prefix);
    printf("%s=%d\n", k, BN_check_prime(p, ctx, NULL));
    snprintf(k, sizeof(k), "%s.p1_prime", prefix);
    printf("%s=%d\n", k, BN_check_prime(p1, ctx, NULL));
    snprintf(k, sizeof(k), "%s.p2_prime", prefix);
    printf("%s=%d\n", k, BN_check_prime(p2, ctx, NULL));
    snprintf(k, sizeof(k), "%s.p1_odd", prefix);
    printf("%s=%d\n", k, BN_is_odd(p1));
    snprintf(k, sizeof(k), "%s.p_ge_xp", prefix);
    printf("%s=%d\n", k, BN_cmp(p, xp) >= 0);
    if (BN_mul(p1p2, p1, p2, ctx) == 1) {
        x931_rp(rp, p1, p2, p1p2, ctx);
        snprintf(k, sizeof(k), "%s.congruent", prefix);
        printf("%s=%d\n", k,
               BN_mod_sub(seen, p, rp, p1p2, ctx) == 1 && BN_is_zero(seen));
        /* The structure that congruence implies: `p == 1 (mod p1)`. */
        snprintf(k, sizeof(k), "%s.p_mod_p1_is_one", prefix);
        printf("%s=%d\n", k,
               BN_div(NULL, seen, p, p1, ctx) == 1 && BN_is_one(seen));
    } else {
        printf("%s.congruent=ERR\n", prefix);
    }
    snprintf(k, sizeof(k), "%s.err", prefix);
    errs(k);
    BN_free(seen);
    BN_free(rp);
    BN_free(p1p2);
}

static void x931_arms(BN_CTX *ctx)
{
    BIGNUM *xp = from_hex("2000000000000000000000000000000000000000000000ABCDE");
    BIGNUM *xp1 = from_hex("10000000000000000000012345");
    BIGNUM *xp2 = from_hex("10000000000000000000054321");
    BIGNUM *p = BN_new();
    BIGNUM *p1 = BN_new();
    BIGNUM *p2 = BN_new();
    BIGNUM *Xp = BN_new();
    BIGNUM *Xq = BN_new();
    BIGNUM *seen = BN_new();
    BIGNUM *e = BN_new();
    BIGNUM *even_e = BN_new();
    int i;

    if (xp == NULL || xp1 == NULL || xp2 == NULL || p == NULL || p1 == NULL || p2 == NULL
        || Xp == NULL || Xq == NULL || seen == NULL || e == NULL || even_e == NULL) {
        printf("x931.alloc=0\n");
        return;
    }
    BN_set_word(e, 65537);
    BN_set_word(even_e, 65536);

    /* The width guard: `nbits` is the sum of the two widths and must be 1024 + 256s. Every
     * refusal answers 0 and raises nothing. */
    {
        static const int bad[] = { 0, 512, 1023, 1025, 1281, -1 };

        for (i = 0; i < (int)(sizeof(bad) / sizeof(bad[0])); i++) {
            char k[160];

            ERR_clear_error();
            snprintf(k, sizeof(k), "x931.xpq.bad%d.ret", bad[i]);
            printf("%s=%d\n", k, BN_X931_generate_Xpq(Xp, Xq, bad[i], ctx));
            snprintf(k, sizeof(k), "x931.xpq.bad%d.err", bad[i]);
            errs(k);
        }
    }

    /* The accepted width: two halves with their top two bits set, separated by more than
     * 2^(nbits - 100). `BN_num_bits` reads the magnitude, so the difference's sign is not
     * part of the observation. */
    ERR_clear_error();
    printf("x931.xpq.ret=%d\n", BN_X931_generate_Xpq(Xp, Xq, 1024, ctx));
    printf("x931.xpq.xp_width=%d\n", BN_num_bits(Xp));
    printf("x931.xpq.xp_top=%d\n", BN_is_bit_set(Xp, 511));
    printf("x931.xpq.xp_second=%d\n", BN_is_bit_set(Xp, 510));
    printf("x931.xpq.xq_width=%d\n", BN_num_bits(Xq));
    printf("x931.xpq.xq_top=%d\n", BN_is_bit_set(Xq, 511));
    printf("x931.xpq.xq_second=%d\n", BN_is_bit_set(Xq, 510));
    if (BN_sub(seen, Xp, Xq) == 1)
        printf("x931.xpq.separated=%d\n", BN_num_bits(seen) > 512 - 100);
    else
        printf("x931.xpq.separated=ERR\n");
    errs("x931.xpq.err");

    /* An even exponent is refused before any work: the guard is the whole body's first
     * line. */
    ERR_clear_error();
    printf("x931.even_e.ret=%d\n",
           BN_X931_derive_prime_ex(p, p1, p2, xp, xp1, xp2, even_e, ctx, NULL));
    errs("x931.even_e.err");

    /* The fixed-input derivation. Nothing here is a draw except Miller-Rabin's bases, whose
     * answers do not vary. */
    ERR_clear_error();
    printf("x931.derive.ret=%d\n",
           BN_X931_derive_prime_ex(p, p1, p2, xp, xp1, xp2, e, ctx, NULL));
    x931_check("x931.derive", p, p1, p2, xp, ctx);

    /* The generator that draws its own `Xp1`/`Xp2` and writes them back. */
    ERR_clear_error();
    printf("x931.generate.ret=%d\n",
           BN_X931_generate_prime_ex(p, p1, p2, xp1, xp2, xp, e, ctx, NULL));
    printf("x931.generate.xp1_width=%d\n", BN_num_bits(xp1));
    printf("x931.generate.xp1_top=%d\n", BN_is_bit_set(xp1, 100));
    printf("x931.generate.xp2_width=%d\n", BN_num_bits(xp2));
    printf("x931.generate.xp2_top=%d\n", BN_is_bit_set(xp2, 100));
    x931_check("x931.generate", p, p1, p2, xp, ctx);

    BN_free(even_e);
    BN_free(e);
    BN_free(seen);
    BN_free(Xq);
    BN_free(Xp);
    BN_free(p2);
    BN_free(p1);
    BN_free(p);
    BN_free(xp2);
    BN_free(xp1);
    BN_free(xp);
}

/*
 * =============================================================================================
 * 7. The GF(2^m) square root and quadratic solve
 *
 * `crypto/bn/bn_gf2m.c` is the binary-curve layer's field arithmetic, and its two solving
 * entries -- `BN_GF2m_mod_sqrt` and `BN_GF2m_mod_solve_quad` -- are what `crypto/ec/ec2_oct.c`
 * reaches to decompress a point. Every observable here is a relation the authority's own
 * algebra must satisfy, checked from committed fields:
 *
 *   - the square root satisfies `y^2 == a (mod f)`;
 *   - the quadratic solve satisfies `z^2 + z == a (mod f)`;
 *   - a solve with no root raises `BN_R_NO_SOLUTION`;
 *   - the even-degree retry loop's ceiling raises `BN_R_TOO_MANY_ITERATIONS` on a modulus
 *     whose absolute trace vanishes;
 *   - a modulus `BN_GF2m_poly2arr` cannot represent raises `BN_R_INVALID_LENGTH`; and a
 *     degree-zero modulus is the `reduction mod 1` arm that answers zero.
 *
 * `a` and the modulus are committed, so a relation's answer is the same on both sides. The
 * square root is `a^(2^(m-1))` and is deterministic; the even-degree solve draws, so its root
 * is never printed -- only whether it satisfies the relation, which it must on either side.
 * No field element of a secret enters the transcript, because there is no secret here: every
 * input is a constant in this file.
 * =============================================================================================
 */

/* `x^163 + x^7 + x^6 + x^3 + 1` -- an irreducible odd-degree binary field. */
static const int GF2M_F163[] = {163, 7, 6, 3, 0, -1};
/* `x^8 + x^4 + x^3 + x + 1` -- the AES field, even degree. */
static const int GF2M_F8[] = {8, 4, 3, 1, 0, -1};
/*
 * `x^6 + x^5 + x^4 + x^3 + x^2 + x + 1 = (x^3 + x + 1)(x^3 + x^2 + 1)`: reducible, and its
 * absolute trace functional vanishes identically, so the even-degree loop never sees a
 * non-zero `w` and reaches `MAX_ITERATIONS`.
 */
static const int GF2M_F6_REDUCIBLE[] = {6, 5, 4, 3, 2, 1, 0, -1};
/* `p[0] == 0`: the `reduction mod 1` arm. */
static const int GF2M_DEGREE_ZERO[] = {0, -1};

/* The polynomial an exponent list names, as a `BIGNUM`. */
static BIGNUM *gf2m_field(const int *exps)
{
    BIGNUM *b = BN_new();

    for (int i = 0; exps[i] >= 0; i++)
        BN_set_bit(b, exps[i]);
    return b;
}

/* `y^2 == a (mod f)`? */
static int gf2m_sqrt_relation(const BIGNUM *y, const BIGNUM *a, const int *p, BN_CTX *ctx)
{
    BIGNUM *s = BN_new(), *am = BN_new();
    int ok = 0;

    if (s != NULL && am != NULL && BN_GF2m_mod_sqr_arr(s, y, p, ctx) == 1
        && BN_GF2m_mod_arr(am, a, p) == 1)
        ok = BN_ucmp(s, am) == 0;
    BN_free(s);
    BN_free(am);
    return ok;
}

/* `z^2 + z == a (mod f)`? */
static int gf2m_quad_relation(const BIGNUM *z, const BIGNUM *a, const int *p, BN_CTX *ctx)
{
    BIGNUM *s = BN_new(), *am = BN_new();
    int ok = 0;

    if (s != NULL && am != NULL && BN_GF2m_mod_sqr_arr(s, z, p, ctx) == 1
        && BN_GF2m_add(s, s, z) == 1 && BN_GF2m_mod_arr(am, a, p) == 1)
        ok = BN_ucmp(s, am) == 0;
    BN_free(s);
    BN_free(am);
    return ok;
}

static void gf2m_arms(BN_CTX *ctx)
{
    BIGNUM *a = from_hex("1ABCDEF0123456789ABCDEF0123456789ABCDEF");
    BIGNUM *a8 = from_hex("57");
    BIGNUM *one = BN_new();
    BIGNUM *six = BN_new();
    BIGNUM *zero_a = BN_new();
    BIGNUM *y = BN_new();
    BIGNUM *z = BN_new();
    BIGNUM *p163 = gf2m_field(GF2M_F163);
    BIGNUM *peven = BN_new();

    if (a == NULL || a8 == NULL || one == NULL || six == NULL || zero_a == NULL || y == NULL
        || z == NULL || p163 == NULL || peven == NULL) {
        printf("gf2m.alloc=0\n");
        return;
    }
    BN_set_word(one, 1);
    BN_set_word(six, 6);
    /* The non-odd modulus: `x^8 + x^4`, which `BN_GF2m_poly2arr` refuses. */
    BN_set_bit(peven, 8);
    BN_set_bit(peven, 4);

    /* --- 7a. The square root, `_arr` and wrapper -------------------------------------- */

    ERR_clear_error();
    printf("gf2m.sqrt.arr.ret=%d\n", BN_GF2m_mod_sqrt_arr(y, a, GF2M_F163, ctx));
    printf("gf2m.sqrt.arr.rel=%d\n", gf2m_sqrt_relation(y, a, GF2M_F163, ctx));
    errs("gf2m.sqrt.arr.err");

    ERR_clear_error();
    printf("gf2m.sqrt.bn.ret=%d\n", BN_GF2m_mod_sqrt(y, a, p163, ctx));
    printf("gf2m.sqrt.bn.rel=%d\n", gf2m_sqrt_relation(y, a, GF2M_F163, ctx));
    errs("gf2m.sqrt.bn.err");

    ERR_clear_error();
    printf("gf2m.sqrt.even.ret=%d\n", BN_GF2m_mod_sqrt_arr(y, a8, GF2M_F8, ctx));
    printf("gf2m.sqrt.even.rel=%d\n", gf2m_sqrt_relation(y, a8, GF2M_F8, ctx));
    errs("gf2m.sqrt.even.err");

    ERR_clear_error();
    BN_set_word(y, 0x77);
    printf("gf2m.sqrt.degree0.ret=%d\n", BN_GF2m_mod_sqrt_arr(y, a, GF2M_DEGREE_ZERO, ctx));
    printf("gf2m.sqrt.degree0.is_zero=%d\n", BN_is_zero(y));
    errs("gf2m.sqrt.degree0.err");

    ERR_clear_error();
    printf("gf2m.sqrt.badmod.ret=%d\n", BN_GF2m_mod_sqrt(y, a, peven, ctx));
    errs("gf2m.sqrt.badmod.err");

    /* --- 7b. The quadratic solve, odd degree (deterministic half-trace) --------------- */

    ERR_clear_error();
    printf("gf2m.quad.odd.ret=%d\n", BN_GF2m_mod_solve_quad_arr(z, six, GF2M_F163, ctx));
    printf("gf2m.quad.odd.rel=%d\n", gf2m_quad_relation(z, six, GF2M_F163, ctx));
    errs("gf2m.quad.odd.err");

    ERR_clear_error();
    printf("gf2m.quad.bn.ret=%d\n", BN_GF2m_mod_solve_quad(z, six, p163, ctx));
    printf("gf2m.quad.bn.rel=%d\n", gf2m_quad_relation(z, six, GF2M_F163, ctx));
    errs("gf2m.quad.bn.err");

    /* `a = 1` has `trace(1) = m mod 2 = 1`, so no root exists on an odd-degree field. */
    ERR_clear_error();
    printf("gf2m.quad.nosol.ret=%d\n", BN_GF2m_mod_solve_quad_arr(z, one, GF2M_F163, ctx));
    errs("gf2m.quad.nosol.err");

    /* --- 7c. The quadratic solve, even degree (a draw, observed as its relation) ------ */

    ERR_clear_error();
    printf("gf2m.quad.even.ret=%d\n", BN_GF2m_mod_solve_quad_arr(z, one, GF2M_F8, ctx));
    printf("gf2m.quad.even.rel=%d\n", gf2m_quad_relation(z, one, GF2M_F8, ctx));
    errs("gf2m.quad.even.err");

    ERR_clear_error();
    printf("gf2m.quad.even2.ret=%d\n", BN_GF2m_mod_solve_quad_arr(z, six, GF2M_F8, ctx));
    printf("gf2m.quad.even2.rel=%d\n", gf2m_quad_relation(z, six, GF2M_F8, ctx));
    errs("gf2m.quad.even2.err");

    /*
     * The reducible modulus whose trace vanishes: `w` is zero on every draw, so the loop
     * runs to `MAX_ITERATIONS` and raises `BN_R_TOO_MANY_ITERATIONS`. The draw count is
     * not printed -- the reason and the count of errors are the observation.
     */
    ERR_clear_error();
    printf("gf2m.quad.ceiling.ret=%d\n",
           BN_GF2m_mod_solve_quad_arr(z, one, GF2M_F6_REDUCIBLE, ctx));
    errs("gf2m.quad.ceiling.err");

    /* --- 7d. The remaining refusals and the zero inputs ------------------------------- */

    ERR_clear_error();
    printf("gf2m.quad.degree0.ret=%d\n",
           BN_GF2m_mod_solve_quad_arr(z, one, GF2M_DEGREE_ZERO, ctx));
    printf("gf2m.quad.degree0.is_zero=%d\n", BN_is_zero(z));
    errs("gf2m.quad.degree0.err");

    ERR_clear_error();
    printf("gf2m.quad.badmod.ret=%d\n", BN_GF2m_mod_solve_quad(z, one, peven, ctx));
    errs("gf2m.quad.badmod.err");

    /* `a == 0` is answered before any work, on both degrees. */
    ERR_clear_error();
    printf("gf2m.quad.a0.ret=%d\n", BN_GF2m_mod_solve_quad_arr(z, zero_a, GF2M_F163, ctx));
    printf("gf2m.quad.a0.is_zero=%d\n", BN_is_zero(z));
    errs("gf2m.quad.a0.err");

    BN_free(peven);
    BN_free(p163);
    BN_free(z);
    BN_free(y);
    BN_free(zero_a);
    BN_free(six);
    BN_free(one);
    BN_free(a8);
    BN_free(a);
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

    /* ---- 5. The blinding family: identities, never values -------------------------- */

    blind_arms(ctx);

    /* ---- 6. The prime family: committed answers, counts and properties -------------- */

    prime_answer_arms(ctx);
    prime_deprecated_arms(ctx);
    prime_callback_arms(ctx);
    prime_generation_arms(ctx);
    x931_arms(ctx);

    /* ---- 7. The GF(2^m) square root and quadratic solve ------------------------------ */

    gf2m_arms(ctx);

    BN_free(rnd);
    BN_free(range);
    BN_free(zero);
    BN_free(negative);
    BN_CTX_free(ctx);

    printf("done=1\n");
    return 0;
}
