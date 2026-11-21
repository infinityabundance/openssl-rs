/*
 * Cost measurement for the constant-time BN exponentiation.
 *
 * Reports wall-clock microseconds per BN_mod_exp_mont_consttime call at the
 * DH/RSA modulus widths named in the repair receipt (2048, 3072, 8192), plus the
 * RSA-2048 CRT shape (two 1024-bit halves through
 * BN_mod_exp_mont_consttime_x2).  The modulus is a random odd number of the
 * requested width; the exponent has the same declared width with its top bit
 * set.  Montgomery REDC needs only an odd modulus, so primality is irrelevant
 * to the cost being measured.
 *
 * The number of allocations per call is not visible from C.  Pair this with
 * alloc_probe.so (LD_PRELOAD): the probe exposes allocprobe_reset() and
 * allocprobe_fail_after(), which this harness calls around the timed loop.
 *
 * Build:
 *   cc -O2 -g -Iartifacts/phase2/install/include bench_bn.c \
 *      -Lartifacts/phase2/install/lib -lcrypto -lm \
 *      -Wl,-rpath,<abs>/artifacts/phase2/install/lib -o /tmp/bench_bn
 * Run:
 *   LD_PRELOAD=/tmp/alloc_probe.so LD_LIBRARY_PATH=... /tmp/bench_bn
 */
#define _GNU_SOURCE
#include <openssl/bn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

extern void allocprobe_reset(void) __attribute__((weak));
extern void allocprobe_fail_after(unsigned long n) __attribute__((weak));
extern unsigned long allocprobe_mallocs(void) __attribute__((weak));
extern unsigned long allocprobe_frees(void) __attribute__((weak));

static double now_us(void)
{
    struct timespec ts;

    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec * 1e6 + (double)ts.tv_nsec / 1e3;
}

/* A random odd modulus and a same-width exponent with its top bit set. */
static int make_operands(int bits, BIGNUM **m, BIGNUM **e)
{
    *m = BN_new();
    *e = BN_new();
    if (*m == NULL || *e == NULL)
        return 0;
    return BN_rand(*m, bits, BN_RAND_TOP_ONE, BN_RAND_BOTTOM_ODD) &&
           BN_rand(*e, bits, BN_RAND_TOP_ONE, BN_RAND_BOTTOM_ANY);
}

static int bench_one(int bits, int iterations)
{
    BN_CTX *ctx = BN_CTX_new();
    BIGNUM *m = NULL, *e = NULL, *base = BN_new(), *r = BN_new();
    double t0, t1;
    int i, ok = 0;

    if (ctx == NULL || base == NULL || r == NULL)
        goto out;
    if (!make_operands(bits, &m, &e))
        goto out;
    if (!BN_set_word(base, 3))
        goto out;

    /* Warm up once so the first call's cold allocations are not the headline. */
    if (!BN_mod_exp_mont_consttime(r, base, e, m, ctx, NULL))
        goto out;

    if (allocprobe_reset != NULL)
        allocprobe_reset();
    t0 = now_us();
    for (i = 0; i < iterations; i++) {
        if (!BN_mod_exp_mont_consttime(r, base, e, m, ctx, NULL))
            goto out;
    }
    t1 = now_us();

    printf("modexp bits=%d iterations=%d us_per_call=%.1f allocs_per_call=",
           bits, iterations, (t1 - t0) / (double)iterations);
    if (allocprobe_mallocs != NULL)
        printf("%.0f", (double)allocprobe_mallocs() / (double)iterations);
    else
        printf("n/a");
    printf("\n");
    ok = 1;

out:
    BN_free(m);
    BN_free(e);
    BN_free(base);
    BN_free(r);
    BN_CTX_free(ctx);
    return ok;
}

/* RSA-2048 private op, CRT shape: two 1024-bit exponentiations in one call. */
static int bench_rsa_crt(int iterations)
{
    BN_CTX *ctx = BN_CTX_new();
    BIGNUM *p = NULL, *q = NULL, *dp = NULL, *dq = NULL;
    BIGNUM *base = BN_new(), *r1 = BN_new(), *r2 = BN_new();
    double t0, t1;
    int i, ok = 0;

    if (ctx == NULL || base == NULL || r1 == NULL || r2 == NULL)
        goto out;
    if (!make_operands(1024, &p, &dp) || !make_operands(1024, &q, &dq))
        goto out;
    if (!BN_set_word(base, 3))
        goto out;
    if (!BN_mod_exp_mont_consttime_x2(r1, base, dp, p, NULL, r2, base, dq, q, NULL, ctx))
        goto out;

    if (allocprobe_reset != NULL)
        allocprobe_reset();
    t0 = now_us();
    for (i = 0; i < iterations; i++) {
        if (!BN_mod_exp_mont_consttime_x2(r1, base, dp, p, NULL, r2, base, dq, q, NULL, ctx))
            goto out;
    }
    t1 = now_us();

    printf("rsa2048_crt iterations=%d us_per_call=%.1f allocs_per_call=",
           iterations, (t1 - t0) / (double)iterations);
    if (allocprobe_mallocs != NULL)
        printf("%.0f", (double)allocprobe_mallocs() / (double)iterations);
    else
        printf("n/a");
    printf("\n");
    ok = 1;

out:
    BN_free(p);
    BN_free(q);
    BN_free(dp);
    BN_free(dq);
    BN_free(base);
    BN_free(r1);
    BN_free(r2);
    BN_CTX_free(ctx);
    return ok;
}

int main(int argc, char **argv)
{
    int failure = (argc > 1 && strcmp(argv[1], "fail") == 0);

    if (failure) {
        /* Allocate the operands first, then fail the allocation the ladder asks
         * for after a fixed count.  The point is the behaviour on a failed
         * allocation inside the ladder, not on a failed setup. */
        BN_CTX *ctx = BN_CTX_new();
        BIGNUM *m = NULL, *e = NULL, *base = BN_new(), *r = BN_new();

        if (ctx == NULL || base == NULL || r == NULL || !make_operands(2048, &m, &e)) {
            fprintf(stderr, "fail setup failed\n");
            return 2;
        }
        if (allocprobe_fail_after != NULL)
            allocprobe_fail_after(64);
        fprintf(stderr, "fail: calling with allocation 64 forced to fail\n");
        fflush(stderr);
        (void)BN_mod_exp_mont_consttime(r, base, e, m, ctx, NULL);
        fprintf(stderr, "fail: call returned without an allocation failure\n");
        return 1;
    }

    if (!bench_one(2048, 50))
        return 1;
    if (!bench_one(3072, 20))
        return 1;
    if (!bench_one(8192, 4))
        return 1;
    if (!bench_rsa_crt(50))
        return 1;
    return 0;
}
