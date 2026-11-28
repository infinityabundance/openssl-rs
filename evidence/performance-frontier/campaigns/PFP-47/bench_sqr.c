/*
 * bench_sqr.c — PFP-47: the authority's a == b squaring path against its own
 * multiply path, at the Montgomery operand widths this crate's ladder uses.
 *
 * Both variants call BN_mod_mul_montgomery with two BIGNUMs of *equal value*:
 *   sqr: r = a * a   (the same BIGNUM pointer twice -> bn_mul_mont sees ap == bp
 *                     and, for n >= 8 and n % 8 == 0, enters bn_sqr8x_mont)
 *   mul: r = a * b   (two distinct BIGNUM allocations with equal limbs ->
 *                     bn_mul_mont sees ap != bp and enters bn_mul4x_mont, which
 *                     takes the ADX bn_mulx4x_mont arm on this CPU)
 *
 * Only the pointer identity differs, so the ratio is the dedicated-squaring
 * schedule's own advantage in the authority, not a change of arithmetic.
 *
 * One process, one width. Interleaved repetitions; each repetition times a batch
 * of `iters` calls of each variant and records the batch mean. The printed
 * figure is the median per-call nanoseconds over repetitions, and the ratio is
 * the median of the per-repetition paired ratios mul/sqr (< 1 would mean the
 * multiply path is faster). A bootstrap 95% interval is printed for the ratio.
 *
 * Exit status is non-zero if the two results differ or a call fails; a failed
 * setup is never reported as a RESULT.
 */

#define _GNU_SOURCE
#include <openssl/bn.h>

#include <math.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static double now_ns(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec * 1e9 + (double)ts.tv_nsec;
}

static int cmp_double(const void *pa, const void *pb)
{
    double a = *(const double *)pa, b = *(const double *)pb;
    return (a > b) - (a < b);
}

static double median(double *v, int n)
{
    qsort(v, (size_t)n, sizeof(double), cmp_double);
    if (n & 1)
        return v[n / 2];
    return 0.5 * (v[n / 2 - 1] + v[n / 2]);
}

static int build_modulus(int bits, BIGNUM **out, BN_CTX *ctx)
{
    BIGNUM *p = NULL;
    switch (bits) {
    case 256: {
        BIGNUM *r = BN_new();
        if (r == NULL || BN_generate_prime_ex(r, 256, 0, NULL, NULL, NULL) != 1) {
            BN_free(r);
            return 0;
        }
        p = r;
        break;
    }
    case 1024: p = BN_get_rfc2409_prime_1024(NULL); break;
    case 1536: p = BN_get_rfc3526_prime_1536(NULL); break;
    case 2048: p = BN_get_rfc3526_prime_2048(NULL); break;
    case 3072: p = BN_get_rfc3526_prime_3072(NULL); break;
    case 4096: p = BN_get_rfc3526_prime_4096(NULL); break;
    default: return 0;
    }
    (void)ctx;
    if (p == NULL)
        return 0;
    *out = p;
    return 1;
}

int main(int argc, char **argv)
{
    int bits = 2048, iters = 20000, reps = 15, i, r;
    BIGNUM *p = NULL, *a = NULL, *b = NULL, *rs = NULL, *rm = NULL;
    BN_MONT_CTX *mont = NULL;
    BN_CTX *ctx = NULL;
    double *sqr = NULL, *mul = NULL, *ratio = NULL;
    volatile BN_ULONG sink = 0;
    unsigned char seed[64];

    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--bits") == 0 && i + 1 < argc)
            bits = atoi(argv[++i]);
        else if (strcmp(argv[i], "--iters") == 0 && i + 1 < argc)
            iters = atoi(argv[++i]);
        else if (strcmp(argv[i], "--reps") == 0 && i + 1 < argc)
            reps = atoi(argv[++i]);
        else {
            fprintf(stderr, "usage: %s [--bits N] [--iters N] [--reps N]\n", argv[0]);
            return 2;
        }
    }
    if (iters < 100 || reps < 3)
        return 2;

    ctx = BN_CTX_new();
    if (ctx == NULL || !build_modulus(bits, &p, ctx))
        goto bad;

    a = BN_new();
    b = BN_new();
    rs = BN_new();
    rm = BN_new();
    mont = BN_MONT_CTX_new();
    if (a == NULL || b == NULL || rs == NULL || rm == NULL || mont == NULL)
        goto bad;
    if (BN_MONT_CTX_set(mont, p, ctx) != 1)
        goto bad;

    for (i = 0; i < (int)sizeof(seed); i++)
        seed[i] = (unsigned char)(0x9e ^ (i * 37));
    if (BN_rand(a, bits, BN_RAND_TOP_ONE, BN_RAND_BOTTOM_ODD) != 1)
        goto bad;
    if (BN_nnmod(a, a, p, ctx) != 1)
        goto bad;
    if (BN_copy(b, a) == NULL)
        goto bad;

    /*
     * BN_copy allocates fresh storage, so a and b are distinct BIGNUM objects with
     * equal limbs; BN_ucmp proves the values equal. The only difference the n_mont
     * dispatch can observe is the two operand pointers.
     */
    if (BN_ucmp(a, b) != 0) {
        fprintf(stderr, "FATAL: operands are not equal in value\n");
        goto bad;
    }

    if (BN_mod_mul_montgomery(rs, a, a, mont, ctx) != 1)
        goto bad;
    if (BN_mod_mul_montgomery(rm, a, b, mont, ctx) != 1)
        goto bad;
    if (BN_cmp(rs, rm) != 0) {
        fprintf(stderr, "FATAL: squaring and multiply results differ\n");
        goto bad;
    }

    sqr = calloc((size_t)reps, sizeof(double));
    mul = calloc((size_t)reps, sizeof(double));
    ratio = calloc((size_t)reps, sizeof(double));
    if (sqr == NULL || mul == NULL || ratio == NULL)
        goto bad;

    /* Warm up both arms. */
    for (i = 0; i < iters / 4; i++) {
        BN_mod_mul_montgomery(rs, a, a, mont, ctx);
        BN_mod_mul_montgomery(rm, a, b, mont, ctx);
    }

    for (r = 0; r < reps; r++) {
        double t0, t1;
        int j;
        /* Alternate which variant runs first so cache/ordering bias cancels. */
        if ((r & 1) == 0) {
            t0 = now_ns();
            for (j = 0; j < iters; j++)
                BN_mod_mul_montgomery(rs, a, a, mont, ctx);
            t1 = now_ns();
            sqr[r] = (t1 - t0) / iters;

            t0 = now_ns();
            for (j = 0; j < iters; j++)
                BN_mod_mul_montgomery(rm, a, b, mont, ctx);
            t1 = now_ns();
            mul[r] = (t1 - t0) / iters;
        } else {
            t0 = now_ns();
            for (j = 0; j < iters; j++)
                BN_mod_mul_montgomery(rm, a, b, mont, ctx);
            t1 = now_ns();
            mul[r] = (t1 - t0) / iters;

            t0 = now_ns();
            for (j = 0; j < iters; j++)
                BN_mod_mul_montgomery(rs, a, a, mont, ctx);
            t1 = now_ns();
            sqr[r] = (t1 - t0) / iters;
        }
        sink ^= (BN_ULONG)BN_get_word(rs) ^ (BN_ULONG)BN_get_word(rm);
        ratio[r] = mul[r] / sqr[r];
    }

    {
        double sqr_med = median(sqr, reps);
        double mul_med = median(mul, reps);
        double ratio_med = median(ratio, reps);
        double boot[2000];
        int bi, bj;
        srand(12345);
        for (bi = 0; bi < 2000; bi++) {
            double acc = 0.0;
            for (bj = 0; bj < reps; bj++)
                acc += ratio[rand() % reps];
            boot[bi] = acc / reps;
        }
        qsort(boot, 2000, sizeof(double), cmp_double);

        printf("PFP47 bits=%d limbs=%d iters=%d reps=%d\n",
               bits, (bits + 63) / 64, iters, reps);
        printf("RESULT bits=%d sqr_ns=%.4f mul_ns=%.4f\n", bits, sqr_med, mul_med);
        printf("RATIO bits=%d mul_over_sqr=%.6f ci95=[%.6f,%.6f]\n",
               bits, ratio_med, boot[49], boot[1949]);
        printf("CHECK %s\n", BN_cmp(rs, rm) == 0 ? "equal" : "DIFFER");
        printf("SINK %lu\n", (unsigned long)sink);
    }

    BN_MONT_CTX_free(mont);
    BN_CTX_free(ctx);
    BN_free(p);
    BN_free(a);
    BN_free(b);
    BN_free(rs);
    BN_free(rm);
    free(sqr);
    free(mul);
    free(ratio);
    return 0;

bad:
    fprintf(stderr, "FATAL: setup failed at bits=%d\n", bits);
    BN_MONT_CTX_free(mont);
    BN_CTX_free(ctx);
    BN_free(p);
    BN_free(a);
    BN_free(b);
    BN_free(rs);
    BN_free(rm);
    free(sqr);
    free(mul);
    free(ratio);
    return 1;
}
