/*
 * PFP-4 / W3 — whole-operation profile of the ECDSA P-256 signing path.
 *
 * This harness is measurement-only. It links against one libcrypto.so.3 (the
 * candidate digest under test) and attributes the wall time of ECDSA_do_sign to
 * the public operations the pipeline is built from:
 *
 *   sign      ECDSA_do_sign              — the whole operation (random nonce)
 *   signex    ECDSA_do_sign_ex(kinv,r)   — the s-expression + export only
 *   mul       EC_POINT_mul(k, NULL)      — the fixed-base k*G arm
 *   inverse   BN_mod_inverse (CONSTTIME) — k^-1 mod n
 *   nmod      BN_nnmod(x, n)             — the field-to-order reduction
 *   rand      RAND_priv_bytes(32)        — the nonce draw
 *   affine    EC_POINT_get_affine_coordinates + BN_nnmod — to_affine + r
 *
 * No implementation is changed; this only observes the loaded DSO.
 *
 * The private scalar and digest are deterministic and identical on both
 * subjects, so the printed public key is an observable a caller can compare.
 */

#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/stat.h>

#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/obj_mac.h>
#include <openssl/rand.h>

static double now_us(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec * 1e6 + (double)ts.tv_nsec / 1e3;
}

static void fill_seeded(unsigned long long seed, unsigned char *p, size_t n)
{
    unsigned long long s = seed ? seed : 0x9e3779b97f4a7c15ULL;
    size_t i;
    for (i = 0; i < n; i++) {
        s ^= s << 13;
        s ^= s >> 7;
        s ^= s << 17;
        p[i] = (unsigned char)(s >> 24);
    }
}

/* One batch: `iters` calls of `step`, returns microseconds per call. */
typedef int (*step_fn)(void);

static double batch(int iters, step_fn step)
{
    double t0, t1;
    int i;
    for (i = 0; i < iters; i++)
        if (!step())
            return -1.0;
    t0 = now_us();
    for (i = 0; i < iters; i++)
        if (!step())
            return -1.0;
    t1 = now_us();
    return (t1 - t0) / (double)iters;
}

static int cmp_double(const void *a, const void *b)
{
    double x = *(const double *)a, y = *(const double *)b;
    return (x > y) - (x < y);
}

static double measure(const char *name, int iters, step_fn step)
{
    enum { RUNS = 7 };
    double s[RUNS];
    int r;
    double med;
    for (r = 0; r < RUNS; r++) {
        s[r] = batch(iters / 4, step); /* warm-up */
        s[r] = batch(iters, step);
        if (s[r] < 0.0) {
            printf("MODE %-8s failed\n", name);
            return -1.0;
        }
    }
    qsort(s, RUNS, sizeof(double), cmp_double);
    med = s[RUNS / 2];
    printf("MODE %-8s median_us=%.3f min_us=%.3f max_us=%.3f iters=%d runs=%d\n",
           name, med, s[0], s[RUNS - 1], iters, RUNS);
    return med;
}

/* ---- fixed fixture ------------------------------------------------------ */

static EC_KEY *eck;
static EC_POINT *R;
static BN_CTX *ctx;
static BIGNUM *priv, *order, *dgst_bn, *order_e;
static unsigned char dgst[32];
static BIGNUM *ex_kinv, *ex_r;
static BIGNUM *tmp_x, *tmp_mod;

static int gen_priv(void)
{
    unsigned char sb[32];
    fill_seeded(0x45434400ULL, sb, sizeof(sb));
    sb[0] &= 0x7f;
    priv = BN_bin2bn(sb, (int)sizeof(sb), NULL);
    return priv != NULL;
}

static int setup(void)
{
    const EC_GROUP *grp;
    unsigned char pubbuf[65];
    size_t plen;

    eck = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    if (eck == NULL || !gen_priv())
        return 0;
    if (!EC_KEY_set_private_key(eck, priv))
        return 0;
    grp = EC_KEY_get0_group(eck);
    order = BN_dup(EC_GROUP_get0_order(grp));
    R = EC_POINT_new(grp);
    ctx = BN_CTX_new();
    if (grp == NULL || order == NULL || R == NULL || ctx == NULL)
        return 0;
    if (!EC_POINT_mul(grp, R, priv, NULL, NULL, ctx))
        return 0;
    if (!EC_KEY_set_public_key(eck, R))
        return 0;
    plen = EC_POINT_point2oct(grp, R, POINT_CONVERSION_COMPRESSED, pubbuf,
                              sizeof(pubbuf), ctx);
    if (plen == 0)
        return 0;

    fill_seeded(0x44494700ULL, dgst, sizeof(dgst));

    /* Fixed (kinv, r) for the signex mode: use the private scalar as the
     * nonce. This measures the s-expression, not the nonce path. */
    tmp_x = BN_new();
    tmp_mod = BN_new();
    ex_kinv = BN_new();
    ex_r = BN_new();
    if (tmp_x == NULL || tmp_mod == NULL || ex_kinv == NULL || ex_r == NULL)
        return 0;
    if (!EC_POINT_get_affine_coordinates(grp, R, tmp_x, NULL, ctx))
        return 0;
    if (!BN_nnmod(ex_r, tmp_x, order, ctx))
        return 0;
    {
        BIGNUM *k = BN_dup(priv);
        if (k == NULL)
            return 0;
        BN_set_flags(k, BN_FLG_CONSTTIME);
        if (BN_mod_inverse(ex_kinv, k, order, ctx) == NULL) {
            BN_free(k);
            return 0;
        }
        BN_free(k);
    }

    printf("CHECK pub=");
    {
        size_t i;
        for (i = 0; i < plen; i++)
            printf("%02x", pubbuf[i]);
    }
    printf(" r=%d\n", BN_num_bits(ex_r));

    dgst_bn = BN_bin2bn(dgst, (int)sizeof(dgst), NULL);
    order_e = BN_dup(order);
    if (dgst_bn == NULL || order_e == NULL || !BN_sub_word(order_e, 2))
        return 0;
    return 1;
}

/* ---- steps -------------------------------------------------------------- */

static int step_sign(void)
{
    ECDSA_SIG *s = ECDSA_do_sign(dgst, (int)sizeof(dgst), eck);
    if (s == NULL)
        return 0;
    ECDSA_SIG_free(s);
    return 1;
}

static int step_signex(void)
{
    ECDSA_SIG *s = ECDSA_do_sign_ex(dgst, (int)sizeof(dgst), ex_kinv, ex_r, eck);
    if (s == NULL)
        return 0;
    ECDSA_SIG_free(s);
    return 1;
}

static int step_mul(void)
{
    const EC_GROUP *grp = EC_KEY_get0_group(eck);
    return EC_POINT_mul(grp, R, priv, NULL, NULL, ctx) == 1;
}

static int step_inverse(void)
{
    return BN_mod_inverse(tmp_mod, priv, order, ctx) != NULL;
}

static int step_ordinv(void)
{
    /* The order inverse reached by ecdsa_sign_setup is the Fermat exponent
     * x^(order-2) mod order through the constant-time fixed-top ladder. The
     * public BN_mod_exp with a CONSTTIME base selects the same class of
     * constant-time exponentiation, so this is the magnitude of that step. */
    BN_set_flags(priv, BN_FLG_CONSTTIME);
    return BN_mod_exp(tmp_mod, priv, order_e, order, ctx) == 1;
}

static int step_nmod(void)
{
    return BN_nnmod(tmp_mod, dgst_bn, order, ctx) == 1;
}

static int step_rand(void)
{
    unsigned char b[32];
    return RAND_priv_bytes(b, sizeof(b)) == 1;
}

/* to_affine + r = x mod n, in place on a dedicated point. */
static int step_affine(void)
{
    const EC_GROUP *grp = EC_KEY_get0_group(eck);
    if (EC_POINT_get_affine_coordinates(grp, R, tmp_x, NULL, ctx) != 1)
        return 0;
    return BN_nnmod(tmp_mod, tmp_x, order, ctx) == 1;
}

static void verify_loaded(const char *expect)
{
    Dl_info info;
    struct stat a, b;
    if (dladdr((void *)ECDSA_do_sign, &info) == 0 || info.dli_fname == NULL) {
        printf("LOADED unknown\n");
        return;
    }
    printf("LOADED %s\n", info.dli_fname);
    if (expect != NULL && stat(info.dli_fname, &a) == 0 && stat(expect, &b) == 0)
        printf("IDENTITY dev_ino_match=%d size_match=%d\n",
               a.st_dev == b.st_dev && a.st_ino == b.st_ino,
               a.st_size == b.st_size);
}

int main(int argc, char **argv)
{
    const char *mode;
    const char *expect = NULL;
    int iters = 2000;
    double sign_us;

    if (argc < 2) {
        fprintf(stderr,
                "usage: %s <sign|signex|mul|inverse|ordinv|nmod|rand|affine|all> "
                "[iters] [expected_dso]\n", argv[0]);
        return 2;
    }
    mode = argv[1];
    if (argc > 2)
        iters = atoi(argv[2]);
    if (argc > 3)
        expect = argv[3];

    if (!setup()) {
        fprintf(stderr, "setup failed\n");
        return 1;
    }
    verify_loaded(expect);

    if (strcmp(mode, "sign") == 0 || strcmp(mode, "all") == 0) {
        sign_us = measure("sign", iters, step_sign);
        if (sign_us > 0.0 && strcmp(mode, "all") == 0) {
            double mul, sx, inv, nm, rnd, aff, oinv;
            mul = measure("mul", iters, step_mul);
            sx = measure("signex", iters, step_signex);
            inv = measure("inverse", iters, step_inverse);
            oinv = measure("ordinv", iters, step_ordinv);
            nm = measure("nmod", iters, step_nmod);
            rnd = measure("rand", iters, step_rand);
            aff = measure("affine", iters, step_affine);
            printf(
                "DECOMP sign=%.3f mul=%.3f signex=%.3f inverse=%.3f ordinv=%.3f "
                "nmod=%.3f rand=%.3f affine=%.3f\n",
                sign_us, mul, sx, inv, oinv, nm, rnd, aff);
            printf("FRACTION_KG %.6f\n", mul / sign_us);
            printf("FRACTION_OUTSIDE_KG %.6f\n", 1.0 - mul / sign_us);
        }
        return sign_us > 0.0 ? 0 : 1;
    }
    if (strcmp(mode, "signex") == 0)
        return measure("signex", iters, step_signex) > 0.0 ? 0 : 1;
    if (strcmp(mode, "mul") == 0)
        return measure("mul", iters, step_mul) > 0.0 ? 0 : 1;
    if (strcmp(mode, "inverse") == 0)
        return measure("inverse", iters, step_inverse) > 0.0 ? 0 : 1;
    if (strcmp(mode, "ordinv") == 0)
        return measure("ordinv", iters, step_ordinv) > 0.0 ? 0 : 1;
    if (strcmp(mode, "nmod") == 0)
        return measure("nmod", iters, step_nmod) > 0.0 ? 0 : 1;
    if (strcmp(mode, "rand") == 0)
        return measure("rand", iters, step_rand) > 0.0 ? 0 : 1;
    if (strcmp(mode, "affine") == 0)
        return measure("affine", iters, step_affine) > 0.0 ? 0 : 1;

    fprintf(stderr, "unknown mode %s\n", mode);
    return 2;
}
