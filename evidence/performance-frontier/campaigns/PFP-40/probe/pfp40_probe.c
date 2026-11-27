/*
 * pfp40_probe.c — PFP-40 direct wall probe for the two components of an RSA
 * blinding re-creation, on whichever libcrypto is loaded with --lib.
 *
 * The blinding path is:
 *   A  <- BN_priv_rand_range(n)          (random draw)
 *   Ai <- int_bn_mod_inverse(A, n)       (modular inversion; the modulus has
 *                                         BN_FLG_CONSTTIME, so both arms take
 *                                         their constant-time inverse)
 *   A  <- A^e mod n via bn_mod_exp       (e is the RSA public exponent)
 *   A, Ai <- to Montgomery form
 *
 * This probe drives exactly those two expensive calls with the same geometry
 * the re-creation uses: the modulus is a duplicate of the key's n with
 * BN_FLG_CONSTTIME set, and A[^e] is taken with the same cached Montgomery
 * context (built once).  It reports per-call min/median/mean.
 *
 * Modes:
 *   info N        print the public exponent's bit length and limb count
 *   inverse-ct N  N x BN_mod_inverse(NULL, base, n_consttime, ctx)
 *   exp-ct N      N x BN_mod_exp_mont(r, base, e, n_consttime, ctx, mont)
 *
 * --lib selects libcrypto (candidate distribution DSO or the authority).
 * --rsa-der is the same PKCS#8/PKCS#1 DER fixture PFP-7 used.
 */

#define _GNU_SOURCE
#include <openssl/bn.h>
#include <openssl/rsa.h>

#include <dlfcn.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

typedef struct {
    void *h;
    RSA *(*d2i_RSAPrivateKey)(RSA **, const unsigned char **, long);
    void (*RSA_free)(RSA *);
    const BIGNUM *(*RSA_get0_n)(const RSA *);
    const BIGNUM *(*RSA_get0_e)(const RSA *);

    BIGNUM *(*BN_new)(void);
    void (*BN_free)(BIGNUM *);
    BIGNUM *(*BN_dup)(const BIGNUM *);
    BIGNUM *(*BN_bin2bn)(const unsigned char *, int, BIGNUM *);
    void (*BN_set_flags)(BIGNUM *, int);
    int (*BN_num_bits)(const BIGNUM *);
    BN_CTX *(*BN_CTX_new)(void);
    void (*BN_CTX_free)(BN_CTX *);
    BN_MONT_CTX *(*BN_MONT_CTX_new)(void);
    int (*BN_MONT_CTX_set)(BN_MONT_CTX *, const BIGNUM *, BN_CTX *);
    void (*BN_MONT_CTX_free)(BN_MONT_CTX *);
    BIGNUM *(*BN_mod_inverse)(BIGNUM *, const BIGNUM *, const BIGNUM *, BN_CTX *);
    int (*BN_mod_exp_mont)(BIGNUM *, const BIGNUM *, const BIGNUM *,
                           const BIGNUM *, BN_CTX *, BN_MONT_CTX *);
    int (*BN_priv_rand_range_ex)(BIGNUM *, const BIGNUM *, unsigned int, BN_CTX *);
} api_t;

#define BN_FLG_CONSTTIME_LOCAL 0x04

static api_t api;

static void *need_sym(const char *name)
{
    void *p = dlsym(api.h, name);
    if (p == NULL) {
        fprintf(stderr, "pfp40: missing symbol %s: %s\n", name, dlerror());
        exit(2);
    }
    return p;
}

#define LOAD(field, name) do { *(void **)(&api.field) = need_sym(name); } while (0)

static void load_api(void)
{
    LOAD(d2i_RSAPrivateKey, "d2i_RSAPrivateKey");
    LOAD(RSA_free, "RSA_free");
    LOAD(RSA_get0_n, "RSA_get0_n");
    LOAD(RSA_get0_e, "RSA_get0_e");
    LOAD(BN_new, "BN_new");
    LOAD(BN_free, "BN_free");
    LOAD(BN_dup, "BN_dup");
    LOAD(BN_bin2bn, "BN_bin2bn");
    LOAD(BN_set_flags, "BN_set_flags");
    LOAD(BN_num_bits, "BN_num_bits");
    LOAD(BN_CTX_new, "BN_CTX_new");
    LOAD(BN_CTX_free, "BN_CTX_free");
    LOAD(BN_MONT_CTX_new, "BN_MONT_CTX_new");
    LOAD(BN_MONT_CTX_set, "BN_MONT_CTX_set");
    LOAD(BN_MONT_CTX_free, "BN_MONT_CTX_free");
    LOAD(BN_mod_inverse, "BN_mod_inverse");
    LOAD(BN_mod_exp_mont, "BN_mod_exp_mont");
    LOAD(BN_priv_rand_range_ex, "BN_priv_rand_range_ex");
}

static double now_ns(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec * 1e9 + (double)ts.tv_nsec;
}

static int cmp_double(const void *a, const void *b)
{
    double x = *(const double *)a, y = *(const double *)b;
    return (x > y) - (x < y);
}

static void report(const char *mode, double *s, int n)
{
    double *t = malloc(sizeof(double) * (size_t)n);
    double sum = 0.0;
    int i;
    memcpy(t, s, sizeof(double) * (size_t)n);
    qsort(t, (size_t)n, sizeof(double), cmp_double);
    for (i = 0; i < n; i++)
        sum += s[i];
    printf("RESULT %s n=%d min_ns=%.1f median_ns=%.1f mean_ns=%.1f\n",
           mode, n, t[0], t[n / 2], sum / (double)n);
    free(t);
}

static unsigned char *read_file(const char *path, long *len)
{
    FILE *f = fopen(path, "rb");
    unsigned char *buf;
    long n;
    if (f == NULL)
        return NULL;
    fseek(f, 0, SEEK_END);
    n = ftell(f);
    fseek(f, 0, SEEK_SET);
    buf = malloc((size_t)n);
    if (buf == NULL || fread(buf, 1, (size_t)n, f) != (size_t)n) {
        free(buf);
        fclose(f);
        return NULL;
    }
    fclose(f);
    *len = n;
    return buf;
}

int main(int argc, char **argv)
{
    const char *lib = NULL, *der_path = NULL, *mode = NULL;
    int iters = 1, i;
    long der_len = 0;
    unsigned char *der = NULL;
    const unsigned char *q;
    RSA *rsa = NULL;
    const BIGNUM *n = NULL, *e = NULL;
    BIGNUM *nc = NULL, *base = NULL, *r = NULL;
    BN_CTX *ctx = NULL;
    BN_MONT_CTX *mont = NULL;
    double *s = NULL;
    int ok = 0;
    unsigned char buf[256];

    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--lib") == 0 && i + 1 < argc)
            lib = argv[++i];
        else if (strcmp(argv[i], "--rsa-der") == 0 && i + 1 < argc)
            der_path = argv[++i];
        else if (strcmp(argv[i], "--mode") == 0 && i + 1 < argc)
            mode = argv[++i];
        else if (strcmp(argv[i], "--iters") == 0 && i + 1 < argc)
            iters = atoi(argv[++i]);
        else {
            fprintf(stderr, "usage: %s --lib <dso> --rsa-der <der> --mode <m> "
                    "[--iters N]\n", argv[0]);
            return 2;
        }
    }
    if (lib == NULL || der_path == NULL || mode == NULL) {
        fprintf(stderr, "pfp40: --lib, --rsa-der and --mode are required\n");
        return 2;
    }

    api.h = dlopen(lib, RTLD_NOW | RTLD_LOCAL);
    if (api.h == NULL) {
        fprintf(stderr, "pfp40: dlopen: %s\n", dlerror());
        return 2;
    }
    {
        Dl_info info;
        if (dladdr(need_sym("BN_mod_inverse"), &info) != 0)
            printf("LIB %s\n", info.dli_fname);
    }
    load_api();

    der = read_file(der_path, &der_len);
    if (der == NULL) {
        fprintf(stderr, "pfp40: cannot read %s\n", der_path);
        goto out;
    }
    q = der;
    rsa = api.d2i_RSAPrivateKey(NULL, &q, der_len);
    if (rsa == NULL) {
        fprintf(stderr, "pfp40: d2i_RSAPrivateKey failed\n");
        goto out;
    }
    n = api.RSA_get0_n(rsa);
    e = api.RSA_get0_e(rsa);
    if (n == NULL || e == NULL)
        goto out;

    if (strcmp(mode, "info") == 0) {
        printf("INFO e_bits=%d n_bits=%d\n", api.BN_num_bits(e), api.BN_num_bits(n));
        ok = 1;
        goto out;
    }

    ctx = api.BN_CTX_new();
    nc = api.BN_dup(n);
    base = api.BN_new();
    r = api.BN_new();
    if (ctx == NULL || nc == NULL || base == NULL || r == NULL)
        goto out;
    /* Exactly the geometry of the re-creation: the modulus carries
     * BN_FLG_CONSTTIME (copied there by BN_BLINDING_new / RSA_setup_blinding). */
    api.BN_set_flags(nc, BN_FLG_CONSTTIME_LOCAL);
    memset(buf, 0, sizeof(buf));
    buf[0] = 0x11;
    buf[255] = 0x03;
    if (api.BN_bin2bn(buf, (int)sizeof(buf), base) == NULL)
        goto out;
    mont = api.BN_MONT_CTX_new();
    if (mont == NULL || api.BN_MONT_CTX_set(mont, nc, ctx) != 1)
        goto out;

    s = malloc(sizeof(double) * (size_t)(iters > 0 ? iters : 1));
    if (s == NULL)
        goto out;

    if (strcmp(mode, "inverse-ct") == 0) {
        BIGNUM *inv = api.BN_mod_inverse(NULL, base, nc, ctx);
        if (inv == NULL)
            goto out;
        api.BN_free(inv);
        for (i = 0; i < iters; i++) {
            double t0 = now_ns();
            inv = api.BN_mod_inverse(NULL, base, nc, ctx);
            double t1 = now_ns();
            if (inv == NULL)
                goto out;
            api.BN_free(inv);
            s[i] = t1 - t0;
        }
        report("inverse-ct", s, iters);
        ok = 1;
    } else if (strcmp(mode, "exp-ct") == 0) {
        if (api.BN_mod_exp_mont(r, base, e, nc, ctx, mont) != 1)
            goto out;
        for (i = 0; i < iters; i++) {
            double t0 = now_ns();
            int rc = api.BN_mod_exp_mont(r, base, e, nc, ctx, mont);
            double t1 = now_ns();
            if (rc != 1)
                goto out;
            s[i] = t1 - t0;
        }
        report("exp-ct", s, iters);
        ok = 1;
    } else if (strcmp(mode, "rand") == 0) {
        if (api.BN_priv_rand_range_ex(base, nc, 0, ctx) != 1)
            goto out;
        for (i = 0; i < iters; i++) {
            double t0 = now_ns();
            int rc = api.BN_priv_rand_range_ex(base, nc, 0, ctx);
            double t1 = now_ns();
            if (rc != 1)
                goto out;
            s[i] = t1 - t0;
        }
        report("rand", s, iters);
        ok = 1;
    } else {
        fprintf(stderr, "pfp40: unknown mode %s\n", mode);
    }

out:
    free(s);
    if (mont != NULL)
        api.BN_MONT_CTX_free(mont);
    api.BN_free(r);
    api.BN_free(base);
    api.BN_free(nc);
    if (ctx != NULL)
        api.BN_CTX_free(ctx);
    free(der);
    if (rsa != NULL)
        api.RSA_free(rsa);
    printf("%s %s\n", ok ? "DONE" : "FAILED", mode != NULL ? mode : "-");
    return ok ? 0 : 1;
}
