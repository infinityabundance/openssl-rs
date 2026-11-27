/*
 * pfp7_rsa.c — PFP-7 stage-isolating RSA-2048 harness.
 *
 * One process, one library, selected at run time with --lib and opened with
 * dlopen(RTLD_NOW|RTLD_LOCAL), exactly as bench_pfp5.c does. No link-time
 * libcrypto dependency; the loaded DSO is printed with its realpath/dev/ino.
 *
 * Modes (all deterministic inputs; no BN_rand):
 *   priv-nopad N   N x RSA_private_encrypt(RSA_NO_PADDING)   steady state
 *   priv-pkcs1 N   N x RSA_private_encrypt(RSA_PKCS1_PADDING)
 *   dec-pkcs1 N    N x RSA_private_decrypt(RSA_PKCS1_PADDING) on a valid block
 *   dec-oaep N     N x RSA_private_decrypt(RSA_PKCS1_OAEP_PADDING)
 *   noblind N      RSA_blinding_off, then N x RSA_private_encrypt(NO_PADDING)
 *   half N         N x BN_mod_exp_mont_consttime on p, exponent dmp1 (one CRT half)
 *   vrfy N         N x BN_mod_exp_mont with e = 65537, modulus n (result check)
 *   inverse N      N x BN_mod_inverse mod n (blinding parameter construction)
 *
 * Each mode first performs one warm-up call (so the one-time blinding /
 * Montgomery-context construction is excluded from the timed loop), then times
 * N calls and prints one RESULT line with per-call nanoseconds: min, median,
 * mean. Latency is read from the N=1 form; throughput from the N-large form.
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

#define MAXSYM 64

typedef struct {
    void *h;
    RSA *(*d2i_RSAPrivateKey)(RSA **, const unsigned char **, long);
    void (*RSA_free)(RSA *);
    int (*RSA_size)(const RSA *);
    int (*RSA_private_encrypt)(int, const unsigned char *, unsigned char *, RSA *, int);
    int (*RSA_private_decrypt)(int, const unsigned char *, unsigned char *, RSA *, int);
    int (*RSA_public_encrypt)(int, const unsigned char *, unsigned char *, RSA *, int);
    void (*RSA_blinding_off)(RSA *);
    const BIGNUM *(*RSA_get0_n)(const RSA *);
    const BIGNUM *(*RSA_get0_e)(const RSA *);
    int (*RSA_get0_factors)(const RSA *, const BIGNUM **, const BIGNUM **);
    int (*RSA_get0_crt_params)(const RSA *, const BIGNUM **, const BIGNUM **, const BIGNUM **);

    BIGNUM *(*BN_new)(void);
    void (*BN_free)(BIGNUM *);
    BIGNUM *(*BN_dup)(const BIGNUM *);
    BIGNUM *(*BN_bin2bn)(const unsigned char *, int, BIGNUM *);
    BN_CTX *(*BN_CTX_new)(void);
    void (*BN_CTX_free)(BN_CTX *);
    int (*BN_mod_exp_mont_consttime)(BIGNUM *, const BIGNUM *, const BIGNUM *,
                                     const BIGNUM *, BN_CTX *, BN_MONT_CTX *);
    int (*BN_mod_exp_mont)(BIGNUM *, const BIGNUM *, const BIGNUM *,
                           const BIGNUM *, BN_CTX *, BN_MONT_CTX *);
    BIGNUM *(*BN_mod_inverse)(BIGNUM *, const BIGNUM *, const BIGNUM *, BN_CTX *);
} api_t;

static api_t api;

static void *need_sym(const char *name)
{
    void *p = dlsym(api.h, name);
    if (p == NULL) {
        fprintf(stderr, "pfp7: missing symbol %s: %s\n", name, dlerror());
        exit(2);
    }
    return p;
}

#define LOAD(field, name) do { *(void **)(&api.field) = need_sym(name); } while (0)

static void load_api(void)
{
    LOAD(d2i_RSAPrivateKey, "d2i_RSAPrivateKey");
    LOAD(RSA_free, "RSA_free");
    LOAD(RSA_size, "RSA_size");
    LOAD(RSA_private_encrypt, "RSA_private_encrypt");
    LOAD(RSA_private_decrypt, "RSA_private_decrypt");
    LOAD(RSA_public_encrypt, "RSA_public_encrypt");
    LOAD(RSA_blinding_off, "RSA_blinding_off");
    LOAD(RSA_get0_n, "RSA_get0_n");
    LOAD(RSA_get0_e, "RSA_get0_e");
    LOAD(RSA_get0_factors, "RSA_get0_factors");
    LOAD(RSA_get0_crt_params, "RSA_get0_crt_params");
    LOAD(BN_new, "BN_new");
    LOAD(BN_free, "BN_free");
    LOAD(BN_dup, "BN_dup");
    LOAD(BN_bin2bn, "BN_bin2bn");
    LOAD(BN_CTX_new, "BN_CTX_new");
    LOAD(BN_CTX_free, "BN_CTX_free");
    LOAD(BN_mod_exp_mont_consttime, "BN_mod_exp_mont_consttime");
    LOAD(BN_mod_exp_mont, "BN_mod_exp_mont");
    LOAD(BN_mod_inverse, "BN_mod_inverse");
}

static double now_ns(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec * 1e9 + (double)ts.tv_nsec;
}

static unsigned char *read_file(const char *path, long *len)
{
    FILE *f = fopen(path, "rb");
    unsigned char *buf;
    long n;
    if (f == NULL) {
        return NULL;
    }
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

static int cmp_double(const void *a, const void *b)
{
    double x = *(const double *)a, y = *(const double *)b;
    return (x > y) - (x < y);
}

static void report(const char *mode, double *s, int n)
{
    double *t = malloc(sizeof(double) * (size_t)n);
    int i;
    double sum = 0.0;
    memcpy(t, s, sizeof(double) * (size_t)n);
    qsort(t, (size_t)n, sizeof(double), cmp_double);
    for (i = 0; i < n; i++) {
        sum += s[i];
    }
    printf("RESULT %s n=%d min_ns=%.1f median_ns=%.1f mean_ns=%.1f\n",
           mode, n, t[0], t[n / 2], sum / (double)n);
    fflush(stdout);
    free(t);
}

/* Independent-ish private operations: successive calls share only the cached
 * blinding; the operand is fixed, so this is a saturated single-thread
 * throughput loop, not a latency chain. */
static int loop_priv(RSA *rsa, int iters, int padding, unsigned char *in,
                     unsigned char *out, int len)
{
    double *s = malloc(sizeof(double) * (size_t)(iters > 0 ? iters : 1));
    int i, rc = 0;
    int flen = (padding == RSA_NO_PADDING) ? len : 32;
    if (s == NULL) {
        return 0;
    }
    for (i = 0; i < iters; i++) {
        double t0 = now_ns();
        int r = api.RSA_private_encrypt(flen, in, out, rsa, padding);
        double t1 = now_ns();
        if (r != len) {
            fprintf(stderr, "pfp7: private_encrypt rc=%d\n", r);
            free(s);
            return 0;
        }
        s[i] = t1 - t0;
    }
    report(padding == RSA_NO_PADDING ? "priv-nopad" : "priv-pkcs1", s, iters);
    {
        /* Outlier census: the periodic blinding re-creation (BN_BLINDING_COUNTER
         * = 32) is visible as occasional multi-millisecond calls.  Print the
         * index of every call above twice the median, so the period is measured
         * rather than inferred. */
        double *t = malloc(sizeof(double) * (size_t)(iters > 0 ? iters : 1));
        int k, shown = 0, out = 0;
        if (t != NULL) {
            memcpy(t, s, sizeof(double) * (size_t)iters);
            qsort(t, (size_t)iters, sizeof(double), cmp_double);
            for (k = 0; k < iters; k++) {
                if (s[k] > 2.0 * t[iters / 2]) {
                    out++;
                    if (shown < 12) {
                        printf("OUTLIER i=%d ns=%.0f\n", k, s[k]);
                        shown++;
                    }
                }
            }
            printf("OUTLIER count=%d of %d\n", out, iters);
            if (iters >= 105) {
                /* The PFP-0/PFP-6 statistic: 5 warm-up calls, then the median of
                 * five 20-call batch means.  Reproduced here from the per-call
                 * samples so latency, throughput and the row statistic all come
                 * from one process. */
                double bm[5];
                for (int b = 0; b < 5; b++) {
                    double sum = 0.0;
                    for (int j = 5 + b * 20; j < 5 + (b + 1) * 20; j++) sum += s[j];
                    bm[b] = sum / 20.0;
                }
                for (int x = 1; x < 5; x++) {
                    for (int y = x; y > 0 && bm[y - 1] > bm[y]; y--) {
                        double t2 = bm[y]; bm[y] = bm[y - 1]; bm[y - 1] = t2;
                    }
                }
                printf("BLOCKMED ns=%.1f blocks=%.1f,%.1f,%.1f,%.1f,%.1f\n",
                       bm[2], bm[0], bm[1], bm[2], bm[3], bm[4]);
            }
            free(t);
        }
    }
    rc = 1;
    free(s);
    return rc;
}

static int loop_dec(RSA *rsa, int iters, int padding, unsigned char *ct,
                    unsigned char *pt, int len, const char *tag)
{
    double *s = malloc(sizeof(double) * (size_t)(iters > 0 ? iters : 1));
    int i;
    if (s == NULL) {
        return 0;
    }
    for (i = 0; i < iters; i++) {
        double t0 = now_ns();
        int r = api.RSA_private_decrypt(len, ct, pt, rsa, padding);
        double t1 = now_ns();
        if (r <= 0) {
            fprintf(stderr, "pfp7: private_decrypt rc=%d\n", r);
            free(s);
            return 0;
        }
        s[i] = t1 - t0;
    }
    report(tag, s, iters);
    free(s);
    return 1;
}

static void make_base(unsigned char *buf, int len, unsigned char tag)
{
    int i;
    memset(buf, 0, (size_t)len);
    buf[0] = tag; /* below 0x80, so the value is below 2^(8*len - 1) */
    for (i = 1; i < len; i++) {
        buf[i] = (unsigned char)(0x31 + (i * 29) % 200);
    }
}

static int loop_half(RSA *rsa, int iters)
{
    const BIGNUM *p = NULL, *q = NULL, *dmp1 = NULL, *dmq1 = NULL, *iqmp = NULL;
    BN_CTX *ctx = api.BN_CTX_new();
    BIGNUM *r = api.BN_new();
    BIGNUM *base = NULL;
    double *s = malloc(sizeof(double) * (size_t)(iters > 0 ? iters : 1));
    int i, ok = 0;
    unsigned char buf[128];

    api.RSA_get0_factors(rsa, &p, &q);
    api.RSA_get0_crt_params(rsa, &dmp1, &dmq1, &iqmp);
    if (p == NULL || dmp1 == NULL || ctx == NULL || r == NULL) {
        goto out;
    }
    base = api.BN_new();
    if (base == NULL) {
        goto out;
    }
    make_base(buf, (int)sizeof(buf), 0x6a);
    if (api.BN_bin2bn(buf, (int)sizeof(buf), base) == NULL) {
        goto out;
    }
    if (api.BN_mod_exp_mont_consttime(r, base, dmp1, p, ctx, NULL) != 1) {
        goto out;
    }
    for (i = 0; i < iters; i++) {
        double t0 = now_ns();
        int rc = api.BN_mod_exp_mont_consttime(r, base, dmp1, p, ctx, NULL);
        double t1 = now_ns();
        if (rc != 1) {
            goto out;
        }
        s[i] = t1 - t0;
    }
    report("half", s, iters);
    ok = 1;
out:
    free(s);
    api.BN_free(base);
    api.BN_free(r);
    if (ctx != NULL) {
        api.BN_CTX_free(ctx);
    }
    return ok;
}

static int loop_vrfy(RSA *rsa, int iters)
{
    const BIGNUM *n = api.RSA_get0_n(rsa), *e = api.RSA_get0_e(rsa);
    BN_CTX *ctx = api.BN_CTX_new();
    BIGNUM *r = api.BN_new();
    BIGNUM *base = api.BN_new();
    double *s = malloc(sizeof(double) * (size_t)(iters > 0 ? iters : 1));
    int i, ok = 0;
    unsigned char buf[256];

    if (n == NULL || e == NULL || ctx == NULL || r == NULL || base == NULL) {
        goto out;
    }
    make_base(buf, (int)sizeof(buf), 0x5c);
    if (api.BN_bin2bn(buf, (int)sizeof(buf), base) == NULL) {
        goto out;
    }
    if (api.BN_mod_exp_mont(r, base, e, n, ctx, NULL) != 1) {
        goto out;
    }
    for (i = 0; i < iters; i++) {
        double t0 = now_ns();
        int rc = api.BN_mod_exp_mont(r, base, e, n, ctx, NULL);
        double t1 = now_ns();
        if (rc != 1) {
            goto out;
        }
        s[i] = t1 - t0;
    }
    report("vrfy", s, iters);
    ok = 1;
out:
    free(s);
    api.BN_free(base);
    api.BN_free(r);
    if (ctx != NULL) {
        api.BN_CTX_free(ctx);
    }
    return ok;
}

static int loop_inverse(RSA *rsa, int iters)
{
    const BIGNUM *n = api.RSA_get0_n(rsa);
    BN_CTX *ctx = api.BN_CTX_new();
    BIGNUM *val = api.BN_new();
    double *s = malloc(sizeof(double) * (size_t)(iters > 0 ? iters : 1));
    int i, ok = 0;
    unsigned char buf[256];

    if (n == NULL || ctx == NULL || val == NULL) {
        goto out;
    }
    memset(buf, 0, sizeof(buf));
    buf[0] = 0x11;
    buf[255] = 0x03;
    api.BN_bin2bn(buf, (int)sizeof(buf), val);
    for (i = 0; i < iters; i++) {
        double t0 = now_ns();
        BIGNUM *inv = api.BN_mod_inverse(NULL, val, n, ctx);
        double t1 = now_ns();
        if (inv == NULL) {
            goto out;
        }
        api.BN_free(inv);
        s[i] = t1 - t0;
    }
    report("inverse", s, iters);
    ok = 1;
out:
    free(s);
    api.BN_free(val);
    if (ctx != NULL) {
        api.BN_CTX_free(ctx);
    }
    return ok;
}

int main(int argc, char **argv)
{
    const char *lib = NULL, *der_path = NULL, *mode = NULL;
    int iters = 1, i, ok = 0;
    long der_len = 0;
    unsigned char *der = NULL, *in = NULL, *out = NULL, *ct = NULL, *pt = NULL;
    const unsigned char *q;
    RSA *rsa = NULL;
    int len;

    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--lib") == 0 && i + 1 < argc) {
            lib = argv[++i];
        } else if (strcmp(argv[i], "--rsa-der") == 0 && i + 1 < argc) {
            der_path = argv[++i];
        } else if (strcmp(argv[i], "--mode") == 0 && i + 1 < argc) {
            mode = argv[++i];
        } else if (strcmp(argv[i], "--iters") == 0 && i + 1 < argc) {
            iters = atoi(argv[++i]);
        } else {
            fprintf(stderr, "usage: %s --lib <dso> --rsa-der <der> --mode <m> "
                    "[--iters N]\n", argv[0]);
            return 2;
        }
    }
    if (lib == NULL || der_path == NULL || mode == NULL) {
        fprintf(stderr, "pfp7: --lib, --rsa-der and --mode are required\n");
        return 2;
    }

    api.h = dlopen(lib, RTLD_NOW | RTLD_LOCAL);
    if (api.h == NULL) {
        fprintf(stderr, "pfp7: dlopen: %s\n", dlerror());
        return 2;
    }
    {
        Dl_info info;
        if (dladdr(need_sym("BN_new"), &info) != 0) {
            printf("LIB %s\n", info.dli_fname);
        }
    }
    load_api();

    der = read_file(der_path, &der_len);
    if (der == NULL) {
        fprintf(stderr, "pfp7: cannot read %s\n", der_path);
        goto out;
    }
    q = der;
    rsa = api.d2i_RSAPrivateKey(NULL, &q, der_len);
    if (rsa == NULL) {
        fprintf(stderr, "pfp7: d2i_RSAPrivateKey failed\n");
        goto out;
    }
    len = api.RSA_size(rsa);
    in = calloc(1, (size_t)len);
    out = malloc((size_t)len);
    ct = malloc((size_t)len);
    pt = malloc((size_t)len);
    if (in == NULL || out == NULL || ct == NULL || pt == NULL) {
        goto out;
    }
    /* Valid, deterministic inputs: 0x00 || 0x02 || non-zero pad || 0x00 || msg */
    in[0] = 0x00;
    in[1] = 0x02;
    for (i = 2; i < len - 16; i++) {
        in[i] = (unsigned char)(1 + (i * 7) % 255);
    }
    in[len - 17] = 0x00;
    for (i = len - 16; i < len; i++) {
        in[i] = (unsigned char)(0xa0 + (i % 32));
    }
    if (api.RSA_public_encrypt(16, in + len - 16, ct, rsa,
                               RSA_PKCS1_OAEP_PADDING) <= 0) {
        fprintf(stderr, "pfp7: public_encrypt failed\n");
        goto out;
    }

    if (strcmp(mode, "priv-nopad") == 0) {
        ok = loop_priv(rsa, iters, RSA_NO_PADDING, in, out, len);
    } else if (strcmp(mode, "priv-pkcs1") == 0) {
        ok = loop_priv(rsa, iters, RSA_PKCS1_PADDING, in, out, len);
    } else if (strcmp(mode, "dec-pkcs1") == 0) {
        ok = loop_dec(rsa, iters, RSA_PKCS1_PADDING, ct, pt, len, "dec-pkcs1");
    } else if (strcmp(mode, "dec-oaep") == 0) {
        ok = loop_dec(rsa, iters, RSA_PKCS1_OAEP_PADDING, ct, pt, len, "dec-oaep");
    } else if (strcmp(mode, "noblind") == 0) {
        api.RSA_blinding_off(rsa);
        ok = loop_priv(rsa, iters, RSA_NO_PADDING, in, out, len);
    } else if (strcmp(mode, "half") == 0) {
        ok = loop_half(rsa, iters);
    } else if (strcmp(mode, "vrfy") == 0) {
        ok = loop_vrfy(rsa, iters);
    } else if (strcmp(mode, "inverse") == 0) {
        ok = loop_inverse(rsa, iters);
    } else {
        fprintf(stderr, "pfp7: unknown mode %s\n", mode);
    }

out:
    free(der);
    free(in);
    free(out);
    free(ct);
    free(pt);
    if (rsa != NULL) {
        api.RSA_free(rsa);
    }
    printf("%s %s\n", ok ? "DONE" : "FAILED", mode != NULL ? mode : "-");
    return ok ? 0 : 1;
}
