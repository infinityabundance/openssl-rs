/*
 * bench_p256.c — PFP-11 phase 2 P-256 control instrument.
 *
 * One OpenSSL-compatible libcrypto.so.3 per process. Times ECDSA_do_sign on
 * P-256 (NID 415) over a fixed 32-byte digest, verifying each signature so the
 * timed loop cannot silently measure a failing operation. Prints one RESULT
 * line: the median of `runs` internal timings.
 *
 * This exists only because the PFP-5 harness's single-workload path does not
 * include ecdsa256 and its population path would execute unrelated workloads.
 */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

typedef struct ecdsa_sig_st ECDSA_SIG;
typedef struct ec_key_st EC_KEY;

static void *h;

static EC_KEY *(*p_EC_KEY_new_by_curve_name)(int);
static void (*p_EC_KEY_free)(EC_KEY *);
static int (*p_EC_KEY_generate_key)(EC_KEY *);
static ECDSA_SIG *(*p_ECDSA_do_sign)(const unsigned char *, int, EC_KEY *);
static int (*p_ECDSA_do_verify)(const unsigned char *, int, const ECDSA_SIG *,
                                EC_KEY *);
static void (*p_ECDSA_SIG_free)(ECDSA_SIG *);

#define LOAD(var, name)                                                        \
    do {                                                                       \
        *(void **)(&var) = dlsym(h, name);                                     \
        if (var == NULL) {                                                     \
            fprintf(stderr, "missing %s\n", name);                             \
            return 2;                                                          \
        }                                                                      \
    } while (0)

static double now_us(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec * 1e6 + (double)ts.tv_nsec / 1e3;
}

static int cmp_double(const void *a, const void *b)
{
    double x = *(const double *)a, y = *(const double *)b;
    return (x > y) - (x < y);
}

int main(int argc, char **argv)
{
    const char *lib = NULL;
    int iters = 20, runs = 5, i, r;
    const int nid_p256 = 415; /* NID_X9_62_prime256v1 */
    unsigned char dgst[32];
    EC_KEY *key;
    double *s;
    int ok = 1;

    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--lib") == 0 && i + 1 < argc)
            lib = argv[++i];
        else if (strcmp(argv[i], "--iters") == 0 && i + 1 < argc)
            iters = atoi(argv[++i]);
        else if (strcmp(argv[i], "--runs") == 0 && i + 1 < argc)
            runs = atoi(argv[++i]);
        else {
            fprintf(stderr, "usage: %s --lib PATH [--iters N] [--runs N]\n",
                    argv[0]);
            return 2;
        }
    }
    if (lib == NULL)
        return 2;

    h = dlopen(lib, RTLD_NOW | RTLD_LOCAL);
    if (h == NULL) {
        fprintf(stderr, "dlopen: %s\n", dlerror());
        return 2;
    }
    LOAD(p_EC_KEY_new_by_curve_name, "EC_KEY_new_by_curve_name");
    LOAD(p_EC_KEY_free, "EC_KEY_free");
    LOAD(p_EC_KEY_generate_key, "EC_KEY_generate_key");
    LOAD(p_ECDSA_do_sign, "ECDSA_do_sign");
    LOAD(p_ECDSA_do_verify, "ECDSA_do_verify");
    LOAD(p_ECDSA_SIG_free, "ECDSA_SIG_free");

    for (i = 0; i < 32; i++)
        dgst[i] = (unsigned char)(i * 37 + 11);

    key = p_EC_KEY_new_by_curve_name(nid_p256);
    if (key == NULL || p_EC_KEY_generate_key(key) != 1)
        return 3;

    s = calloc((size_t)runs, sizeof(*s));
    if (s == NULL)
        return 3;

    for (r = 0; r < runs; r++) {
        double t0 = now_us(), t1;
        for (i = 0; i < iters; i++) {
            ECDSA_SIG *sig = p_ECDSA_do_sign(dgst, 32, key);
            if (sig == NULL) {
                ok = 0;
                break;
            }
            if (p_ECDSA_do_verify(dgst, 32, sig, key) != 1)
                ok = 0;
            p_ECDSA_SIG_free(sig);
        }
        t1 = now_us();
        if (!ok) {
            fprintf(stderr, "P-256 sign/verify failed\n");
            return 4;
        }
        s[r] = (t1 - t0) / (double)iters;
    }
    qsort(s, (size_t)runs, sizeof(*s), cmp_double);
    {
        double med = (runs % 2) ? s[runs / 2]
                                : (s[runs / 2 - 1] + s[runs / 2]) / 2.0;
        printf("RESULT ecdsa256 mode=prepared median_us=%.3f min_us=%.3f "
               "max_us=%.3f spread=%.4f iters=%d runs=%d\n",
               med, s[0], s[runs - 1], med > 0.0 ? (s[runs - 1] - s[0]) / med : 0.0,
               iters, runs);
    }
    free(s);
    p_EC_KEY_free(key);
    dlclose(h);
    return 0;
}
