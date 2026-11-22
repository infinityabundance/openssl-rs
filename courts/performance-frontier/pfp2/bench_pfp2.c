/*
 * bench_pfp2.c — PFP-2 end-to-end mutation control.
 *
 * Runs one workload through exactly one `libcrypto.so.3` per process, selected
 * at run time with `--lib <absolute path>` and opened with
 * `dlopen(RTLD_NOW | RTLD_LOCAL)`. The process prints the library it actually
 * mapped and the mapping's realpath, device, inode and size, so the runner can
 * refuse a stale or substituted artefact.
 *
 * Workloads (byte-identical inputs on both sides):
 *   ecdsa256   ECDSA_do_sign on P-256 with a fixed key
 *   p256-mul   EC_POINT_mul of the generator by a fixed scalar
 *
 * Timing: an unrecorded warm-up call, then `runs` timed batches of `iters`
 * calls. The printed figure is the median batch mean plus every sample. One
 * process is one independent repetition; operations inside a batch are not.
 *
 * This harness measures the end-to-end consequence of the field engine. It does
 * not measure field kernels directly; that is done in-process by
 * `ec::p256::tests::pfp2_kernel_measurement`.
 */

#define _GNU_SOURCE
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/obj_mac.h>

#include <dlfcn.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>

typedef struct {
    void *handle;
    EC_KEY *(*EC_KEY_new_by_curve_name)(int);
    void (*EC_KEY_free)(EC_KEY *);
    int (*EC_KEY_generate_key)(EC_KEY *);
    const EC_GROUP *(*EC_KEY_get0_group)(const EC_KEY *);
    ECDSA_SIG *(*ECDSA_do_sign)(const unsigned char *, int, EC_KEY *);
    void (*ECDSA_SIG_free)(ECDSA_SIG *);
    int (*ECDSA_do_verify)(const unsigned char *, int, const ECDSA_SIG *, EC_KEY *);
    EC_POINT *(*EC_POINT_new)(const EC_GROUP *);
    void (*EC_POINT_free)(EC_POINT *);
    int (*EC_POINT_mul)(const EC_GROUP *, EC_POINT *, const BIGNUM *,
                        const EC_POINT *, const BIGNUM *, BN_CTX *);
    BN_CTX *(*BN_CTX_new)(void);
    void (*BN_CTX_free)(BN_CTX *);
    BIGNUM *(*BN_bin2bn)(const unsigned char *, int, BIGNUM *);
    void (*BN_free)(BIGNUM *);
} api_t;

static void die(const char *what) {
    fprintf(stderr, "bench_pfp2: %s\n", what);
    exit(2);
}

static void *need(api_t *a, const char *name) {
    void *p = dlsym(a->handle, name);
    if (p == NULL) {
        fprintf(stderr, "bench_pfp2: missing symbol %s\n", name);
        exit(2);
    }
    return p;
}

static uint64_t now_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec;
}

static int cmp_double(const void *a, const void *b) {
    double x = *(const double *)a, y = *(const double *)b;
    return (x > y) - (x < y);
}

/* Print the loaded object's realpath, device, inode and size, and the number of
 * /proc/self/maps entries whose path is that realpath. The runner compares every
 * field with `stat(2)` on the on-disk DSO. */
static void report_loaded(api_t *a) {
    Dl_info info;
    if (dladdr((void *)a->EC_KEY_new_by_curve_name, &info) == 0 ||
        info.dli_fname == NULL) {
        printf("LOADED realpath=unknown\n");
        printf("MAPS entries=0\n");
        return;
    }
    char real[4096];
    const char *path = info.dli_fname;
    char *resolved = realpath(path, real);
    if (resolved != NULL) path = resolved;

    struct stat st;
    unsigned long long dev = 0, ino = 0, size = 0;
    if (stat(path, &st) == 0) {
        dev = (unsigned long long)st.st_dev;
        ino = (unsigned long long)st.st_ino;
        size = (unsigned long long)st.st_size;
    }

    int entries = 0;
    FILE *maps = fopen("/proc/self/maps", "r");
    if (maps != NULL) {
        char line[8192];
        while (fgets(line, sizeof line, maps) != NULL) {
            if (strstr(line, path) != NULL) entries++;
        }
        fclose(maps);
    }
    printf("LOADED realpath=%s dev=%llu ino=%llu size=%llu\n", path, dev, ino, size);
    printf("MAPS entries=%d\n", entries);
}

int main(int argc, char **argv) {
    const char *lib = NULL;
    int iters = 16, runs = 5;
    int mode_ecdsa = 1, mode_mul = 1;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--lib") == 0 && i + 1 < argc) {
            lib = argv[++i];
        } else if (strcmp(argv[i], "--iters") == 0 && i + 1 < argc) {
            iters = atoi(argv[++i]);
        } else if (strcmp(argv[i], "--runs") == 0 && i + 1 < argc) {
            runs = atoi(argv[++i]);
        } else if (strcmp(argv[i], "--ecdsa") == 0) {
            mode_ecdsa = 1;
            mode_mul = 0;
        } else if (strcmp(argv[i], "--mul") == 0) {
            mode_ecdsa = 0;
            mode_mul = 1;
        } else {
            fprintf(stderr,
                    "usage: %s --lib <libcrypto.so.3> [--iters N] [--runs R] [--ecdsa|--mul]\n",
                    argv[0]);
            return 2;
        }
    }
    if (lib == NULL) die("--lib is required");
    if (iters < 1 || runs < 1 || runs > 64) die("invalid iteration or run count");

    api_t a;
    memset(&a, 0, sizeof a);
    a.handle = dlopen(lib, RTLD_NOW | RTLD_LOCAL);
    if (a.handle == NULL) {
        fprintf(stderr, "bench_pfp2: dlopen: %s\n", dlerror());
        return 2;
    }
    a.EC_KEY_new_by_curve_name = need(&a, "EC_KEY_new_by_curve_name");
    a.EC_KEY_free = need(&a, "EC_KEY_free");
    a.EC_KEY_generate_key = need(&a, "EC_KEY_generate_key");
    a.EC_KEY_get0_group = need(&a, "EC_KEY_get0_group");
    a.ECDSA_do_sign = need(&a, "ECDSA_do_sign");
    a.ECDSA_SIG_free = need(&a, "ECDSA_SIG_free");
    a.ECDSA_do_verify = need(&a, "ECDSA_do_verify");
    a.EC_POINT_new = need(&a, "EC_POINT_new");
    a.EC_POINT_free = need(&a, "EC_POINT_free");
    a.EC_POINT_mul = need(&a, "EC_POINT_mul");
    a.BN_CTX_new = need(&a, "BN_CTX_new");
    a.BN_CTX_free = need(&a, "BN_CTX_free");
    a.BN_bin2bn = need(&a, "BN_bin2bn");
    a.BN_free = need(&a, "BN_free");

    printf("LIB %s\n", lib);
    report_loaded(&a);

    unsigned char dgst[32];
    for (int i = 0; i < 32; i++) dgst[i] = (unsigned char)(0x5a ^ i);

    EC_KEY *key = a.EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    if (key == NULL) die("P-256 key");
    if (a.EC_KEY_generate_key(key) != 1) die("key generation");
    const EC_GROUP *group = a.EC_KEY_get0_group(key);

    unsigned char scalar_bytes[32];
    for (int i = 0; i < 32; i++) scalar_bytes[i] = (unsigned char)(0x11 * (i + 1));
    BIGNUM *scalar = a.BN_bin2bn(scalar_bytes, 32, NULL);
    if (scalar == NULL) die("scalar");
    BN_CTX *ctx = a.BN_CTX_new();
    if (ctx == NULL) die("BN_CTX");
    EC_POINT *point = a.EC_POINT_new(group);
    if (point == NULL) die("point");

    if (mode_ecdsa) {
        ECDSA_SIG *sig = a.ECDSA_do_sign(dgst, 32, key);
        if (sig == NULL) die("ECDSA_do_sign");
        int ok = a.ECDSA_do_verify(dgst, 32, sig, key);
        a.ECDSA_SIG_free(sig);
        printf("CHECK ecdsa256 verify=%d\n", ok);
        if (ok != 1) die("the signature did not verify");

        double samples[64];
        for (int r = 0; r < runs; r++) {
            uint64_t start = now_ns();
            for (int i = 0; i < iters; i++) {
                ECDSA_SIG *s = a.ECDSA_do_sign(dgst, 32, key);
                if (s == NULL) die("ECDSA_do_sign in batch");
                a.ECDSA_SIG_free(s);
            }
            uint64_t end = now_ns();
            samples[r] = (double)(end - start) / (double)iters / 1000.0;
        }
        qsort(samples, (size_t)runs, sizeof(double), cmp_double);
        double med = samples[runs / 2];
        printf("RESULT ecdsa256\tmedian_us=%.3f\titers=%d\truns=%d\tsamples=", med, iters,
               runs);
        for (int r = 0; r < runs; r++) printf("%s%.3f", r ? "," : "", samples[r]);
        printf("\n");
    }

    if (mode_mul) {
        if (a.EC_POINT_mul(group, point, scalar, NULL, NULL, ctx) != 1) die("EC_POINT_mul");
        double samples[64];
        for (int r = 0; r < runs; r++) {
            uint64_t start = now_ns();
            for (int i = 0; i < iters; i++) {
                if (a.EC_POINT_mul(group, point, scalar, NULL, NULL, ctx) != 1) {
                    die("EC_POINT_mul in batch");
                }
            }
            uint64_t end = now_ns();
            samples[r] = (double)(end - start) / (double)iters / 1000.0;
        }
        qsort(samples, (size_t)runs, sizeof(double), cmp_double);
        double med = samples[runs / 2];
        printf("RESULT p256-mul\tmedian_us=%.3f\titers=%d\truns=%d\tsamples=", med, iters,
               runs);
        for (int r = 0; r < runs; r++) printf("%s%.3f", r ? "," : "", samples[r]);
        printf("\n");
        printf("CHECK p256-mul ok=1\n");
    }

    a.EC_POINT_free(point);
    a.BN_CTX_free(ctx);
    a.BN_free(scalar);
    a.EC_KEY_free(key);
    dlclose(a.handle);
    return 0;
}
