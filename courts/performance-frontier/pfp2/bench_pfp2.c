/*
 * bench_pfp2.c — PFP-2 end-to-end comparison and mutation control.
 *
 * Runs one workload through exactly one `libcrypto.so.3` per process, selected
 * at run time with `--lib <absolute path>` and opened with
 * `dlopen(RTLD_NOW | RTLD_LOCAL)`. The process prints the library it actually
 * mapped and the mapping's realpath, device, inode and size, so the runner can
 * refuse a stale or substituted artefact.
 *
 * Workloads (byte-identical inputs on every side):
 *   ecdsa256   ECDSA_do_sign on P-256 with the PFP-0 fixed key and digest
 *   p256-mul   EC_POINT_mul of the generator by a fixed scalar
 *
 * The `ecdsa256` operand derivation, setup and CHECK line reproduce
 * `courts/phase18/timing/bench_api.c`: the private scalar is
 * `make_operand(0x45434400, top_clear, odd)` and the digest is
 * `make_operand(0x44494700, top_clear, even)`, so the PFP-0 `ecdsa256` ratio is
 * the comparator for this row.
 *
 * Timing: an unrecorded warm-up pass of `iters/4`, then `runs` timed batches of
 * `iters` calls. The printed figure is the median batch mean plus every sample.
 * One process is one independent repetition; operations inside a batch are not.
 *
 * Allocation counts: in `--alloc` mode the harness calls the weak
 * `allocprobe_reset`/`allocprobe_mallocs`/`allocprobe_alloc_calls` hooks exported
 * by alloc_probe.so (LD_PRELOAD), does one short batch, and reports both the
 * unified allocation-entry count and the legacy malloc-class count per call,
 * matching `bench_api.c`.
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

extern void allocprobe_reset(void) __attribute__((weak));
extern unsigned long allocprobe_mallocs(void) __attribute__((weak));
extern unsigned long allocprobe_alloc_calls(void) __attribute__((weak));

typedef struct {
    void *handle;
    EC_KEY *(*EC_KEY_new_by_curve_name)(int);
    void (*EC_KEY_free)(EC_KEY *);
    int (*EC_KEY_set_private_key)(EC_KEY *, const BIGNUM *);
    int (*EC_KEY_set_public_key)(EC_KEY *, const EC_POINT *);
    const EC_GROUP *(*EC_KEY_get0_group)(const EC_KEY *);
    ECDSA_SIG *(*ECDSA_do_sign)(const unsigned char *, int, EC_KEY *);
    void (*ECDSA_SIG_free)(ECDSA_SIG *);
    int (*ECDSA_do_verify)(const unsigned char *, int, const ECDSA_SIG *, EC_KEY *);
    EC_POINT *(*EC_POINT_new)(const EC_GROUP *);
    void (*EC_POINT_free)(EC_POINT *);
    int (*EC_POINT_mul)(const EC_GROUP *, EC_POINT *, const BIGNUM *,
                        const EC_POINT *, const BIGNUM *, BN_CTX *);
    size_t (*EC_POINT_point2oct)(const EC_GROUP *, const EC_POINT *,
                                 point_conversion_form_t, unsigned char *, size_t,
                                 BN_CTX *);
    BN_CTX *(*BN_CTX_new)(void);
    void (*BN_CTX_free)(BN_CTX *);
    BIGNUM *(*BN_bin2bn)(const unsigned char *, int, BIGNUM *);
    void (*BN_free)(BIGNUM *);
} api_t;

static api_t a;
static EC_KEY *eck;
static unsigned char ec_dgst[32];

static void die(const char *what) {
    fprintf(stderr, "bench_pfp2: %s\n", what);
    exit(2);
}

static void *need(void *handle, const char *name) {
    void *p = dlsym(handle, name);
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

/* The PFP-0 operand derivation, byte for byte. */
static void fill_seeded(uint64_t seed, unsigned char *p, size_t n) {
    uint64_t s = seed ? seed : UINT64_C(0x9e3779b97f4a7c15);
    size_t i;
    for (i = 0; i < n; i++) {
        s ^= s >> 12;
        s ^= s << 25;
        s ^= s >> 27;
        p[i] = (unsigned char)(s >> 56);
    }
}

static void make_operand(unsigned char *p, size_t n, uint64_t seed, int top_set,
                         int odd) {
    fill_seeded(seed, p, n);
    if (top_set)
        p[0] |= 0x80;
    else
        p[0] &= 0x7f;
    if (odd)
        p[n - 1] |= 1;
    else
        p[n - 1] &= 0xfe;
}

/* Print the loaded object's realpath, device, inode and size, and the number of
 * /proc/self/maps entries whose path is that realpath. The runner compares every
 * field with `stat(2)` on the on-disk DSO. */
static void report_loaded(void) {
    Dl_info info;
    if (dladdr((void *)a.EC_KEY_new_by_curve_name, &info) == 0 ||
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

static int ec_step(void) {
    ECDSA_SIG *s = a.ECDSA_do_sign(ec_dgst, (int)sizeof(ec_dgst), eck);
    if (s == NULL) return 0;
    a.ECDSA_SIG_free(s);
    return 1;
}

static int ec_setup(unsigned char *pubbuf, size_t *plen_out, EC_POINT **pub_out,
                    BIGNUM **priv_out, BN_CTX **ctx_out) {
    BIGNUM *priv = NULL;
    EC_POINT *pub = NULL;
    BN_CTX *ctx = NULL;
    const EC_GROUP *grp;
    unsigned char sb[32];
    size_t plen;

    eck = a.EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    if (eck == NULL) return 0;

    make_operand(sb, sizeof(sb), UINT64_C(0x45434400), 0, 1);
    priv = a.BN_bin2bn(sb, (int)sizeof(sb), NULL);
    if (priv == NULL || !a.EC_KEY_set_private_key(eck, priv)) goto fail;

    grp = a.EC_KEY_get0_group(eck);
    if (grp == NULL) goto fail;
    pub = a.EC_POINT_new(grp);
    ctx = a.BN_CTX_new();
    if (pub == NULL || ctx == NULL) goto fail;
    if (!a.EC_POINT_mul(grp, pub, priv, NULL, NULL, ctx)) goto fail;
    if (!a.EC_KEY_set_public_key(eck, pub)) goto fail;

    plen = a.EC_POINT_point2oct(grp, pub, POINT_CONVERSION_COMPRESSED, pubbuf, 65,
                                ctx);
    if (plen == 0) goto fail;

    *pub_out = pub;
    *priv_out = priv;
    *ctx_out = ctx;
    *plen_out = plen;
    return 1;

fail:
    if (priv) a.BN_free(priv);
    if (pub) a.EC_POINT_free(pub);
    if (ctx) a.BN_CTX_free(ctx);
    if (eck) a.EC_KEY_free(eck);
    eck = NULL;
    return 0;
}

static void ec_teardown(EC_POINT *pub, BIGNUM *priv, BN_CTX *ctx) {
    if (priv) a.BN_free(priv);
    if (pub) a.EC_POINT_free(pub);
    if (ctx) a.BN_CTX_free(ctx);
    if (eck) a.EC_KEY_free(eck);
    eck = NULL;
}

/* One timed batch mean plus every sample, in microseconds per call. */
static void timed(const char *name, int iters, int runs, int alloc_mode,
                  int (*step)(void)) {
    int warm = iters / 4;
    int i, r;
    if (warm < 1) warm = 1;
    for (i = 0; i < warm; i++)
        if (!step()) die("warm-up step failed");

    if (alloc_mode) {
        int probe = (allocprobe_reset != NULL && allocprobe_mallocs != NULL);
        if (probe) allocprobe_reset();
        for (i = 0; i < iters; i++)
            if (!step()) die("allocation step failed");
        if (probe) {
            unsigned long malloc_class = allocprobe_mallocs();
            unsigned long all_calls = (allocprobe_alloc_calls != NULL)
                                          ? allocprobe_alloc_calls()
                                          : malloc_class;
            printf("ALLOC %s allocs_per_op=%.3f malloc_per_op=%.3f iters=%d\n",
                   name, (double)all_calls / (double)iters,
                   (double)malloc_class / (double)iters, iters);
        } else {
            printf("ALLOC %s allocs_per_op=n/a malloc_per_op=n/a iters=%d\n",
                   name, iters);
        }
        fflush(stdout);
        return;
    }

    {
        double samples[64];
        for (r = 0; r < runs; r++) {
            uint64_t start = now_ns();
            for (i = 0; i < iters; i++)
                if (!step()) die("timed step failed");
            uint64_t end = now_ns();
            samples[r] = (double)(end - start) / (double)iters / 1000.0;
        }
        qsort(samples, (size_t)runs, sizeof(double), cmp_double);
        printf("RESULT %s\tmedian_us=%.3f\titers=%d\truns=%d\tsamples=", name,
               samples[runs / 2], iters, runs);
        for (r = 0; r < runs; r++) printf("%s%.3f", r ? "," : "", samples[r]);
        printf("\n");
    }
}

static unsigned char mul_scalar[32];
static const EC_GROUP *mul_group;
static EC_POINT *mul_point;
static BN_CTX *mul_ctx;
static BIGNUM *mul_bn;

static int mul_step(void) {
    return a.EC_POINT_mul(mul_group, mul_point, mul_bn, NULL, NULL, mul_ctx);
}

int main(int argc, char **argv) {
    const char *lib = NULL;
    int iters = 500, runs = 5, alloc_mode = 0;
    int mode_ecdsa = 1, mode_mul = 0;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--lib") == 0 && i + 1 < argc) {
            lib = argv[++i];
        } else if (strcmp(argv[i], "--iters") == 0 && i + 1 < argc) {
            iters = atoi(argv[++i]);
        } else if (strcmp(argv[i], "--runs") == 0 && i + 1 < argc) {
            runs = atoi(argv[++i]);
        } else if (strcmp(argv[i], "--alloc") == 0) {
            alloc_mode = 1;
        } else if (strcmp(argv[i], "--ecdsa") == 0) {
            mode_ecdsa = 1;
            mode_mul = 0;
        } else if (strcmp(argv[i], "--mul") == 0) {
            mode_ecdsa = 0;
            mode_mul = 1;
        } else {
            fprintf(stderr,
                    "usage: %s --lib <libcrypto.so.3> [--iters N] [--runs R] "
                    "[--alloc] [--ecdsa|--mul]\n",
                    argv[0]);
            return 2;
        }
    }
    if (lib == NULL) die("--lib is required");
    if (iters < 1 || runs < 1 || runs > 64) die("invalid iteration or run count");

    memset(&a, 0, sizeof a);
    a.handle = dlopen(lib, RTLD_NOW | RTLD_LOCAL);
    if (a.handle == NULL) {
        fprintf(stderr, "bench_pfp2: dlopen: %s\n", dlerror());
        return 2;
    }
#define LOAD(field, symbol) a.field = need(a.handle, symbol)
    LOAD(EC_KEY_new_by_curve_name, "EC_KEY_new_by_curve_name");
    LOAD(EC_KEY_free, "EC_KEY_free");
    LOAD(EC_KEY_set_private_key, "EC_KEY_set_private_key");
    LOAD(EC_KEY_set_public_key, "EC_KEY_set_public_key");
    LOAD(EC_KEY_get0_group, "EC_KEY_get0_group");
    LOAD(ECDSA_do_sign, "ECDSA_do_sign");
    LOAD(ECDSA_SIG_free, "ECDSA_SIG_free");
    LOAD(ECDSA_do_verify, "ECDSA_do_verify");
    LOAD(EC_POINT_new, "EC_POINT_new");
    LOAD(EC_POINT_free, "EC_POINT_free");
    LOAD(EC_POINT_mul, "EC_POINT_mul");
    LOAD(EC_POINT_point2oct, "EC_POINT_point2oct");
    LOAD(BN_CTX_new, "BN_CTX_new");
    LOAD(BN_CTX_free, "BN_CTX_free");
    LOAD(BN_bin2bn, "BN_bin2bn");
    LOAD(BN_free, "BN_free");
#undef LOAD

    printf("LIB %s\n", lib);
    report_loaded();

    if (mode_ecdsa) {
        unsigned char pubbuf[65];
        size_t plen, i;
        EC_POINT *pub = NULL;
        BIGNUM *priv = NULL;
        BN_CTX *ctx = NULL;

        if (!ec_setup(pubbuf, &plen, &pub, &priv, &ctx)) die("P-256 key setup");
        make_operand(ec_dgst, sizeof(ec_dgst), UINT64_C(0x44494700), 0, 0);

        ECDSA_SIG *s = a.ECDSA_do_sign(ec_dgst, (int)sizeof(ec_dgst), eck);
        if (s == NULL) die("ECDSA_do_sign");
        int ok = a.ECDSA_do_verify(ec_dgst, (int)sizeof(ec_dgst), s, eck);
        a.ECDSA_SIG_free(s);
        if (ok != 1) die("the signature did not verify");

        printf("CHECK ecdsa256 pub=");
        for (i = 0; i < plen; i++) printf("%02x", pubbuf[i]);
        printf(" verify=1\n");
        fflush(stdout);

        timed("ecdsa256", iters, runs, alloc_mode, ec_step);
        ec_teardown(pub, priv, ctx);
    }

    if (mode_mul) {
        unsigned char pubbuf[65];
        size_t plen;
        EC_POINT *pub = NULL;
        BIGNUM *priv = NULL;
        BN_CTX *ctx = NULL;

        if (!ec_setup(pubbuf, &plen, &pub, &priv, &ctx)) die("P-256 key setup");
        (void)plen;
        mul_group = a.EC_KEY_get0_group(eck);

        make_operand(mul_scalar, sizeof(mul_scalar), UINT64_C(0x5343414c), 0, 1);
        mul_bn = a.BN_bin2bn(mul_scalar, (int)sizeof(mul_scalar), NULL);
        mul_ctx = a.BN_CTX_new();
        mul_point = a.EC_POINT_new(mul_group);
        if (mul_bn == NULL || mul_ctx == NULL || mul_point == NULL) die("mul setup");
        if (!mul_step()) die("EC_POINT_mul");
        printf("CHECK p256-mul ok=1\n");
        fflush(stdout);

        timed("p256-mul", iters, runs, alloc_mode, mul_step);

        a.EC_POINT_free(mul_point);
        a.BN_CTX_free(mul_ctx);
        a.BN_free(mul_bn);
        ec_teardown(pub, priv, ctx);
    }

    dlclose(a.handle);
    return 0;
}
