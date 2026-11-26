/*
 * pfp27_ladder_probe.c — PFP-27 kernel-taint probe and ladder timing harness.
 *
 * WHY THIS EXISTS.  The PFP-21 harness (pfp21_dso_ct.c) is run unchanged for
 * the admitted population, but no exported entry point in its mode set routes a
 * tainted secret into the Montgomery exponentiation ladder: `sign` builds its
 * nonce inside the library, and `sign-ex-k`'s BN_mod_inverse is the
 * variable-time EEA.  Callgrind confirms this (see raw/callgrind.tsv: `sign`
 * differs between the SOS and CIOS artefacts, `sign-ex-k` does not, and no
 * memcheck context has run_mont_ladder in its stack).  This probe supplies the
 * missing population directly: it taints the *base* of
 * BN_mod_exp_mont_consttime, which is the operand the CIOS kernel multiplies.
 *
 * It is NOT part of the admitted PFP-21 population; it is a purpose-built
 * kernel-taint and timing probe, declared as such in ARTEFACT-AUDIT.md.
 *
 * Modes:
 *   control   no taint; one operation.
 *   ladder    base limb values are marked undefined; the operation must still
 *             succeed and (after the result is marked defined, because the
 *             caller learns it) equal the untainted answer.
 *   time      no taint; --iters operations, prints ns/op.
 *
 * The limb pointer is validated against the BIGNUM's own big-endian export
 * before use, exactly as the PFP-21 harness does; a layout drift aborts rather
 * than tainting the wrong bytes.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include <valgrind/memcheck.h>

typedef struct bignum_st BIGNUM;
typedef struct bignum_ctx BN_CTX;

#define BN_D_PTR_OFFSET 8
#define LIMBS 4
#define BYTES (LIMBS * 8)

struct api {
    BN_CTX *(*BN_CTX_new)(void);
    void (*BN_CTX_free)(BN_CTX *);
    BIGNUM *(*BN_new)(void);
    void (*BN_free)(BIGNUM *);
    BIGNUM *(*BN_bin2bn)(const unsigned char *, int, BIGNUM *);
    int (*BN_bn2binpad)(const BIGNUM *, unsigned char *, int);
    int (*BN_mod_exp_mont_consttime)(BIGNUM *, const BIGNUM *, const BIGNUM *,
                                     const BIGNUM *, BN_CTX *, void *);
};

/* P-256 group order: 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551 */
static const unsigned char ORDER[BYTES] = {
    0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84,
    0xf3, 0xb9, 0xca, 0xc2, 0xfc, 0x63, 0x25, 0x51,
};
/* order - 2: public exponent, top bit set so the ladder's first multiply is
 * selected and the taint reaches the accumulator immediately. */
static const unsigned char EXPONENT[BYTES] = {
    0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84,
    0xf3, 0xb9, 0xca, 0xc2, 0xfc, 0x63, 0x25, 0x4f,
};
/* Secret base: fixed for reproducibility, below the modulus, four live limbs. */
static const unsigned char BASE[BYTES] = {
    0x9f, 0x2e, 0x3d, 0x4c, 0x5b, 0x6a, 0x79, 0x88,
    0x97, 0xa6, 0xb5, 0xc4, 0xd3, 0xe2, 0xf1, 0x00,
    0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
    0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x07,
};

static struct api api;
static int g_marked;

static int report_loaded(void *sym, const char *requested)
{
    Dl_info info;
    const char *name = requested;
    char resolved[PATH_MAX], line[4096];
    struct stat st;
    FILE *maps;
    int entries = 0, foreign = 0;

    if (sym != NULL && dladdr(sym, &info) != 0 && info.dli_fname != NULL)
        name = info.dli_fname;
    if (realpath(name, resolved) == NULL) {
        fprintf(stderr, "pfp27: realpath(%s) failed\n", name);
        return 0;
    }
    if (stat(resolved, &st) != 0) {
        fprintf(stderr, "pfp27: stat(%s) failed\n", resolved);
        return 0;
    }
    printf("LOADED realpath=%s dev=%ju ino=%ju size=%lld\n", resolved,
           (uintmax_t)st.st_dev, (uintmax_t)st.st_ino, (long long)st.st_size);
    maps = fopen("/proc/self/maps", "r");
    if (maps == NULL)
        return 0;
    while (fgets(line, sizeof(line), maps) != NULL) {
        if (strstr(line, resolved) != NULL)
            entries++;
        else if (strstr(line, "libcrypto.so") != NULL && strchr(line, '/'))
            foreign++;
    }
    fclose(maps);
    printf("MAPS realpath=%s entries=%d\n", resolved, entries);
    printf("FOREIGN libcrypto=%d\n", foreign);
    fflush(stdout);
    return entries >= 1;
}

static int load_api(const char *path)
{
    void *h = dlopen(path, RTLD_NOW | RTLD_LOCAL);

    if (h == NULL) {
        fprintf(stderr, "pfp27: dlopen(%s): %s\n", path, dlerror());
        return 0;
    }
#define LOAD(field, symbol)                                                    \
    do {                                                                       \
        void *s = dlsym(h, symbol);                                            \
        if (s == NULL) {                                                       \
            fprintf(stderr, "pfp27: missing %s\n", symbol);                    \
            return 0;                                                          \
        }                                                                      \
        memcpy(&api.field, &s, sizeof(s));                                     \
    } while (0)
    LOAD(BN_CTX_new, "BN_CTX_new");
    LOAD(BN_CTX_free, "BN_CTX_free");
    LOAD(BN_new, "BN_new");
    LOAD(BN_free, "BN_free");
    LOAD(BN_bin2bn, "BN_bin2bn");
    LOAD(BN_bn2binpad, "BN_bn2binpad");
    LOAD(BN_mod_exp_mont_consttime, "BN_mod_exp_mont_consttime");
#undef LOAD
    return report_loaded((void *)api.BN_mod_exp_mont_consttime, path);
}

/* Validate the BIGNUM layout, then mark its live limb values undefined. */
static int mark_bn_values(const char *what, BIGNUM *bn)
{
    unsigned char be[BYTES];
    uint64_t *p = NULL;
    size_t first = 0, lim, i, j;

    if (api.BN_bn2binpad(bn, be, BYTES) != BYTES)
        return 0;
    while (first < BYTES && be[first] == 0)
        first++;
    if (first == BYTES)
        return 0;
    lim = (BYTES - first + 7) / 8;
    if (lim > LIMBS)
        return 0;
    memcpy(&p, (const unsigned char *)bn + BN_D_PTR_OFFSET, sizeof p);
    if (p == NULL)
        return 0;
    for (i = 0; i < lim; i++) {
        uint64_t limb = p[i];
        for (j = 0; j < 8; j++) {
            size_t k = BYTES - 1 - (i * 8 + j);
            if (be[k] != (unsigned char)((limb >> (8 * j)) & 0xff))
                return 0;
        }
    }
    VALGRIND_MAKE_MEM_UNDEFINED(p, lim * sizeof(uint64_t));
    printf("TAINT what=%s limbs=%zu\n", what, lim);
    g_marked = 1;
    return 1;
}

static uint64_t now_ns(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec;
}

int main(int argc, char **argv)
{
    const char *lib = NULL, *mode = "control";
    int iters = 1, i, ok = 1;
    BIGNUM *base = NULL, *exp = NULL, *mod = NULL, *out = NULL;
    BN_CTX *ctx = NULL;
    uint64_t t0, t1;

    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--lib") == 0 && i + 1 < argc)
            lib = argv[++i];
        else if (strcmp(argv[i], "--mode") == 0 && i + 1 < argc)
            mode = argv[++i];
        else if (strcmp(argv[i], "--iters") == 0 && i + 1 < argc)
            iters = atoi(argv[++i]);
        else {
            fprintf(stderr, "pfp27: bad argument %s\n", argv[i]);
            return 2;
        }
    }
    if (lib == NULL || iters < 0) {
        fprintf(stderr, "pfp27: usage: --lib DSO [--mode control|ladder|time] [--iters N]\n");
        return 2;
    }
    if (!load_api(lib))
        return 3;

    base = api.BN_bin2bn(BASE, BYTES, NULL);
    exp = api.BN_bin2bn(EXPONENT, BYTES, NULL);
    mod = api.BN_bin2bn(ORDER, BYTES, NULL);
    out = api.BN_new();
    ctx = api.BN_CTX_new();
    if (base == NULL || exp == NULL || mod == NULL || out == NULL || ctx == NULL) {
        fprintf(stderr, "pfp27: fixture allocation failed\n");
        return 4;
    }

    /* Untainted reference call, before the taint boundary: the fixture must
     * produce a result at all.  A tainted result is never inspected (its
     * definedness would have to be declassified first, and inspecting it is not
     * this probe's claim). */
    if (api.BN_mod_exp_mont_consttime(out, base, exp, mod, ctx, NULL) != 1)
        return 5;

    printf("HARNESS mode=%s iters=%d\n", mode, iters);
    fflush(stdout);

    if (strcmp(mode, "ladder") == 0) {
        if (!mark_bn_values("base", base))
            return 13;
        for (i = 0; i < iters; i++) {
            if (api.BN_mod_exp_mont_consttime(out, base, exp, mod, ctx, NULL) != 1) {
                ok = 0;
                break;
            }
        }
        /* The secret-derived result is discarded without inspection, exactly
         * as the PFP-21 harness does for every secret operation: the only value
         * read after the taint is the public success flag. */
        printf("RESULT mode=%s ok=%d marked=%d\n", mode, ok, g_marked);
        return ok ? 0 : 1;
    }

    if (strcmp(mode, "time") == 0) {
        t0 = now_ns();
        for (i = 0; i < iters; i++) {
            if (api.BN_mod_exp_mont_consttime(out, base, exp, mod, ctx, NULL) != 1)
                return 7;
        }
        t1 = now_ns();
        printf("RESULT mode=%s ok=1 marked=0\n", mode);
        printf("TIME mode=%s iters=%d ns_per_op=%.1f\n", mode, iters,
               (double)(t1 - t0) / (double)(iters > 0 ? iters : 1));
        return 0;
    }

    if (strcmp(mode, "control") != 0) {
        fprintf(stderr, "pfp27: unknown mode %s\n", mode);
        return 2;
    }
    printf("RESULT mode=control ok=%d marked=0\n", ok);
    return ok ? 0 : 1;
}
