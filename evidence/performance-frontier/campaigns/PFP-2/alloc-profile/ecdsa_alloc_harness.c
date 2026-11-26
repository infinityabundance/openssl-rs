/*
 * ecdsa_alloc_harness.c — allocation-site profile of one P-256 signing
 * measurement unit, for PFP-24.
 *
 * This is a **new** harness, not a modification of `courts/phase18/timing/
 * bench_api.c` (`e1add483…`), whose identity the PFP-2 timing record binds. The
 * operand construction, the key, the digest and the measured step are
 * transcribed from it so the allocations attributed here are the ones the
 * timing/allocation instrument counts:
 *
 *   - private scalar: xorshift64 seed 0x45434400, top bit clear, odd;
 *   - digest:         xorshift64 seed 0x44494700, top bit clear, even;
 *   - public key derived through the library under test by EC_POINT_mul;
 *   - measured step:  ECDSA_do_sign(dgst, 32, eck) + ECDSA_SIG_free().
 *
 * `--sign-ops 0` performs setup + one verify + the CHECK line and no signing
 * operation. `--sign-ops N` then repeats the measured step N times. Running the
 * same binary under two N and differencing the DHAT program-point trees
 * attributes allocations to the signing path by stack, not by guess.
 *
 * The LOADED/MAPS lines are the same identity observables the timing runner
 * checks, so a profile row can be tied to a DSO digest.
 *
 * Build:
 *   cc -O2 -g -Wall -Wextra ecdsa_alloc_harness.c -ldl -lm -o ecdsa_alloc_harness
 */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <inttypes.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>

typedef struct {
    void *(*EC_KEY_new_by_curve_name)(int);
    void (*EC_KEY_free)(void *);
    const void *(*EC_KEY_get0_group)(const void *);
    int (*EC_KEY_set_private_key)(void *, const void *);
    int (*EC_KEY_set_public_key)(void *, const void *);
    void *(*EC_POINT_new)(const void *);
    void (*EC_POINT_free)(void *);
    int (*EC_POINT_mul)(const void *, void *, const void *, const void *,
                        const void *, void *);
    size_t (*EC_POINT_point2oct)(const void *, const void *, int, unsigned char *,
                                 size_t, void *);
    void *(*BN_bin2bn)(const unsigned char *, int, void *);
    void (*BN_free)(void *);
    void *(*BN_CTX_new)(void);
    void (*BN_CTX_free)(void *);
    void *(*ECDSA_do_sign)(const unsigned char *, int, void *);
    int (*ECDSA_do_verify)(const unsigned char *, int, const void *, void *);
    void (*ECDSA_SIG_free)(void *);
    int (*ECDSA_size)(const void *);
} api_t;

static api_t api;
static void *ecal;

/*
 * The measured-step allocation counters, exactly as `bench_api.c` reaches them:
 * weak, served by `alloc_probe.so` under LD_PRELOAD and absent otherwise.
 */
extern void allocprobe_reset(void) __attribute__((weak));
extern unsigned long allocprobe_mallocs(void) __attribute__((weak));
extern unsigned long allocprobe_alloc_calls(void) __attribute__((weak));

static void fill_seeded(uint64_t seed, unsigned char *p, size_t n)
{
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
                         int odd)
{
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

static int report_loaded(void *sym, const char *requested)
{
    Dl_info info;
    const char *name = requested;
    char resolved[PATH_MAX];
    struct stat st;
    FILE *maps;
    char line[4096];
    int entries = 0;

    if (sym != NULL && dladdr(sym, &info) != 0 && info.dli_fname != NULL)
        name = info.dli_fname;
    if (realpath(name, resolved) == NULL) {
        fprintf(stderr, "harness: realpath(%s) failed\n", name);
        return 0;
    }
    if (stat(resolved, &st) != 0) {
        fprintf(stderr, "harness: stat(%s) failed\n", resolved);
        return 0;
    }
    printf("LOADED realpath=%s dev=%ju ino=%ju size=%lld\n", resolved,
           (uintmax_t)st.st_dev, (uintmax_t)st.st_ino, (long long)st.st_size);

    maps = fopen("/proc/self/maps", "r");
    if (maps == NULL) {
        fprintf(stderr, "harness: cannot read /proc/self/maps\n");
        return 0;
    }
    while (fgets(line, sizeof(line), maps) != NULL) {
        if (strstr(line, resolved) != NULL)
            entries++;
    }
    fclose(maps);
    printf("MAPS realpath=%s entries=%d\n", resolved, entries);
    fflush(stdout);
    if (entries < 1) {
        fprintf(stderr, "harness: %s is not present in /proc/self/maps\n",
                resolved);
        return 0;
    }
    return 1;
}

static int load_api(const char *path)
{
    void *h = dlopen(path, RTLD_NOW | RTLD_LOCAL);

    if (h == NULL) {
        fprintf(stderr, "harness: dlopen(%s): %s\n", path, dlerror());
        return 0;
    }
    ecal = h;
#define LOAD(field, symbol)                                                    \
    do {                                                                       \
        void *s = dlsym(h, symbol);                                            \
        if (s == NULL) {                                                       \
            fprintf(stderr, "harness: missing %s\n", symbol);                  \
            return 0;                                                          \
        }                                                                      \
        memcpy(&api.field, &s, sizeof(s));                                     \
    } while (0)

    LOAD(EC_KEY_new_by_curve_name, "EC_KEY_new_by_curve_name");
    LOAD(EC_KEY_free, "EC_KEY_free");
    LOAD(EC_KEY_get0_group, "EC_KEY_get0_group");
    LOAD(EC_KEY_set_private_key, "EC_KEY_set_private_key");
    LOAD(EC_KEY_set_public_key, "EC_KEY_set_public_key");
    LOAD(EC_POINT_new, "EC_POINT_new");
    LOAD(EC_POINT_free, "EC_POINT_free");
    LOAD(EC_POINT_mul, "EC_POINT_mul");
    LOAD(EC_POINT_point2oct, "EC_POINT_point2oct");
    LOAD(BN_bin2bn, "BN_bin2bn");
    LOAD(BN_free, "BN_free");
    LOAD(BN_CTX_new, "BN_CTX_new");
    LOAD(BN_CTX_free, "BN_CTX_free");
    LOAD(ECDSA_do_sign, "ECDSA_do_sign");
    LOAD(ECDSA_do_verify, "ECDSA_do_verify");
    LOAD(ECDSA_SIG_free, "ECDSA_SIG_free");
    LOAD(ECDSA_size, "ECDSA_size");
#undef LOAD

    {
        void *sym = NULL;
        Dl_info info;

        memcpy(&sym, &api.EC_KEY_new_by_curve_name, sizeof(sym));
        if (sym != NULL && dladdr(sym, &info) != 0 && info.dli_fname != NULL)
            printf("LIB %s\n", info.dli_fname);
        else
            printf("LIB %s\n", path);
        fflush(stdout);
        if (!report_loaded(sym, path))
            return 0;
    }
    return 1;
}

int main(int argc, char **argv)
{
    const char *lib = NULL;
    int sign_ops = -1;
    int verify = 1;
    int alloc_count = 0;
    void *eck = NULL, *priv = NULL, *pub = NULL, *ctx = NULL;
    const void *grp;
    unsigned char sb[32], pubbuf[65];
    size_t plen, i;
    int ok = 0, n;

    for (i = 1; i < (size_t)argc; i++) {
        if (strcmp(argv[i], "--lib") == 0 && i + 1 < (size_t)argc)
            lib = argv[++i];
        else if (strcmp(argv[i], "--sign-ops") == 0 && i + 1 < (size_t)argc)
            sign_ops = atoi(argv[++i]);
        else if (strcmp(argv[i], "--no-verify") == 0)
            verify = 0;
        else if (strcmp(argv[i], "--alloc-count") == 0)
            alloc_count = 1;
        else {
            fprintf(stderr,
                    "usage: %s --lib <libcrypto.so.3> --sign-ops <N> "
                    "[--no-verify]\n",
                    argv[0]);
            return 2;
        }
    }
    if (lib == NULL || sign_ops < 0) {
        fprintf(stderr, "harness: --lib and --sign-ops are required\n");
        return 2;
    }
    if (!load_api(lib))
        return 2;

    /* --- key construction, exactly as bench_api's ecdsa_setup ------------- */
    eck = api.EC_KEY_new_by_curve_name(415 /* NID_X9_62_prime256v1 */);
    if (eck == NULL)
        goto out;

    make_operand(sb, sizeof(sb), UINT64_C(0x45434400), 0, 1);
    priv = api.BN_bin2bn(sb, (int)sizeof(sb), NULL);
    if (priv == NULL || !api.EC_KEY_set_private_key(eck, priv))
        goto out;

    grp = api.EC_KEY_get0_group(eck);
    if (grp == NULL)
        goto out;
    pub = api.EC_POINT_new(grp);
    ctx = api.BN_CTX_new();
    if (pub == NULL || ctx == NULL)
        goto out;
    if (!api.EC_POINT_mul(grp, pub, priv, NULL, NULL, ctx))
        goto out;
    if (!api.EC_KEY_set_public_key(eck, pub))
        goto out;

    plen = api.EC_POINT_point2oct(grp, pub, 2 /* COMPRESSED */, pubbuf, 65, ctx);
    if (plen == 0)
        goto out;

    /* --- the CHECK observable, and one verify, as in run_ecdsa ------------ */
    {
        unsigned char dgst[32];
        void *sig;

        make_operand(dgst, sizeof(dgst), UINT64_C(0x44494700), 0, 0);
        sig = api.ECDSA_do_sign(dgst, (int)sizeof(dgst), eck);
        if (sig == NULL) {
            fprintf(stderr, "harness: ECDSA_do_sign failed\n");
            goto out;
        }
        if (verify &&
            api.ECDSA_do_verify(dgst, (int)sizeof(dgst), sig, eck) != 1) {
            fprintf(stderr, "harness: ECDSA_do_verify failed\n");
            api.ECDSA_SIG_free(sig);
            goto out;
        }
        printf("CHECK ecdsa256 pub=");
        for (i = 0; i < plen; i++)
            printf("%02x", pubbuf[i]);
        printf(" verify=%d\n", verify ? 1 : 0);
        fflush(stdout);
        api.ECDSA_SIG_free(sig);
    }

    /* --- the measured step, N times -------------------------------------- */
    {
        int probe = (allocprobe_reset != NULL && allocprobe_mallocs != NULL);

        if (alloc_count && probe)
            allocprobe_reset();
        for (n = 0; n < sign_ops; n++) {
            unsigned char dgst[32];
            void *sig;

            make_operand(dgst, sizeof(dgst), UINT64_C(0x44494700), 0, 0);
            sig = api.ECDSA_do_sign(dgst, (int)sizeof(dgst), eck);
            if (sig == NULL) {
                fprintf(stderr, "harness: sign %d failed\n", n);
                goto out;
            }
            api.ECDSA_SIG_free(sig);
        }
        if (alloc_count) {
            if (probe) {
                unsigned long all = (allocprobe_alloc_calls != NULL)
                                        ? allocprobe_alloc_calls()
                                        : allocprobe_mallocs();

                printf("ALLOC ecdsa256 allocs_per_op=%.3f malloc_per_op=%.3f "
                       "iters=%d\n",
                       (double)all / (double)sign_ops,
                       (double)allocprobe_mallocs() / (double)sign_ops,
                       sign_ops);
            } else {
                printf("ALLOC ecdsa256 allocs_per_op=n/a iters=%d\n", sign_ops);
            }
        }
    }
    printf("SIGN_OPS %d\n", sign_ops);
    fflush(stdout);
    ok = 1;

out:
    if (ctx)
        api.BN_CTX_free(ctx);
    if (pub)
        api.EC_POINT_free(pub);
    if (priv)
        api.BN_free(priv);
    if (eck)
        api.EC_KEY_free(eck);
    if (ok && ecal)
        dlclose(ecal);
    return ok ? 0 : 1;
}
