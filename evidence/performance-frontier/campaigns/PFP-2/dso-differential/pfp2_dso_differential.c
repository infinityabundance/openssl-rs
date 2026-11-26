/*
 * pfp2_dso_differential.c — DSO-bound differential court for PFP-2.
 *
 * One process loads exactly one libcrypto.so.3 with
 * dlopen(RTLD_NOW | RTLD_LOCAL) and calls only its exported, ABI-visible
 * entry points.  It prints:
 *
 *   LIB    <file that served BN_new, from dladdr>
 *   LOADED realpath=<path> dev=<dev> ino=<ino> size=<size>
 *   MAPS   realpath=<path> entries=<n>
 *
 * so the runner can prove the process mapped the intended on-disk DSO by
 * comparing the reported realpath/dev/ino/size with stat(2).  This is the
 * loader pattern of courts/phase18/timing/bench_api.c.
 *
 * Modes (all deterministic from --seed):
 *
 *   mul-g   N cases of k*G, serialised as an uncompressed P-256 point
 *   mul-p   N cases of k*P with P = j*G (variable base)
 *   sign    N ECDSA signatures over deterministic 32-byte digests, written DER
 *           into one file as [u32 big-endian length][DER] records
 *   verify  N ECDSA verifications of the records written by another process
 *
 * The harness links no libcrypto.  The k*G operation shape is the one the
 * campaign's ctgrind harness (minimal_mul.c) uses, widened to a fixed
 * population.  Internal field operations (p256::mont_reduce_into,
 * p256::wide_mul_x86, bn::limbs::normalise) have no exported entry point and
 * are therefore exercised only through this public path; the record says so.
 */

#define _GNU_SOURCE
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/obj_mac.h>

#include <dlfcn.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

typedef struct {
    BIGNUM *(*BN_new)(void);
    void (*BN_free)(BIGNUM *);
    BIGNUM *(*BN_bin2bn)(const unsigned char *, int, BIGNUM *);
    BN_CTX *(*BN_CTX_new)(void);
    void (*BN_CTX_free)(BN_CTX *);

    EC_GROUP *(*EC_GROUP_new_by_curve_name)(int);
    void (*EC_GROUP_free)(EC_GROUP *);
    const EC_POINT *(*EC_GROUP_get0_generator)(const EC_GROUP *);
    EC_POINT *(*EC_POINT_new)(const EC_GROUP *);
    void (*EC_POINT_free)(EC_POINT *);
    int (*EC_POINT_mul)(const EC_GROUP *, EC_POINT *, const BIGNUM *,
                        const EC_POINT *, const BIGNUM *, BN_CTX *);
    size_t (*EC_POINT_point2oct)(const EC_GROUP *, const EC_POINT *,
                                 point_conversion_form_t, unsigned char *,
                                 size_t, BN_CTX *);

    EC_KEY *(*EC_KEY_new_by_curve_name)(int);
    void (*EC_KEY_free)(EC_KEY *);
    const EC_GROUP *(*EC_KEY_get0_group)(const EC_KEY *);
    int (*EC_KEY_set_private_key)(EC_KEY *, const BIGNUM *);
    int (*EC_KEY_set_public_key)(EC_KEY *, const EC_POINT *);
    ECDSA_SIG *(*ECDSA_do_sign)(const unsigned char *, int, EC_KEY *);
    int (*ECDSA_do_verify)(const unsigned char *, int, const ECDSA_SIG *,
                           EC_KEY *);
    void (*ECDSA_SIG_free)(ECDSA_SIG *);
    int (*i2d_ECDSA_SIG)(const ECDSA_SIG *, unsigned char **);
    ECDSA_SIG *(*d2i_ECDSA_SIG)(ECDSA_SIG **, const unsigned char **, long);
} api_t;

static api_t api;

/* Domain tags keep each deterministic stream independent. */
#define DOMAIN_G      UINT64_C(0x503246474d554c31)
#define DOMAIN_BASE   UINT64_C(0x5032464742415331)
#define DOMAIN_SCALAR UINT64_C(0x5032464753434c31)
#define DOMAIN_KEY    UINT64_C(0x503246474b455931)
#define DOMAIN_MSG    UINT64_C(0x503246474d534731)

#define POINT_LEN 65

static uint64_t splitmix_at(uint64_t x)
{
    uint64_t z = x + UINT64_C(0x9e3779b97f4a7c15);

    z = (z ^ (z >> 30)) * UINT64_C(0xbf58476d1ce4e5b9);
    z = (z ^ (z >> 27)) * UINT64_C(0x94d049bb133111eb);
    return z ^ (z >> 31);
}

/* Deterministic 32 bytes for (seed, domain, index). */
static void bytes_for(uint64_t seed, uint64_t domain, unsigned index,
                      unsigned char out[32])
{
    uint64_t base = seed ^ domain ^ ((uint64_t)index * UINT64_C(0x9e3779b97f4a7c15));
    int i;

    for (i = 0; i < 4; i++) {
        uint64_t word = splitmix_at(base + (uint64_t)i * UINT64_C(0xd1b54a32d192ed03));
        memcpy(out + i * 8, &word, sizeof word);
    }
}

/*
 * A scalar in [1, 2^255).  n is about 1.16e77 > 2^255, so every value is a
 * valid P-256 scalar and, being non-zero, no multiple is the point at
 * infinity.  The top bit is cleared and the low bit set on the big-endian
 * encoding so the bound and non-zero property are explicit, not incidental.
 */
static void scalar_for(uint64_t seed, uint64_t domain, unsigned index,
                       unsigned char out[32])
{
    bytes_for(seed, domain, index, out);
    out[0] &= 0x7f;
    out[31] |= 0x01;
}

static void print_hex(const unsigned char *p, size_t n)
{
    size_t i;

    for (i = 0; i < n; i++)
        printf("%02x", p[i]);
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
        fprintf(stderr, "pfp2_dso_differential: realpath(%s) failed\n", name);
        return 0;
    }
    if (stat(resolved, &st) != 0) {
        fprintf(stderr, "pfp2_dso_differential: stat(%s) failed\n", resolved);
        return 0;
    }
    printf("LOADED realpath=%s dev=%ju ino=%ju size=%lld\n", resolved,
           (uintmax_t)st.st_dev, (uintmax_t)st.st_ino, (long long)st.st_size);

    maps = fopen("/proc/self/maps", "r");
    if (maps == NULL) {
        fprintf(stderr, "pfp2_dso_differential: cannot read /proc/self/maps\n");
        return 0;
    }
    while (fgets(line, sizeof line, maps) != NULL) {
        if (strstr(line, resolved) != NULL)
            entries++;
    }
    fclose(maps);
    printf("MAPS realpath=%s entries=%d\n", resolved, entries);
    fflush(stdout);
    return entries >= 1;
}

static int load_api(const char *path)
{
    void *h = dlopen(path, RTLD_NOW | RTLD_LOCAL);

    if (h == NULL) {
        fprintf(stderr, "pfp2_dso_differential: dlopen(%s): %s\n", path,
                dlerror());
        return 0;
    }
#define LOAD(field, symbol)                                                    \
    do {                                                                       \
        void *s = dlsym(h, symbol);                                            \
        if (s == NULL) {                                                       \
            fprintf(stderr, "pfp2_dso_differential: missing %s\n", symbol);    \
            return 0;                                                          \
        }                                                                      \
        memcpy(&api.field, &s, sizeof s);                                      \
    } while (0)

    LOAD(BN_new, "BN_new");
    LOAD(BN_free, "BN_free");
    LOAD(BN_bin2bn, "BN_bin2bn");
    LOAD(BN_CTX_new, "BN_CTX_new");
    LOAD(BN_CTX_free, "BN_CTX_free");

    LOAD(EC_GROUP_new_by_curve_name, "EC_GROUP_new_by_curve_name");
    LOAD(EC_GROUP_free, "EC_GROUP_free");
    LOAD(EC_GROUP_get0_generator, "EC_GROUP_get0_generator");
    LOAD(EC_POINT_new, "EC_POINT_new");
    LOAD(EC_POINT_free, "EC_POINT_free");
    LOAD(EC_POINT_mul, "EC_POINT_mul");
    LOAD(EC_POINT_point2oct, "EC_POINT_point2oct");

    LOAD(EC_KEY_new_by_curve_name, "EC_KEY_new_by_curve_name");
    LOAD(EC_KEY_free, "EC_KEY_free");
    LOAD(EC_KEY_get0_group, "EC_KEY_get0_group");
    LOAD(EC_KEY_set_private_key, "EC_KEY_set_private_key");
    LOAD(EC_KEY_set_public_key, "EC_KEY_set_public_key");
    LOAD(ECDSA_do_sign, "ECDSA_do_sign");
    LOAD(ECDSA_do_verify, "ECDSA_do_verify");
    LOAD(ECDSA_SIG_free, "ECDSA_SIG_free");
    LOAD(i2d_ECDSA_SIG, "i2d_ECDSA_SIG");
    LOAD(d2i_ECDSA_SIG, "d2i_ECDSA_SIG");
#undef LOAD

    {
        void *sym = NULL;
        Dl_info info;

        memcpy(&sym, &api.BN_new, sizeof sym);
        if (sym != NULL && dladdr(sym, &info) != 0 && info.dli_fname != NULL)
            printf("LIB %s\n", info.dli_fname);
        else
            printf("LIB %s\n", path);
        if (!report_loaded(sym, path))
            return 0;
    }
    return 1;
}

static int serialize(const EC_GROUP *group, const EC_POINT *point, BN_CTX *ctx,
                     unsigned char out[POINT_LEN])
{
    size_t n = api.EC_POINT_point2oct(group, point, POINT_CONVERSION_UNCOMPRESSED,
                                      out, POINT_LEN, ctx);

    return n == POINT_LEN;
}

static int run_mul(uint64_t seed, unsigned count, int variable_base)
{
    EC_GROUP *group = api.EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
    BN_CTX *ctx = api.BN_CTX_new();
    const EC_POINT *gen = NULL;
    EC_POINT *r = NULL, *q = NULL;
    BIGNUM *k = NULL, *j = NULL;
    unsigned char kb[32], jb[32], pubbuf[POINT_LEN];
    unsigned i;
    int ok = 0;

    if (group == NULL || ctx == NULL)
        goto out;
    gen = api.EC_GROUP_get0_generator(group);
    r = api.EC_POINT_new(group);
    if (gen == NULL || r == NULL)
        goto out;
    if (variable_base) {
        q = api.EC_POINT_new(group);
        if (q == NULL)
            goto out;
    }
    k = api.BN_new();
    j = api.BN_new();
    if (k == NULL || (variable_base && j == NULL))
        goto out;

    for (i = 0; i < count; i++) {
        scalar_for(seed, DOMAIN_SCALAR, i, kb);
        if (api.BN_bin2bn(kb, (int)sizeof kb, k) == NULL)
            goto out;
        if (variable_base) {
            scalar_for(seed, DOMAIN_BASE, i, jb);
            if (api.BN_bin2bn(jb, (int)sizeof jb, j) == NULL)
                goto out;
            if (api.EC_POINT_mul(group, q, j, NULL, NULL, ctx) != 1)
                goto out;
            if (api.EC_POINT_mul(group, r, NULL, q, k, ctx) != 1)
                goto out;
        } else {
            if (api.EC_POINT_mul(group, r, k, NULL, NULL, ctx) != 1)
                goto out;
        }
        if (!serialize(group, r, ctx, pubbuf))
            goto out;
        if (variable_base) {
            printf("POINT i=%u j=", i);
            print_hex(jb, sizeof jb);
            printf(" k=");
            print_hex(kb, sizeof kb);
            printf(" point=");
        } else {
            printf("POINT i=%u k=", i);
            print_hex(kb, sizeof kb);
            printf(" point=");
        }
        print_hex(pubbuf, sizeof pubbuf);
        printf("\n");
    }
    ok = 1;
out:
    api.BN_free(k);
    api.BN_free(j);
    api.EC_POINT_free(r);
    api.EC_POINT_free(q);
    api.EC_GROUP_free(group);
    api.BN_CTX_free(ctx);
    return ok;
}

typedef struct {
    EC_KEY *key;
    unsigned char pub[POINT_LEN];
} derived_key;

static int derive_key(uint64_t seed, derived_key *out)
{
    EC_KEY *key = NULL;
    EC_POINT *pub = NULL;
    BN_CTX *ctx = NULL;
    BIGNUM *d = NULL;
    const EC_GROUP *group;
    unsigned char kb[32];
    int ok = 0;

    key = api.EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    if (key == NULL)
        goto done;
    group = api.EC_KEY_get0_group(key);
    pub = api.EC_POINT_new(group);
    ctx = api.BN_CTX_new();
    d = api.BN_new();
    if (group == NULL || pub == NULL || ctx == NULL || d == NULL)
        goto done;
    scalar_for(seed, DOMAIN_KEY, 0, kb);
    if (api.BN_bin2bn(kb, (int)sizeof kb, d) == NULL)
        goto done;
    if (api.EC_POINT_mul(group, pub, d, NULL, NULL, ctx) != 1)
        goto done;
    if (!serialize(group, pub, ctx, out->pub))
        goto done;
    if (api.EC_KEY_set_private_key(key, d) != 1)
        goto done;
    if (api.EC_KEY_set_public_key(key, pub) != 1)
        goto done;
    out->key = key;
    key = NULL;
    ok = 1;
done:
    api.BN_free(d);
    api.EC_POINT_free(pub);
    api.BN_CTX_free(ctx);
    api.EC_KEY_free(key);
    return ok;
}

static unsigned char *read_file(const char *path, long *out_len)
{
    FILE *f = fopen(path, "rb");
    long len;
    unsigned char *buf;

    if (f == NULL)
        return NULL;
    if (fseek(f, 0, SEEK_END) != 0) {
        fclose(f);
        return NULL;
    }
    len = ftell(f);
    if (len <= 0 || fseek(f, 0, SEEK_SET) != 0) {
        fclose(f);
        return NULL;
    }
    buf = malloc((size_t)len);
    if (buf == NULL) {
        fclose(f);
        return NULL;
    }
    if (fread(buf, 1, (size_t)len, f) != (size_t)len) {
        free(buf);
        fclose(f);
        return NULL;
    }
    fclose(f);
    *out_len = len;
    return buf;
}

static int run_sign(uint64_t seed, unsigned count, const char *sigfile)
{
    derived_key dk;
    FILE *f = NULL;
    unsigned i;
    int ok = 0;

    if (!derive_key(seed, &dk))
        return 0;
    f = fopen(sigfile, "wb");
    if (f == NULL) {
        api.EC_KEY_free(dk.key);
        return 0;
    }
    for (i = 0; i < count; i++) {
        unsigned char msg[32], prefix[4];
        ECDSA_SIG *sig;
        unsigned char *der = NULL, *p;
        int len, self;

        bytes_for(seed, DOMAIN_MSG, i, msg);
        sig = api.ECDSA_do_sign(msg, (int)sizeof msg, dk.key);
        if (sig == NULL)
            goto out;
        self = api.ECDSA_do_verify(msg, (int)sizeof msg, sig, dk.key);
        len = api.i2d_ECDSA_SIG(sig, NULL);
        if (len <= 0) {
            api.ECDSA_SIG_free(sig);
            goto out;
        }
        der = malloc((size_t)len);
        if (der == NULL) {
            api.ECDSA_SIG_free(sig);
            goto out;
        }
        p = der;
        if (api.i2d_ECDSA_SIG(sig, &p) != len) {
            free(der);
            api.ECDSA_SIG_free(sig);
            goto out;
        }
        prefix[0] = (unsigned char)((unsigned)len >> 24);
        prefix[1] = (unsigned char)((unsigned)len >> 16);
        prefix[2] = (unsigned char)((unsigned)len >> 8);
        prefix[3] = (unsigned char)((unsigned)len);
        if (fwrite(prefix, 1, 4, f) != 4 ||
            fwrite(der, 1, (size_t)len, f) != (size_t)len) {
            free(der);
            api.ECDSA_SIG_free(sig);
            goto out;
        }
        printf("SIGN i=%u ok=1 self=%d len=%d msg=", i, self == 1, len);
        print_hex(msg, sizeof msg);
        printf(" pub=");
        print_hex(dk.pub, sizeof dk.pub);
        printf("\n");
        if (self != 1) {
            free(der);
            api.ECDSA_SIG_free(sig);
            goto out;
        }
        free(der);
        api.ECDSA_SIG_free(sig);
    }
    ok = 1;
out:
    if (f != NULL && fclose(f) != 0)
        ok = 0;
    api.EC_KEY_free(dk.key);
    return ok;
}

static int run_verify(uint64_t seed, unsigned count, const char *sigfile)
{
    derived_key dk;
    unsigned char *blob;
    long blob_len = 0;
    size_t off = 0;
    unsigned i;
    int ok = 0;

    if (!derive_key(seed, &dk))
        return 0;
    blob = read_file(sigfile, &blob_len);
    if (blob == NULL) {
        api.EC_KEY_free(dk.key);
        return 0;
    }
    for (i = 0; i < count; i++) {
        unsigned char msg[32];
        const unsigned char *p;
        unsigned long len;
        ECDSA_SIG *sig;
        int verified;

        if (off + 4 > (size_t)blob_len)
            goto out;
        len = ((unsigned long)blob[off] << 24) |
              ((unsigned long)blob[off + 1] << 16) |
              ((unsigned long)blob[off + 2] << 8) |
              (unsigned long)blob[off + 3];
        off += 4;
        if (len == 0 || off + len > (size_t)blob_len)
            goto out;
        p = blob + off;
        sig = api.d2i_ECDSA_SIG(NULL, &p, (long)len);
        if (sig == NULL)
            goto out;
        bytes_for(seed, DOMAIN_MSG, i, msg);
        verified = api.ECDSA_do_verify(msg, (int)sizeof msg, sig, dk.key);
        printf("VERIFY i=%u ok=%d msg=", i, verified == 1);
        print_hex(msg, sizeof msg);
        printf(" pub=");
        print_hex(dk.pub, sizeof dk.pub);
        printf("\n");
        api.ECDSA_SIG_free(sig);
        off += len;
        if (verified != 1)
            goto out;
    }
    if (off != (size_t)blob_len)
        goto out;
    ok = 1;
out:
    free(blob);
    api.EC_KEY_free(dk.key);
    return ok;
}

int main(int argc, char **argv)
{
    const char *lib = NULL, *mode = NULL, *sigfile = NULL;
    uint64_t seed = 0;
    unsigned count = 0;
    int i, ok;

    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--lib") == 0 && i + 1 < argc)
            lib = argv[++i];
        else if (strcmp(argv[i], "--mode") == 0 && i + 1 < argc)
            mode = argv[++i];
        else if (strcmp(argv[i], "--seed") == 0 && i + 1 < argc)
            seed = strtoull(argv[++i], NULL, 0);
        else if (strcmp(argv[i], "--count") == 0 && i + 1 < argc)
            count = (unsigned)strtoul(argv[++i], NULL, 10);
        else if (strcmp(argv[i], "--sigfile") == 0 && i + 1 < argc)
            sigfile = argv[++i];
        else {
            fprintf(stderr,
                    "usage: %s --lib <libcrypto.so.3> --mode "
                    "<mul-g|mul-p|sign|verify> --seed <hex> --count <n> "
                    "[--sigfile <file>]\n",
                    argv[0]);
            return 2;
        }
    }
    if (lib == NULL || mode == NULL || count == 0) {
        fprintf(stderr, "pfp2_dso_differential: --lib, --mode and --count are "
                        "required\n");
        return 2;
    }
    if ((strcmp(mode, "sign") == 0 || strcmp(mode, "verify") == 0) &&
        sigfile == NULL) {
        fprintf(stderr, "pfp2_dso_differential: %s needs --sigfile\n", mode);
        return 2;
    }
    if (!load_api(lib))
        return 2;

    printf("SEED 0x%016llx\n", (unsigned long long)seed);
    printf("COUNT %u\n", count);
    printf("MODE %s\n", mode);
    fflush(stdout);

    if (strcmp(mode, "mul-g") == 0)
        ok = run_mul(seed, count, 0);
    else if (strcmp(mode, "mul-p") == 0)
        ok = run_mul(seed, count, 1);
    else if (strcmp(mode, "sign") == 0)
        ok = run_sign(seed, count, sigfile);
    else if (strcmp(mode, "verify") == 0)
        ok = run_verify(seed, count, sigfile);
    else {
        fprintf(stderr, "pfp2_dso_differential: unknown mode %s\n", mode);
        return 2;
    }
    if (!ok) {
        fprintf(stderr, "pfp2_dso_differential: %s failed\n", mode);
        return 1;
    }
    return 0;
}
