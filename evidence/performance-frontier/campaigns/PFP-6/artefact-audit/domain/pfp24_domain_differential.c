/*
 * pfp22_domain_differential.c — PFP-22 differential domain completion.
 *
 * A superset of pfp2_dso_differential.c (sha256
 * fd67b943889ab710af9f3c246e3119c2f28561dc6a47084ee96f5a5d5f64affc).  The
 * measurement instrument is unchanged:
 *
 *   - one process dlopens exactly one libcrypto.so.3 and calls only exported,
 *     ABI-visible entry points;
 *   - it prints LIB (from dladdr(BN_new)), LOADED realpath/dev/ino/size and
 *     MAPS entries, so the runner can prove the mapped file against stat(2);
 *   - every case is serialised with EC_POINT_point2oct(POINT_CONVERSION_
 *     UNCOMPRESSED) and compared byte-for-byte between candidate and authority;
 *   - the original mul-g / mul-p modes call the original bytes_for/scalar_for
 *     generator and print the original line format, so their output remains
 *     byte-identical to the earlier differential runs (the "comparability"
 *     check in run_domain.sh asserts the historical digests).
 *
 * What is added is population only: the upper half of the scalar domain,
 * the order boundaries, the exceptional/structural cases and limb occupancy.
 * For the exceptional class the serialiser records the actual SEC1 octet
 * length, so the point at infinity (one 0x00 byte) is representable and
 * compared rather than being a fatal error.
 *
 * The harness links no libcrypto.  Internal field operations still have no
 * exported entry point and are exercised only through EC_POINT_mul; no
 * source-level test is substituted while this court is called DSO-bound.
 */

#define _GNU_SOURCE
#include <openssl/bn.h>
#include <openssl/ec.h>
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
    int (*EC_POINT_set_to_infinity)(const EC_GROUP *, EC_POINT *);
    int (*EC_POINT_is_at_infinity)(const EC_GROUP *, const EC_POINT *);
    int (*EC_POINT_oct2point)(const EC_GROUP *, EC_POINT *,
                              const unsigned char *, size_t, BN_CTX *);
} api_t;

static api_t api;

/* Domain tags keep each deterministic stream independent.  The first five are
 * the original pfp2 tags and must not change: the comparable base population
 * is defined by them.  The rest tag the new classes. */
#define DOMAIN_G      UINT64_C(0x503246474d554c31)
#define DOMAIN_BASE   UINT64_C(0x5032464742415331)
#define DOMAIN_SCALAR UINT64_C(0x5032464753434c31)
#define DOMAIN_UPPER  UINT64_C(0x5032464755505048) /* PFP-22 upper half */
#define DOMAIN_LIMB   UINT64_C(0x503246474c494d42) /* PFP-22 limb occupancy */

#define POINT_LEN 65

/* P-256 group order n, big-endian. */
static const unsigned char P256_ORDER[32] = {
    0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84,
    0xf3, 0xb9, 0xca, 0xc2, 0xfc, 0x63, 0x25, 0x51
};

static uint64_t splitmix_at(uint64_t x)
{
    uint64_t z = x + UINT64_C(0x9e3779b97f4a7c15);

    z = (z ^ (z >> 30)) * UINT64_C(0xbf58476d1ce4e5b9);
    z = (z ^ (z >> 27)) * UINT64_C(0x94d049bb133111eb);
    return z ^ (z >> 31);
}

/* Deterministic 32 bytes for a mixed seed word. */
static void bytes_from(uint64_t base, unsigned char out[32])
{
    int i;

    for (i = 0; i < 4; i++) {
        uint64_t word = splitmix_at(base + (uint64_t)i * UINT64_C(0xd1b54a32d192ed03));
        memcpy(out + i * 8, &word, sizeof word);
    }
}

/* Original generator: identical to pfp2_dso_differential.c. */
static void bytes_for(uint64_t seed, uint64_t domain, unsigned index,
                      unsigned char out[32])
{
    bytes_from(seed ^ domain ^ ((uint64_t)index * UINT64_C(0x9e3779b97f4a7c15)), out);
}

/* Original scalar in [1, 2^255): top bit cleared, low bit set. */
static void scalar_for(uint64_t seed, uint64_t domain, unsigned index,
                       unsigned char out[32])
{
    bytes_for(seed, domain, index, out);
    out[0] &= 0x7f;
    out[31] |= 0x01;
}

/* PFP-22: uniform in [2^255, q-1] by rejection.  The top bit forces
 * >= 2^255; a draw >= q is redrawn with the next attempt.  Acceptance
 * probability is ~1 - 2^-32, so the loop terminates with overwhelming
 * probability and is deterministic in (seed, domain, index). */
static void upper_half_for(uint64_t seed, uint64_t domain, unsigned index,
                           unsigned char out[32])
{
    unsigned attempt;

    for (attempt = 0;; attempt++) {
        uint64_t base = seed ^ domain
            ^ ((uint64_t)index * UINT64_C(0x9e3779b97f4a7c15))
            ^ ((uint64_t)attempt * UINT64_C(0x2545f4914f6cdd1d));

        bytes_from(base, out);
        out[0] |= 0x80;                            /* >= 2^255 */
        if (memcmp(out, P256_ORDER, 32) < 0)       /* < q => <= q-1 */
            return;
    }
}

static void print_hex(const unsigned char *p, size_t n)
{
    size_t i;

    for (i = 0; i < n; i++)
        printf("%02x", p[i]);
}

static int hexval(char c)
{
    if (c >= '0' && c <= '9')
        return c - '0';
    if (c >= 'a' && c <= 'f')
        return c - 'a' + 10;
    if (c >= 'A' && c <= 'F')
        return c - 'A' + 10;
    return -1;
}

/* Decode a big-endian hex string; returns byte count or -1. */
static int hex_to_bytes(const char *hex, unsigned char *out, int max)
{
    int n = (int)strlen(hex);
    int i;

    if (n <= 0 || (n & 1) != 0 || n / 2 > max)
        return -1;
    for (i = 0; i < n / 2; i++) {
        int hi = hexval(hex[2 * i]);
        int lo = hexval(hex[2 * i + 1]);

        if (hi < 0 || lo < 0)
            return -1;
        out[i] = (unsigned char)((hi << 4) | lo);
    }
    return n / 2;
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
        fprintf(stderr, "pfp22_domain_differential: realpath(%s) failed\n", name);
        return 0;
    }
    if (stat(resolved, &st) != 0) {
        fprintf(stderr, "pfp22_domain_differential: stat(%s) failed\n", resolved);
        return 0;
    }
    printf("LOADED realpath=%s dev=%ju ino=%ju size=%lld\n", resolved,
           (uintmax_t)st.st_dev, (uintmax_t)st.st_ino, (long long)st.st_size);

    maps = fopen("/proc/self/maps", "r");
    if (maps == NULL) {
        fprintf(stderr, "pfp22_domain_differential: cannot read /proc/self/maps\n");
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
        fprintf(stderr, "pfp22_domain_differential: dlopen(%s): %s\n", path,
                dlerror());
        return 0;
    }
#define LOAD(field, symbol)                                                    \
    do {                                                                       \
        void *s = dlsym(h, symbol);                                            \
        if (s == NULL) {                                                       \
            fprintf(stderr, "pfp22_domain_differential: missing %s\n", symbol); \
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
    LOAD(EC_POINT_set_to_infinity, "EC_POINT_set_to_infinity");
    LOAD(EC_POINT_is_at_infinity, "EC_POINT_is_at_infinity");
    LOAD(EC_POINT_oct2point, "EC_POINT_oct2point");
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

/* The original fixed-width serialiser, used by the comparable modes. */
static int serialize(const EC_GROUP *group, const EC_POINT *point, BN_CTX *ctx,
                     unsigned char out[POINT_LEN])
{
    size_t n = api.EC_POINT_point2oct(group, point, POINT_CONVERSION_UNCOMPRESSED,
                                      out, POINT_LEN, ctx);

    return n == POINT_LEN;
}

/* Multiplication + serialisation that reports failure rather than aborting.
 * A successful infinity encodes as one 0x00 byte, which is a success (len 1). */
static int mul_octet(EC_GROUP *group, EC_POINT *r, const BIGNUM *n,
                     const EC_POINT *q, const BIGNUM *m, BN_CTX *ctx,
                     unsigned char *buf, size_t *len)
{
    size_t nn;

    if (api.EC_POINT_mul(group, r, n, q, m, ctx) != 1)
        return 0;
    nn = api.EC_POINT_point2oct(group, r, POINT_CONVERSION_UNCOMPRESSED, buf,
                                POINT_LEN, ctx);
    if (nn == 0)
        return 0;
    *len = nn;
    return 1;
}

/* Deterministic case line.  k/j/in are hex encodings of the exact inputs;
 * pt is the serialised result or NULL for a recorded rejection. */
static void emit_case(const char *cls, unsigned index, const char *tag,
                      const unsigned char *k, int klen,
                      const unsigned char *j, int jlen,
                      const unsigned char *in, int inlen,
                      const unsigned char *pt, size_t ptlen)
{
    printf("POINT class=%s i=%u", cls, index);
    if (tag != NULL)
        printf(" case=%s", tag);
    if (k != NULL) {
        printf(" k=");
        print_hex(k, (size_t)klen);
    } else {
        printf(" k=-");
    }
    if (j != NULL) {
        printf(" j=");
        print_hex(j, (size_t)jlen);
    }
    if (in != NULL) {
        printf(" in=");
        print_hex(in, (size_t)inlen);
    }
    if (pt != NULL) {
        printf(" status=ok point=");
        print_hex(pt, ptlen);
    } else {
        printf(" status=rej point=-");
    }
    printf("\n");
}

/* --------------------------------------------------------------------------
 * Comparable base population: byte-identical to pfp2_dso_differential.c.
 * ------------------------------------------------------------------------ */

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

/* --------------------------------------------------------------------------
 * Class 1: upper half of the scalar domain, [2^255, q-1].
 * ------------------------------------------------------------------------ */

static int run_upper(uint64_t seed, unsigned count, int variable_base)
{
    const char *cls = variable_base ? "upper-p" : "upper-g";
    EC_GROUP *group = NULL;
    BN_CTX *ctx = NULL;
    const EC_POINT *gen = NULL;
    EC_POINT *r = NULL, *p = NULL;
    BIGNUM *k = NULL, *j = NULL;
    unsigned char kb[32], jb[32], oct[POINT_LEN];
    unsigned i;
    int ok = 0;

    group = api.EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
    ctx = api.BN_CTX_new();
    if (group == NULL || ctx == NULL)
        goto out;
    gen = api.EC_GROUP_get0_generator(group);
    r = api.EC_POINT_new(group);
    k = api.BN_new();
    j = api.BN_new();
    if (gen == NULL || r == NULL || k == NULL || j == NULL)
        goto out;
    if (variable_base) {
        p = api.EC_POINT_new(group);
        if (p == NULL)
            goto out;
    }

    for (i = 0; i < count; i++) {
        size_t len = 0;
        int good = 1;

        upper_half_for(seed, DOMAIN_UPPER, i, kb);
        if (api.BN_bin2bn(kb, (int)sizeof kb, k) == NULL)
            goto out;
        if (variable_base) {
            scalar_for(seed, DOMAIN_BASE, i, jb);
            if (api.BN_bin2bn(jb, (int)sizeof jb, j) == NULL)
                goto out;
            if (api.EC_POINT_mul(group, p, j, NULL, NULL, ctx) != 1)
                good = 0;
            if (good && mul_octet(group, r, NULL, p, k, ctx, oct, &len) != 1)
                good = 0;
            emit_case(cls, i, NULL, kb, (int)sizeof kb, jb, (int)sizeof jb,
                      NULL, 0, good ? oct : NULL, len);
        } else {
            if (mul_octet(group, r, k, NULL, NULL, ctx, oct, &len) != 1)
                good = 0;
            emit_case(cls, i, NULL, kb, (int)sizeof kb, NULL, 0,
                      NULL, 0, good ? oct : NULL, len);
        }
    }
    ok = 1;
out:
    api.BN_free(k);
    api.BN_free(j);
    api.EC_POINT_free(r);
    api.EC_POINT_free(p);
    api.EC_GROUP_free(group);
    api.BN_CTX_free(ctx);
    return ok;
}

/* --------------------------------------------------------------------------
 * Class 2: order boundaries.  Values are exact big-endian byte strings; the
 * API is given them verbatim (2q-1 is 33 bytes).  Whether the operation is
 * accepted or rejected is part of the compared output.
 * ------------------------------------------------------------------------ */

#define BOUNDARY_N 8
static const char *const BOUNDARY_HEX[BOUNDARY_N] = {
    "01",                                                                 /* 1       */
    "02",                                                                 /* 2       */
    "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc63254f",   /* q-2     */
    "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632550",   /* q-1     */
    "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551",   /* q       */
    "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632552",   /* q+1     */
    "01fffffffe00000001ffffffffffffffff79cdf55b4e2f3d09e7739585f8c64aa1", /* 2q-1    */
    "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"    /* 2^256-1 */
};
static const char *const BOUNDARY_LABEL[BOUNDARY_N] = {
    "one", "two", "q-2", "q-1", "q", "q+1", "2q-1", "2^256-1"
};

static int run_boundary(uint64_t seed, unsigned count, int variable_base)
{
    const char *cls = variable_base ? "boundary-p" : "boundary-g";
    EC_GROUP *group = NULL;
    BN_CTX *ctx = NULL;
    const EC_POINT *gen = NULL;
    EC_POINT *r = NULL, *p = NULL;
    BIGNUM *k = NULL, *j = NULL;
    unsigned char jb[32], oct[POINT_LEN];
    unsigned i;
    int base_ok = 1;
    int ok = 0;

    if (count > BOUNDARY_N)
        return 0;

    group = api.EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
    ctx = api.BN_CTX_new();
    if (group == NULL || ctx == NULL)
        goto out;
    gen = api.EC_GROUP_get0_generator(group);
    r = api.EC_POINT_new(group);
    k = api.BN_new();
    j = api.BN_new();
    if (gen == NULL || r == NULL || k == NULL || j == NULL)
        goto out;
    if (variable_base) {
        p = api.EC_POINT_new(group);
        if (p == NULL)
            goto out;
        scalar_for(seed, DOMAIN_BASE, 0, jb);
        if (api.BN_bin2bn(jb, (int)sizeof jb, j) == NULL)
            goto out;
        if (api.EC_POINT_mul(group, p, j, NULL, NULL, ctx) != 1)
            base_ok = 0;
    }

    for (i = 0; i < count; i++) {
        unsigned char kb[64];
        size_t len = 0;
        int klen, good = 1;

        klen = hex_to_bytes(BOUNDARY_HEX[i], kb, (int)sizeof kb);
        if (klen <= 0)
            goto out;
        if (api.BN_bin2bn(kb, klen, k) == NULL)
            goto out;
        if (variable_base) {
            if (!base_ok || mul_octet(group, r, NULL, p, k, ctx, oct, &len) != 1)
                good = 0;
            emit_case(cls, i, BOUNDARY_LABEL[i], kb, klen, jb, (int)sizeof jb,
                      NULL, 0, good ? oct : NULL, len);
        } else {
            if (mul_octet(group, r, k, NULL, NULL, ctx, oct, &len) != 1)
                good = 0;
            emit_case(cls, i, BOUNDARY_LABEL[i], kb, klen, NULL, 0,
                      NULL, 0, good ? oct : NULL, len);
        }
    }
    ok = 1;
out:
    api.BN_free(k);
    api.BN_free(j);
    api.EC_POINT_free(r);
    api.EC_POINT_free(p);
    api.EC_GROUP_free(group);
    api.BN_CTX_free(ctx);
    return ok;
}

/* --------------------------------------------------------------------------
 * Class 3: exceptional and structural cases.
 *
 *   0 zero_alllimbs_g      scalar 0 (all-zero limbs), k*G      -> infinity
 *   1 zero_alllimbs_p      scalar 0, k*P (non-generator)       -> infinity
 *   2 allff_limbs_g        scalar 2^256-1, k*G
 *   3 allff_limbs_p        scalar 2^256-1, k*P
 *   4 infinity_base_5      base = infinity, k = 5              -> infinity
 *   5 infinity_base_zero   base = infinity, k = 0              -> infinity
 *   6 generator_base_7     base = G, k = 7
 *   7 nongenerator_base_7  base = jG, k = 7
 *   8 decode_generator_mul7  oct2point(G) accepted, then 7*decoded
 *   9 reject_offcurve      oct2point of (0,0) must be rejected
 *
 * P-256 has prime order n, so it has no non-trivial small-order point; the
 * only order-1 point is infinity, exercised by cases 4 and 5.
 * ------------------------------------------------------------------------ */

#define EXCEPTIONAL_N 10

static int run_exceptional(uint64_t seed, unsigned count)
{
    EC_GROUP *group = NULL;
    BN_CTX *ctx = NULL;
    const EC_POINT *gen = NULL;
    EC_POINT *r = NULL, *p = NULL, *inf = NULL, *dec = NULL;
    BIGNUM *k = NULL, *j = NULL;
    unsigned char jb[32], kb[POINT_LEN], oct[POINT_LEN], in[POINT_LEN];
    unsigned char seven[32], five[32];
    unsigned idx = 0;
    size_t len;
    int good;
    int ok = 0;

    (void)count; /* fixed population; the runner asserts EXCEPTIONAL_N */

    group = api.EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
    ctx = api.BN_CTX_new();
    if (group == NULL || ctx == NULL)
        goto out;
    gen = api.EC_GROUP_get0_generator(group);
    r = api.EC_POINT_new(group);
    p = api.EC_POINT_new(group);
    inf = api.EC_POINT_new(group);
    dec = api.EC_POINT_new(group);
    k = api.BN_new();
    j = api.BN_new();
    if (gen == NULL || r == NULL || p == NULL || inf == NULL || dec == NULL
        || k == NULL || j == NULL)
        goto out;

    memset(seven, 0, sizeof seven);
    seven[31] = 7;
    memset(five, 0, sizeof five);
    five[31] = 5;

    /* non-generator point P = j*G */
    scalar_for(seed, DOMAIN_BASE, 0, jb);
    if (api.BN_bin2bn(jb, (int)sizeof jb, j) == NULL)
        goto out;
    if (api.EC_POINT_mul(group, p, j, NULL, NULL, ctx) != 1)
        goto out;
    if (api.EC_POINT_set_to_infinity(group, inf) != 1)
        goto out;

    /* case 0: zero scalar, base G */
    memset(kb, 0, 32);
    if (api.BN_bin2bn(kb, 32, k) == NULL)
        goto out;
    len = 0;
    good = mul_octet(group, r, k, NULL, NULL, ctx, oct, &len) == 1;
    emit_case("exceptional", idx++, "zero_alllimbs_g", kb, 32, NULL, 0,
              NULL, 0, good ? oct : NULL, len);

    /* case 1: zero scalar, base P */
    len = 0;
    good = mul_octet(group, r, NULL, p, k, ctx, oct, &len) == 1;
    emit_case("exceptional", idx++, "zero_alllimbs_p", kb, 32, jb, 32,
              NULL, 0, good ? oct : NULL, len);

    /* case 2: all-0xff scalar, base G */
    memset(kb, 0xff, 32);
    if (api.BN_bin2bn(kb, 32, k) == NULL)
        goto out;
    len = 0;
    good = mul_octet(group, r, k, NULL, NULL, ctx, oct, &len) == 1;
    emit_case("exceptional", idx++, "allff_limbs_g", kb, 32, NULL, 0,
              NULL, 0, good ? oct : NULL, len);

    /* case 3: all-0xff scalar, base P */
    len = 0;
    good = mul_octet(group, r, NULL, p, k, ctx, oct, &len) == 1;
    emit_case("exceptional", idx++, "allff_limbs_p", kb, 32, jb, 32,
              NULL, 0, good ? oct : NULL, len);

    /* case 4: infinity base, scalar 5 */
    if (api.BN_bin2bn(five, 32, k) == NULL)
        goto out;
    len = 0;
    good = mul_octet(group, r, NULL, inf, k, ctx, oct, &len) == 1;
    emit_case("exceptional", idx++, "infinity_base_5", five, 32, NULL, 0,
              NULL, 0, good ? oct : NULL, len);

    /* case 5: infinity base, scalar 0 */
    memset(kb, 0, 32);
    if (api.BN_bin2bn(kb, 32, k) == NULL)
        goto out;
    len = 0;
    good = mul_octet(group, r, NULL, inf, k, ctx, oct, &len) == 1;
    emit_case("exceptional", idx++, "infinity_base_zero", kb, 32, NULL, 0,
              NULL, 0, good ? oct : NULL, len);

    /* case 6: generator base, scalar 7 (variable-base call with q = G) */
    if (api.BN_bin2bn(seven, 32, k) == NULL)
        goto out;
    len = 0;
    good = mul_octet(group, r, NULL, gen, k, ctx, oct, &len) == 1;
    emit_case("exceptional", idx++, "generator_base_7", seven, 32, NULL, 0,
              NULL, 0, good ? oct : NULL, len);

    /* case 7: non-generator base, scalar 7 */
    len = 0;
    good = mul_octet(group, r, NULL, p, k, ctx, oct, &len) == 1;
    emit_case("exceptional", idx++, "nongenerator_base_7", seven, 32, jb, 32,
              NULL, 0, good ? oct : NULL, len);

    /* case 8: decode the generator octets with oct2point, then 7*decoded */
    {
        size_t glen = api.EC_POINT_point2oct(group, gen,
                                             POINT_CONVERSION_UNCOMPRESSED,
                                             in, POINT_LEN, ctx);
        good = 0;
        len = 0;
        if (glen > 0 && glen <= POINT_LEN
            && api.EC_POINT_oct2point(group, dec, in, glen, ctx) == 1
            && mul_octet(group, r, NULL, dec, k, ctx, oct, &len) == 1)
            good = 1;
        emit_case("exceptional", idx++, "decode_generator_mul7", seven, 32,
                  NULL, 0, in, (int)glen, good ? oct : NULL, len);
    }

    /* case 9: an off-curve (0, 0) uncompressed point must be rejected */
    {
        int accepted;
        size_t l = 0;

        memset(in, 0, POINT_LEN);
        in[0] = 0x04;                 /* x = 0, y = 0; (0,0) is not on P-256 */
        accepted = api.EC_POINT_oct2point(group, dec, in, POINT_LEN, ctx);
        if (accepted == 1)
            l = api.EC_POINT_point2oct(group, dec,
                                       POINT_CONVERSION_UNCOMPRESSED, oct,
                                       POINT_LEN, ctx);
        emit_case("exceptional", idx++, "reject_offcurve", NULL, 0,
                  NULL, 0, in, POINT_LEN, accepted == 1 ? oct : NULL, l);
    }

    ok = 1;
out:
    api.BN_free(k);
    api.BN_free(j);
    api.EC_POINT_free(r);
    api.EC_POINT_free(p);
    api.EC_POINT_free(inf);
    api.EC_POINT_free(dec);
    api.EC_GROUP_free(group);
    api.BN_CTX_free(ctx);
    return ok;
}

/* --------------------------------------------------------------------------
 * Class 4: limb occupancy.
 *   - exactly one non-zero 64-bit limb, in each of the four positions, with
 *     limb value 1 and 0xffffffffffffffff                         (8 cases);
 *   - four values whose most-significant limb is zero (< 2^192)   (4 cases).
 * ------------------------------------------------------------------------ */

#define LIMB_SINGLE 8
#define LIMB_TOPZERO 4
#define LIMB_N (LIMB_SINGLE + LIMB_TOPZERO)

static void limb_value(unsigned pos, uint64_t v, unsigned char out[32])
{
    int i;

    memset(out, 0, 32);
    for (i = 0; i < 8; i++)
        out[8 * pos + i] = (unsigned char)(v >> (8 * (7 - i)));
}

static int run_limb(uint64_t seed, unsigned count, int variable_base)
{
    const char *cls = variable_base ? "limb-p" : "limb-g";
    EC_GROUP *group = NULL;
    BN_CTX *ctx = NULL;
    const EC_POINT *gen = NULL;
    EC_POINT *r = NULL, *p = NULL;
    BIGNUM *k = NULL, *j = NULL;
    unsigned char jb[32], kb[32], oct[POINT_LEN];
    unsigned idx = 0, pos, i;
    int ok = 0;

    if (count > LIMB_N)
        return 0;

    group = api.EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
    ctx = api.BN_CTX_new();
    if (group == NULL || ctx == NULL)
        goto out;
    gen = api.EC_GROUP_get0_generator(group);
    r = api.EC_POINT_new(group);
    k = api.BN_new();
    j = api.BN_new();
    if (gen == NULL || r == NULL || k == NULL || j == NULL)
        goto out;
    if (variable_base) {
        p = api.EC_POINT_new(group);
        if (p == NULL)
            goto out;
        scalar_for(seed, DOMAIN_BASE, 0, jb);
        if (api.BN_bin2bn(jb, (int)sizeof jb, j) == NULL)
            goto out;
        if (api.EC_POINT_mul(group, p, j, NULL, NULL, ctx) != 1)
            goto out;
    }

    for (pos = 0; pos < 4; pos++) {
        int f;

        for (f = 0; f < 2; f++) {
            uint64_t v = f == 0 ? UINT64_C(1) : ~UINT64_C(0);
            char tag[32];
            size_t len = 0;
            int good;

            limb_value(pos, v, kb);
            if (api.BN_bin2bn(kb, (int)sizeof kb, k) == NULL)
                goto out;
            snprintf(tag, sizeof tag, "limb%u_%s", pos, f == 0 ? "01" : "ff");
            if (variable_base)
                good = mul_octet(group, r, NULL, p, k, ctx, oct, &len) == 1;
            else
                good = mul_octet(group, r, k, NULL, NULL, ctx, oct, &len) == 1;
            emit_case(cls, idx++, tag, kb, (int)sizeof kb,
                      variable_base ? jb : NULL, variable_base ? 32 : 0,
                      NULL, 0, good ? oct : NULL, len);
        }
    }

    for (i = 0; i < LIMB_TOPZERO; i++) {
        char tag[32];
        size_t len = 0;
        int good;

        scalar_for(seed, DOMAIN_LIMB, i, kb);
        memset(kb, 0, 8);             /* most-significant limb zero */
        if (api.BN_bin2bn(kb, (int)sizeof kb, k) == NULL)
            goto out;
        snprintf(tag, sizeof tag, "toplimbzero_%u", i);
        if (variable_base)
            good = mul_octet(group, r, NULL, p, k, ctx, oct, &len) == 1;
        else
            good = mul_octet(group, r, k, NULL, NULL, ctx, oct, &len) == 1;
        emit_case(cls, idx++, tag, kb, (int)sizeof kb,
                  variable_base ? jb : NULL, variable_base ? 32 : 0,
                  NULL, 0, good ? oct : NULL, len);
    }

    ok = 1;
out:
    api.BN_free(k);
    api.BN_free(j);
    api.EC_POINT_free(r);
    api.EC_POINT_free(p);
    api.EC_GROUP_free(group);
    api.BN_CTX_free(ctx);
    return ok;
}

int main(int argc, char **argv)
{
    const char *lib = NULL, *mode = NULL;
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
        else {
            fprintf(stderr,
                    "usage: %s --lib <libcrypto.so.3> --mode <mode> "
                    "--seed <hex> --count <n>\n", argv[0]);
            return 2;
        }
    }
    if (lib == NULL || mode == NULL || count == 0) {
        fprintf(stderr, "pfp22_domain_differential: --lib, --mode and --count "
                        "are required\n");
        return 2;
    }
    if (!load_api(lib))
        return 2;

    printf("SEED 0x%016llx\n", (unsigned long long)seed);
    printf("COUNT %u\n", count);
    printf("MODE %s\n", mode);
    printf("NOTE class=exceptional small_order=none prime_order_group\n");
    fflush(stdout);

    if (strcmp(mode, "mul-g") == 0)
        ok = run_mul(seed, count, 0);
    else if (strcmp(mode, "mul-p") == 0)
        ok = run_mul(seed, count, 1);
    else if (strcmp(mode, "upper-g") == 0)
        ok = run_upper(seed, count, 0);
    else if (strcmp(mode, "upper-p") == 0)
        ok = run_upper(seed, count, 1);
    else if (strcmp(mode, "boundary-g") == 0)
        ok = run_boundary(seed, count, 0);
    else if (strcmp(mode, "boundary-p") == 0)
        ok = run_boundary(seed, count, 1);
    else if (strcmp(mode, "exceptional") == 0)
        ok = run_exceptional(seed, count);
    else if (strcmp(mode, "limb-g") == 0)
        ok = run_limb(seed, count, 0);
    else if (strcmp(mode, "limb-p") == 0)
        ok = run_limb(seed, count, 1);
    else {
        fprintf(stderr, "pfp22_domain_differential: unknown mode %s\n", mode);
        return 2;
    }
    if (!ok) {
        fprintf(stderr, "pfp22_domain_differential: %s failed\n", mode);
        return 1;
    }
    return 0;
}
