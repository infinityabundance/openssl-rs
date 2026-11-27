/*
 * pfp4_dso_sign.c — DSO-bound ECDSA differential court for PFP-4.
 *
 * One process loads exactly one libcrypto.so.3 with
 * dlopen(RTLD_NOW | RTLD_LOCAL) and calls only exported, ABI-visible entry
 * points.  It prints LIB / LOADED / MAPS so the runner can prove the mapped
 * on-disk DSO by realpath/dev/ino/size and a /proc/self/maps entry.
 *
 * Modes:
 *
 *   sign-rand  N signatures through the shipped `ECDSA_do_sign` path.  A
 *              deterministic legacy RAND_METHOD is installed first, so the
 *              library's own nonce draw is identical in both processes.  This
 *              is the mode that exercises `ecdsa_sign_setup`'s order inverse
 *              end to end.
 *   sign-ex    N signatures through `ECDSA_do_sign_ex` with a harness-chosen
 *              nonce `k`, `r = x(kG) mod n` and `kinv = k^-1 mod n`.  The
 *              defining equation `s*k = m + r*d (mod n)` is checked for every
 *              case.  This exercises the `s` expression and DER export with a
 *              supplied nonce.
 *   verify     N verifications of the records written by another process.
 *
 * The harness links no libcrypto.  The RAND override is the documented
 * (deprecated) `RAND_set_rand_method` table; both DSOs honour it, which the
 * probe `court/tmp/pfp4-probe/rand_probe.c` established before this harness
 * was written.
 */

#define _GNU_SOURCE
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/obj_mac.h>
#include <openssl/rand.h>

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
    int (*BN_bn2binpad)(const BIGNUM *, unsigned char *, int);
    int (*BN_mod_mul)(BIGNUM *, const BIGNUM *, const BIGNUM *, const BIGNUM *,
                      BN_CTX *);
    int (*BN_mod_add)(BIGNUM *, const BIGNUM *, const BIGNUM *, const BIGNUM *,
                      BN_CTX *);
    int (*BN_nnmod)(BIGNUM *, const BIGNUM *, const BIGNUM *, BN_CTX *);
    BIGNUM *(*BN_mod_inverse)(BIGNUM *, const BIGNUM *, const BIGNUM *,
                              BN_CTX *);
    int (*BN_cmp)(const BIGNUM *, const BIGNUM *);
    int (*BN_is_zero)(const BIGNUM *);
    int (*BN_set_word)(BIGNUM *, BN_ULONG);
    BN_CTX *(*BN_CTX_new)(void);
    void (*BN_CTX_free)(BN_CTX *);

    EC_GROUP *(*EC_GROUP_new_by_curve_name)(int);
    const BIGNUM *(*EC_GROUP_get0_order)(const EC_GROUP *);
    EC_POINT *(*EC_POINT_new)(const EC_GROUP *);
    void (*EC_POINT_free)(EC_POINT *);
    int (*EC_POINT_mul)(const EC_GROUP *, EC_POINT *, const BIGNUM *,
                        const EC_POINT *, const BIGNUM *, BN_CTX *);
    int (*EC_POINT_get_affine_coordinates)(const EC_GROUP *, const EC_POINT *,
                                           BIGNUM *, BIGNUM *, BN_CTX *);
    size_t (*EC_POINT_point2oct)(const EC_GROUP *, const EC_POINT *,
                                 point_conversion_form_t, unsigned char *,
                                 size_t, BN_CTX *);

    EC_KEY *(*EC_KEY_new_by_curve_name)(int);
    void (*EC_KEY_free)(EC_KEY *);
    const EC_GROUP *(*EC_KEY_get0_group)(const EC_KEY *);
    int (*EC_KEY_set_private_key)(EC_KEY *, const BIGNUM *);
    int (*EC_KEY_set_public_key)(EC_KEY *, const EC_POINT *);
    ECDSA_SIG *(*ECDSA_do_sign)(const unsigned char *, int, EC_KEY *);
    ECDSA_SIG *(*ECDSA_do_sign_ex)(const unsigned char *, int, const BIGNUM *,
                                   const BIGNUM *, EC_KEY *);
    int (*ECDSA_sign_ex)(int, const unsigned char *, int, unsigned char *,
                         unsigned int *, const BIGNUM *, const BIGNUM *,
                         EC_KEY *);
    int (*ECDSA_do_verify)(const unsigned char *, int, const ECDSA_SIG *,
                           EC_KEY *);
    void (*ECDSA_SIG_get0)(const ECDSA_SIG *, const BIGNUM **, const BIGNUM **);
    void (*ECDSA_SIG_free)(ECDSA_SIG *);
    int (*i2d_ECDSA_SIG)(const ECDSA_SIG *, unsigned char **);
    ECDSA_SIG *(*d2i_ECDSA_SIG)(ECDSA_SIG **, const unsigned char **, long);

    int (*RAND_set_rand_method)(const RAND_METHOD *);
} api_t;

static api_t api;

#define DOMAIN_KEY UINT64_C(0x503446344b455931)
#define DOMAIN_MSG UINT64_C(0x503446344d534731)
#define DOMAIN_SCALAR UINT64_C(0x5034463453434c31)
#define DOMAIN_RAND UINT64_C(0x5034463452414e44)
#define POINT_LEN 65

/* Deterministic RAND_METHOD: a public xorshift stream. */
static uint64_t rand_state;

static unsigned char rand_next_byte(void)
{
    rand_state ^= rand_state << 13;
    rand_state ^= rand_state >> 7;
    rand_state ^= rand_state << 17;
    return (unsigned char)(rand_state >> 24);
}

static int det_seed(const void *buf, int num)
{
    (void)buf;
    (void)num;
    return 1;
}

static int det_bytes(unsigned char *buf, int num)
{
    int i;

    for (i = 0; i < num; i++)
        buf[i] = rand_next_byte();
    return 1;
}

static int det_add(const void *buf, int num, double randomness)
{
    (void)buf;
    (void)num;
    (void)randomness;
    return 1;
}

static RAND_METHOD det_method = {det_seed, det_bytes, NULL, det_add,
                                 det_bytes, NULL};

static uint64_t splitmix_at(uint64_t x)
{
    uint64_t z = x + UINT64_C(0x9e3779b97f4a7c15);

    z = (z ^ (z >> 30)) * UINT64_C(0xbf58476d1ce4e5b9);
    z = (z ^ (z >> 27)) * UINT64_C(0x94d049bb133111eb);
    return z ^ (z >> 31);
}

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

/* A scalar in [1, 2^255): top bit clear (below n ~ 2^256) and low bit set. */
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

static void print_bn32(const BIGNUM *b)
{
    unsigned char buf[32];

    if (api.BN_bn2binpad(b, buf, 32) != 32) {
        printf("<bad>");
        return;
    }
    print_hex(buf, 32);
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
        fprintf(stderr, "pfp4_dso_sign: realpath(%s) failed\n", name);
        return 0;
    }
    if (stat(resolved, &st) != 0) {
        fprintf(stderr, "pfp4_dso_sign: stat(%s) failed\n", resolved);
        return 0;
    }
    printf("LOADED realpath=%s dev=%ju ino=%ju size=%lld\n", resolved,
           (uintmax_t)st.st_dev, (uintmax_t)st.st_ino, (long long)st.st_size);

    maps = fopen("/proc/self/maps", "r");
    if (maps == NULL) {
        fprintf(stderr, "pfp4_dso_sign: cannot read /proc/self/maps\n");
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
        fprintf(stderr, "pfp4_dso_sign: dlopen(%s): %s\n", path, dlerror());
        return 0;
    }
#define LOAD(field, symbol)                                                    \
    do {                                                                       \
        void *s = dlsym(h, symbol);                                            \
        if (s == NULL) {                                                       \
            fprintf(stderr, "pfp4_dso_sign: missing %s\n", symbol);            \
            return 0;                                                          \
        }                                                                      \
        memcpy(&api.field, &s, sizeof s);                                      \
    } while (0)

    LOAD(BN_new, "BN_new");
    LOAD(BN_free, "BN_free");
    LOAD(BN_bin2bn, "BN_bin2bn");
    LOAD(BN_bn2binpad, "BN_bn2binpad");
    LOAD(BN_mod_mul, "BN_mod_mul");
    LOAD(BN_mod_add, "BN_mod_add");
    LOAD(BN_nnmod, "BN_nnmod");
    LOAD(BN_mod_inverse, "BN_mod_inverse");
    LOAD(BN_cmp, "BN_cmp");
    LOAD(BN_is_zero, "BN_is_zero");
    LOAD(BN_set_word, "BN_set_word");
    LOAD(BN_CTX_new, "BN_CTX_new");
    LOAD(BN_CTX_free, "BN_CTX_free");

    LOAD(EC_GROUP_new_by_curve_name, "EC_GROUP_new_by_curve_name");
    LOAD(EC_GROUP_get0_order, "EC_GROUP_get0_order");
    LOAD(EC_POINT_new, "EC_POINT_new");
    LOAD(EC_POINT_free, "EC_POINT_free");
    LOAD(EC_POINT_mul, "EC_POINT_mul");
    LOAD(EC_POINT_get_affine_coordinates, "EC_POINT_get_affine_coordinates");
    LOAD(EC_POINT_point2oct, "EC_POINT_point2oct");

    LOAD(EC_KEY_new_by_curve_name, "EC_KEY_new_by_curve_name");
    LOAD(EC_KEY_free, "EC_KEY_free");
    LOAD(EC_KEY_get0_group, "EC_KEY_get0_group");
    LOAD(EC_KEY_set_private_key, "EC_KEY_set_private_key");
    LOAD(EC_KEY_set_public_key, "EC_KEY_set_public_key");
    LOAD(ECDSA_do_sign, "ECDSA_do_sign");
    LOAD(ECDSA_do_sign_ex, "ECDSA_do_sign_ex");
    LOAD(ECDSA_sign_ex, "ECDSA_sign_ex");
    LOAD(ECDSA_do_verify, "ECDSA_do_verify");
    LOAD(ECDSA_SIG_get0, "ECDSA_SIG_get0");
    LOAD(ECDSA_SIG_free, "ECDSA_SIG_free");
    LOAD(i2d_ECDSA_SIG, "i2d_ECDSA_SIG");
    LOAD(d2i_ECDSA_SIG, "d2i_ECDSA_SIG");

    LOAD(RAND_set_rand_method, "RAND_set_rand_method");
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

/* Build the fixed P-256 key: d from the seed, public = d*G. */
static EC_KEY *make_key(uint64_t seed, BN_CTX *ctx, BIGNUM **d_out,
                        BIGNUM **order_out, unsigned char pub_oct[POINT_LEN])
{
    unsigned char db[32];
    BIGNUM *d;
    EC_KEY *key = api.EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    const EC_GROUP *group;
    const BIGNUM *order;
    EC_POINT *pub;

    if (key == NULL)
        return NULL;
    group = api.EC_KEY_get0_group(key);
    order = api.EC_GROUP_get0_order(group);
    if (group == NULL || order == NULL)
        return NULL;

    bytes_for(seed, DOMAIN_KEY, 0, db);
    d = api.BN_bin2bn(db, 32, NULL);
    if (d == NULL || api.BN_nnmod(d, d, order, ctx) != 1)
        return NULL;
    if (api.BN_is_zero(d) && api.BN_set_word(d, 1) != 1)
        return NULL;
    if (api.EC_KEY_set_private_key(key, d) != 1)
        return NULL;

    pub = api.EC_POINT_new(group);
    if (pub == NULL)
        return NULL;
    if (api.EC_POINT_mul(group, pub, d, NULL, NULL, ctx) != 1 ||
        api.EC_KEY_set_public_key(key, pub) != 1)
        return NULL;
    if (api.EC_POINT_point2oct(group, pub, POINT_CONVERSION_UNCOMPRESSED,
                               pub_oct, POINT_LEN, ctx) != POINT_LEN)
        return NULL;
    api.EC_POINT_free(pub);

    *d_out = d;
    *order_out = (BIGNUM *)order;
    return key;
}

static int write_record(FILE *f, const unsigned char *der, int len)
{
    unsigned char hdr[4];

    hdr[0] = (unsigned char)((unsigned)len >> 24);
    hdr[1] = (unsigned char)((unsigned)len >> 16);
    hdr[2] = (unsigned char)((unsigned)len >> 8);
    hdr[3] = (unsigned char)((unsigned)len);
    if (fwrite(hdr, 1, 4, f) != 4)
        return 0;
    return fwrite(der, 1, (size_t)len, f) == (size_t)len;
}

static int emit_sig(FILE *f, unsigned index, const ECDSA_SIG *sig, int self,
                    int eq)
{
    const BIGNUM *r = NULL, *s = NULL;
    unsigned char *der = NULL, *p;
    int len;

    api.ECDSA_SIG_get0(sig, &r, &s);
    if (r == NULL || s == NULL)
        return 0;
    len = api.i2d_ECDSA_SIG(sig, NULL);
    if (len <= 0)
        return 0;
    der = malloc((size_t)len);
    if (der == NULL)
        return 0;
    p = der;
    if (api.i2d_ECDSA_SIG(sig, &p) != len) {
        free(der);
        return 0;
    }
    if (!write_record(f, der, len)) {
        free(der);
        return 0;
    }
    free(der);

    printf("SIG i=%u ok=1 self=%d", index, self);
    if (eq >= 0)
        printf(" eq=%d", eq);
    printf(" r=");
    print_bn32(r);
    printf(" s=");
    print_bn32(s);
    printf("\n");
    return 1;
}

static int run_sign_rand(uint64_t seed, unsigned count, const char *sigfile)
{
    BN_CTX *ctx = api.BN_CTX_new();
    BIGNUM *d = NULL, *order = NULL;
    unsigned char pub_oct[POINT_LEN];
    EC_KEY *key;
    FILE *f;
    unsigned i;
    int ok = 1;

    if (ctx == NULL)
        return 0;
    key = make_key(seed, ctx, &d, &order, pub_oct);
    if (key == NULL)
        return 0;
    printf("PUB ");
    print_hex(pub_oct, POINT_LEN);
    printf("\n");

    /* Install the deterministic nonce source after the key is fixed. */
    if (api.RAND_set_rand_method(&det_method) != 1) {
        fprintf(stderr, "pfp4_dso_sign: RAND_set_rand_method failed\n");
        return 0;
    }

    f = fopen(sigfile, "wb");
    if (f == NULL)
        return 0;
    for (i = 0; i < count && ok; i++) {
        unsigned char msg[32];
        ECDSA_SIG *sig;
        int self;

        /* The nonce is the first RAND draw of each sign.  The authority's
         * ladder also blinds coordinates afterwards and PFP-3's comb does not,
         * so the intervening consumption differs by design; restarting the
         * stream per signature keeps the first draw identical on both sides. */
        rand_state = seed ^ DOMAIN_RAND ^
                     ((uint64_t)i * UINT64_C(0x9e3779b97f4a7c15));
        bytes_for(seed, DOMAIN_MSG, i, msg);
        sig = api.ECDSA_do_sign(msg, (int)sizeof msg, key);
        if (sig == NULL) {
            fprintf(stderr, "pfp4_dso_sign: sign failed at %u\n", i);
            ok = 0;
            break;
        }
        self = api.ECDSA_do_verify(msg, (int)sizeof msg, sig, key);
        if (self != 1)
            ok = 0;
        if (!emit_sig(f, i, sig, self, -1))
            ok = 0;
        api.ECDSA_SIG_free(sig);
    }
    fclose(f);
    api.EC_KEY_free(key);
    api.BN_free(d);
    api.BN_CTX_free(ctx);
    return ok;
}

static int run_sign_ex(uint64_t seed, unsigned count, const char *sigfile)
{
    BN_CTX *ctx = api.BN_CTX_new();
    BIGNUM *d = NULL, *order = NULL;
    unsigned char pub_oct[POINT_LEN];
    EC_KEY *key;
    const EC_GROUP *group;
    FILE *f;
    unsigned i;
    int ok = 1;
    BIGNUM *m = api.BN_new();
    BIGNUM *lhs = api.BN_new();
    BIGNUM *rd = api.BN_new();
    BIGNUM *rhs = api.BN_new();
    BIGNUM *x = api.BN_new();
    BIGNUM *r = api.BN_new();
    BIGNUM *k = api.BN_new();
    BIGNUM *kinv = api.BN_new();
    EC_POINT *pt = NULL;

    if (ctx == NULL || m == NULL || lhs == NULL || rd == NULL || rhs == NULL ||
        x == NULL || r == NULL || k == NULL || kinv == NULL)
        return 0;
    key = make_key(seed, ctx, &d, &order, pub_oct);
    if (key == NULL)
        return 0;
    group = api.EC_KEY_get0_group(key);
    pt = api.EC_POINT_new(group);
    if (pt == NULL)
        return 0;
    printf("PUB ");
    print_hex(pub_oct, POINT_LEN);
    printf("\n");

    f = fopen(sigfile, "wb");
    if (f == NULL)
        return 0;
    for (i = 0; i < count && ok; i++) {
        unsigned char msg[32];
        unsigned char kb[32];
        unsigned probe = 0;
        ECDSA_SIG *sig;
        const BIGNUM *sr = NULL;
        const BIGNUM *ss = NULL;
        int self = 0, eq = 0;

        bytes_for(seed, DOMAIN_MSG, i, msg);
        if (api.BN_bin2bn(msg, (int)sizeof msg, m) == NULL)
            ok = 0;

        /* Pick a deterministic nonce k with k*G != infinity and r != 0. */
        for (;;) {
            scalar_for(seed, DOMAIN_SCALAR, i * 16 + probe, kb);
            probe++;
            if (api.BN_bin2bn(kb, 32, k) == NULL) {
                ok = 0;
                break;
            }
            if (api.EC_POINT_mul(group, pt, k, NULL, NULL, ctx) != 1 ||
                api.EC_POINT_get_affine_coordinates(group, pt, x, NULL, ctx) != 1 ||
                api.BN_nnmod(r, x, order, ctx) != 1) {
                ok = 0;
                break;
            }
            if (!api.BN_is_zero(r))
                break;
        }
        if (!ok)
            break;
        if (api.BN_mod_inverse(kinv, k, order, ctx) == NULL) {
            ok = 0;
            break;
        }

        sig = api.ECDSA_do_sign_ex(msg, (int)sizeof msg, kinv, r, key);
        if (sig == NULL) {
            fprintf(stderr, "pfp4_dso_sign: sign-ex failed at %u\n", i);
            ok = 0;
            break;
        }
        api.ECDSA_SIG_get0(sig, &sr, &ss);
        if (sr == NULL || ss == NULL || api.BN_cmp(sr, r) != 0) {
            fprintf(stderr, "pfp4_dso_sign: supplied r not used at %u\n", i);
            ok = 0;
        }
        /* s*k == m + r*d (mod n) */
        if (api.BN_nnmod(m, m, order, ctx) != 1 ||
            api.BN_mod_mul(lhs, ss, k, order, ctx) != 1 ||
            api.BN_mod_mul(rd, sr, d, order, ctx) != 1 ||
            api.BN_mod_add(rhs, m, rd, order, ctx) != 1 ||
            api.BN_cmp(lhs, rhs) != 0) {
            eq = 0;
            ok = 0;
        } else {
            eq = 1;
        }
        self = api.ECDSA_do_verify(msg, (int)sizeof msg, sig, key);
        if (self != 1)
            ok = 0;
        /* `ECDSA_sign_ex` must emit the same DER as the SIG object path. */
        {
            unsigned char *dbuf = NULL, *dp;
            unsigned char sbuf[512];
            unsigned int slen = 0;
            int dlen = api.i2d_ECDSA_SIG(sig, NULL);

            dbuf = (dlen > 0) ? malloc((size_t)dlen) : NULL;
            if (dbuf == NULL) {
                ok = 0;
            } else {
                dp = dbuf;
                if (api.i2d_ECDSA_SIG(sig, &dp) != dlen ||
                    api.ECDSA_sign_ex(0, msg, (int)sizeof msg, sbuf, &slen,
                                      kinv, r, key) != 1 ||
                    (int)slen != dlen || memcmp(sbuf, dbuf, (size_t)dlen) != 0) {
                    fprintf(stderr, "pfp4_dso_sign: ECDSA_sign_ex differs at %u\n",
                            i);
                    ok = 0;
                }
                free(dbuf);
            }
        }
        if (!emit_sig(f, i, sig, self, eq))
            ok = 0;
        api.ECDSA_SIG_free(sig);
    }
    fclose(f);
    api.EC_POINT_free(pt);
    api.EC_KEY_free(key);
    api.BN_free(d);
    api.BN_free(m);
    api.BN_free(lhs);
    api.BN_free(rd);
    api.BN_free(rhs);
    api.BN_free(x);
    api.BN_free(r);
    api.BN_free(k);
    api.BN_free(kinv);
    api.BN_CTX_free(ctx);
    return ok;
}

static unsigned char *read_file(const char *path, long *out_len)
{
    FILE *f = fopen(path, "rb");
    unsigned char *buf;
    long len;

    if (f == NULL)
        return NULL;
    if (fseek(f, 0, SEEK_END) != 0) {
        fclose(f);
        return NULL;
    }
    len = ftell(f);
    if (len < 0 || fseek(f, 0, SEEK_SET) != 0) {
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

static int run_verify(uint64_t seed, unsigned count, const char *sigfile)
{
    BN_CTX *ctx = api.BN_CTX_new();
    BIGNUM *d = NULL, *order = NULL;
    unsigned char pub_oct[POINT_LEN];
    EC_KEY *key;
    unsigned char *blob;
    long blob_len = 0, off = 0;
    unsigned i;
    int ok = 1;

    if (ctx == NULL)
        return 0;
    key = make_key(seed, ctx, &d, &order, pub_oct);
    if (key == NULL)
        return 0;
    printf("PUB ");
    print_hex(pub_oct, POINT_LEN);
    printf("\n");

    blob = read_file(sigfile, &blob_len);
    if (blob == NULL)
        return 0;

    for (i = 0; i < count && ok; i++) {
        unsigned char msg[32];
        unsigned long len;
        const unsigned char *p;
        ECDSA_SIG *sig;
        int verified;

        if (off + 4 > blob_len) {
            ok = 0;
            break;
        }
        len = ((unsigned long)blob[off] << 24) |
              ((unsigned long)blob[off + 1] << 16) |
              ((unsigned long)blob[off + 2] << 8) |
              (unsigned long)blob[off + 3];
        off += 4;
        if (off + (long)len > blob_len) {
            ok = 0;
            break;
        }
        p = blob + off;
        sig = api.d2i_ECDSA_SIG(NULL, &p, (long)len);
        off += (long)len;
        if (sig == NULL) {
            ok = 0;
            break;
        }
        bytes_for(seed, DOMAIN_MSG, i, msg);
        verified = api.ECDSA_do_verify(msg, (int)sizeof msg, sig, key);
        if (verified != 1)
            ok = 0;
        printf("VERIFY i=%u ok=%d\n", i, verified);
        api.ECDSA_SIG_free(sig);
    }
    free(blob);
    api.EC_KEY_free(key);
    api.BN_free(d);
    api.BN_CTX_free(ctx);
    return ok;
}

int main(int argc, char **argv)
{
    const char *lib = NULL, *mode = NULL, *sigfile = NULL;
    uint64_t seed = 0;
    unsigned count = 0;
    int i, ok = 0;

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
    }

    if (lib == NULL || mode == NULL || count == 0) {
        fprintf(stderr, "pfp4_dso_sign: --lib, --mode and --count are required\n");
        return 2;
    }
    if ((strcmp(mode, "sign-rand") == 0 || strcmp(mode, "sign-ex") == 0 ||
         strcmp(mode, "verify") == 0) &&
        sigfile == NULL) {
        fprintf(stderr, "pfp4_dso_sign: %s needs --sigfile\n", mode);
        return 2;
    }
    if (!load_api(lib))
        return 1;

    printf("SEED 0x%016llx\n", (unsigned long long)seed);
    printf("MODE %s\n", mode);

    if (strcmp(mode, "sign-rand") == 0)
        ok = run_sign_rand(seed, count, sigfile);
    else if (strcmp(mode, "sign-ex") == 0)
        ok = run_sign_ex(seed, count, sigfile);
    else if (strcmp(mode, "verify") == 0)
        ok = run_verify(seed, count, sigfile);
    else
        fprintf(stderr, "pfp4_dso_sign: unknown mode %s\n", mode);

    if (!ok) {
        fprintf(stderr, "pfp4_dso_sign: %s failed\n", mode);
        return 1;
    }
    return 0;
}
