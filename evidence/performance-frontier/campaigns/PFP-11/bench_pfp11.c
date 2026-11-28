/*
 * bench_pfp11.c — PFP-11 per-curve workload instrument.
 *
 * One OpenSSL-compatible `libcrypto.so.3` per process, selected with
 * `--lib <absolute path>` and opened `dlopen(RTLD_NOW | RTLD_LOCAL)`. The
 * harness is not linked against libcrypto and never has two mappings.
 *
 * Operations (one per invocation, so one process is one independent
 * repetition):
 *   ecdsa-sign    --curve p384|p521   ECDSA_do_sign over a 32-byte SHA-256 digest
 *   ecdsa-verify  --curve p384|p521   ECDSA_do_verify of a signature made in-process
 *   x25519-derive                     EVP_PKEY_derive over a fixed key pair
 *   ed25519-sign                      EVP_DigestSign one-shot
 *   ed25519-verify                    EVP_DigestVerify one-shot
 *
 * There is no configurable digest for Ed25519 (the algorithm fixes SHA-512);
 * ECDSA is driven with one digest (32 bytes, `0x44494700` operand source) so
 * every ECDSA row in this campaign uses the same digest length.
 *
 * Timing: warm-up of iters/4, then `runs` timed batches of `iters` calls.
 * Each sample is a batch mean in microseconds per call; the printed figure is
 * the median with min/max/spread. One process is one repetition.
 *
 * `--once` prints only the CHECK line, for the cross-library differential.
 *
 * Exit status is non-zero on any failed setup or self-check; a zero-time or
 * failed operation is never reported as a RESULT.
 */

#define _GNU_SOURCE
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/evp.h>
#include <openssl/obj_mac.h>

#include <dlfcn.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>

typedef struct {
    BIGNUM *(*BN_new)(void);
    void (*BN_free)(BIGNUM *);
    BIGNUM *(*BN_bin2bn)(const unsigned char *, int, BIGNUM *);
    BIGNUM *(*BN_copy)(BIGNUM *, const BIGNUM *);
    int (*BN_sub_word)(BIGNUM *, BN_ULONG);
    BN_CTX *(*BN_CTX_new)(void);
    void (*BN_CTX_free)(BN_CTX *);

    EC_KEY *(*EC_KEY_new_by_curve_name)(int);
    void (*EC_KEY_free)(EC_KEY *);
    const EC_GROUP *(*EC_KEY_get0_group)(const EC_KEY *);
    const BIGNUM *(*EC_GROUP_get0_order)(const EC_GROUP *);
    int (*EC_POINT_oct2point)(const EC_GROUP *, EC_POINT *, const unsigned char *,
                              size_t, BN_CTX *);
    int (*EC_KEY_set_private_key)(EC_KEY *, const BIGNUM *);
    int (*EC_KEY_set_public_key)(EC_KEY *, const EC_POINT *);
    EC_POINT *(*EC_POINT_new)(const EC_GROUP *);
    void (*EC_POINT_free)(EC_POINT *);
    int (*EC_POINT_mul)(const EC_GROUP *, EC_POINT *, const BIGNUM *,
                        const EC_POINT *, const BIGNUM *, BN_CTX *);
    size_t (*EC_POINT_point2oct)(const EC_GROUP *, const EC_POINT *,
                                 point_conversion_form_t, unsigned char *,
                                 size_t, BN_CTX *);
    ECDSA_SIG *(*ECDSA_do_sign)(const unsigned char *, int, EC_KEY *);
    int (*ECDSA_do_verify)(const unsigned char *, int, const ECDSA_SIG *,
                           EC_KEY *);
    void (*ECDSA_SIG_free)(ECDSA_SIG *);
    ECDSA_SIG *(*d2i_ECDSA_SIG)(ECDSA_SIG **, const unsigned char **, long);
    int (*i2d_ECDSA_SIG)(const ECDSA_SIG *, unsigned char **);

    EVP_PKEY *(*EVP_PKEY_new_raw_private_key)(int, void *, const unsigned char *,
                                              size_t);
    EVP_PKEY *(*EVP_PKEY_new_raw_public_key)(int, void *, const unsigned char *,
                                             size_t);
    int (*EVP_PKEY_get_raw_public_key)(const EVP_PKEY *, unsigned char *,
                                       size_t *);
    void (*EVP_PKEY_free)(EVP_PKEY *);

    EVP_PKEY_CTX *(*EVP_PKEY_CTX_new)(EVP_PKEY *, void *);
    void (*EVP_PKEY_CTX_free)(EVP_PKEY_CTX *);
    int (*EVP_PKEY_derive_init)(EVP_PKEY_CTX *);
    int (*EVP_PKEY_derive_set_peer)(EVP_PKEY_CTX *, EVP_PKEY *);
    int (*EVP_PKEY_derive)(EVP_PKEY_CTX *, unsigned char *, size_t *);

    EVP_MD_CTX *(*EVP_MD_CTX_new)(void);
    void (*EVP_MD_CTX_free)(EVP_MD_CTX *);
    int (*EVP_DigestSignInit)(EVP_MD_CTX *, EVP_PKEY_CTX **, const EVP_MD *,
                              void *, EVP_PKEY *);
    int (*EVP_DigestSign)(EVP_MD_CTX *, unsigned char *, size_t *,
                          const unsigned char *, size_t);
    int (*EVP_DigestVerifyInit)(EVP_MD_CTX *, EVP_PKEY_CTX **, const EVP_MD *,
                                void *, EVP_PKEY *);
    int (*EVP_DigestVerify)(EVP_MD_CTX *, const unsigned char *, size_t,
                            const unsigned char *, size_t);
} api_t;

static api_t api;
static const char *g_op;
static const char *g_curve;
static const char *g_pub;
static const char *g_dgst;
static const char *g_sig;
static int g_once;

static double now_us(void)
{
    struct timespec ts;

    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec * 1e6 + (double)ts.tv_nsec / 1e3;
}

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

static int load_api(const char *path)
{
    void *h = dlopen(path, RTLD_NOW | RTLD_LOCAL);

    if (h == NULL) {
        fprintf(stderr, "bench_pfp11: dlopen(%s): %s\n", path, dlerror());
        return 0;
    }
#define LOAD(field, symbol)                                                    \
    do {                                                                       \
        void *s = dlsym(h, symbol);                                            \
        if (s == NULL) {                                                       \
            fprintf(stderr, "bench_pfp11: missing %s\n", symbol);              \
            return 0;                                                          \
        }                                                                      \
        memcpy(&api.field, &s, sizeof(s));                                     \
    } while (0)

    LOAD(BN_new, "BN_new");
    LOAD(BN_free, "BN_free");
    LOAD(BN_bin2bn, "BN_bin2bn");
    LOAD(BN_copy, "BN_copy");
    LOAD(BN_sub_word, "BN_sub_word");
    LOAD(BN_CTX_new, "BN_CTX_new");
    LOAD(BN_CTX_free, "BN_CTX_free");

    LOAD(EC_KEY_new_by_curve_name, "EC_KEY_new_by_curve_name");
    LOAD(EC_KEY_free, "EC_KEY_free");
    LOAD(EC_KEY_get0_group, "EC_KEY_get0_group");
    LOAD(EC_GROUP_get0_order, "EC_GROUP_get0_order");
    LOAD(EC_POINT_oct2point, "EC_POINT_oct2point");
    LOAD(EC_KEY_set_private_key, "EC_KEY_set_private_key");
    LOAD(EC_KEY_set_public_key, "EC_KEY_set_public_key");
    LOAD(EC_POINT_new, "EC_POINT_new");
    LOAD(EC_POINT_free, "EC_POINT_free");
    LOAD(EC_POINT_mul, "EC_POINT_mul");
    LOAD(EC_POINT_point2oct, "EC_POINT_point2oct");
    LOAD(ECDSA_do_sign, "ECDSA_do_sign");
    LOAD(ECDSA_do_verify, "ECDSA_do_verify");
    LOAD(ECDSA_SIG_free, "ECDSA_SIG_free");
    LOAD(d2i_ECDSA_SIG, "d2i_ECDSA_SIG");
    LOAD(i2d_ECDSA_SIG, "i2d_ECDSA_SIG");

    LOAD(EVP_PKEY_new_raw_private_key, "EVP_PKEY_new_raw_private_key");
    LOAD(EVP_PKEY_new_raw_public_key, "EVP_PKEY_new_raw_public_key");
    LOAD(EVP_PKEY_get_raw_public_key, "EVP_PKEY_get_raw_public_key");
    LOAD(EVP_PKEY_free, "EVP_PKEY_free");
    LOAD(EVP_PKEY_CTX_new, "EVP_PKEY_CTX_new");
    LOAD(EVP_PKEY_CTX_free, "EVP_PKEY_CTX_free");
    LOAD(EVP_PKEY_derive_init, "EVP_PKEY_derive_init");
    LOAD(EVP_PKEY_derive_set_peer, "EVP_PKEY_derive_set_peer");
    LOAD(EVP_PKEY_derive, "EVP_PKEY_derive");
    LOAD(EVP_MD_CTX_new, "EVP_MD_CTX_new");
    LOAD(EVP_MD_CTX_free, "EVP_MD_CTX_free");
    LOAD(EVP_DigestSignInit, "EVP_DigestSignInit");
    LOAD(EVP_DigestSign, "EVP_DigestSign");
    LOAD(EVP_DigestVerifyInit, "EVP_DigestVerifyInit");
    LOAD(EVP_DigestVerify, "EVP_DigestVerify");
#undef LOAD

    {
        void *sym = NULL;
        Dl_info info;

        memcpy(&sym, &api.BN_new, sizeof(sym));
        if (sym != NULL && dladdr(sym, &info) != 0 && info.dli_fname != NULL)
            printf("LIB %s\n", info.dli_fname);
        else
            printf("LIB %s\n", path);
        fflush(stdout);
    }
    return 1;
}

static int measure(const char *name, int iters, int runs, int (*step)(void))
{
    int i, r, warm;
    double *s;

    warm = iters / 4;
    if (warm < 1)
        warm = 1;
    for (i = 0; i < warm; i++) {
        if (!step()) {
            fprintf(stderr, "bench_pfp11: warmup failed: %s\n", name);
            return 0;
        }
    }

    s = calloc((size_t)runs, sizeof(*s));
    if (s == NULL)
        return 0;
    for (r = 0; r < runs; r++) {
        double t0, t1;

        t0 = now_us();
        for (i = 0; i < iters; i++) {
            if (!step()) {
                fprintf(stderr, "bench_pfp11: run failed: %s\n", name);
                free(s);
                return 0;
            }
        }
        t1 = now_us();
        s[r] = (t1 - t0) / (double)iters;
    }
    for (i = 1; i < runs; i++) {
        double v = s[i];
        int j = i;

        while (j > 0 && s[j - 1] > v) {
            s[j] = s[j - 1];
            j--;
        }
        s[j] = v;
    }
    {
        double med = (runs % 2) ? s[runs / 2]
                                : (s[runs / 2 - 1] + s[runs / 2]) / 2.0;
        printf("RESULT %s curve=%s median_us=%.3f min_us=%.3f max_us=%.3f "
               "spread=%.4f iters=%d runs=%d\n",
               name, g_curve ? g_curve : "-", med, s[0], s[runs - 1],
               med > 0.0 ? (s[runs - 1] - s[0]) / med : 0.0, iters, runs);
        fflush(stdout);
    }
    free(s);
    return 1;
}

static void print_hex(const char *tag, const unsigned char *p, size_t n)
{
    size_t i;

    printf("%s ", tag);
    for (i = 0; i < n; i++)
        printf("%02x", p[i]);
    printf("\n");
}

/* ---- ECDSA P-384 / P-521 ------------------------------------------------ */

static EC_KEY *eck;
static unsigned char ec_dgst[32];
static ECDSA_SIG *ec_sig;

static int ec_curve_nid(void)
{
    if (strcmp(g_curve, "p384") == 0)
        return NID_secp384r1;
    if (strcmp(g_curve, "p521") == 0)
        return NID_secp521r1;
    return 0;
}

static size_t ec_scalar_len(void)
{
    return strcmp(g_curve, "p384") == 0 ? 48u : 66u;
}

static int ecdsa_setup(unsigned char *pubbuf, size_t *plen)
{
    BIGNUM *priv = NULL;
    EC_POINT *pub = NULL;
    BN_CTX *ctx = NULL;
    const EC_GROUP *grp;
    unsigned char sb[66];
    int nid = ec_curve_nid();
    size_t n = ec_scalar_len();

    if (nid == 0)
        return 0;
    eck = api.EC_KEY_new_by_curve_name(nid);
    if (eck == NULL)
        return 0;

    /* Top byte zero (and top bit of the next byte clear for P-521) keeps the
     * scalar well below the group order on both curves without needing the
     * order object in the harness. */
    memset(sb, 0, sizeof(sb));
    fill_seeded(UINT64_C(0x50313131), sb, n);
    sb[0] = 0;
    if (n > 32)
        sb[1] &= 0x3f;
    sb[n - 1] |= 1;

    priv = api.BN_bin2bn(sb, (int)n, NULL);
    if (priv == NULL || !api.EC_KEY_set_private_key(eck, priv))
        goto fail;
    grp = api.EC_KEY_get0_group(eck);
    if (grp == NULL)
        goto fail;
    pub = api.EC_POINT_new(grp);
    ctx = api.BN_CTX_new();
    if (pub == NULL || ctx == NULL)
        goto fail;
    if (!api.EC_POINT_mul(grp, pub, priv, NULL, NULL, ctx))
        goto fail;
    if (!api.EC_KEY_set_public_key(eck, pub))
        goto fail;
    *plen = api.EC_POINT_point2oct(grp, pub, POINT_CONVERSION_COMPRESSED,
                                   pubbuf, 133, ctx);
    if (*plen == 0)
        goto fail;
    api.BN_free(priv);
    api.EC_POINT_free(pub);
    api.BN_CTX_free(ctx);
    return 1;

fail:
    if (priv)
        api.BN_free(priv);
    if (pub)
        api.EC_POINT_free(pub);
    if (ctx)
        api.BN_CTX_free(ctx);
    if (eck)
        api.EC_KEY_free(eck);
    eck = NULL;
    return 0;
}

static int ec_sign_step(void)
{
    ECDSA_SIG *s = api.ECDSA_do_sign(ec_dgst, (int)sizeof(ec_dgst), eck);

    if (s == NULL)
        return 0;
    api.ECDSA_SIG_free(s);
    return 1;
}

static int ec_verify_step(void)
{
    return api.ECDSA_do_verify(ec_dgst, (int)sizeof(ec_dgst), ec_sig, eck) == 1;
}

static int run_ecdsa(int iters, int runs, int sign)
{
    unsigned char pubbuf[133];
    size_t plen = 0;
    int ok;

    if (!ecdsa_setup(pubbuf, &plen)) {
        fprintf(stderr, "bench_pfp11: ecdsa setup failed\n");
        return 0;
    }
    fill_seeded(UINT64_C(0x44494700), ec_dgst, sizeof(ec_dgst));
    ec_sig = api.ECDSA_do_sign(ec_dgst, (int)sizeof(ec_dgst), eck);
    if (ec_sig == NULL || api.ECDSA_do_verify(ec_dgst, (int)sizeof(ec_dgst),
                                              ec_sig, eck) != 1) {
        fprintf(stderr, "bench_pfp11: ecdsa self-check failed\n");
        return 0;
    }
    printf("CHECK ecdsa-%s pub=", g_curve);
    {
        size_t i;

        for (i = 0; i < plen; i++)
            printf("%02x", pubbuf[i]);
    }
    printf(" verify=1\n");
    fflush(stdout);

    if (g_once) {
        api.ECDSA_SIG_free(ec_sig);
        ec_sig = NULL;
        api.EC_KEY_free(eck);
        eck = NULL;
        return 1;
    }
    ok = measure(sign ? "ecdsa-sign" : "ecdsa-verify", iters, runs,
                 sign ? ec_sign_step : ec_verify_step);
    api.ECDSA_SIG_free(ec_sig);
    ec_sig = NULL;
    api.EC_KEY_free(eck);
    eck = NULL;
    return ok;
}

/* ---- X25519 ------------------------------------------------------------- */

static EVP_PKEY *x_priv;
static EVP_PKEY *x_peer;
static EVP_PKEY_CTX *x_ctx;
static size_t x_secret_len;

static int x25519_setup(unsigned char *secret)
{
    unsigned char a[32], b[32], bpub[32];
    size_t blen = sizeof(bpub);

    fill_seeded(UINT64_C(0x58323535), a, sizeof(a));
    fill_seeded(UINT64_C(0x50454552), b, sizeof(b));
    x_priv = api.EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, NULL, a,
                                              sizeof(a));
    {
        EVP_PKEY *tmp = api.EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, NULL,
                                                         b, sizeof(b));

        if (tmp == NULL)
            return 0;
        if (!api.EVP_PKEY_get_raw_public_key(tmp, bpub, &blen)) {
            api.EVP_PKEY_free(tmp);
            return 0;
        }
        api.EVP_PKEY_free(tmp);
    }
    if (x_priv == NULL)
        return 0;
    x_peer = api.EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, NULL, bpub, blen);
    if (x_peer == NULL)
        return 0;
    x_ctx = api.EVP_PKEY_CTX_new(x_priv, NULL);
    if (x_ctx == NULL)
        return 0;
    if (api.EVP_PKEY_derive_init(x_ctx) <= 0)
        return 0;
    if (api.EVP_PKEY_derive_set_peer(x_ctx, x_peer) <= 0)
        return 0;
    x_secret_len = 32;
    if (api.EVP_PKEY_derive(x_ctx, secret, &x_secret_len) <= 0)
        return 0;
    return 1;
}

static int x25519_step(void)
{
    unsigned char secret[64];
    size_t len = sizeof(secret);

    return api.EVP_PKEY_derive(x_ctx, secret, &len) > 0;
}

static int run_x25519(int iters, int runs)
{
    unsigned char secret[64];
    int ok;

    if (!x25519_setup(secret)) {
        fprintf(stderr, "bench_pfp11: x25519 setup failed\n");
        return 0;
    }
    print_hex("CHECK x25519-derive shared=", secret, x_secret_len);
    fflush(stdout);
    if (g_once) {
        api.EVP_PKEY_CTX_free(x_ctx);
        api.EVP_PKEY_free(x_peer);
        api.EVP_PKEY_free(x_priv);
        return 1;
    }
    ok = measure("x25519-derive", iters, runs, x25519_step);
    api.EVP_PKEY_CTX_free(x_ctx);
    api.EVP_PKEY_free(x_peer);
    api.EVP_PKEY_free(x_priv);
    return ok;
}

/* ---- Ed25519 ------------------------------------------------------------ */

static EVP_PKEY *ed_key;
static unsigned char ed_msg[64];
static unsigned char ed_sig[64];
static size_t ed_siglen = sizeof(ed_sig);

static int ed25519_setup(void)
{
    unsigned char seed[32], pub[32];
    size_t publen = sizeof(pub);

    fill_seeded(UINT64_C(0x45443235), seed, sizeof(seed));
    ed_key = api.EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, NULL, seed,
                                              sizeof(seed));
    if (ed_key == NULL)
        return 0;
    if (!api.EVP_PKEY_get_raw_public_key(ed_key, pub, &publen))
        return 0;
    fill_seeded(UINT64_C(0x4d534730), ed_msg, sizeof(ed_msg));
    print_hex("CHECK ed25519 pub=", pub, publen);
    return 1;
}

static int ed_sign_step(void)
{
    EVP_MD_CTX *m = api.EVP_MD_CTX_new();
    size_t n = sizeof(ed_sig);
    int ok;

    if (m == NULL)
        return 0;
    ok = api.EVP_DigestSignInit(m, NULL, NULL, NULL, ed_key) > 0 &&
         api.EVP_DigestSign(m, ed_sig, &n, ed_msg, sizeof(ed_msg)) > 0;
    api.EVP_MD_CTX_free(m);
    return ok;
}

static int ed_verify_step(void)
{
    EVP_MD_CTX *m = api.EVP_MD_CTX_new();
    int ok;

    if (m == NULL)
        return 0;
    ok = api.EVP_DigestVerifyInit(m, NULL, NULL, NULL, ed_key) > 0 &&
         api.EVP_DigestVerify(m, ed_sig, ed_siglen, ed_msg, sizeof(ed_msg)) == 1;
    api.EVP_MD_CTX_free(m);
    return ok;
}

static int run_ed25519(int iters, int runs, int sign)
{
    int ok;

    if (!ed25519_setup()) {
        fprintf(stderr, "bench_pfp11: ed25519 setup failed\n");
        return 0;
    }
    if (!ed_sign_step() || !ed_verify_step()) {
        fprintf(stderr, "bench_pfp11: ed25519 self-check failed\n");
        return 0;
    }
    print_hex("CHECK ed25519 sig=", ed_sig, ed_siglen);
    fflush(stdout);
    if (g_once) {
        api.EVP_PKEY_free(ed_key);
        return 1;
    }
    ok = measure(sign ? "ed25519-sign" : "ed25519-verify", iters, runs,
                 sign ? ed_sign_step : ed_verify_step);
    api.EVP_PKEY_free(ed_key);
    return ok;
}

/* ---- differential population (PFP-22 classes where they apply) -------- */

static void hex_enc(const unsigned char *p, size_t n, char *out)
{
    static const char d[] = "0123456789abcdef";
    size_t i;

    for (i = 0; i < n; i++) {
        out[2 * i] = d[p[i] >> 4];
        out[2 * i + 1] = d[p[i] & 15];
    }
    out[2 * n] = '\0';
}

static int hex_nib(char c)
{
    if (c >= '0' && c <= '9')
        return c - '0';
    if (c >= 'a' && c <= 'f')
        return c - 'a' + 10;
    if (c >= 'A' && c <= 'F')
        return c - 'A' + 10;
    return -1;
}

static int hex_dec(const char *s, unsigned char *out, size_t cap, size_t *n)
{
    size_t len = strlen(s), i;

    if (len % 2 != 0 || len / 2 > cap)
        return 0;
    for (i = 0; i < len / 2; i++) {
        int a = hex_nib(s[2 * i]), b = hex_nib(s[2 * i + 1]);

        if (a < 0 || b < 0)
            return 0;
        out[i] = (unsigned char)((a << 4) | b);
    }
    *n = len / 2;
    return 1;
}

static int ecdsa_one_case(const BIGNUM *priv, const unsigned char *dgst,
                          size_t dlen, int k)
{
    const EC_GROUP *grp = api.EC_KEY_get0_group(eck);
    EC_POINT *pub = NULL;
    BN_CTX *ctx = NULL;
    ECDSA_SIG *s = NULL;
    unsigned char pubbuf[133], *der = NULL, *q;
    char pubhex[300], dgsthex[300], sighex[600];
    size_t plen;
    int len, ok = 0;

    pub = api.EC_POINT_new(grp);
    ctx = api.BN_CTX_new();
    if (pub == NULL || ctx == NULL || grp == NULL)
        goto out;
    if (!api.EC_KEY_set_private_key(eck, priv))
        goto out;
    if (!api.EC_POINT_mul(grp, pub, priv, NULL, NULL, ctx))
        goto out;
    if (!api.EC_KEY_set_public_key(eck, pub))
        goto out;
    plen = api.EC_POINT_point2oct(grp, pub, POINT_CONVERSION_UNCOMPRESSED,
                                  pubbuf, sizeof(pubbuf), ctx);
    if (plen == 0)
        goto out;
    s = api.ECDSA_do_sign(dgst, (int)dlen, eck);
    if (s == NULL || api.ECDSA_do_verify(dgst, (int)dlen, s, eck) != 1)
        goto out;
    len = api.i2d_ECDSA_SIG(s, NULL);
    if (len <= 0)
        goto out;
    der = malloc((size_t)len);
    if (der == NULL)
        goto out;
    q = der;
    if (api.i2d_ECDSA_SIG(s, &q) != len)
        goto out;

    hex_enc(pubbuf, plen, pubhex);
    hex_enc(dgst, dlen, dgsthex);
    hex_enc(der, (size_t)len, sighex);
    printf("CASE %s k=%d pub=%s dgst=%s sig=%s verify=1\n", g_curve, k,
           pubhex, dgsthex, sighex);
    ok = 1;
out:
    if (s)
        api.ECDSA_SIG_free(s);
    free(der);
    if (pub)
        api.EC_POINT_free(pub);
    if (ctx)
        api.BN_CTX_free(ctx);
    return ok;
}

static int run_ecdsa_diff(void)
{
    const EC_GROUP *grp;
    const BIGNUM *order;
    unsigned char dg[6][66];
    static const size_t dgl[6] = {32, 32, 32, 32, 64, 66};
    unsigned char sb[66];
    size_t n = ec_scalar_len();
    int i, j, k = 0, ok = 1;

    eck = api.EC_KEY_new_by_curve_name(ec_curve_nid());
    if (eck == NULL)
        return 0;
    grp = api.EC_KEY_get0_group(eck);
    order = api.EC_GROUP_get0_order(grp);
    if (order == NULL)
        return 0;

    memset(dg[0], 0, 32); /* zero digest */
    memset(dg[1], 0xff, 32); /* 2^256-1: > q for neither curve, < q */
    fill_seeded(UINT64_C(0x44473031), dg[2], 32);
    fill_seeded(UINT64_C(0x44473032), dg[3], 32);
    memset(dg[4], 0xff, 64); /* 2^512-1: > q for P-384 */
    memset(dg[5], 0xff, 66); /* 2^528-1: > q for both */

    /* Small scalars, pseudorandom scalars, and the order boundary q-1, q-2. */
    for (i = 0; i < 8 && ok; i++) {
        BIGNUM *priv = NULL;

        memset(sb, 0, sizeof(sb));
        if (i < 3) {
            sb[n - 1] = (unsigned char)(i + 1);
            priv = api.BN_bin2bn(sb, (int)n, NULL);
        } else if (i < 6) {
            fill_seeded(UINT64_C(0x50524956) + (uint64_t)i, sb, n);
            sb[0] = 0;
            if (n > 32)
                sb[1] &= 0x3f;
            sb[n - 1] |= 1;
            priv = api.BN_bin2bn(sb, (int)n, NULL);
        } else {
            priv = api.BN_new();
            if (priv != NULL && api.BN_copy(priv, order) == NULL) {
                api.BN_free(priv);
                priv = NULL;
            }
            if (priv != NULL)
                api.BN_sub_word(priv, (BN_ULONG)(i == 6 ? 1 : 2));
        }
        if (priv == NULL) {
            ok = 0;
            break;
        }
        for (j = 0; j < 6; j++)
            if (ok && !ecdsa_one_case(priv, dg[j], dgl[j], k++))
                ok = 0;
        api.BN_free(priv);
    }
    api.EC_KEY_free(eck);
    eck = NULL;
    return ok;
}

static int run_ecdsa_verify_external(const char *pubhex, const char *dgsthex,
                                     const char *sighex)
{
    unsigned char pubbuf[200], dgst[200], sigbuf[600];
    size_t plen = 0, dlen = 0, slen = 0;
    const EC_GROUP *grp;
    EC_POINT *pub = NULL;
    BN_CTX *ctx = NULL;
    ECDSA_SIG *s = NULL;
    const unsigned char *p;
    int ret = 0;

    if (!hex_dec(pubhex, pubbuf, sizeof(pubbuf), &plen) ||
        !hex_dec(dgsthex, dgst, sizeof(dgst), &dlen) ||
        !hex_dec(sighex, sigbuf, sizeof(sigbuf), &slen))
        return 0;
    eck = api.EC_KEY_new_by_curve_name(ec_curve_nid());
    if (eck == NULL)
        return 0;
    grp = api.EC_KEY_get0_group(eck);
    pub = api.EC_POINT_new(grp);
    ctx = api.BN_CTX_new();
    if (pub == NULL || ctx == NULL)
        goto out;
    if (!api.EC_POINT_oct2point(grp, pub, pubbuf, plen, ctx))
        goto out;
    if (!api.EC_KEY_set_public_key(eck, pub))
        goto out;
    p = sigbuf;
    s = api.d2i_ECDSA_SIG(NULL, &p, (long)slen);
    if (s == NULL)
        goto out;
    ret = api.ECDSA_do_verify(dgst, (int)dlen, s, eck);
    printf("EXTERNAL verify=%d\n", ret);
out:
    if (s)
        api.ECDSA_SIG_free(s);
    if (pub)
        api.EC_POINT_free(pub);
    if (ctx)
        api.BN_CTX_free(ctx);
    api.EC_KEY_free(eck);
    eck = NULL;
    return ret == 1;
}

static int run_ed25519_diff(void)
{
    static const size_t mlen[4] = {0, 1, 64, 64};
    unsigned char seed[32], msg[64];
    int s, m;

    for (s = 0; s < 8; s++) {
        unsigned char pub[32];
        size_t publen = sizeof(pub);
        EVP_PKEY *key;

        if (s == 0)
            memset(seed, 0, 32);
        else if (s == 1)
            memset(seed, 0xff, 32);
        else
            fill_seeded(UINT64_C(0x45443244) + (uint64_t)s, seed, 32);
        key = api.EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, NULL, seed, 32);
        if (key == NULL)
            return 0;
        if (!api.EVP_PKEY_get_raw_public_key(key, pub, &publen))
            return 0;
        for (m = 0; m < 4; m++) {
            unsigned char sig[64];
            size_t siglen = sizeof(sig);
            EVP_MD_CTX *mc = api.EVP_MD_CTX_new();
            EVP_MD_CTX *mv;
            int ok;

            if (m == 3)
                memset(msg, 0xff, mlen[m]);
            else
                fill_seeded(UINT64_C(0x4d534744) + (uint64_t)m, msg, mlen[m]);
            if (mc == NULL)
                return 0;
            ok = api.EVP_DigestSignInit(mc, NULL, NULL, NULL, key) > 0 &&
                 api.EVP_DigestSign(mc, sig, &siglen, msg, mlen[m]) > 0;
            api.EVP_MD_CTX_free(mc);
            if (!ok)
                return 0;
            mv = api.EVP_MD_CTX_new();
            if (mv == NULL)
                return 0;
            ok = api.EVP_DigestVerifyInit(mv, NULL, NULL, NULL, key) > 0 &&
                 api.EVP_DigestVerify(mv, sig, siglen, msg, mlen[m]) == 1;
            api.EVP_MD_CTX_free(mv);
            if (!ok)
                return 0;
            {
                char pubhex[80], sighex[160];

                hex_enc(pub, publen, pubhex);
                hex_enc(sig, siglen, sighex);
                printf("CASE ed25519 s=%d m=%d pub=%s sig=%s verify=1\n", s, m,
                       pubhex, sighex);
            }
        }
        api.EVP_PKEY_free(key);
    }
    return 1;
}

static int run_x25519_diff(void)
{
    int a, b;

    for (a = 0; a < 6; a++) {
        unsigned char pa[32];

        if (a == 0)
            memset(pa, 0, 32);
        else if (a == 1)
            memset(pa, 0xff, 32);
        else
            fill_seeded(UINT64_C(0x58324141) + (uint64_t)a, pa, 32);
        for (b = 0; b < 6; b++) {
            unsigned char pb[32], bpub[32], secret[64];
            size_t blen = sizeof(bpub), slen = sizeof(secret);
            EVP_PKEY *ka, *pbkey, *peer;
            EVP_PKEY_CTX *cx;
            int ok;

            if (b == 0)
                memset(pb, 0, 32);
            else if (b == 1)
                memset(pb, 0xff, 32);
            else
                fill_seeded(UINT64_C(0x58324242) + (uint64_t)b, pb, 32);
            ka = api.EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, NULL, pa, 32);
            pbkey = api.EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, NULL, pb, 32);
            if (ka == NULL || pbkey == NULL)
                return 0;
            if (!api.EVP_PKEY_get_raw_public_key(pbkey, bpub, &blen))
                return 0;
            api.EVP_PKEY_free(pbkey);
            peer = api.EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, NULL, bpub, blen);
            if (peer == NULL)
                return 0;
            cx = api.EVP_PKEY_CTX_new(ka, NULL);
            if (cx == NULL)
                return 0;
            ok = api.EVP_PKEY_derive_init(cx) > 0 &&
                 api.EVP_PKEY_derive_set_peer(cx, peer) > 0 &&
                 api.EVP_PKEY_derive(cx, secret, &slen) > 0;
            if (ok) {
                char shex[160];

                hex_enc(secret, slen, shex);
                printf("CASE x25519 a=%d b=%d shared=%s derive=1\n", a, b, shex);
            } else {
                printf("CASE x25519 a=%d b=%d shared=- derive=0\n", a, b);
            }
            api.EVP_PKEY_CTX_free(cx);
            api.EVP_PKEY_free(peer);
            api.EVP_PKEY_free(ka);
        }
    }
    return 1;
}

/* ---- driver ------------------------------------------------------------- */

static void usage(void)
{
    fprintf(stderr,
            "usage: bench_pfp11 --lib PATH --op OP [--curve p384|p521] "
            "[--iters N] [--runs N] [--once] [--pub HEX --dgst HEX --sig HEX]\n");
}

int main(int argc, char **argv)
{
    const char *lib = NULL;
    int iters = 20, runs = 1, i, ok;

    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--lib") == 0 && i + 1 < argc)
            lib = argv[++i];
        else if (strcmp(argv[i], "--op") == 0 && i + 1 < argc)
            g_op = argv[++i];
        else if (strcmp(argv[i], "--curve") == 0 && i + 1 < argc)
            g_curve = argv[++i];
        else if (strcmp(argv[i], "--pub") == 0 && i + 1 < argc)
            g_pub = argv[++i];
        else if (strcmp(argv[i], "--dgst") == 0 && i + 1 < argc)
            g_dgst = argv[++i];
        else if (strcmp(argv[i], "--sig") == 0 && i + 1 < argc)
            g_sig = argv[++i];
        else if (strcmp(argv[i], "--iters") == 0 && i + 1 < argc)
            iters = atoi(argv[++i]);
        else if (strcmp(argv[i], "--runs") == 0 && i + 1 < argc)
            runs = atoi(argv[++i]);
        else if (strcmp(argv[i], "--once") == 0)
            g_once = 1;
        else {
            usage();
            return 2;
        }
    }
    if (lib == NULL || g_op == NULL) {
        usage();
        return 2;
    }
    if ((strcmp(g_op, "ecdsa-sign") == 0 || strcmp(g_op, "ecdsa-verify") == 0 ||
         strcmp(g_op, "ecdsa-diff") == 0 ||
         strcmp(g_op, "ecdsa-verify-external") == 0) &&
        g_curve == NULL) {
        usage();
        return 2;
    }
    if (strcmp(g_op, "ecdsa-verify-external") == 0 &&
        (g_pub == NULL || g_dgst == NULL || g_sig == NULL)) {
        usage();
        return 2;
    }
    if (!load_api(lib))
        return 1;

    if (strcmp(g_op, "ecdsa-sign") == 0)
        ok = run_ecdsa(iters, runs, 1);
    else if (strcmp(g_op, "ecdsa-verify") == 0)
        ok = run_ecdsa(iters, runs, 0);
    else if (strcmp(g_op, "x25519-derive") == 0)
        ok = run_x25519(iters, runs);
    else if (strcmp(g_op, "ed25519-sign") == 0)
        ok = run_ed25519(iters, runs, 1);
    else if (strcmp(g_op, "ed25519-verify") == 0)
        ok = run_ed25519(iters, runs, 0);
    else if (strcmp(g_op, "ecdsa-diff") == 0)
        ok = run_ecdsa_diff();
    else if (strcmp(g_op, "ecdsa-verify-external") == 0)
        ok = run_ecdsa_verify_external(g_pub, g_dgst, g_sig);
    else if (strcmp(g_op, "ed25519-diff") == 0)
        ok = run_ed25519_diff();
    else if (strcmp(g_op, "x25519-diff") == 0)
        ok = run_x25519_diff();
    else {
        usage();
        return 2;
    }
    return ok ? 0 : 1;
}
