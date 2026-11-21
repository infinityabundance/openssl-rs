/*
 * bench_api.c — T21 cross-library workload benchmark.
 *
 * Runs one OpenSSL-compatible workload through exactly one `libcrypto.so.3`
 * per process. The library is selected at run time with `--lib <absolute path>`
 * and opened with `dlopen(RTLD_NOW | RTLD_LOCAL)`, so:
 *
 *   * the harness itself is not linked against libcrypto, and carries no
 *     link-time symbol-version requirement that could couple it to one build;
 *   * a process never has two libcrypto mappings (one invocation, one library);
 *   * the library that actually served the calls is printed (`LIB ...`, taken
 *     from dladdr(BN_new)), so the runner can prove which DSO ran.
 *
 * Workloads (identical byte inputs on both sides — no BN_rand):
 *   modexp2048 / modexp8192  BN_mod_exp_mont_consttime, full-width exponent
 *   dh2048 / dh3072          DH_compute_key, full-width private exponent
 *   rsa2048                  RSA_private_encrypt(RSA_NO_PADDING), CRT key
 *   ecdsa256                 ECDSA_do_sign on P-256
 *
 * Correctness:
 *   * rsa2048: the private result is fed back through RSA_public_decrypt and
 *     must recover the input in the same process;
 *   * ecdsa256: each signature is verified with ECDSA_do_verify and the derived
 *     public key is printed;
 *   * modexp/dh: the deterministic result is printed; the runner requires the
 *     candidate and authority lines to be byte-identical (the authority's value
 *     is the known answer);
 *   * every printed CHECK line is compared between the two processes.
 *
 * Timing method: one warm-up pass of iters/4, then `runs` timed batches of
 * `iters` calls each. Each sample is a batch mean in microseconds per call;
 * the reported figure is the median sample, with min/max and relative spread.
 *
 * Allocation counts: in `--alloc` mode the harness calls the weak
 * `allocprobe_reset`/`allocprobe_mallocs` hooks exported by alloc_probe.so
 * (LD_PRELOAD), does one short batch, and reports mallocs per call. Without the
 * preload the hooks are NULL and the line says `n/a`.
 */

#define _GNU_SOURCE
#include <openssl/bn.h>
#include <openssl/dh.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/obj_mac.h>
#include <openssl/rsa.h>

#include <dlfcn.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

extern void allocprobe_reset(void) __attribute__((weak));
extern unsigned long allocprobe_mallocs(void) __attribute__((weak));

typedef struct {
    BIGNUM *(*BN_new)(void);
    void (*BN_free)(BIGNUM *);
    BIGNUM *(*BN_bin2bn)(const unsigned char *, int, BIGNUM *);
    int (*BN_set_word)(BIGNUM *, BN_ULONG);
    int (*BN_bn2binpad)(const BIGNUM *, unsigned char *, int);
    BN_CTX *(*BN_CTX_new)(void);
    void (*BN_CTX_free)(BN_CTX *);
    int (*BN_mod_exp_mont_consttime)(BIGNUM *, const BIGNUM *, const BIGNUM *,
                                     const BIGNUM *, BN_CTX *, BN_MONT_CTX *);

    DH *(*DH_new)(void);
    void (*DH_free)(DH *);
    int (*DH_set0_pqg)(DH *, BIGNUM *, BIGNUM *, BIGNUM *);
    int (*DH_set0_key)(DH *, BIGNUM *, BIGNUM *);
    int (*DH_compute_key)(unsigned char *, const BIGNUM *, DH *);
    int (*DH_size)(const DH *);

    RSA *(*d2i_RSAPrivateKey)(RSA **, const unsigned char **, long);
    void (*RSA_free)(RSA *);
    int (*RSA_size)(const RSA *);
    int (*RSA_private_encrypt)(int, const unsigned char *, unsigned char *,
                               RSA *, int);
    int (*RSA_public_decrypt)(int, const unsigned char *, unsigned char *,
                              RSA *, int);

    EC_KEY *(*EC_KEY_new_by_curve_name)(int);
    void (*EC_KEY_free)(EC_KEY *);
    const EC_GROUP *(*EC_KEY_get0_group)(const EC_KEY *);
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
} api_t;

static api_t api;

static double now_us(void)
{
    struct timespec ts;

    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec * 1e6 + (double)ts.tv_nsec / 1e3;
}

/* Deterministic byte source: xorshift64, seeded per operand. */
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

/*
 * Fill n bytes deterministically. `top_set` sets/clears the top bit; `odd`
 * sets/clears the low bit. With the top bit clear the value is < 2^(8n-1), so a
 * same-width modulus with the top bit set is strictly larger.
 */
static void make_operand(unsigned char *p, size_t n, uint64_t seed,
                         int top_set, int odd)
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

static int load_api(const char *path)
{
    void *h = dlopen(path, RTLD_NOW | RTLD_LOCAL);

    if (h == NULL) {
        fprintf(stderr, "bench_api: dlopen(%s): %s\n", path, dlerror());
        return 0;
    }
#define LOAD(field, symbol)                                                    \
    do {                                                                       \
        void *s = dlsym(h, symbol);                                            \
        if (s == NULL) {                                                       \
            fprintf(stderr, "bench_api: missing %s\n", symbol);                \
            return 0;                                                          \
        }                                                                      \
        memcpy(&api.field, &s, sizeof(s));                                     \
    } while (0)

    LOAD(BN_new, "BN_new");
    LOAD(BN_free, "BN_free");
    LOAD(BN_bin2bn, "BN_bin2bn");
    LOAD(BN_set_word, "BN_set_word");
    LOAD(BN_bn2binpad, "BN_bn2binpad");
    LOAD(BN_CTX_new, "BN_CTX_new");
    LOAD(BN_CTX_free, "BN_CTX_free");
    LOAD(BN_mod_exp_mont_consttime, "BN_mod_exp_mont_consttime");

    LOAD(DH_new, "DH_new");
    LOAD(DH_free, "DH_free");
    LOAD(DH_set0_pqg, "DH_set0_pqg");
    LOAD(DH_set0_key, "DH_set0_key");
    LOAD(DH_compute_key, "DH_compute_key");
    LOAD(DH_size, "DH_size");

    LOAD(d2i_RSAPrivateKey, "d2i_RSAPrivateKey");
    LOAD(RSA_free, "RSA_free");
    LOAD(RSA_size, "RSA_size");
    LOAD(RSA_private_encrypt, "RSA_private_encrypt");
    LOAD(RSA_public_decrypt, "RSA_public_decrypt");

    LOAD(EC_KEY_new_by_curve_name, "EC_KEY_new_by_curve_name");
    LOAD(EC_KEY_free, "EC_KEY_free");
    LOAD(EC_KEY_get0_group, "EC_KEY_get0_group");
    LOAD(EC_KEY_set_private_key, "EC_KEY_set_private_key");
    LOAD(EC_KEY_set_public_key, "EC_KEY_set_public_key");
    LOAD(EC_POINT_new, "EC_POINT_new");
    LOAD(EC_POINT_free, "EC_POINT_free");
    LOAD(EC_POINT_mul, "EC_POINT_mul");
    LOAD(EC_POINT_point2oct, "EC_POINT_point2oct");
    LOAD(ECDSA_do_sign, "ECDSA_do_sign");
    LOAD(ECDSA_do_verify, "ECDSA_do_verify");
    LOAD(ECDSA_SIG_free, "ECDSA_SIG_free");
#undef LOAD

    {
        void *sym = NULL;
        Dl_info info;

        memcpy(&sym, &api.BN_new, sizeof(sym));
        if (sym != NULL && dladdr(sym, &info) != 0 && info.dli_fname != NULL)
            printf("LIB %s\n", info.dli_fname);
        else
            printf("LIB %s\n", path);
    }
    return 1;
}

static int measure(const char *name, int iters, int runs, int (*step)(void),
                   int alloc_mode)
{
    int i, r, warm;

    warm = iters / 4;
    if (warm < 1)
        warm = 1;
    for (i = 0; i < warm; i++) {
        if (!step()) {
            fprintf(stderr, "bench_api: warmup failed: %s\n", name);
            return 0;
        }
    }

    if (alloc_mode) {
        int probe = (allocprobe_reset != NULL && allocprobe_mallocs != NULL);

        if (probe)
            allocprobe_reset();
        for (i = 0; i < iters; i++) {
            if (!step()) {
                fprintf(stderr, "bench_api: alloc run failed: %s\n", name);
                return 0;
            }
        }
        if (probe)
            printf("ALLOC %s allocs_per_op=%.3f iters=%d\n", name,
                   (double)allocprobe_mallocs() / (double)iters, iters);
        else
            printf("ALLOC %s allocs_per_op=n/a iters=%d\n", name, iters);
        fflush(stdout);
        return 1;
    }

    {
        double *s = calloc((size_t)runs, sizeof(*s));
        double med, mn, mx;

        if (s == NULL)
            return 0;
        for (r = 0; r < runs; r++) {
            double t0, t1;

            t0 = now_us();
            for (i = 0; i < iters; i++) {
                if (!step()) {
                    fprintf(stderr, "bench_api: run failed: %s\n", name);
                    free(s);
                    return 0;
                }
            }
            t1 = now_us();
            s[r] = (t1 - t0) / (double)iters;
        }
        /* Insertion sort: runs is small. */
        for (i = 1; i < runs; i++) {
            double v = s[i];
            int j = i;

            while (j > 0 && s[j - 1] > v) {
                s[j] = s[j - 1];
                j--;
            }
            s[j] = v;
        }
        med = (runs % 2) ? s[runs / 2]
                         : (s[runs / 2 - 1] + s[runs / 2]) / 2.0;
        mn = s[0];
        mx = s[runs - 1];
        printf("RESULT %s median_us=%.3f min_us=%.3f max_us=%.3f "
               "spread=%.4f iters=%d runs=%d\n",
               name, med, mn, mx, med > 0.0 ? (mx - mn) / med : 0.0, iters,
               runs);
        fflush(stdout);
        free(s);
    }
    return 1;
}

/* ---- raw modular exponentiation --------------------------------------- */

static BIGNUM *mx_m, *mx_e, *mx_a, *mx_r;
static BN_CTX *mx_ctx;

static int mx_step(void)
{
    return api.BN_mod_exp_mont_consttime(mx_r, mx_a, mx_e, mx_m, mx_ctx, NULL);
}

static int run_modexp(const char *name, int bits, int iters, int runs,
                      int alloc_mode)
{
    size_t n = (size_t)bits / 8;
    unsigned char *mb = malloc(n), *eb = malloc(n), *ab = malloc(n),
                  *ob = malloc(n);
    size_t i;
    int ok = 0;

    if (mb == NULL || eb == NULL || ab == NULL || ob == NULL)
        goto out;
    make_operand(mb, n, UINT64_C(0x4d4f4400) + (uint64_t)bits, 1, 1);
    make_operand(eb, n, UINT64_C(0x45585000) + (uint64_t)bits, 1, 1);
    make_operand(ab, n, UINT64_C(0x42415300) + (uint64_t)bits, 0, 1);

    mx_m = api.BN_bin2bn(mb, (int)n, NULL);
    mx_e = api.BN_bin2bn(eb, (int)n, NULL);
    mx_a = api.BN_bin2bn(ab, (int)n, NULL);
    mx_r = api.BN_new();
    mx_ctx = api.BN_CTX_new();
    if (mx_m == NULL || mx_e == NULL || mx_a == NULL || mx_r == NULL ||
        mx_ctx == NULL)
        goto out;

    if (!api.BN_mod_exp_mont_consttime(mx_r, mx_a, mx_e, mx_m, mx_ctx, NULL))
        goto out;
    if (api.BN_bn2binpad(mx_r, ob, (int)n) != (int)n)
        goto out;
    printf("CHECK %s hex=", name);
    for (i = 0; i < n; i++)
        printf("%02x", ob[i]);
    printf("\n");
    fflush(stdout);

    ok = measure(name, iters, runs, mx_step, alloc_mode);

out:
    if (mx_m)
        api.BN_free(mx_m);
    if (mx_e)
        api.BN_free(mx_e);
    if (mx_a)
        api.BN_free(mx_a);
    if (mx_r)
        api.BN_free(mx_r);
    if (mx_ctx)
        api.BN_CTX_free(mx_ctx);
    free(mb);
    free(eb);
    free(ab);
    free(ob);
    mx_m = mx_e = mx_a = mx_r = NULL;
    mx_ctx = NULL;
    return ok;
}

/* ---- DH shared secret -------------------------------------------------- */

static DH *dh;
static BIGNUM *dh_peer;
static unsigned char *dh_out;

static int dh_step(void)
{
    return api.DH_compute_key(dh_out, dh_peer, dh) > 0;
}

static int run_dh(const char *name, int bits, int iters, int runs,
                  int alloc_mode)
{
    size_t n = (size_t)bits / 8;
    unsigned char *pb = malloc(n), *vb = malloc(n), *qb = malloc(n);
    BIGNUM *p = NULL, *g = NULL, *priv = NULL, *peer = NULL;
    int dh_len, r, i, ok = 0;

    if (pb == NULL || vb == NULL || qb == NULL)
        goto out;
    make_operand(pb, n, UINT64_C(0x44485000) + (uint64_t)bits, 1, 1);
    make_operand(vb, n, UINT64_C(0x50524900) + (uint64_t)bits, 0, 1);
    make_operand(qb, n, UINT64_C(0x50454500) + (uint64_t)bits, 0, 1);

    p = api.BN_bin2bn(pb, (int)n, NULL);
    priv = api.BN_bin2bn(vb, (int)n, NULL);
    peer = api.BN_bin2bn(qb, (int)n, NULL);
    g = api.BN_new();
    dh = api.DH_new();
    if (p == NULL || priv == NULL || peer == NULL || g == NULL || dh == NULL)
        goto out;
    if (!api.BN_set_word(g, 2))
        goto out;
    if (!api.DH_set0_pqg(dh, p, NULL, g))
        goto out;
    p = NULL;
    g = NULL;
    if (!api.DH_set0_key(dh, NULL, priv))
        goto out;
    priv = NULL;

    dh_peer = peer;
    dh_len = api.DH_size(dh);
    if (dh_len <= 0)
        goto out;
    dh_out = malloc((size_t)dh_len);
    if (dh_out == NULL)
        goto out;
    r = api.DH_compute_key(dh_out, dh_peer, dh);
    if (r <= 0)
        goto out;
    printf("CHECK %s hex=", name);
    for (i = 0; i < r; i++)
        printf("%02x", dh_out[i]);
    printf("\n");
    fflush(stdout);

    ok = measure(name, iters, runs, dh_step, alloc_mode);

out:
    if (p)
        api.BN_free(p);
    if (g)
        api.BN_free(g);
    if (priv)
        api.BN_free(priv);
    if (peer)
        api.BN_free(peer);
    if (dh)
        api.DH_free(dh);
    free(pb);
    free(vb);
    free(qb);
    free(dh_out);
    dh = NULL;
    dh_peer = NULL;
    dh_out = NULL;
    return ok;
}

/* ---- RSA-2048 private operation (CRT key) ------------------------------ */

static RSA *rsa;
static unsigned char *rsa_in, *rsa_out;
static int rsa_len;

static int rsa_step(void)
{
    return api.RSA_private_encrypt(rsa_len, rsa_in, rsa_out, rsa,
                                   RSA_NO_PADDING) == rsa_len;
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
    if (len <= 0 || fseek(f, 0, SEEK_SET) != 0) {
        fclose(f);
        return NULL;
    }
    buf = malloc((size_t)len);
    if (buf == NULL || fread(buf, 1, (size_t)len, f) != (size_t)len) {
        free(buf);
        fclose(f);
        return NULL;
    }
    fclose(f);
    *out_len = len;
    return buf;
}

static int run_rsa(const char *der_path, int iters, int runs, int alloc_mode)
{
    long der_len = 0;
    unsigned char *der = read_file(der_path, &der_len);
    unsigned char *back = NULL;
    const unsigned char *q;
    int bl, i, ok = 0;

    if (der == NULL) {
        fprintf(stderr, "bench_api: cannot read %s\n", der_path);
        return 0;
    }
    q = der;
    rsa = api.d2i_RSAPrivateKey(NULL, &q, der_len);
    if (rsa == NULL) {
        fprintf(stderr, "bench_api: d2i_RSAPrivateKey failed\n");
        free(der);
        return 0;
    }

    rsa_len = api.RSA_size(rsa);
    rsa_in = calloc(1, (size_t)rsa_len);
    rsa_out = malloc((size_t)rsa_len);
    back = malloc((size_t)rsa_len);
    if (rsa_in == NULL || rsa_out == NULL || back == NULL)
        goto out;

    make_operand(rsa_in, (size_t)rsa_len, UINT64_C(0x52534100), 0, 0);
    rsa_in[0] = 0; /* < n for any 2048-bit modulus */

    if (api.RSA_private_encrypt(rsa_len, rsa_in, rsa_out, rsa,
                                RSA_NO_PADDING) != rsa_len)
        goto out;
    bl = api.RSA_public_decrypt(rsa_len, rsa_out, back, rsa, RSA_NO_PADDING);
    if (bl != rsa_len || memcmp(back, rsa_in, (size_t)rsa_len) != 0) {
        fprintf(stderr, "bench_api: RSA round-trip check failed\n");
        goto out;
    }

    printf("CHECK rsa2048 verify=1 hex=");
    for (i = 0; i < rsa_len; i++)
        printf("%02x", rsa_out[i]);
    printf("\n");
    fflush(stdout);

    ok = measure("rsa2048", iters, runs, rsa_step, alloc_mode);

out:
    free(der);
    free(back);
    free(rsa_in);
    free(rsa_out);
    if (rsa)
        api.RSA_free(rsa);
    rsa = NULL;
    rsa_in = rsa_out = NULL;
    return ok;
}

/* ---- ECDSA P-256 sign -------------------------------------------------- */

static EC_KEY *eck;
static unsigned char ec_dgst[32];

static int ec_step(void)
{
    ECDSA_SIG *s = api.ECDSA_do_sign(ec_dgst, (int)sizeof(ec_dgst), eck);

    if (s == NULL)
        return 0;
    api.ECDSA_SIG_free(s);
    return 1;
}

static int run_ecdsa(int iters, int runs, int alloc_mode)
{
    BIGNUM *priv = NULL;
    EC_POINT *pub = NULL;
    BN_CTX *ctx = NULL;
    ECDSA_SIG *s = NULL;
    unsigned char sb[32], pubbuf[65];
    const EC_GROUP *grp;
    size_t plen, i;
    int ok = 0;

    eck = api.EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    if (eck == NULL)
        return 0;

    make_operand(sb, sizeof(sb), UINT64_C(0x45434400), 0, 1);
    priv = api.BN_bin2bn(sb, (int)sizeof(sb), NULL);
    if (priv == NULL)
        goto out;
    if (!api.EC_KEY_set_private_key(eck, priv))
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

    make_operand(ec_dgst, sizeof(ec_dgst), UINT64_C(0x44494700), 0, 0);

    s = api.ECDSA_do_sign(ec_dgst, (int)sizeof(ec_dgst), eck);
    if (s == NULL) {
        fprintf(stderr, "bench_api: ECDSA_do_sign failed\n");
        goto out;
    }
    if (api.ECDSA_do_verify(ec_dgst, (int)sizeof(ec_dgst), s, eck) != 1) {
        fprintf(stderr, "bench_api: ECDSA_do_verify failed\n");
        goto out;
    }

    plen = api.EC_POINT_point2oct(grp, pub, POINT_CONVERSION_COMPRESSED,
                                  pubbuf, sizeof(pubbuf), ctx);
    if (plen == 0)
        goto out;
    printf("CHECK ecdsa256 pub=");
    for (i = 0; i < plen; i++)
        printf("%02x", pubbuf[i]);
    printf(" verify=1\n");
    fflush(stdout);

    ok = measure("ecdsa256", iters, runs, ec_step, alloc_mode);

out:
    if (s)
        api.ECDSA_SIG_free(s);
    if (priv)
        api.BN_free(priv);
    if (pub)
        api.EC_POINT_free(pub);
    if (ctx)
        api.BN_CTX_free(ctx);
    if (eck)
        api.EC_KEY_free(eck);
    eck = NULL;
    return ok;
}

int main(int argc, char **argv)
{
    const char *lib = NULL, *rsa_der = NULL;
    int alloc_mode = 0;
    int i, ok = 1;

    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--lib") == 0 && i + 1 < argc) {
            lib = argv[++i];
        } else if (strcmp(argv[i], "--rsa-der") == 0 && i + 1 < argc) {
            rsa_der = argv[++i];
        } else if (strcmp(argv[i], "--alloc") == 0) {
            alloc_mode = 1;
        } else {
            fprintf(stderr,
                    "usage: %s --lib <libcrypto.so.3> --rsa-der <pkcs1.der> "
                    "[--alloc]\n",
                    argv[0]);
            return 2;
        }
    }
    if (lib == NULL || rsa_der == NULL) {
        fprintf(stderr, "bench_api: --lib and --rsa-der are required\n");
        return 2;
    }
    if (!load_api(lib))
        return 2;

    if (alloc_mode) {
        ok &= run_modexp("modexp2048", 2048, 5, 1, 1);
        ok &= run_dh("dh2048", 2048, 5, 1, 1);
        ok &= run_dh("dh3072", 3072, 5, 1, 1);
        ok &= run_rsa(rsa_der, 5, 1, 1);
        ok &= run_ecdsa(5, 1, 1);
        ok &= run_modexp("modexp8192", 8192, 3, 1, 1);
    } else {
        ok &= run_modexp("modexp2048", 2048, 20, 5, 0);
        ok &= run_dh("dh2048", 2048, 20, 5, 0);
        ok &= run_dh("dh3072", 3072, 10, 5, 0);
        ok &= run_rsa(rsa_der, 20, 5, 0);
        ok &= run_ecdsa(500, 5, 0);
        ok &= run_modexp("modexp8192", 8192, 2, 5, 0);
    }
    return ok ? 0 : 1;
}
