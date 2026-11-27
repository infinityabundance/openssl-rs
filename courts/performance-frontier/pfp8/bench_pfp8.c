/*
 * bench_pfp8.c — PFP-8 DH key-generation and shared-secret harness.
 *
 * The PFP-5/PFP-1 workload driver measures only `DH_compute_key`.  PFP-8 must
 * measure key generation and the shared secret separately, and must run against
 * both a named group (the `DH_new_by_nid` path the prepared-group optimisation
 * could reach) and the same group loaded explicitly (`DH_set0_pqg`, the
 * unprepared path).
 *
 * Operand provenance, so a reader can reproduce the row:
 *   --params FILE   a tracked p=/q= fixture derived from src/bn/dh_data.rs by
 *                   courts/performance-frontier/baseline/extract_dh_fixtures.py
 *                   (ffdhe2048, ffdhe3072, modp2048); g is always 2 for these
 *                   safe-prime groups.
 *   --nid N         the named-group path; N is the OpenSSL NID (1126 ffdhe2048,
 *                   1127 ffdhe3072, 1213 modp2048).
 *   --priv HEX      the private exponent bytes.  `keygen-fixed` sets this and
 *                   calls `DH_generate_key`, which reuses the supplied private
 *                   key and computes `g^priv mod p`; `compute` uses it for
 *                   `peer^priv mod p`.
 *   --peer HEX      the peer public value for `compute`.
 *
 * Operations:
 *   keygen        fresh object per iteration, `DH_generate_key` (real RNG and
 *                 private-key generation), then free.
 *   keygen-fixed  fresh object per iteration, set `--priv`, `DH_generate_key`
 *                 (the public-key exponentiation only), print the public key
 *                 once, then free.
 *   compute       one object, set `--priv`, repeatedly `DH_compute_key` with
 *                 `--peer`, print the shared secret once.
 *
 * Output is line-oriented: `CHECK <name> hex=...` and
 * `RESULT <name> op=... median_us=... min_us=... max_us=... iters=... runs=...`
 * so the PFP campaign analysers can consume it unchanged.
 */
#include <dlfcn.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <openssl/bn.h>
#include <openssl/dh.h>

typedef struct {
    BIGNUM *(*BN_new)(void);
    void (*BN_free)(BIGNUM *);
    BIGNUM *(*BN_bin2bn)(const unsigned char *, int, BIGNUM *);
    int (*BN_set_word)(BIGNUM *, BN_ULONG);
    int (*BN_bn2binpad)(const BIGNUM *, unsigned char *, int);
    int (*BN_num_bits)(const BIGNUM *);

    DH *(*DH_new)(void);
    DH *(*DH_new_by_nid)(int);
    void (*DH_free)(DH *);
    int (*DH_set0_pqg)(DH *, BIGNUM *, BIGNUM *, BIGNUM *);
    int (*DH_set0_key)(DH *, BIGNUM *, BIGNUM *);
    int (*DH_generate_key)(DH *);
    int (*DH_compute_key)(unsigned char *, const BIGNUM *, DH *);
    int (*DH_size)(const DH *);
    void (*DH_get0_key)(const DH *, const BIGNUM **, const BIGNUM **);
} api_t;

static api_t api;

static int g_nid = 0;
static const char *g_params = NULL;
static const char *g_op = NULL;
static int g_iters = 20;
static int g_runs = 5;
static unsigned char *g_priv = NULL;
static size_t g_priv_len = 0;
static unsigned char *g_peer = NULL;
static size_t g_peer_len = 0;

static double now_us(void)
{
    struct timespec ts;

    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec * 1e6 + (double)ts.tv_nsec / 1e3;
}

static unsigned char *read_file(const char *path, long *out_len)
{
    FILE *f = fopen(path, "rb");
    unsigned char *buf;
    long len;

    if (f == NULL)
        return NULL;
    if (fseek(f, 0, SEEK_END) != 0 || (len = ftell(f)) < 0 ||
        fseek(f, 0, SEEK_SET) != 0) {
        fclose(f);
        return NULL;
    }
    buf = malloc((size_t)len + 1);
    if (buf == NULL || fread(buf, 1, (size_t)len, f) != (size_t)len) {
        free(buf);
        fclose(f);
        return NULL;
    }
    fclose(f);
    buf[len] = '\0';
    *out_len = len;
    return buf;
}

static int hex_nibble(char c)
{
    if (c >= '0' && c <= '9')
        return c - '0';
    if (c >= 'a' && c <= 'f')
        return c - 'a' + 10;
    if (c >= 'A' && c <= 'F')
        return c - 'A' + 10;
    return -1;
}

static int parse_hex_alloc(const char *s, unsigned char **out, size_t *n)
{
    size_t len = strlen(s), i;
    unsigned char *buf;

    if (len == 0 || (len & 1u) != 0)
        return 0;
    buf = malloc(len / 2);
    if (buf == NULL)
        return 0;
    for (i = 0; i < len / 2; i++) {
        int hi = hex_nibble(s[2 * i]);
        int lo = hex_nibble(s[2 * i + 1]);

        if (hi < 0 || lo < 0) {
            free(buf);
            return 0;
        }
        buf[i] = (unsigned char)((hi << 4) | lo);
    }
    *out = buf;
    *n = len / 2;
    return 1;
}

static int read_dh_params(const char *path, unsigned char **p, size_t *pn,
                          unsigned char **q, size_t *qn)
{
    long len = 0;
    unsigned char *raw = read_file(path, &len);
    char *text, *line, *save = NULL;
    int have_p = 0, have_q = 0;

    if (raw == NULL)
        return 0;
    text = malloc((size_t)len + 1);
    if (text == NULL) {
        free(raw);
        return 0;
    }
    memcpy(text, raw, (size_t)len);
    text[len] = '\0';
    free(raw);

    for (line = strtok_r(text, "\n", &save); line != NULL;
         line = strtok_r(NULL, "\n", &save)) {
        while (*line == ' ' || *line == '\t')
            line++;
        if (strncmp(line, "p=", 2) == 0) {
            if (have_p || !parse_hex_alloc(line + 2, p, pn)) {
                free(text);
                return 0;
            }
            have_p = 1;
        } else if (strncmp(line, "q=", 2) == 0) {
            if (have_q || !parse_hex_alloc(line + 2, q, qn)) {
                free(text);
                return 0;
            }
            have_q = 1;
        }
    }
    free(text);
    if (!have_p || !have_q || *pn == 0 || *qn == 0) {
        free(*p);
        free(*q);
        *p = NULL;
        *q = NULL;
        return 0;
    }
    return 1;
}

/*
 * Build the object the caller asked for: the named-group path when `--nid` is
 * present, otherwise the explicit `DH_set0_pqg` path from the tracked fixture.
 * Returns NULL on failure.  The caller owns the result.
 */
static DH *make_dh(void)
{
    DH *dh;

    if (g_nid != 0)
        return api.DH_new_by_nid(g_nid);
    if (g_params == NULL)
        return NULL;

    {
        unsigned char *p = NULL, *q = NULL;
        size_t pn = 0, qn = 0;
        BIGNUM *bp = NULL, *bq = NULL, *bg = NULL;

        if (!read_dh_params(g_params, &p, &pn, &q, &qn))
            return NULL;
        bp = api.BN_bin2bn(p, (int)pn, NULL);
        bq = api.BN_bin2bn(q, (int)qn, NULL);
        bg = api.BN_new();
        free(p);
        free(q);
        if (bp == NULL || bq == NULL || bg == NULL || api.BN_set_word(bg, 2) != 1) {
            api.BN_free(bp);
            api.BN_free(bq);
            api.BN_free(bg);
            return NULL;
        }
        dh = api.DH_new();
        if (dh == NULL) {
            api.BN_free(bp);
            api.BN_free(bq);
            api.BN_free(bg);
            return NULL;
        }
        if (api.DH_set0_pqg(dh, bp, bq, bg) != 1) {
            api.BN_free(bp);
            api.BN_free(bq);
            api.BN_free(bg);
            api.DH_free(dh);
            return NULL;
        }
    }
    return dh;
}

static BIGNUM *bn_from_hex(const unsigned char *p, size_t n)
{
    return api.BN_bin2bn(p, (int)n, NULL);
}

static void print_hex(const char *name, const BIGNUM *v, int bytes)
{
    unsigned char *out = malloc((size_t)bytes);
    int i;

    if (out == NULL)
        return;
    if (api.BN_bn2binpad(v, out, bytes) != bytes) {
        free(out);
        return;
    }
    printf("CHECK %s hex=", name);
    for (i = 0; i < bytes; i++)
        printf("%02x", out[i]);
    printf("\n");
    fflush(stdout);
    free(out);
}

static int measure(const char *name, int (*step)(void))
{
    double *s = calloc((size_t)g_runs, sizeof(*s));
    int i, r;
    double med, mn, mx;

    if (s == NULL)
        return 0;
    for (r = 0; r < g_runs; r++) {
        double t0, t1;

        t0 = now_us();
        for (i = 0; i < g_iters; i++) {
            if (!step()) {
                fprintf(stderr, "bench_pfp8: run failed: %s\n", name);
                free(s);
                return 0;
            }
        }
        t1 = now_us();
        s[r] = (t1 - t0) / (double)g_iters;
    }
    for (i = 1; i < g_runs; i++) {
        double v = s[i];
        int j = i;

        while (j > 0 && s[j - 1] > v) {
            s[j] = s[j - 1];
            j--;
        }
        s[j] = v;
    }
    med = (g_runs % 2) ? s[g_runs / 2]
                       : (s[g_runs / 2 - 1] + s[g_runs / 2]) / 2.0;
    mn = s[0];
    mx = s[g_runs - 1];
    printf("RESULT %s op=%s median_us=%.3f min_us=%.3f max_us=%.3f "
           "spread=%.4f iters=%d runs=%d\n",
           name, g_op, med, mn, mx, med > 0.0 ? (mx - mn) / med : 0.0,
           g_iters, g_runs);
    fflush(stdout);
    free(s);
    return 1;
}

/* ---- keygen: the real operation, fresh object per call ----------------- */

static int keygen_step(void)
{
    DH *dh = make_dh();
    int ok;

    if (dh == NULL)
        return 0;
    ok = api.DH_generate_key(dh) == 1;
    api.DH_free(dh);
    return ok;
}

/* ---- keygen with a supplied private key (public-key exponentiation) ---- */

static int keygen_fixed_once(int print)
{
    DH *dh = make_dh();
    BIGNUM *priv = bn_from_hex(g_priv, g_priv_len);
    const BIGNUM *pub = NULL, *unused = NULL;
    int ok = 0;

    if (dh == NULL || priv == NULL) {
        fprintf(stderr, "keygen-fixed: object or private key allocation failed\n");
        goto out;
    }
    if (api.DH_set0_key(dh, NULL, priv) != 1) {
        fprintf(stderr, "keygen-fixed: DH_set0_key failed\n");
        goto out;
    }
    priv = NULL; /* owned by dh */
    if (api.DH_generate_key(dh) != 1) {
        fprintf(stderr, "keygen-fixed: DH_generate_key failed\n");
        goto out;
    }
    api.DH_get0_key(dh, &pub, &unused);
    if (pub == NULL) {
        fprintf(stderr, "keygen-fixed: no public key\n");
        goto out;
    }
    if (print)
        print_hex("keygen-fixed", pub, api.DH_size(dh));
    ok = 1;
out:
    if (priv != NULL)
        api.BN_free(priv);
    if (dh != NULL)
        api.DH_free(dh);
    return ok;
}

static int keygen_fixed_step(void)
{
    return keygen_fixed_once(0);
}

/* ---- keygen once, printing the generated key pair ---------------------- */

/*
 * One real key generation, printing the private and public values.  The
 * candidate's `DH_generate_key` with a caller-supplied private key is refused
 * by the current source (PFP8-KEYGEN-PRESET-PRIV), so the key-generation
 * differential cross-checks this pair through the other library's
 * `DH_compute_key(g, priv)` instead of using `keygen-fixed`.
 */
static int keygen_once(void)
{
    DH *dh = make_dh();
    const BIGNUM *pub = NULL, *priv = NULL;
    int bytes, ok = 0;

    if (dh == NULL)
        return 0;
    if (api.DH_generate_key(dh) != 1)
        goto out;
    api.DH_get0_key(dh, &pub, &priv);
    if (pub == NULL || priv == NULL)
        goto out;
    bytes = api.DH_size(dh);
    if (bytes <= 0)
        goto out;
    print_hex("keygen-priv", priv, bytes);
    print_hex("keygen-pub", pub, bytes);
    ok = 1;
out:
    api.DH_free(dh);
    return ok;
}

/* ---- one compute, printing the raw return code (refusal tests) --------- */

static int rc_once(void)
{
    DH *dh = make_dh();
    BIGNUM *priv = bn_from_hex(g_priv, g_priv_len);
    BIGNUM *peer = bn_from_hex(g_peer, g_peer_len);
    unsigned char *out = NULL;
    int bytes, rc = -999, ok = 0;

    if (dh == NULL || priv == NULL || peer == NULL)
        goto out;
    if (api.DH_set0_key(dh, NULL, priv) != 1)
        goto out;
    priv = NULL;
    bytes = api.DH_size(dh);
    if (bytes <= 0)
        goto out;
    out = malloc((size_t)bytes);
    if (out == NULL)
        goto out;
    rc = api.DH_compute_key(out, peer, dh);
    printf("RC %d\n", rc);
    fflush(stdout);
    ok = 1;
out:
    if (priv != NULL)
        api.BN_free(priv);
    if (peer != NULL)
        api.BN_free(peer);
    if (out != NULL)
        free(out);
    if (dh != NULL)
        api.DH_free(dh);
    return ok;
}

/* ---- shared secret ------------------------------------------------------ */

static DH *g_dh;
static BIGNUM *g_priv_bn;
static BIGNUM *g_peer_bn;
static unsigned char *g_out;

static int compute_step(void)
{
    return api.DH_compute_key(g_out, g_peer_bn, g_dh) > 0;
}

static int run_compute(const char *name)
{
    int bytes, ok = 0;

    g_dh = make_dh();
    if (g_dh == NULL)
        return 0;
    g_priv_bn = bn_from_hex(g_priv, g_priv_len);
    g_peer_bn = bn_from_hex(g_peer, g_peer_len);
    if (g_priv_bn == NULL || g_peer_bn == NULL)
        goto out;
    if (api.DH_set0_key(g_dh, NULL, g_priv_bn) != 1)
        goto out;
    g_priv_bn = NULL;
    bytes = api.DH_size(g_dh);
    if (bytes <= 0)
        goto out;
    g_out = malloc((size_t)bytes);
    if (g_out == NULL)
        goto out;
    if (api.DH_compute_key(g_out, g_peer_bn, g_dh) <= 0)
        goto out;
    {
        int i;

        printf("CHECK %s hex=", name);
        for (i = 0; i < bytes; i++)
            printf("%02x", g_out[i]);
        printf("\n");
        fflush(stdout);
    }
    ok = measure(name, compute_step);
out:
    if (g_priv_bn != NULL)
        api.BN_free(g_priv_bn);
    if (g_peer_bn != NULL)
        api.BN_free(g_peer_bn);
    if (g_out != NULL)
        free(g_out);
    if (g_dh != NULL)
        api.DH_free(g_dh);
    g_dh = NULL;
    g_priv_bn = NULL;
    g_peer_bn = NULL;
    g_out = NULL;
    return ok;
}

static int load_api(const char *path)
{
    void *h = dlopen(path, RTLD_NOW | RTLD_LOCAL);

    if (h == NULL) {
        fprintf(stderr, "bench_pfp8: dlopen(%s): %s\n", path, dlerror());
        return 0;
    }
#define LOAD(field, symbol)                                                    \
    do {                                                                       \
        void *s = dlsym(h, symbol);                                            \
        if (s == NULL) {                                                       \
            fprintf(stderr, "bench_pfp8: missing %s\n", symbol);               \
            return 0;                                                          \
        }                                                                      \
        memcpy(&api.field, &s, sizeof(s));                                     \
    } while (0)

    LOAD(BN_new, "BN_new");
    LOAD(BN_free, "BN_free");
    LOAD(BN_bin2bn, "BN_bin2bn");
    LOAD(BN_set_word, "BN_set_word");
    LOAD(BN_bn2binpad, "BN_bn2binpad");
    LOAD(BN_num_bits, "BN_num_bits");

    LOAD(DH_new, "DH_new");
    LOAD(DH_new_by_nid, "DH_new_by_nid");
    LOAD(DH_free, "DH_free");
    LOAD(DH_set0_pqg, "DH_set0_pqg");
    LOAD(DH_set0_key, "DH_set0_key");
    LOAD(DH_generate_key, "DH_generate_key");
    LOAD(DH_compute_key, "DH_compute_key");
    LOAD(DH_size, "DH_size");
    LOAD(DH_get0_key, "DH_get0_key");
    return 1;
}

static int parse_args(int argc, char **argv, const char **lib)
{
    int i;

    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--lib") == 0 && i + 1 < argc)
            *lib = argv[++i];
        else if (strcmp(argv[i], "--nid") == 0 && i + 1 < argc)
            g_nid = atoi(argv[++i]);
        else if (strcmp(argv[i], "--params") == 0 && i + 1 < argc)
            g_params = argv[++i];
        else if (strcmp(argv[i], "--op") == 0 && i + 1 < argc)
            g_op = argv[++i];
        else if (strcmp(argv[i], "--priv") == 0 && i + 1 < argc)
            parse_hex_alloc(argv[++i], &g_priv, &g_priv_len);
        else if (strcmp(argv[i], "--peer") == 0 && i + 1 < argc)
            parse_hex_alloc(argv[++i], &g_peer, &g_peer_len);
        else if (strcmp(argv[i], "--iters") == 0 && i + 1 < argc)
            g_iters = atoi(argv[++i]);
        else if (strcmp(argv[i], "--runs") == 0 && i + 1 < argc)
            g_runs = atoi(argv[++i]);
        else {
            fprintf(stderr, "bench_pfp8: unknown argument %s\n", argv[i]);
            return 0;
        }
    }
    return *lib != NULL && g_op != NULL && (g_nid != 0 || g_params != NULL);
}

int main(int argc, char **argv)
{
    const char *lib = NULL;
    const char *name = "dh";
    int ok = 0;

    if (!parse_args(argc, argv, &lib)) {
        fprintf(stderr, "usage: %s --lib DSO (--nid N | --params FILE) --op "
                        "keygen|keygen-fixed|compute [--priv HEX] [--peer HEX] "
                        "[--iters N] [--runs N]\n", argv[0]);
        return 2;
    }
    if (!load_api(lib))
        return 2;

    if (strcmp(g_op, "keygen") == 0) {
        name = g_nid ? "dh-keygen-named" : "dh-keygen-explicit";
        /* One untimed operation proves the operation succeeds. */
        if (!keygen_step())
            return 1;
        ok = measure(name, keygen_step);
    } else if (strcmp(g_op, "keygen-fixed") == 0) {
        if (g_priv == NULL)
            return 2;
        name = g_nid ? "dh-keygen-fixed-named" : "dh-keygen-fixed-explicit";
        if (!keygen_fixed_once(1))
            return 1;
        ok = measure(name, keygen_fixed_step);
    } else if (strcmp(g_op, "keygen-once") == 0) {
        name = g_nid ? "dh-keygen-once-named" : "dh-keygen-once-explicit";
        ok = keygen_once();
    } else if (strcmp(g_op, "rc") == 0) {
        if (g_priv == NULL || g_peer == NULL)
            return 2;
        ok = rc_once();
    } else if (strcmp(g_op, "compute") == 0) {
        if (g_priv == NULL || g_peer == NULL)
            return 2;
        name = g_nid ? "dh-compute-named" : "dh-compute-explicit";
        ok = run_compute(name);
    } else {
        fprintf(stderr, "bench_pfp8: unknown op %s\n", g_op);
        return 2;
    }

    free(g_priv);
    free(g_peer);
    return ok ? 0 : 1;
}
