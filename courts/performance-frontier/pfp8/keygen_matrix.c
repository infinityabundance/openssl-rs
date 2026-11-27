/*
 * keygen_matrix.c — the four `DH_generate_key` key-state combinations, for the
 * PFP8-KEYGEN-PRESET-PRIV obligation.
 *
 * The PFP-8 differential harness (`bench_pfp8.c`) records only two of the four
 * combinations: private key absent (from-scratch key generation) and private key
 * present with the public key absent (`keygen-fixed`).  The authority's
 * `generate_key()` (`crypto/dh/dh_key.c:265-387`) makes four independent
 * decisions — whether to generate a private key and whether a public key slot is
 * already present — and its public-key computation sits *outside* the
 * `if (generate_new_key)` block, so all four combinations call
 * `ossl_dh_generate_public_key()`.  This probe measures, per combination:
 *
 *   - `DH_generate_key`'s return code;
 *   - whether `DH_get0_key` reports a public key, and its padded hex;
 *   - whether a caller-supplied public key slot was overwritten;
 *   - the error queue after the call: count and each entry's (lib, reason).
 *
 * One process, one case: state cannot leak between rows.  Output is one JSON
 * object per line, so the driver can compare the candidate against the
 * OpenSSL 3.6.4 authority entry by entry.
 *
 * Usage:
 *   keygen_matrix --lib DSO (--nid N | --params FILE)
 *                 --priv absent|HEX --pub absent|present
 *
 * `--pub present` installs a sentinel BIGNUM (2) as the public key with
 * `DH_set0_key`, which is the only way an application can preset that slot.
 */
#include <dlfcn.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/bn.h>
#include <openssl/dh.h>
#include <openssl/err.h>

typedef struct {
    BIGNUM *(*BN_new)(void);
    void (*BN_free)(BIGNUM *);
    BIGNUM *(*BN_bin2bn)(const unsigned char *, int, BIGNUM *);
    int (*BN_set_word)(BIGNUM *, BN_ULONG);
    int (*BN_bn2binpad)(const BIGNUM *, unsigned char *, int);
    int (*BN_num_bits)(const BIGNUM *);
    int (*BN_is_word)(const BIGNUM *, BN_ULONG);

    DH *(*DH_new)(void);
    DH *(*DH_new_by_nid)(int);
    void (*DH_free)(DH *);
    int (*DH_set0_pqg)(DH *, BIGNUM *, BIGNUM *, BIGNUM *);
    int (*DH_set0_key)(DH *, BIGNUM *, BIGNUM *);
    int (*DH_generate_key)(DH *);
    int (*DH_size)(const DH *);
    void (*DH_get0_key)(const DH *, const BIGNUM **, const BIGNUM **);

    unsigned long (*ERR_get_error)(void);
    void (*ERR_clear_error)(void);
} api_t;

static api_t api;

static int g_nid;
static const char *g_params;
static const char *g_priv_spec; /* "absent" or hex */
static int g_pub_present;

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

/* Parse an even-length hex string, or a single "0" / "00" as one zero byte. */
static int parse_hex(const char *s, unsigned char **out, size_t *out_len)
{
    size_t n = strlen(s), i;
    unsigned char *buf;

    if (n == 0)
        return 0;
    if (n == 1) {
        int v = hex_nibble(s[0]);

        if (v < 0)
            return 0;
        buf = malloc(1);
        if (buf == NULL)
            return 0;
        buf[0] = (unsigned char)v;
        *out = buf;
        *out_len = 1;
        return 1;
    }
    if (n % 2 != 0)
        return 0;
    buf = malloc(n / 2);
    if (buf == NULL)
        return 0;
    for (i = 0; i < n; i += 2) {
        int hi = hex_nibble(s[i]), lo = hex_nibble(s[i + 1]);

        if (hi < 0 || lo < 0) {
            free(buf);
            return 0;
        }
        buf[i / 2] = (unsigned char)((hi << 4) | lo);
    }
    *out = buf;
    *out_len = n / 2;
    return 1;
}

static BIGNUM *bn_from_hex_spec(const char *spec, size_t *out_len)
{
    unsigned char *raw = NULL;
    size_t n = 0;
    BIGNUM *bn;

    if (!parse_hex(spec, &raw, &n))
        return NULL;
    bn = api.BN_bin2bn(raw, (int)n, NULL);
    free(raw);
    if (out_len != NULL)
        *out_len = n;
    return bn;
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
        /* Strip the leading space of the fixture's " p=..." rows. */
        while (*line == ' ' || *line == '\t')
            line++;
        if (*line == '#')
            continue;
        if (strncmp(line, "p=", 2) == 0) {
            if (have_p || !parse_hex(line + 2, p, pn)) {
                free(text);
                return 0;
            }
            have_p = 1;
        } else if (strncmp(line, "q=", 2) == 0) {
            if (have_q || !parse_hex(line + 2, q, qn)) {
                free(text);
                return 0;
            }
            have_q = 1;
        }
    }
    free(text);
    if (!have_p || !have_q) {
        if (have_p)
            free(*p);
        if (have_q)
            free(*q);
        return 0;
    }
    return 1;
}

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
        BIGNUM *bp, *bq, *bg;

        if (!read_dh_params(g_params, &p, &pn, &q, &qn))
            return NULL;
        bp = api.BN_bin2bn(p, (int)pn, NULL);
        bq = api.BN_bin2bn(q, (int)qn, NULL);
        bg = api.BN_new();
        free(p);
        free(q);
        if (bp == NULL || bq == NULL || bg == NULL ||
            api.BN_set_word(bg, 2) != 1) {
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

/* Print one hex object, or `null`. */
static void print_bn_hex(const BIGNUM *v, int bytes)
{
    unsigned char *out;
    int i;

    if (v == NULL) {
        fputs("null", stdout);
        return;
    }
    out = malloc((size_t)bytes);
    if (out == NULL) {
        fputs("\"alloc-failed\"", stdout);
        return;
    }
    if (api.BN_bn2binpad(v, out, bytes) != bytes) {
        free(out);
        fputs("\"pad-failed\"", stdout);
        return;
    }
    putchar('"');
    for (i = 0; i < bytes; i++)
        printf("%02x", out[i]);
    putchar('"');
    free(out);
}

static const char *g_case;

static int run_case(void)
{
    DH *dh = make_dh();
    const BIGNUM *pub_after = NULL, *priv_after = NULL;
    BIGNUM *priv = NULL, *sentinel = NULL;
    int rc = -1, bytes = -1, pub_present = 0, pub_is_sentinel = 0;
    int priv_present_after = 0;
    unsigned long errs[8];
    int nerrs = 0, i;

    if (dh == NULL) {
        fprintf(stderr, "keygen_matrix: object construction failed\n");
        return 0;
    }
    bytes = api.DH_size(dh);
    if (bytes <= 0) {
        fprintf(stderr, "keygen_matrix: DH_size failed\n");
        api.DH_free(dh);
        return 0;
    }
    if (strcmp(g_priv_spec, "absent") != 0) {
        priv = bn_from_hex_spec(g_priv_spec, NULL);
        if (priv == NULL) {
            fprintf(stderr, "keygen_matrix: bad private key\n");
            api.DH_free(dh);
            return 0;
        }
    }
    if (g_pub_present) {
        sentinel = api.BN_new();
        if (sentinel == NULL || api.BN_set_word(sentinel, 2) != 1) {
            fprintf(stderr, "keygen_matrix: sentinel allocation failed\n");
            api.BN_free(priv);
            api.BN_free(sentinel);
            api.DH_free(dh);
            return 0;
        }
    }
    /* `DH_set0_key` replaces only non-NULL members, which is its contract. */
    if (api.DH_set0_key(dh, sentinel, priv) != 1) {
        fprintf(stderr, "keygen_matrix: DH_set0_key failed\n");
        api.BN_free(priv);
        api.BN_free(sentinel);
        api.DH_free(dh);
        return 0;
    }
    /* Ownership moved into `dh`. */

    api.ERR_clear_error();
    rc = api.DH_generate_key(dh);
    for (i = 0; i < (int)(sizeof(errs) / sizeof(errs[0])); i++) {
        unsigned long e = api.ERR_get_error();

        if (e == 0)
            break;
        errs[nerrs++] = e;
    }

    api.DH_get0_key(dh, &pub_after, &priv_after);
    pub_present = pub_after != NULL;
    priv_present_after = priv_after != NULL;
    if (pub_present && g_pub_present && sentinel != NULL) {
        /* Did the call overwrite the caller's slot?  Compare to 2. */
        pub_is_sentinel = api.BN_num_bits(pub_after) <= 2 &&
                          api.BN_is_word(pub_after, 2);
    }

    printf("{\"case\":\"%s\",\"rc\":%d,\"pub_present\":%s,", g_case,
           rc, pub_present ? "true" : "false");
    printf("\"priv_present_after\":%s,", priv_present_after ? "true" : "false");
    printf("\"pub_is_sentinel\":%s,", pub_is_sentinel ? "true" : "false");
    printf("\"errs\":[");
    for (i = 0; i < nerrs; i++)
        printf("%s[%lu,%d,%d]", i ? "," : "", errs[i],
               ERR_GET_LIB(errs[i]), ERR_GET_REASON(errs[i]));
    printf("],\"pub\":");
    print_bn_hex(pub_after, bytes);
    printf("}\n");
    fflush(stdout);

    api.ERR_clear_error();
    api.DH_free(dh);
    return 1;
}

static int load_api(const char *path)
{
    void *h = dlopen(path, RTLD_NOW | RTLD_LOCAL);

    if (h == NULL) {
        fprintf(stderr, "keygen_matrix: dlopen(%s): %s\n", path, dlerror());
        return 0;
    }
#define LOAD(field, symbol)                                                    \
    do {                                                                       \
        void *s = dlsym(h, symbol);                                            \
        if (s == NULL) {                                                       \
            fprintf(stderr, "keygen_matrix: missing %s\n", symbol);            \
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
    LOAD(BN_is_word, "BN_is_word");
    LOAD(DH_new, "DH_new");
    LOAD(DH_new_by_nid, "DH_new_by_nid");
    LOAD(DH_free, "DH_free");
    LOAD(DH_set0_pqg, "DH_set0_pqg");
    LOAD(DH_set0_key, "DH_set0_key");
    LOAD(DH_generate_key, "DH_generate_key");
    LOAD(DH_size, "DH_size");
    LOAD(DH_get0_key, "DH_get0_key");
    LOAD(ERR_get_error, "ERR_get_error");
    LOAD(ERR_clear_error, "ERR_clear_error");
    return 1;
}

int main(int argc, char **argv)
{
    const char *lib = NULL;
    int i;

    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--lib") == 0 && i + 1 < argc)
            lib = argv[++i];
        else if (strcmp(argv[i], "--nid") == 0 && i + 1 < argc)
            g_nid = atoi(argv[++i]);
        else if (strcmp(argv[i], "--params") == 0 && i + 1 < argc)
            g_params = argv[++i];
        else if (strcmp(argv[i], "--priv") == 0 && i + 1 < argc)
            g_priv_spec = argv[++i];
        else if (strcmp(argv[i], "--pub") == 0 && i + 1 < argc)
            g_pub_present = strcmp(argv[++i], "present") == 0;
        else if (strcmp(argv[i], "--case") == 0 && i + 1 < argc)
            g_case = argv[++i];
        else {
            fprintf(stderr, "keygen_matrix: unknown argument %s\n", argv[i]);
            return 2;
        }
    }
    if (lib == NULL || g_case == NULL || g_priv_spec == NULL ||
        (g_nid == 0 && g_params == NULL)) {
        fprintf(stderr,
                "usage: %s --lib DSO (--nid N | --params FILE) --case NAME "
                "--priv absent|HEX --pub absent|present\n", argv[0]);
        return 2;
    }
    if (!load_api(lib))
        return 2;
    return run_case() ? 0 : 1;
}
