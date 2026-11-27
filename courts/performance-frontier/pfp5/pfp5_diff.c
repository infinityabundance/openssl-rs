/*
 * pfp5_diff.c — PFP-5 differential of the fixed-window ladder against the
 * authority, at the C ABI. One library per process (`--lib`), so a transcript is
 * a statement about exactly one mapped DSO. Run it twice and diff the stdout.
 *
 * Covered:
 *   MX   BN_mod_exp_mont_consttime over odd moduli of 256/1024/2048/3072/8192
 *        bits, bases {0,1,2,m-1,random} and exponents {0,1,2,small,full,ones}.
 *   RSA  deterministic private_encrypt of a fixed block, CRT blinded, CRT
 *        unblinded (RSA_blinding_off) and non-CRT (key rebuilt from n,e,d only),
 *        plus private_decrypt round trips.
 *   DH   DH_compute_key over the recorded FFDHE2048 and MODP2048 groups.
 *
 * Operands are deterministic (xorshift64); no BN_rand and no random bytes.
 */
#define _GNU_SOURCE
#include <openssl/bn.h>
#include <openssl/dh.h>
#include <openssl/rsa.h>

#include <dlfcn.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    BIGNUM *(*BN_new)(void);
    void (*BN_free)(BIGNUM *);
    BIGNUM *(*BN_bin2bn)(const unsigned char *, int, BIGNUM *);
    BIGNUM *(*BN_dup)(const BIGNUM *);
    int (*BN_set_word)(BIGNUM *, BN_ULONG);
    int (*BN_sub)(BIGNUM *, const BIGNUM *, const BIGNUM *);
    int (*BN_bn2binpad)(const BIGNUM *, unsigned char *, int);
    int (*BN_num_bits)(const BIGNUM *);
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
    RSA *(*RSA_new)(void);
    void (*RSA_free)(RSA *);
    int (*RSA_size)(const RSA *);
    void (*RSA_get0_key)(const RSA *, const BIGNUM **, const BIGNUM **,
                         const BIGNUM **);
    int (*RSA_set0_key)(RSA *, BIGNUM *, BIGNUM *, BIGNUM *);
    int (*RSA_private_encrypt)(int, const unsigned char *, unsigned char *,
                               RSA *, int);
    int (*RSA_public_encrypt)(int, const unsigned char *, unsigned char *,
                              RSA *, int);
    int (*RSA_private_decrypt)(int, const unsigned char *, unsigned char *,
                               RSA *, int);
    void (*RSA_blinding_off)(RSA *);
} api_t;

static api_t api;

#define LOAD(field, symbol)                                                    \
    do {                                                                       \
        void *s = dlsym(handle, symbol);                                       \
        if (s == NULL) {                                                       \
            fprintf(stderr, "dlsym(%s) failed: %s\n", symbol, dlerror());      \
            return 0;                                                          \
        }                                                                      \
        memcpy(&api.field, &s, sizeof(s));                                     \
    } while (0)

static int load_api(const char *path)
{
    void *handle = dlopen(path, RTLD_NOW | RTLD_LOCAL);
    if (handle == NULL) {
        fprintf(stderr, "dlopen(%s): %s\n", path, dlerror());
        return 0;
    }
    LOAD(BN_new, "BN_new");
    LOAD(BN_free, "BN_free");
    LOAD(BN_bin2bn, "BN_bin2bn");
    LOAD(BN_dup, "BN_dup");
    LOAD(BN_set_word, "BN_set_word");
    LOAD(BN_sub, "BN_sub");
    LOAD(BN_bn2binpad, "BN_bn2binpad");
    LOAD(BN_num_bits, "BN_num_bits");
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
    LOAD(RSA_new, "RSA_new");
    LOAD(RSA_free, "RSA_free");
    LOAD(RSA_size, "RSA_size");
    LOAD(RSA_get0_key, "RSA_get0_key");
    LOAD(RSA_set0_key, "RSA_set0_key");
    LOAD(RSA_private_encrypt, "RSA_private_encrypt");
    LOAD(RSA_public_encrypt, "RSA_public_encrypt");
    LOAD(RSA_private_decrypt, "RSA_private_decrypt");
    LOAD(RSA_blinding_off, "RSA_blinding_off");
#undef LOAD
    return 1;
}

static uint64_t xs_state;
static uint64_t xs(void)
{
    uint64_t x = xs_state;
    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    xs_state = x;
    return x;
}

static unsigned char *read_file(const char *path, long *len)
{
    FILE *f = fopen(path, "rb");
    unsigned char *b;
    long n;
    if (f == NULL)
        return NULL;
    if (fseek(f, 0, SEEK_END) != 0) { fclose(f); return NULL; }
    n = ftell(f);
    if (n <= 0 || fseek(f, 0, SEEK_SET) != 0) { fclose(f); return NULL; }
    b = malloc((size_t)n);
    if (b != NULL && fread(b, 1, (size_t)n, f) != (size_t)n) { free(b); b = NULL; }
    fclose(f);
    *len = n;
    return b;
}

static int hexval(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static int parse_hex_alloc(const char *s, unsigned char **out, long *outlen)
{
    size_t len = strlen(s), i, o = 0;
    unsigned char *b;
    if (len == 0 || (len & 1) != 0) return 0;
    b = malloc(len / 2);
    if (b == NULL) return 0;
    for (i = 0; i < len; i += 2) {
        int hi = hexval(s[i]), lo = hexval(s[i + 1]);
        if (hi < 0 || lo < 0) { free(b); return 0; }
        b[o++] = (unsigned char)((hi << 4) | lo);
    }
    *out = b;
    *outlen = (long)o;
    return 1;
}

static void print_hex(const char *tag, const unsigned char *b, int n)
{
    int i;
    printf("%s hex=", tag);
    for (i = 0; i < n; i++) printf("%02x", b[i]);
    printf("\n");
}

/* ---- modexp sweep ------------------------------------------------------- */

static void make_modulus(unsigned char *m, size_t n, uint64_t seed)
{
    size_t i;
    xs_state = seed | 1;
    for (i = 0; i < n; i += 8) {
        uint64_t v = xs();
        size_t k = (n - i < 8) ? n - i : 8;
        memcpy(m + i, &v, k);
    }
    m[0] |= 0x80;    /* most-significant byte: exactly n*8 bits */
    m[n - 1] |= 1;   /* least-significant byte: odd */
}

static BIGNUM *make_base(int which, const BIGNUM *m, const unsigned char *mb,
                         size_t n)
{
    BIGNUM *a = api.BN_new();
    BIGNUM *one = api.BN_new();
    unsigned char *raw;
    BIGNUM *r = NULL;
    size_t i;
    (void)mb;
    if (a == NULL || one == NULL) goto out;
    api.BN_set_word(one, 1);
    switch (which) {
    case 0: api.BN_set_word(a, 0); break;
    case 1: api.BN_set_word(a, 1); break;
    case 2: api.BN_set_word(a, 2); break;
    case 3: if (!api.BN_sub(a, m, one)) goto out; break;
    default:
        raw = malloc(n);
        if (raw == NULL) goto out;
        xs_state = 0xb0b0b0b0u + (uint64_t)which;
        for (i = 0; i < n; i += 8) {
            uint64_t v = xs();
            size_t k = (n - i < 8) ? n - i : 8;
            memcpy(raw + i, &v, k);
        }
        /* Clear the top bit of the most-significant byte: the value is then
         * below 2^(8n-1) <= m, whose top bit is set, so it is already the
         * canonical residue. */
        raw[0] &= 0x7f;
        r = api.BN_bin2bn(raw, (int)n, NULL);
        free(raw);
        if (r == NULL) goto out;
        api.BN_free(a);
        a = r;
        r = NULL;
        break;
    }
out:
    if (r != NULL) api.BN_free(r);
    api.BN_free(one);
    return a;
}

static BIGNUM *make_exponent(int which, size_t n, uint64_t seed)
{
    unsigned char *b = malloc(n);
    BIGNUM *e;
    size_t i;
    if (b == NULL) return NULL;
    switch (which) {
    case 0: memset(b, 0, n); break;
    case 1: memset(b, 0, n); b[n - 1] = 1; break;
    case 2: memset(b, 0, n); b[n - 1] = 2; break;
    case 3: memset(b, 0, n); b[n - 1] = 0x5a; b[n - 2] = 0x3c; break;
    case 4:
        xs_state = seed ^ 0x45585000u;
        for (i = 0; i < n; i += 8) {
            uint64_t v = xs();
            size_t k = (n - i < 8) ? n - i : 8;
            memcpy(b + i, &v, k);
        }
        b[0] |= 0x80; /* top bit set: a full-width exponent */
        break;
    default: memset(b, 0xff, n); break;
    }
    if (which == 0)
        e = api.BN_new();
    else
        e = api.BN_bin2bn(b, (int)n, NULL);
    free(b);
    if (e != NULL && which == 0) api.BN_set_word(e, 0);
    return e;
}

static int modexp_sweep(void)
{
    static const int bits[] = {256, 1024, 2048, 3072, 8192};
    static const char *base_id[] = {"zero", "one", "two", "mminus1", "rand"};
    static const char *exp_id[] = {"zero", "one", "two", "small", "full", "ones"};
    BN_CTX *ctx = api.BN_CTX_new();
    size_t bi, ai, ei;
    int ok = 1;
    if (ctx == NULL) return 0;
    for (bi = 0; bi < sizeof(bits) / sizeof(bits[0]); bi++) {
        size_t n = (size_t)bits[bi] / 8;
        unsigned char *mb = malloc(n), *ob = malloc(n);
        BIGNUM *m;
        if (mb == NULL || ob == NULL) { free(mb); free(ob); ok = 0; break; }
        make_modulus(mb, n, 0x4d4f4400u + (uint64_t)bits[bi]);
        m = api.BN_bin2bn(mb, (int)n, NULL);
        if (m == NULL) { free(mb); free(ob); ok = 0; break; }
        for (ai = 0; ai < 5; ai++) {
            BIGNUM *a = make_base((int)ai, m, mb, n);
            if (a == NULL) { ok = 0; break; }
            for (ei = 0; ei < 6; ei++) {
                BIGNUM *e = make_exponent((int)ei, n, 0x45585000u + (uint64_t)bits[bi]);
                BIGNUM *r = api.BN_new();
                char tag[96];
                int ret = 0;
                if (e != NULL && r != NULL)
                    ret = api.BN_mod_exp_mont_consttime(r, a, e, m, ctx, NULL);
                if (ret != 1 || api.BN_bn2binpad(r, ob, (int)n) != (int)n) {
                    int pad = (r == NULL) ? -99 : api.BN_bn2binpad(r, ob, (int)n);
                    fprintf(stderr, "modexp failed at %d bits %s^%s ret=%d pad=%d abits=%d ebits=%d\n",
                            bits[bi], base_id[ai], exp_id[ei], ret, pad,
                            api.BN_num_bits(a), api.BN_num_bits(e));
                    ok = 0;
                } else {
                    snprintf(tag, sizeof(tag), "MX %d %s %s", bits[bi],
                             base_id[ai], exp_id[ei]);
                    print_hex(tag, ob, (int)n);
                }
                api.BN_free(e);
                if (r != NULL) api.BN_free(r);
                if (!ok) break;
            }
            api.BN_free(a);
            if (!ok) break;
        }
        api.BN_free(m);
        free(mb);
        free(ob);
        if (!ok) break;
    }
    api.BN_CTX_free(ctx);
    return ok;
}

/* ---- RSA arms ----------------------------------------------------------- */

static int rsa_arms(const char *der_path)
{
    long len = 0;
    unsigned char *der = read_file(der_path, &len);
    unsigned char msg[512], ct[512], enc1[512], enc2[512], enc3[512], dec[512];
    const unsigned char *pp;
    RSA *k1 = NULL, *k2 = NULL, *plain = NULL;
    const BIGNUM *n = NULL, *e = NULL, *d = NULL;
    int size, i, ok = 1;
    if (der == NULL) return 0;
    pp = der;
    k1 = api.d2i_RSAPrivateKey(NULL, &pp, len);
    pp = der;
    k2 = api.d2i_RSAPrivateKey(NULL, &pp, len);
    if (k1 == NULL || k2 == NULL) { ok = 0; goto out; }
    size = api.RSA_size(k1);
    if (size <= 0 || size > (int)sizeof(msg)) { ok = 0; goto out; }
    memset(msg, 0, (size_t)size);
    msg[0] = 0x00;
    for (i = 1; i < size; i++) msg[i] = (unsigned char)(0x40 + (i & 0x3f));

    /* Deterministic public encryption, then the private decryption that
     * inverts it (the decryption arm). The ciphertext itself is compared too. */
    if (api.RSA_public_encrypt(size, msg, ct, k1, RSA_NO_PADDING) != size) {
        ok = 0; goto out;
    }
    print_hex("RSA ciphertext", ct, size);
    memset(dec, 0, sizeof(dec));
    if (api.RSA_private_decrypt(size, ct, dec, k1, RSA_NO_PADDING) != size ||
        memcmp(dec, msg, (size_t)size) != 0) {
        ok = 0; goto out;
    }
    printf("RSA decrypt-roundtrip=1\n");

    /* Deterministic signature: CRT with blinding (default). */
    if (api.RSA_private_encrypt(size, msg, enc1, k1, RSA_NO_PADDING) != size) {
        ok = 0; goto out;
    }
    print_hex("RSA sig-crt-blinded", enc1, size);

    /* CRT, blinding off. */
    api.RSA_blinding_off(k2);
    if (api.RSA_private_encrypt(size, msg, enc2, k2, RSA_NO_PADDING) != size) {
        ok = 0; goto out;
    }
    print_hex("RSA sig-crt-unblinded", enc2, size);
    printf("RSA blinding-off-equal=%d\n", memcmp(enc1, enc2, (size_t)size) == 0);

    /* non-CRT: rebuild a key from n, e and d only, and sign and decrypt. */
    api.RSA_get0_key(k1, &n, &e, &d);
    plain = api.RSA_new();
    if (plain == NULL || n == NULL || e == NULL || d == NULL) { ok = 0; goto out; }
    if (!api.RSA_set0_key(plain, api.BN_dup(n), api.BN_dup(e), api.BN_dup(d))) {
        ok = 0; goto out;
    }
    if (api.RSA_private_encrypt(size, msg, enc3, plain, RSA_NO_PADDING) != size) {
        ok = 0; goto out;
    }
    print_hex("RSA sig-noncrt", enc3, size);
    printf("RSA crt-equals-noncrt=%d\n", memcmp(enc1, enc3, (size_t)size) == 0);
    memset(dec, 0, sizeof(dec));
    if (api.RSA_private_decrypt(size, ct, dec, plain, RSA_NO_PADDING) != size ||
        memcmp(dec, msg, (size_t)size) != 0) {
        ok = 0; goto out;
    }
    printf("RSA noncrt-decrypt-roundtrip=1\n");

out:
    if (k1) api.RSA_free(k1);
    if (k2) api.RSA_free(k2);
    if (plain) api.RSA_free(plain);
    free(der);
    return ok;
}

/* ---- DH arms ------------------------------------------------------------ */

static int read_dh_params(const char *path, unsigned char **p, long *pn,
                          unsigned char **q, long *qn)
{
    long len = 0;
    unsigned char *raw = read_file(path, &len);
    char *text, *line, *save = NULL;
    int have_p = 0, have_q = 0;
    if (raw == NULL) return 0;
    text = malloc((size_t)len + 1);
    if (text == NULL) { free(raw); return 0; }
    memcpy(text, raw, (size_t)len);
    text[len] = '\0';
    free(raw);
    for (line = strtok_r(text, "\n", &save); line != NULL;
         line = strtok_r(NULL, "\n", &save)) {
        while (*line == ' ' || *line == '\t') line++;
        if (strncmp(line, "p=", 2) == 0) {
            if (have_p || !parse_hex_alloc(line + 2, p, pn)) { free(text); return 0; }
            have_p = 1;
        } else if (strncmp(line, "q=", 2) == 0) {
            if (have_q || !parse_hex_alloc(line + 2, q, qn)) { free(text); return 0; }
            have_q = 1;
        }
    }
    free(text);
    return have_p && have_q;
}

static int dh_arm(const char *name, const char *params)
{
    unsigned char *pb = NULL, *qb = NULL;
    long pn = 0, qn = 0;
    BIGNUM *p = NULL, *q = NULL, *g = NULL, *priv = NULL, *peer = NULL;
    DH *dh = NULL;
    unsigned char *priv_b = NULL, *peer_b = NULL, *out = NULL;
    size_t i;
    int dh_len, r, ok = 0;
    if (!read_dh_params(params, &pb, &pn, &qb, &qn)) goto out;
    priv_b = malloc((size_t)pn);
    peer_b = malloc((size_t)pn);
    if (priv_b == NULL || peer_b == NULL) goto out;
    xs_state = 0x50524900u;
    for (i = 0; i < (size_t)pn; i += 8) {
        uint64_t v = xs();
        size_t k = ((size_t)pn - i < 8) ? (size_t)pn - i : 8;
        memcpy(priv_b + i, &v, k);
    }
    xs_state = 0x50454500u;
    for (i = 0; i < (size_t)pn; i += 8) {
        uint64_t v = xs();
        size_t k = ((size_t)pn - i < 8) ? (size_t)pn - i : 8;
        memcpy(peer_b + i, &v, k);
    }
    priv_b[0] &= 0x7f;
    peer_b[0] &= 0x7f;
    priv = api.BN_bin2bn(priv_b, (int)pn, NULL);
    peer = api.BN_bin2bn(peer_b, (int)pn, NULL);
    p = api.BN_bin2bn(pb, (int)pn, NULL);
    q = api.BN_bin2bn(qb, (int)qn, NULL);
    g = api.BN_new();
    dh = api.DH_new();
    if (p == NULL || q == NULL || g == NULL || dh == NULL || priv == NULL ||
        peer == NULL) goto out;
    if (!api.BN_set_word(g, 2)) goto out;
    if (!api.DH_set0_pqg(dh, p, q, g)) goto out;
    p = q = g = NULL;
    if (!api.DH_set0_key(dh, NULL, priv)) goto out;
    priv = NULL;
    dh_len = api.DH_size(dh);
    if (dh_len <= 0) goto out;
    out = malloc((size_t)dh_len);
    if (out == NULL) goto out;
    r = api.DH_compute_key(out, peer, dh);
    if (r <= 0) goto out;
    {
        char tag[96];
        snprintf(tag, sizeof(tag), "DH %s", name);
        print_hex(tag, out, r);
    }
    ok = 1;
out:
    if (p) api.BN_free(p);
    if (q) api.BN_free(q);
    if (g) api.BN_free(g);
    if (priv) api.BN_free(priv);
    if (peer) api.BN_free(peer);
    if (dh) api.DH_free(dh);
    free(pb); free(qb); free(priv_b); free(peer_b); free(out);
    return ok;
}

int main(int argc, char **argv)
{
    const char *lib = NULL, *rsa_der = NULL, *ffdhe = NULL, *modp = NULL;
    int i, ok = 1;
    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--lib") == 0 && i + 1 < argc) lib = argv[++i];
        else if (strcmp(argv[i], "--rsa-der") == 0 && i + 1 < argc) rsa_der = argv[++i];
        else if (strcmp(argv[i], "--dh-ffdhe2048") == 0 && i + 1 < argc) ffdhe = argv[++i];
        else if (strcmp(argv[i], "--dh-modp2048") == 0 && i + 1 < argc) modp = argv[++i];
        else {
            fprintf(stderr, "usage: %s --lib <so> --rsa-der <der> --dh-ffdhe2048 <hex> --dh-modp2048 <hex>\n", argv[0]);
            return 2;
        }
    }
    if (lib == NULL || rsa_der == NULL || ffdhe == NULL || modp == NULL) {
        fprintf(stderr, "pfp5_diff: all arguments are required\n");
        return 2;
    }
    if (!load_api(lib)) return 2;
    ok &= modexp_sweep();
    ok &= rsa_arms(rsa_der);
    ok &= dh_arm("ffdhe2048", ffdhe);
    ok &= dh_arm("modp2048", modp);
    printf("DONE ok=%d\n", ok);
    return ok ? 0 : 1;
}
