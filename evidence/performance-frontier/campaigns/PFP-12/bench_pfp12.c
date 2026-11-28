/*
 * bench_pfp12.c — PFP-12 AEAD / SHA-2 workload instrument.
 *
 * One OpenSSL-compatible `libcrypto.so.3` per process, selected with
 * `--lib <absolute path>` and opened `dlopen(RTLD_NOW | RTLD_LOCAL)`. The
 * harness is not linked against libcrypto and never has two mappings.
 *
 * One operation per invocation, so one process is one independent replication:
 *
 *   aes128gcm-64       AES-128-GCM, 16-byte AAD, 64-byte plaintext
 *   aes128gcm-16k      AES-128-GCM, 16-byte AAD, 16384-byte plaintext
 *   aes256gcm-64       AES-256-GCM, 16-byte AAD, 64-byte plaintext
 *   aes256gcm-16k      AES-256-GCM, 16-byte AAD, 16384-byte plaintext
 *   chachapoly-64      ChaCha20-Poly1305, 16-byte AAD, 64-byte plaintext
 *   chachapoly-16k     ChaCha20-Poly1305, 16-byte AAD, 16384-byte plaintext
 *   sha256-16k         SHA-256 over a 16384-byte input
 *   sha512-16k         SHA-512 over a 16384-byte input
 *
 * Every AEAD iteration is the *complete* operation in both directions:
 * EVP_EncryptInit_ex (cipher, then key+IV), AAD, plaintext, Final, GET_TAG,
 * then EVP_DecryptInit_ex, AAD, ciphertext, SET_TAG, and
 * EVP_DecryptFinal_ex — whose return value is the tag verification. A failed
 * seal, open or tag check aborts the process; a timing is never printed for an
 * operation that did not verify.
 *
 * `--once` runs the operation once and prints a `CHECK` line (hex output,
 * open result, tamper result) for the cross-library differential.
 * `--kat` prints the NIST GCM known-answer cases and the empty/partial AAD and
 * plaintext boundary cases for both AEAD families.
 *
 * Timing: warm-up of iters/4, then `runs` timed batches of `iters`
 * complete operations. Each sample is a batch mean in microseconds; the
 * printed figure is the median with min/max. One process is one replication.
 *
 * Exit status is non-zero on any failed setup, failed operation, or failed
 * tag rejection; a zero-time or failed operation is never reported as RESULT.
 */

#define _GNU_SOURCE
#include <openssl/evp.h>

#include <dlfcn.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

typedef struct {
    EVP_CIPHER_CTX *(*EVP_CIPHER_CTX_new)(void);
    void (*EVP_CIPHER_CTX_free)(EVP_CIPHER_CTX *);
    int (*EVP_CIPHER_CTX_ctrl)(EVP_CIPHER_CTX *, int, int, void *);

    const EVP_CIPHER *(*EVP_aes_128_gcm)(void);
    const EVP_CIPHER *(*EVP_aes_256_gcm)(void);
    const EVP_CIPHER *(*EVP_chacha20_poly1305)(void);

    int (*EVP_EncryptInit_ex)(EVP_CIPHER_CTX *, const EVP_CIPHER *, ENGINE *,
                              const unsigned char *, const unsigned char *);
    int (*EVP_EncryptUpdate)(EVP_CIPHER_CTX *, unsigned char *, int *,
                             const unsigned char *, int);
    int (*EVP_EncryptFinal_ex)(EVP_CIPHER_CTX *, unsigned char *, int *);
    int (*EVP_DecryptInit_ex)(EVP_CIPHER_CTX *, const EVP_CIPHER *, ENGINE *,
                              const unsigned char *, const unsigned char *);
    int (*EVP_DecryptUpdate)(EVP_CIPHER_CTX *, unsigned char *, int *,
                             const unsigned char *, int);
    int (*EVP_DecryptFinal_ex)(EVP_CIPHER_CTX *, unsigned char *, int *);

    EVP_MD_CTX *(*EVP_MD_CTX_new)(void);
    void (*EVP_MD_CTX_free)(EVP_MD_CTX *);
    const EVP_MD *(*EVP_sha256)(void);
    const EVP_MD *(*EVP_sha512)(void);
    int (*EVP_DigestInit_ex)(EVP_MD_CTX *, const EVP_MD *, ENGINE *);
    int (*EVP_DigestUpdate)(EVP_MD_CTX *, const void *, size_t);
    int (*EVP_DigestFinal_ex)(EVP_MD_CTX *, unsigned char *, unsigned int *);

    int (*OPENSSL_init_crypto)(uint64_t, const void *);
} api_t;

static api_t api;

static const size_t AADLEN = 16;

static unsigned char key16[16];
static unsigned char key32[32];
static unsigned char iv12[12];
static unsigned char aad[16];
static unsigned char pt64[64];
static unsigned char pt16k[16384];
static unsigned char ct[16384 + 64];
static unsigned char tag[16];
static unsigned char back[16384 + 64];

static double now_us(void)
{
    struct timespec ts;

    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec * 1e6 + (double)ts.tv_nsec / 1e3;
}

static void fill_seeded(uint64_t seed, unsigned char *p, size_t n)
{
    uint64_t x = seed;

    for (size_t i = 0; i < n; i++) {
        x = x * 6364136223846793005ULL + 1442695040888963407ULL;
        p[i] = (unsigned char)(x >> 56);
    }
}

static void *must_sym(void *lib, const char *name)
{
    void *p = dlsym(lib, name);

    if (p == NULL) {
        fprintf(stderr, "bench_pfp12: missing symbol %s: %s\n", name, dlerror());
        exit(2);
    }
    return p;
}

#define LOAD(field, name) (api.field = (void *)must_sym(lib, name))
#define LOAD0(field, name) \
    do { api.field = (void *)dlsym(lib, name); } while (0)

static void load_api(void *lib)
{
    LOAD(EVP_CIPHER_CTX_new, "EVP_CIPHER_CTX_new");
    LOAD(EVP_CIPHER_CTX_free, "EVP_CIPHER_CTX_free");
    LOAD(EVP_CIPHER_CTX_ctrl, "EVP_CIPHER_CTX_ctrl");
    LOAD(EVP_aes_128_gcm, "EVP_aes_128_gcm");
    LOAD(EVP_aes_256_gcm, "EVP_aes_256_gcm");
    LOAD(EVP_chacha20_poly1305, "EVP_chacha20_poly1305");
    LOAD(EVP_EncryptInit_ex, "EVP_EncryptInit_ex");
    LOAD(EVP_EncryptUpdate, "EVP_EncryptUpdate");
    LOAD(EVP_EncryptFinal_ex, "EVP_EncryptFinal_ex");
    LOAD(EVP_DecryptInit_ex, "EVP_DecryptInit_ex");
    LOAD(EVP_DecryptUpdate, "EVP_DecryptUpdate");
    LOAD(EVP_DecryptFinal_ex, "EVP_DecryptFinal_ex");
    LOAD(EVP_MD_CTX_new, "EVP_MD_CTX_new");
    LOAD(EVP_MD_CTX_free, "EVP_MD_CTX_free");
    LOAD(EVP_sha256, "EVP_sha256");
    LOAD(EVP_sha512, "EVP_sha512");
    LOAD(EVP_DigestInit_ex, "EVP_DigestInit_ex");
    LOAD(EVP_DigestUpdate, "EVP_DigestUpdate");
    LOAD(EVP_DigestFinal_ex, "EVP_DigestFinal_ex");
    LOAD0(OPENSSL_init_crypto, "OPENSSL_init_crypto");
    if (api.OPENSSL_init_crypto != NULL)
        (void)api.OPENSSL_init_crypto(0, NULL);
}

enum { K_AES128 = 0, K_AES256, K_CHACHA };
enum { M_SHA256 = 0, M_SHA512 };

typedef struct {
    const char *name;
    int aead;
    int which;
    size_t ptlen;
} opdef;

static const opdef OPS[] = {
    {"aes128gcm-64", 1, K_AES128, 64},
    {"aes128gcm-16k", 1, K_AES128, 16384},
    {"aes256gcm-64", 1, K_AES256, 64},
    {"aes256gcm-16k", 1, K_AES256, 16384},
    {"chachapoly-64", 1, K_CHACHA, 64},
    {"chachapoly-16k", 1, K_CHACHA, 16384},
    {"sha256-16k", 0, M_SHA256, 16384},
    {"sha512-16k", 0, M_SHA512, 16384},
};
static const size_t NOPS = sizeof(OPS) / sizeof(OPS[0]);

static const opdef *find_op(const char *name)
{
    for (size_t i = 0; i < NOPS; i++)
        if (strcmp(OPS[i].name, name) == 0)
            return &OPS[i];
    return NULL;
}

static const EVP_CIPHER *cipher_of(int which)
{
    switch (which) {
    case K_AES128:
        return api.EVP_aes_128_gcm();
    case K_AES256:
        return api.EVP_aes_256_gcm();
    default:
        return api.EVP_chacha20_poly1305();
    }
}

static const unsigned char *key_of(int which)
{
    return which == K_AES256 ? key32 : key16;
}

/*
 * Complete AEAD: seal (AAD + plaintext + Final + GET_TAG) followed by open
 * (AAD + ciphertext + SET_TAG + DecryptFinal). Returns 0 only when the seal
 * succeeded *and* the tag verified.
 */
static int aead_round(EVP_CIPHER_CTX *ctx, int which, const unsigned char *pt,
                      size_t ptlen, unsigned char *out, unsigned char *tagout)
{
    const EVP_CIPHER *c = cipher_of(which);
    const unsigned char *key = key_of(which);
    int outl = 0;
    int ctlen = 0;
    int backlen = 0;

    if (api.EVP_EncryptInit_ex(ctx, c, NULL, NULL, NULL) != 1)
        return -1;
    if (api.EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv12) != 1)
        return -1;
    if (AADLEN > 0 && api.EVP_EncryptUpdate(ctx, NULL, &outl, aad, (int)AADLEN) != 1)
        return -1;
    if (ptlen > 0) {
        if (api.EVP_EncryptUpdate(ctx, out, &outl, pt, (int)ptlen) != 1)
            return -1;
        ctlen = outl;
    }
    if (api.EVP_EncryptFinal_ex(ctx, out + ctlen, &outl) != 1)
        return -1;
    ctlen += outl;
    if (api.EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tagout) != 1)
        return -1;

    if (api.EVP_DecryptInit_ex(ctx, c, NULL, NULL, NULL) != 1)
        return -1;
    if (api.EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv12) != 1)
        return -1;
    if (AADLEN > 0 && api.EVP_DecryptUpdate(ctx, NULL, &outl, aad, (int)AADLEN) != 1)
        return -1;
    if (ctlen > 0) {
        if (api.EVP_DecryptUpdate(ctx, back, &outl, out, ctlen) != 1)
            return -1;
        backlen = outl;
    }
    if (api.EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, tagout) != 1)
        return -1;
    if (api.EVP_DecryptFinal_ex(ctx, back + backlen, &outl) != 1)
        return -1;
    return 0;
}

/* Decrypt-only with a supplied tag; returns 0 when the tag is accepted. */
static int aead_open_only(EVP_CIPHER_CTX *ctx, int which, const unsigned char *ctin,
                          size_t ctlen, const unsigned char *tagin, unsigned char *out)
{
    const EVP_CIPHER *c = cipher_of(which);
    const unsigned char *key = key_of(which);
    int outl = 0;

    if (api.EVP_DecryptInit_ex(ctx, c, NULL, NULL, NULL) != 1)
        return -1;
    if (api.EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv12) != 1)
        return -1;
    if (AADLEN > 0 && api.EVP_DecryptUpdate(ctx, NULL, &outl, aad, (int)AADLEN) != 1)
        return -1;
    if (ctlen > 0 && api.EVP_DecryptUpdate(ctx, out, &outl, ctin, (int)ctlen) != 1)
        return -1;
    if (api.EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, (void *)tagin) != 1)
        return -1;
    return api.EVP_DecryptFinal_ex(ctx, out + outl, &outl) == 1 ? 0 : -1;
}

static int sha_round(EVP_MD_CTX *ctx, int which, const unsigned char *in, size_t len,
                     unsigned char *md, unsigned int *mdlen)
{
    const EVP_MD *m = which == M_SHA256 ? api.EVP_sha256() : api.EVP_sha512();

    if (api.EVP_DigestInit_ex(ctx, m, NULL) != 1)
        return -1;
    if (api.EVP_DigestUpdate(ctx, in, len) != 1)
        return -1;
    return api.EVP_DigestFinal_ex(ctx, md, mdlen) == 1 ? 0 : -1;
}

static void print_hex(const char *label, const unsigned char *p, size_t n)
{
    printf("%s=", label);
    for (size_t i = 0; i < n; i++)
        printf("%02x", p[i]);
}

static double bench(const opdef *op, EVP_CIPHER_CTX *cctx, EVP_MD_CTX *mctx,
                    long iters, int runs)
{
    double *samples = calloc((size_t)runs, sizeof(*samples));
    long warm = iters / 4;
    unsigned char md[64];
    unsigned int mdlen = 0;
    double t0, t1;

    if (samples == NULL) {
        fprintf(stderr, "bench_pfp12: out of memory\n");
        exit(2);
    }
    if (warm < 1)
        warm = 1;

    for (long i = 0; i < warm; i++) {
        if (op->aead) {
            if (aead_round(cctx, op->which, pt16k, op->ptlen, ct, tag) != 0) {
                fprintf(stderr, "bench_pfp12: warmup open failed for %s\n", op->name);
                exit(3);
            }
        } else if (sha_round(mctx, op->which, pt16k, op->ptlen, md, &mdlen) != 0) {
            fprintf(stderr, "bench_pfp12: warmup digest failed for %s\n", op->name);
            exit(3);
        }
    }

    for (int r = 0; r < runs; r++) {
        t0 = now_us();
        for (long i = 0; i < iters; i++) {
            if (op->aead) {
                if (aead_round(cctx, op->which, pt16k, op->ptlen, ct, tag) != 0) {
                    fprintf(stderr, "bench_pfp12: open failed for %s\n", op->name);
                    exit(3);
                }
            } else if (sha_round(mctx, op->which, pt16k, op->ptlen, md, &mdlen) != 0) {
                fprintf(stderr, "bench_pfp12: digest failed for %s\n", op->name);
                exit(3);
            }
        }
        t1 = now_us();
        samples[r] = (t1 - t0) / (double)iters;
    }

    for (int a = 0; a < runs; a++)
        for (int b = a + 1; b < runs; b++)
            if (samples[b] < samples[a]) {
                double t = samples[a];
                samples[a] = samples[b];
                samples[b] = t;
            }
    printf("RESULT %s bytes=%zu median_us=%.4f min_us=%.4f max_us=%.4f runs=%d iters=%ld\n",
           op->name, op->ptlen, samples[runs / 2], samples[0], samples[runs - 1], runs,
           iters);
    free(samples);
    return samples[runs / 2];
}

static void once(const opdef *op, EVP_CIPHER_CTX *cctx, EVP_MD_CTX *mctx)
{
    unsigned char md[64];
    unsigned int mdlen = 0;
    unsigned char tampered[16];

    if (!op->aead) {
        if (sha_round(mctx, op->which, pt16k, op->ptlen, md, &mdlen) != 0) {
            fprintf(stderr, "bench_pfp12: digest failed for %s\n", op->name);
            exit(3);
        }
        printf("CHECK %s", op->name);
        print_hex(" md", md, mdlen);
        printf("\n");
        return;
    }

    if (aead_round(cctx, op->which, pt16k, op->ptlen, ct, tag) != 0) {
        fprintf(stderr, "bench_pfp12: open failed for %s\n", op->name);
        exit(3);
    }
    printf("CHECK %s", op->name);
    print_hex(" ct", ct, op->ptlen);
    print_hex(" tag", tag, 16);
    printf(" open=ok");

    memcpy(tampered, tag, 16);
    tampered[0] ^= 0x01;
    if (aead_open_only(cctx, op->which, ct, op->ptlen, tampered, back) == 0) {
        printf(" tamper=ACCEPTED\n");
        exit(4);
    }
    printf(" tamper=rejected\n");
}

static int kat_case(EVP_CIPHER_CTX *ctx, int which, const unsigned char *pt, size_t ptlen,
                    const unsigned char *kv, const unsigned char *ivv, const unsigned char *av,
                    size_t aadlen, const char *name, const char *want_ct,
                    const char *want_tag)
{
    const EVP_CIPHER *c = cipher_of(which);
    int outl = 0, ctlen = 0, backlen = 0, ok = 1;
    static unsigned char kc[16384];
    unsigned char tagc[16];
    char cthex[256];
    char taghex[64];
    size_t i;

    if (api.EVP_EncryptInit_ex(ctx, c, NULL, NULL, NULL) != 1)
        return -1;
    if (api.EVP_EncryptInit_ex(ctx, NULL, NULL, kv, ivv) != 1)
        return -1;
    if (aadlen > 0 && api.EVP_EncryptUpdate(ctx, NULL, &outl, av, (int)aadlen) != 1)
        return -1;
    if (ptlen > 0) {
        if (api.EVP_EncryptUpdate(ctx, kc, &outl, pt, (int)ptlen) != 1)
            return -1;
        ctlen = outl;
    }
    if (api.EVP_EncryptFinal_ex(ctx, kc + ctlen, &outl) != 1)
        return -1;
    ctlen += outl;
    if (api.EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tagc) != 1)
        return -1;

    if (api.EVP_DecryptInit_ex(ctx, c, NULL, NULL, NULL) != 1)
        return -1;
    if (api.EVP_DecryptInit_ex(ctx, NULL, NULL, kv, ivv) != 1)
        return -1;
    if (aadlen > 0 && api.EVP_DecryptUpdate(ctx, NULL, &outl, av, (int)aadlen) != 1)
        return -1;
    if (ctlen > 0) {
        if (api.EVP_DecryptUpdate(ctx, back, &outl, kc, ctlen) != 1)
            return -1;
        backlen = outl;
    }
    if (api.EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, tagc) != 1)
        return -1;
    if (api.EVP_DecryptFinal_ex(ctx, back + backlen, &outl) != 1)
        return -1;

    for (i = 0; i < (size_t)ctlen && i < sizeof(cthex) / 2 - 1; i++)
        snprintf(cthex + 2 * i, 3, "%02x", kc[i]);
    cthex[2 * i] = '\0';
    for (i = 0; i < 16; i++)
        snprintf(taghex + 2 * i, 3, "%02x", tagc[i]);
    taghex[32] = '\0';

    printf("KAT %s ptlen=%zu aadlen=%zu ct=%s tag=%s open=ok\n", name, ptlen, aadlen, cthex,
           taghex);
    if (want_ct != NULL && strcmp(cthex, want_ct) != 0) {
        printf("KAT-MISMATCH %s ct want=%s\n", name, want_ct);
        ok = 0;
    }
    if (want_tag != NULL && strcmp(taghex, want_tag) != 0) {
        printf("KAT-MISMATCH %s tag want=%s\n", name, want_tag);
        ok = 0;
    }
    return ok ? 0 : -1;
}

static int kat(EVP_CIPHER_CTX *ctx)
{
    static const unsigned char zero16[16] = {0};
    static const unsigned char zero12[12] = {0};
    static const unsigned char zero32[32] = {0};
    static const unsigned char ones16[16] = {
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
        0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00};
    static const unsigned char ivb[12] = {
        0xca, 0xfe, 0xba, 0xbe, 0xfa, 0xce, 0xdb, 0xad,
        0xde, 0xca, 0xf8, 0x88};
    int rc = 0;

    /* NIST SP 800-38D / GCM spec test case 1: empty plaintext, empty AAD. */
    rc |= kat_case(ctx, K_AES128, NULL, 0, zero16, zero12, NULL, 0, "aes128-empty-empty",
                   "", "58e2fccefa7e3061367f1d57a4e7455a");
    /* Test case 2: one zero block, empty AAD. */
    rc |= kat_case(ctx, K_AES128, zero16, 16, zero16, zero12, NULL, 0, "aes128-block-empty-aad",
                   "0388dace60b6a392f328c2b971b2fe78",
                   "ab6e47d42cec13bdf53a67b21257bddf");
    /* Boundary cases: empty plaintext with AAD, nonempty with empty AAD. */
    rc |= kat_case(ctx, K_AES128, NULL, 0, key16, ivb, ones16, 16, "aes128-empty-pt-aad",
                   NULL, NULL);
    rc |= kat_case(ctx, K_AES128, ones16, 16, key16, ivb, NULL, 0, "aes128-block-no-aad",
                   NULL, NULL);
    rc |= kat_case(ctx, K_AES128, pt64, 64, key16, ivb, ones16, 16, "aes128-64-aad",
                   NULL, NULL);
    rc |= kat_case(ctx, K_AES128, pt16k, 16384, key16, ivb, ones16, 16, "aes128-16k-aad",
                   NULL, NULL);

    rc |= kat_case(ctx, K_AES256, NULL, 0, zero32, zero12, NULL, 0, "aes256-empty-empty",
                   NULL, NULL);
    rc |= kat_case(ctx, K_AES256, NULL, 0, key32, ivb, ones16, 16, "aes256-empty-pt-aad",
                   NULL, NULL);
    rc |= kat_case(ctx, K_AES256, ones16, 16, key32, ivb, NULL, 0, "aes256-block-no-aad",
                   NULL, NULL);
    rc |= kat_case(ctx, K_AES256, pt64, 64, key32, ivb, ones16, 16, "aes256-64-aad",
                   NULL, NULL);
    rc |= kat_case(ctx, K_AES256, pt16k, 16384, key32, ivb, ones16, 16, "aes256-16k-aad",
                   NULL, NULL);

    rc |= kat_case(ctx, K_CHACHA, NULL, 0, key32, zero12, NULL, 0, "chacha-empty-empty",
                   NULL, NULL);
    rc |= kat_case(ctx, K_CHACHA, NULL, 0, key32, ivb, ones16, 16, "chacha-empty-pt-aad",
                   NULL, NULL);
    rc |= kat_case(ctx, K_CHACHA, ones16, 16, key32, ivb, NULL, 0, "chacha-block-no-aad",
                   NULL, NULL);
    rc |= kat_case(ctx, K_CHACHA, pt64, 64, key32, ivb, ones16, 16, "chacha-64-aad",
                   NULL, NULL);
    rc |= kat_case(ctx, K_CHACHA, pt16k, 16384, key32, ivb, ones16, 16, "chacha-16k-aad",
                   NULL, NULL);
    return rc;
}

static void usage(void)
{
    fprintf(stderr,
            "usage: bench_pfp12 --lib PATH (--op OP [--iters N] [--runs R] | --once --op OP "
            "| --kat)\n");
    exit(2);
}

int main(int argc, char **argv)
{
    const char *libpath = NULL;
    const char *opname = NULL;
    long iters = -1;
    int runs = 5;
    int once_mode = 0, kat_mode = 0;
    void *lib;
    const opdef *op;
    EVP_CIPHER_CTX *cctx;
    EVP_MD_CTX *mctx;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--lib") == 0 && i + 1 < argc)
            libpath = argv[++i];
        else if (strcmp(argv[i], "--op") == 0 && i + 1 < argc)
            opname = argv[++i];
        else if (strcmp(argv[i], "--iters") == 0 && i + 1 < argc)
            iters = strtol(argv[++i], NULL, 10);
        else if (strcmp(argv[i], "--runs") == 0 && i + 1 < argc)
            runs = (int)strtol(argv[++i], NULL, 10);
        else if (strcmp(argv[i], "--once") == 0)
            once_mode = 1;
        else if (strcmp(argv[i], "--kat") == 0)
            kat_mode = 1;
        else
            usage();
    }
    if (libpath == NULL || runs < 1)
        usage();
    if (!kat_mode && opname == NULL)
        usage();

    lib = dlopen(libpath, RTLD_NOW | RTLD_LOCAL);
    if (lib == NULL) {
        fprintf(stderr, "bench_pfp12: dlopen %s: %s\n", libpath, dlerror());
        return 2;
    }
    load_api(lib);

    fill_seeded(0x50465031324b4559ULL, key16, sizeof(key16));
    fill_seeded(0x50465031324b4559ULL + 1, key32, sizeof(key32));
    fill_seeded(0x50465031324b4559ULL + 2, iv12, sizeof(iv12));
    fill_seeded(0x50465031324b4559ULL + 3, aad, sizeof(aad));
    fill_seeded(0x50465031324b4559ULL + 4, pt64, sizeof(pt64));
    fill_seeded(0x50465031324b4559ULL + 5, pt16k, sizeof(pt16k));

    cctx = api.EVP_CIPHER_CTX_new();
    mctx = api.EVP_MD_CTX_new();
    if (cctx == NULL || mctx == NULL) {
        fprintf(stderr, "bench_pfp12: context allocation failed\n");
        return 2;
    }

    if (kat_mode) {
        int rc = kat(cctx);
        api.EVP_CIPHER_CTX_free(cctx);
        api.EVP_MD_CTX_free(mctx);
        dlclose(lib);
        return rc == 0 ? 0 : 5;
    }

    op = find_op(opname);
    if (op == NULL) {
        fprintf(stderr, "bench_pfp12: unknown op %s\n", opname);
        return 2;
    }

    if (once_mode) {
        once(op, cctx, mctx);
    } else {
        if (iters <= 0)
            iters = op->aead ? (op->ptlen >= 16384 ? 8 : 3000) : 64;
        (void)bench(op, cctx, mctx, iters, runs);
    }

    api.EVP_CIPHER_CTX_free(cctx);
    api.EVP_MD_CTX_free(mctx);
    dlclose(lib);
    return 0;
}
