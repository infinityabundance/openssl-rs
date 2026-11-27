/*
 * pfp7_diff.c — PFP-7 deterministic differential against the authority.
 *
 * One library per process (dlopen), the same DER key, the same deterministic
 * inputs, and a transcript of every return code and every output byte.  The
 * runner diffs the candidate transcript against the OpenSSL 3.6.4 authority
 * transcript byte for byte.
 *
 * Matrix: {CRT key, non-CRT key (n, e, d only)} x {blinding on, blinding off}
 *         x {NO_PADDING sign, PKCS#1 sign, NO_PADDING decrypt,
 *            PKCS#1 decrypt of valid and malformed ciphertexts, OAEP decrypt}
 *
 * The malformed PKCS#1 decrypt population is the implicit-rejection surface:
 * a zero-length input, an input longer than the modulus, the all-zero block,
 * n-1, the all-0xff block, and a length-correct block of garbage.  The
 * candidate's observable answer (return code and the untouched/rewritten
 * output buffer, printed in full) must equal the authority's, including the
 * zero-length synthetic answer.
 */

#define _GNU_SOURCE
#include <openssl/bn.h>
#include <openssl/rsa.h>

#include <dlfcn.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    void *h;
    RSA *(*d2i_RSAPrivateKey)(RSA **, const unsigned char **, long);
    RSA *(*RSA_new)(void);
    void (*RSA_free)(RSA *);
    int (*RSA_size)(const RSA *);
    int (*RSA_private_encrypt)(int, const unsigned char *, unsigned char *, RSA *, int);
    int (*RSA_private_decrypt)(int, const unsigned char *, unsigned char *, RSA *, int);
    int (*RSA_public_encrypt)(int, const unsigned char *, unsigned char *, RSA *, int);
    void (*RSA_blinding_off)(RSA *);
    const BIGNUM *(*RSA_get0_n)(const RSA *);
    const BIGNUM *(*RSA_get0_e)(const RSA *);
    const BIGNUM *(*RSA_get0_d)(const RSA *);
    int (*RSA_set0_key)(RSA *, BIGNUM *, BIGNUM *, BIGNUM *);
    BIGNUM *(*BN_dup)(const BIGNUM *);
    void (*BN_free)(BIGNUM *);
    int (*BN_bn2binpad)(const BIGNUM *, unsigned char *, int);
} api_t;

static api_t api;
static void *need(const char *n)
{
    void *p = dlsym(api.h, n);
    if (p == NULL) { fprintf(stderr, "pfp7_diff: missing %s\n", n); exit(2); }
    return p;
}
#define LOAD(f, n) do { *(void **)(&api.f) = need(n); } while (0)

static void load_api(void)
{
    LOAD(d2i_RSAPrivateKey, "d2i_RSAPrivateKey");
    LOAD(RSA_new, "RSA_new");
    LOAD(RSA_free, "RSA_free");
    LOAD(RSA_size, "RSA_size");
    LOAD(RSA_private_encrypt, "RSA_private_encrypt");
    LOAD(RSA_private_decrypt, "RSA_private_decrypt");
    LOAD(RSA_public_encrypt, "RSA_public_encrypt");
    LOAD(RSA_blinding_off, "RSA_blinding_off");
    LOAD(RSA_get0_n, "RSA_get0_n");
    LOAD(RSA_get0_e, "RSA_get0_e");
    LOAD(RSA_get0_d, "RSA_get0_d");
    LOAD(RSA_set0_key, "RSA_set0_key");
    LOAD(BN_dup, "BN_dup");
    LOAD(BN_free, "BN_free");
    LOAD(BN_bn2binpad, "BN_bn2binpad");
}

static unsigned char *read_file(const char *path, long *len)
{
    FILE *f = fopen(path, "rb");
    unsigned char *b;
    long n;
    if (f == NULL) return NULL;
    fseek(f, 0, SEEK_END);
    n = ftell(f);
    fseek(f, 0, SEEK_SET);
    b = malloc((size_t)n);
    if (b == NULL || fread(b, 1, (size_t)n, f) != (size_t)n) { free(b); fclose(f); return NULL; }
    fclose(f);
    *len = n;
    return b;
}

static void hex(const char *tag, int rc, const unsigned char *p, int n)
{
    printf("%s rc=%d out=", tag, rc);
    for (int i = 0; i < n; i++) printf("%02x", p[i]);
    printf("\n");
}

static RSA *make_noncrt(const unsigned char *der, long der_len)
{
    const unsigned char *q = der;
    RSA *src = api.d2i_RSAPrivateKey(NULL, &q, der_len);
    RSA *k;
    if (src == NULL) return NULL;
    k = api.RSA_new();
    if (k == NULL) { api.RSA_free(src); return NULL; }
    if (!api.RSA_set0_key(k, api.BN_dup(api.RSA_get0_n(src)),
                          api.BN_dup(api.RSA_get0_e(src)),
                          api.BN_dup(api.RSA_get0_d(src)))) {
        api.RSA_free(k);
        k = NULL;
    }
    api.RSA_free(src);
    return k;
}

int main(int argc, char **argv)
{
    const char *lib = NULL, *der_path = NULL;
    long der_len = 0;
    unsigned char *der;
    unsigned char *out = NULL, *ref = NULL;
    unsigned char msg[256], ct[256];
    int i, len;

    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--lib") == 0 && i + 1 < argc) lib = argv[++i];
        else if (strcmp(argv[i], "--rsa-der") == 0 && i + 1 < argc) der_path = argv[++i];
    }
    if (lib == NULL || der_path == NULL) return 2;

    api.h = dlopen(lib, RTLD_NOW | RTLD_LOCAL);
    if (api.h == NULL) { fprintf(stderr, "pfp7_diff: dlopen: %s\n", dlerror()); return 2; }
    load_api();
    der = read_file(der_path, &der_len);
    if (der == NULL) return 2;

    for (int mode = 0; mode < 4; mode++) {
        int noncrt = mode & 1, noblind = (mode >> 1) & 1;
        const char *kname = noncrt ? "noncrt" : "crt";
        const char *bname = noblind ? "noblind" : "blind";
        const unsigned char *q = der;
        RSA *rsa = noncrt ? make_noncrt(der, der_len)
                          : api.d2i_RSAPrivateKey(NULL, &q, der_len);
        if (rsa == NULL) { printf("KEY %s-%s FAILED\n", kname, bname); continue; }
        len = api.RSA_size(rsa);
        if (noblind) api.RSA_blinding_off(rsa);
        if (out == NULL) {
            out = malloc(256);
            ref = malloc(256);
            if (out == NULL || ref == NULL) return 2;
        }

        /* Deterministic operands. */
        for (i = 0; i < len; i++) {
            msg[i] = (unsigned char)(0x10 + (i * 37) % 220);
        }
        msg[0] = 0x00;

        /* 1. Sign, NO_PADDING, four inputs. */
        for (int c = 0; c < 4; c++) {
            unsigned char m2[256];
            char tag[96];
            memcpy(m2, msg, (size_t)len);
            m2[c] ^= (unsigned char)(0x5a + c);
            memset(out, 0xaa, (size_t)len);
            snprintf(tag, sizeof(tag), "sign-nopad-%s-%s-%d", kname, bname, c);
            hex(tag, api.RSA_private_encrypt(len, m2, out, rsa, RSA_NO_PADDING), out, len);
        }

        /* 2. Sign, PKCS#1 v1.5, four messages. */
        for (int c = 0; c < 4; c++) {
            unsigned char m2[64];
            char tag[96];
            for (int j = 0; j < 64; j++) m2[j] = (unsigned char)(0x30 + ((j + c * 7) * 11) % 200);
            m2[0] = (unsigned char)(0x30 + c);
            memset(out, 0xaa, (size_t)len);
            snprintf(tag, sizeof(tag), "sign-pkcs1-%s-%s-%d", kname, bname, c);
            hex(tag, api.RSA_private_encrypt(64, m2, out, rsa, RSA_PKCS1_PADDING), out, len);
        }

        /* 3. Decrypt, NO_PADDING, three ciphertexts. */
        for (int c = 0; c < 3; c++) {
            char tag[96];
            unsigned char m2[256];
            memcpy(m2, msg, (size_t)len);
            m2[c] ^= 0x3c;
            if (api.RSA_public_encrypt(len, m2, ct, rsa, RSA_NO_PADDING) != len) {
                printf("ENC %s failed\n", kname);
                break;
            }
            memset(out, 0xaa, (size_t)len);
            snprintf(tag, sizeof(tag), "dec-nopad-%s-%s-%d", kname, bname, c);
            hex(tag, api.RSA_private_decrypt(len, ct, out, rsa, RSA_NO_PADDING), out, len);
        }

        /* 4. Decrypt, PKCS#1 v1.5, valid ciphertexts. */
        for (int c = 0; c < 3; c++) {
            char tag[96];
            unsigned char m2[64];
            for (int j = 0; j < 64; j++) m2[j] = (unsigned char)(0x41 + ((j + c) * 5) % 90);
            if (api.RSA_public_encrypt(64, m2, ct, rsa, RSA_PKCS1_PADDING) != len) {
                printf("ENC %s failed\n", kname);
                break;
            }
            memset(out, 0xaa, (size_t)len);
            snprintf(tag, sizeof(tag), "dec-pkcs1-%s-%s-%d", kname, bname, c);
            hex(tag, api.RSA_private_decrypt(len, ct, out, rsa, RSA_PKCS1_PADDING), out, len);
        }

        /* 5. Malformed PKCS#1 population (implicit rejection surface). */
        {
            static const char *names[] = {"zero-len", "over-long", "all-zero",
                                          "n-minus-1", "all-ff", "garbage"};
            unsigned char blk[257];
            for (int c = 0; c < 6; c++) {
                int flen = len;
                char tag[96];
                memset(blk, 0, sizeof(blk));
                switch (c) {
                case 0: flen = 0; break;
                case 1: flen = len + 1; blk[0] = 0x01; break;
                case 2: flen = len; break;                       /* all zero */
                case 3:                                            /* n - 1 */
                    memset(blk, 0xff, (size_t)len);
                    blk[0] = 0x7f;
                    break;
                case 4: memset(blk, 0xff, (size_t)len); break;
                case 5:
                    for (i = 0; i < len; i++) blk[i] = (unsigned char)(0x02 + (i * 3) % 251);
                    break;
                }
                memset(out, 0xaa, (size_t)len);
                snprintf(tag, sizeof(tag), "dec-pkcs1-mal-%s-%s-%s", kname, bname, names[c]);
                hex(tag, api.RSA_private_decrypt(flen, blk, out, rsa, RSA_PKCS1_PADDING),
                    out, len);
            }
        }

        /* 6. Decrypt, OAEP, two ciphertexts. */
        for (int c = 0; c < 2; c++) {
            char tag[96];
            unsigned char m2[48];
            for (int j = 0; j < 48; j++) m2[j] = (unsigned char)(0x60 + ((j + c) * 9) % 150);
            if (api.RSA_public_encrypt(48, m2, ct, rsa, RSA_PKCS1_OAEP_PADDING) != len) {
                printf("ENC %s failed\n", kname);
                break;
            }
            memset(out, 0xaa, (size_t)len);
            snprintf(tag, sizeof(tag), "dec-oaep-%s-%s-%d", kname, bname, c);
            hex(tag, api.RSA_private_decrypt(len, ct, out, rsa, RSA_PKCS1_OAEP_PADDING), out, len);
        }


        /* 7. Malformed sweep: 128 deterministic malformed blocks, so the
         * implicit-rejection answer length distribution (including a
         * zero-length synthetic answer, if this population contains one) is
         * compared case by case.  FNV-1a of the 256-byte output keeps the
         * transcript small while remaining exact. */
        for (int c = 0; c < 1024; c++) {
            unsigned char blk[256];
            char tag[96];
            int flen = len;
            uint64_t h = 0xcbf29ce484222325ull;
            int rc;
            uint32_t x = (uint32_t)c * 2654435761u + 0x9e3779b9u;
            for (i = 0; i < len; i++) {
                /* per-case deterministic xorshift: a different malformed block
                 * for every c, so the implicit-rejection answer lengths span
                 * the whole range the KDK can produce. */
                x ^= x << 13; x ^= x >> 17; x ^= x << 5;
                blk[i] = (unsigned char)(x & 0xff);
            }
            blk[0] = 0x00;                /* below n */
            if (!(c & 1)) blk[1] = 0x02;  /* half look like a PKCS#1 block */
            memset(out, 0xaa, (size_t)len);
            snprintf(tag, sizeof(tag), "sweep-%s-%s-%03d", kname, bname, c);
            rc = api.RSA_private_decrypt(flen, blk, out, rsa, RSA_PKCS1_PADDING);
            for (i = 0; i < len; i++) { h ^= out[i]; h *= 0x100000001b3ull; }
            printf("%s rc=%d out=%016llx\n", tag, rc, (unsigned long long)h);
        }

        api.RSA_free(rsa);
    }
    free(der);
    free(out);
    free(ref);
    printf("DONE\n");
    return 0;
}
