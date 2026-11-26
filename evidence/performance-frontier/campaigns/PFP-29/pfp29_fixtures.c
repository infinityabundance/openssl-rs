/*
 * pfp29_fixtures.c — produce the RSA-2048 fixture used by the PFP-29
 * differential and taint populations.
 *
 * Runs against an explicitly dlopen()ed DSO (the 3.6.4 authority, digest
 * 611e511d…): it generates one RSA-2048 key, prints its components as hex, and
 * encrypts a fixed message with PKCS#1 v1.5 so both subjects decrypt the same
 * ciphertext.  The output file is frozen in raw/rsa-fixture.txt; every later
 * run consumes it rather than regenerating, so the population is fixed.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct bignum_st BIGNUM;
typedef struct rsa_st RSA;

struct api {
    RSA *(*RSA_new)(void);
    void (*RSA_free)(RSA *);
    int (*RSA_generate_key_ex)(RSA *, int, BIGNUM *, void *);
    void (*RSA_get0_key)(const RSA *, const BIGNUM **, const BIGNUM **,
                         const BIGNUM **);
    void (*RSA_get0_factors)(const RSA *, const BIGNUM **, const BIGNUM **);
    void (*RSA_get0_crt_params)(const RSA *, const BIGNUM **, const BIGNUM **,
                                const BIGNUM **);
    BIGNUM *(*BN_bin2bn)(const unsigned char *, int, BIGNUM *);
    void (*BN_free)(BIGNUM *);
    char *(*BN_bn2hex)(const BIGNUM *);
    void (*CRYPTO_free)(void *, const char *, int);
    int (*RSA_public_encrypt)(int, const unsigned char *, unsigned char *, RSA *,
                              int);
    int (*RSA_bits)(const RSA *);
};

static const unsigned char MSG[] = "PFP-29 RSA fixture message";

static void dump(FILE *f, const char *name, const BIGNUM *bn,
                 struct api *api)
{
    char *hex = api->BN_bn2hex(bn);
    fprintf(f, "%s %s\n", name, hex ? hex : "-");
    if (hex)
        api->CRYPTO_free(hex, NULL, 0);
}

static void hexdump(FILE *f, const char *name, const unsigned char *buf,
                    size_t len)
{
    size_t i;
    fprintf(f, "%s ", name);
    for (i = 0; i < len; i++)
        fprintf(f, "%02x", buf[i]);
    fprintf(f, "\n");
}

int main(int argc, char **argv)
{
    struct api api;
    void *h;
    RSA *rsa = NULL;
    BIGNUM *e = NULL;
    const BIGNUM *n, *ee, *d, *p, *q, *dmp1, *dmq1, *iqmp;
    unsigned char ct[512];
    int ctlen, bits;
    const char *lib = argc > 1 ? argv[1] : NULL;

    if (lib == NULL) {
        fprintf(stderr, "usage: %s <libcrypto.so.3> > fixture.txt\n", argv[0]);
        return 2;
    }
    h = dlopen(lib, RTLD_NOW | RTLD_LOCAL);
    if (h == NULL) {
        fprintf(stderr, "dlopen: %s\n", dlerror());
        return 3;
    }
#define LOAD(f, s)                                                             \
    do {                                                                       \
        void *p = dlsym(h, s);                                                 \
        if (p == NULL) {                                                       \
            fprintf(stderr, "missing %s\n", s);                                \
            return 4;                                                          \
        }                                                                      \
        memcpy(&api.f, &p, sizeof(p));                                         \
    } while (0)
    LOAD(RSA_new, "RSA_new");
    LOAD(RSA_free, "RSA_free");
    LOAD(RSA_generate_key_ex, "RSA_generate_key_ex");
    LOAD(RSA_get0_key, "RSA_get0_key");
    LOAD(RSA_get0_factors, "RSA_get0_factors");
    LOAD(RSA_get0_crt_params, "RSA_get0_crt_params");
    LOAD(BN_bin2bn, "BN_bin2bn");
    LOAD(BN_free, "BN_free");
    LOAD(BN_bn2hex, "BN_bn2hex");
    LOAD(CRYPTO_free, "CRYPTO_free");
    LOAD(RSA_public_encrypt, "RSA_public_encrypt");
    LOAD(RSA_bits, "RSA_bits");
#undef LOAD

    rsa = api.RSA_new();
    e = api.BN_bin2bn((const unsigned char *)"\x01\x00\x01", 3, NULL);
    if (rsa == NULL || e == NULL || api.RSA_generate_key_ex(rsa, 2048, e, NULL) != 1) {
        fprintf(stderr, "RSA key generation failed\n");
        return 5;
    }
    api.RSA_get0_key(rsa, &n, &ee, &d);
    api.RSA_get0_factors(rsa, &p, &q);
    api.RSA_get0_crt_params(rsa, &dmp1, &dmq1, &iqmp);
    bits = api.RSA_bits(rsa);
    if (bits != 2048 || n == NULL || e == NULL || d == NULL || p == NULL ||
        q == NULL || dmp1 == NULL || dmq1 == NULL || iqmp == NULL) {
        fprintf(stderr, "generated key lacks 2048-bit CRT components\n");
        return 6;
    }
    ctlen = api.RSA_public_encrypt((int)(sizeof MSG - 1), MSG, ct, rsa, 1 /* PKCS1 */);
    if (ctlen <= 0) {
        fprintf(stderr, "RSA_public_encrypt failed\n");
        return 7;
    }

    fprintf(stdout, "# PFP-29 RSA-2048 fixture, authority-generated\n");
    fprintf(stdout, "bits 2048\n");
    dump(stdout, "n", n, &api);
    dump(stdout, "e", e, &api);
    dump(stdout, "d", d, &api);
    dump(stdout, "p", p, &api);
    dump(stdout, "q", q, &api);
    dump(stdout, "dmp1", dmp1, &api);
    dump(stdout, "dmq1", dmq1, &api);
    dump(stdout, "iqmp", iqmp, &api);
    hexdump(stdout, "ct", ct, (size_t)ctlen);
    hexdump(stdout, "msg", MSG, sizeof MSG - 1);
    fflush(stdout);
    api.RSA_free(rsa);
    api.BN_free(e);
    return 0;
}
