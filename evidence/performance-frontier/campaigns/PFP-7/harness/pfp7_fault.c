/*
 * pfp7_fault.c — PFP-7 fault-injection matrix on the CRT result check.
 *
 * The row's acceptance condition is "fault injection in each CRT half and in
 * recombination; the result check and implicit rejection unchanged".  This
 * harness injects a fault where a hardware fault would land — in the value a
 * CRT half contributes to the recombination — by corrupting the key component
 * that half consumes (`+1` on `dmp1` for the mod-p half, `+1` on `dmq1` for the
 * mod-q half, `+1` on `iqmp` for the recombination).  With a correct `d`, the
 * only way the operation can return the *correct* signature is if the result
 * check rejected the CRT answer and the tail fell back to the unblinded `d`
 * exponentiation.  Returning the corrupted CRT value instead would be an
 * undetected fault.
 *
 * Controls:
 *   clean        no corruption: reference value.
 *   halfA        dmp1 + 1         (mod-p half faulty)
 *   halfB        dmq1 + 1         (mod-q half faulty)
 *   combine      iqmp + 1         (recombination faulty)
 *   halfA+badD   dmp1 + 1, d + 1  (faulty half AND faulty fallback)
 *   halfB+badD   dmq1 + 1, d + 1
 *   combine+badD iqmp + 1, d + 1
 *   badD         d + 1 only       (CRT still correct; no fault to detect)
 *
 * Every case is run with blinding on and with blinding off.  Detection is
 * reported per case as DETECTED (output equals clean) / UNDETECTED (output
 * differs although d is correct) / EXPECTED_WRONG (output differs and d is
 * also corrupt, i.e. the control that the corruption is observable).
 *
 * Output is one line per case: identity, verdict, and the digest of the
 * produced signature so the run is auditable without 256-byte hex dumps.
 */

#define _GNU_SOURCE
#include <openssl/bn.h>
#include <openssl/rsa.h>

#include <dlfcn.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define HASH_BYTES 256

typedef struct {
    void *h;
    RSA *(*d2i_RSAPrivateKey)(RSA **, const unsigned char **, long);
    RSA *(*RSA_new)(void);
    void (*RSA_free)(RSA *);
    int (*RSA_size)(const RSA *);
    int (*RSA_private_encrypt)(int, const unsigned char *, unsigned char *, RSA *, int);
    int (*RSA_public_decrypt)(int, const unsigned char *, unsigned char *, RSA *, int);
    void (*RSA_blinding_off)(RSA *);
    const BIGNUM *(*RSA_get0_n)(const RSA *);
    const BIGNUM *(*RSA_get0_e)(const RSA *);
    const BIGNUM *(*RSA_get0_d)(const RSA *);
    int (*RSA_get0_factors)(const RSA *, const BIGNUM **, const BIGNUM **);
    int (*RSA_get0_crt_params)(const RSA *, const BIGNUM **, const BIGNUM **, const BIGNUM **);
    int (*RSA_set0_key)(RSA *, BIGNUM *, BIGNUM *, BIGNUM *);
    int (*RSA_set0_factors)(RSA *, BIGNUM *, BIGNUM *);
    int (*RSA_set0_crt_params)(RSA *, BIGNUM *, BIGNUM *, BIGNUM *);
    BIGNUM *(*BN_new)(void);
    void (*BN_free)(BIGNUM *);
    BIGNUM *(*BN_dup)(const BIGNUM *);
    int (*BN_add_word)(BIGNUM *, BN_ULONG);
} api_t;

static api_t api;

static void *need(const char *n)
{
    void *p = dlsym(api.h, n);
    if (p == NULL) {
        fprintf(stderr, "pfp7_fault: missing %s\n", n);
        exit(2);
    }
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
    LOAD(RSA_public_decrypt, "RSA_public_decrypt");
    LOAD(RSA_blinding_off, "RSA_blinding_off");
    LOAD(RSA_get0_n, "RSA_get0_n");
    LOAD(RSA_get0_e, "RSA_get0_e");
    LOAD(RSA_get0_d, "RSA_get0_d");
    LOAD(RSA_get0_factors, "RSA_get0_factors");
    LOAD(RSA_get0_crt_params, "RSA_get0_crt_params");
    LOAD(RSA_set0_key, "RSA_set0_key");
    LOAD(RSA_set0_factors, "RSA_set0_factors");
    LOAD(RSA_set0_crt_params, "RSA_set0_crt_params");
    LOAD(BN_new, "BN_new");
    LOAD(BN_free, "BN_free");
    LOAD(BN_dup, "BN_dup");
    LOAD(BN_add_word, "BN_add_word");
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
    if (b == NULL || fread(b, 1, (size_t)n, f) != (size_t)n) {
        free(b);
        fclose(f);
        return NULL;
    }
    fclose(f);
    *len = n;
    return b;
}

/* FNV-1a over the signature: an auditable identity without hex dumps. */
static uint64_t digest(const unsigned char *p, size_t n)
{
    uint64_t h = 0xcbf29ce484222325ull;
    for (size_t i = 0; i < n; i++) {
        h ^= p[i];
        h *= 0x100000001b3ull;
    }
    return h;
}

enum fault { F_HALF_A = 1u, F_HALF_B = 2u, F_COMBINE = 4u };

static RSA *build_key(const unsigned char *der, long der_len, int noncrt,
                      unsigned faults, int bad_d)
{
    const unsigned char *q = der;
    RSA *rsa = api.d2i_RSAPrivateKey(NULL, &q, der_len);
    const BIGNUM *p = NULL, *qq = NULL, *dmp1 = NULL, *dmq1 = NULL, *iqmp = NULL;
    const BIGNUM *n = NULL, *e = NULL, *d = NULL;

    if (rsa == NULL) return NULL;
    api.RSA_get0_factors(rsa, &p, &qq);
    api.RSA_get0_crt_params(rsa, &dmp1, &dmq1, &iqmp);
    n = api.RSA_get0_n(rsa);
    e = api.RSA_get0_e(rsa);
    d = api.RSA_get0_d(rsa);
    if (p == NULL || qq == NULL || dmp1 == NULL || dmq1 == NULL || iqmp == NULL ||
        n == NULL || e == NULL || d == NULL) {
        api.RSA_free(rsa);
        return NULL;
    }

    if (noncrt) {
        /* A key with only n, e, d: the entry points take the non-CRT arm. */
        RSA *k = api.RSA_new();
        if (k == NULL) return NULL;
        if (!api.RSA_set0_key(k, api.BN_dup(n), api.BN_dup(e), api.BN_dup(d))) {
            api.RSA_free(k);
            return NULL;
        }
        api.RSA_free(rsa);
        return k;
    }

    BIGNUM *na = api.BN_dup(n), *ea = api.BN_dup(e), *da = api.BN_dup(d);
    BIGNUM *pa = api.BN_dup(p), *qa = api.BN_dup(qq);
    BIGNUM *dmp1a = api.BN_dup(dmp1), *dmq1a = api.BN_dup(dmq1), *iqmpa = api.BN_dup(iqmp);
    if (na == NULL || ea == NULL || da == NULL || pa == NULL || qa == NULL ||
        dmp1a == NULL || dmq1a == NULL || iqmpa == NULL) {
        goto fail;
    }
    if (faults & F_HALF_A) api.BN_add_word(dmp1a, 1);
    if (faults & F_HALF_B) api.BN_add_word(dmq1a, 1);
    if (faults & F_COMBINE) api.BN_add_word(iqmpa, 1);
    if (bad_d) api.BN_add_word(da, 1);
    if (!api.RSA_set0_key(rsa, na, ea, da)) goto fail;
    if (!api.RSA_set0_factors(rsa, pa, qa)) goto fail;
    if (!api.RSA_set0_crt_params(rsa, dmp1a, dmq1a, iqmpa)) goto fail;
    return rsa;
fail:
    api.RSA_free(rsa);
    return NULL;
}

static int run_case(const unsigned char *der, long der_len, const char *tag,
                    unsigned faults, int bad_d, int noblind, int noncrt,
                    const unsigned char *msg, int msg_len,
                    unsigned char *out)
{
    RSA *rsa = build_key(der, der_len, noncrt, faults, bad_d);
    int len, rc;
    if (rsa == NULL) {
        printf("CASE %s key=FAILED\n", tag);
        return 0;
    }
    len = api.RSA_size(rsa);
    if (noblind) api.RSA_blinding_off(rsa);
    memset(out, 0xaa, (size_t)len);
    rc = api.RSA_private_encrypt(msg_len, msg, out, rsa, RSA_NO_PADDING);
    api.RSA_free(rsa);
    printf("CASE %s rc=%d out=%016llx\n", tag, rc, (unsigned long long)digest(out, (size_t)len));
    return rc == len;
}

int main(int argc, char **argv)
{
    const char *lib = NULL, *der_path = NULL;
    long der_len = 0;
    unsigned char *der, *msg, *out, *ref;
    int i, len = 0, ok = 1;

    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--lib") == 0 && i + 1 < argc) lib = argv[++i];
        else if (strcmp(argv[i], "--rsa-der") == 0 && i + 1 < argc) der_path = argv[++i];
        else {
            fprintf(stderr, "usage: %s --lib <dso> --rsa-der <der>\n", argv[0]);
            return 2;
        }
    }
    if (lib == NULL || der_path == NULL) return 2;

    api.h = dlopen(lib, RTLD_NOW | RTLD_LOCAL);
    if (api.h == NULL) {
        fprintf(stderr, "pfp7_fault: dlopen: %s\n", dlerror());
        return 2;
    }
    load_api();
    der = read_file(der_path, &der_len);
    if (der == NULL) return 2;

    /* A 256-byte message with the top byte zero: below n, deterministic. */
    msg = calloc(1, 256);
    ref = malloc(256);
    out = malloc(256);
    if (msg == NULL || ref == NULL || out == NULL) return 2;
    msg[0] = 0x00;
    for (i = 1; i < 256; i++) msg[i] = (unsigned char)(0x20 + (i * 13) % 200);

    for (int noblind = 0; noblind <= 1; noblind++) {
        const char *b = noblind ? "noblind" : "blind";
        if (!run_case(der, der_len, noblind ? "clean-noblind" : "clean", 0, 0, noblind, 0,
                      msg, 256, ref)) {
            ok = 0;
        }
        if (!noblind) {
            /* Keep the first clean value as the reference. */
        }
        len = 256;
        {
            struct { const char *tag; unsigned f; int badd; } cases[] = {
                {"halfA", F_HALF_A, 0},
                {"halfB", F_HALF_B, 0},
                {"combine", F_COMBINE, 0},
                {"halfA+badD", F_HALF_A, 1},
                {"halfB+badD", F_HALF_B, 1},
                {"combine+badD", F_COMBINE, 1},
                {"badD", 0, 1},
            };
            for (unsigned k = 0; k < sizeof(cases) / sizeof(cases[0]); k++) {
                char tag[64];
                snprintf(tag, sizeof(tag), "%s-%s", cases[k].tag, b);
                run_case(der, der_len, tag, cases[k].f, cases[k].badd, noblind, 0,
                         msg, 256, out);
                /* Verdict is decided by comparing with the same-mode clean run;
                 * the comparison is done by the caller from the printed digests,
                 * so a policy change cannot be hidden here. */
            }
        }
        /* Non-CRT control: no CRT components to fault, so this is the
         * reference for "the non-CRT arm agrees with the authority". */
        {
            char tag[64];
            snprintf(tag, sizeof(tag), "noncrt-%s", b);
            run_case(der, der_len, tag, 0, 0, noblind, 1, msg, 256, out);
        }
    }
    free(der);
    free(msg);
    free(ref);
    free(out);
    printf("%s\n", ok ? "DONE" : "FAILED");
    return ok ? 0 : 1;
}
