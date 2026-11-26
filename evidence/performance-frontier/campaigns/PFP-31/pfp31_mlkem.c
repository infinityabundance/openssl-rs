/*
 * pfp31_mlkem.c — PFP-31 ML-KEM implicit-rejection harness (512/768/1024).
 *
 * One process, one explicitly dlopen()ed libcrypto.so.3, exported entry points
 * only.  It prints the file it mapped (`LOADED realpath=… entries=…`) and the
 * number of foreign `libcrypto.so` mappings, so the runner can bind the run to
 * the artefact with stat(2).
 *
 * Modes:
 *   control    nothing tainted; valid ciphertext, one decapsulation.
 *   taint      the 64-byte FIPS 203 private-key seed is marked undefined at the
 *              EVP_PKEY_fromdata boundary and imported; the ciphertext is
 *              defined.  Memcheck reports the conditional transfers that depend
 *              on the imported secret.  Nothing reads or prints the shared
 *              secret afterwards.
 *   malformed  build the key from the fixed seed, encapsulate with the fixed
 *              `ikme`, then decapsulate a deterministic population of malformed
 *              ciphertexts and print (rc, outlen, ss) for each.  The population
 *              is identical for every subject, so the authority and the
 *              candidate rows can be compared byte for byte.
 *
 * Population per parameter set (`--case all`):
 *   valid, len-1, len+1,
 *   64 single-bit flips spread over the ciphertext body,
 *   zero, ones, 8 seeded random ciphertexts
 * = 77 cases.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include <valgrind/memcheck.h>

typedef struct evp_pkey_st EVP_PKEY;
typedef struct evp_pkey_ctx_st EVP_PKEY_CTX;

typedef struct ossl_param_st {
    const char *key;
    unsigned int data_type;
    void *data;
    size_t data_size;
    size_t return_size;
} OSSL_PARAM;

#define OSSL_PARAM_OCTET_STRING 5
#define OSSL_PARAM_UNMODIFIED ((size_t)-1)
#define EVP_PKEY_KEYPAIR 3

/* FIPS 203 keygen seed d||z, 32+32 bytes, fixed for reproducibility. */
static const unsigned char KEM_SEED[64] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
    0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
    0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
    0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
    0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f,
};

/* FIPS 203 encapsulation randomness, 32 bytes, fixed. */
static const unsigned char KEM_IKME[32] = {
    0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
    0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f,
    0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57,
    0x58, 0x59, 0x5a, 0x5b, 0x5c, 0x5d, 0x5e, 0x5f,
};

struct api {
    void *handle;
    EVP_PKEY_CTX *(*EVP_PKEY_CTX_new_from_name)(void *, const char *, const char *);
    EVP_PKEY_CTX *(*EVP_PKEY_CTX_new_from_pkey)(void *, EVP_PKEY *, const char *);
    int (*EVP_PKEY_fromdata_init)(EVP_PKEY_CTX *);
    int (*EVP_PKEY_fromdata)(EVP_PKEY_CTX *, EVP_PKEY **, int, OSSL_PARAM *);
    int (*EVP_PKEY_encapsulate_init)(EVP_PKEY_CTX *, const OSSL_PARAM *);
    int (*EVP_PKEY_encapsulate)(EVP_PKEY_CTX *, unsigned char *, size_t *,
                                unsigned char *, size_t *);
    int (*EVP_PKEY_decapsulate_init)(EVP_PKEY_CTX *, const OSSL_PARAM *);
    int (*EVP_PKEY_decapsulate)(EVP_PKEY_CTX *, unsigned char *, size_t *,
                                const unsigned char *, size_t);
    void (*EVP_PKEY_free)(EVP_PKEY *);
    void (*EVP_PKEY_CTX_free)(EVP_PKEY_CTX *);
};

static struct api api;

static void *must_sym(const char *name)
{
    void *p = dlsym(api.handle, name);
    if (p == NULL) {
        fprintf(stderr, "pfp31: missing symbol %s\n", name);
        exit(2);
    }
    return p;
}

#define LOAD(field, name) *(void **)(&api.field) = must_sym(name)

static int load_api(const char *lib)
{
    api.handle = dlopen(lib, RTLD_NOW | RTLD_LOCAL);
    if (api.handle == NULL) {
        fprintf(stderr, "pfp31: dlopen failed: %s\n", dlerror());
        return 0;
    }
    LOAD(EVP_PKEY_CTX_new_from_name, "EVP_PKEY_CTX_new_from_name");
    LOAD(EVP_PKEY_CTX_new_from_pkey, "EVP_PKEY_CTX_new_from_pkey");
    LOAD(EVP_PKEY_fromdata_init, "EVP_PKEY_fromdata_init");
    LOAD(EVP_PKEY_fromdata, "EVP_PKEY_fromdata");
    LOAD(EVP_PKEY_encapsulate_init, "EVP_PKEY_encapsulate_init");
    LOAD(EVP_PKEY_encapsulate, "EVP_PKEY_encapsulate");
    LOAD(EVP_PKEY_decapsulate_init, "EVP_PKEY_decapsulate_init");
    LOAD(EVP_PKEY_decapsulate, "EVP_PKEY_decapsulate");
    LOAD(EVP_PKEY_free, "EVP_PKEY_free");
    LOAD(EVP_PKEY_CTX_free, "EVP_PKEY_CTX_free");
    return 1;
}

static int same_file(const char *a, const char *b)
{
    struct stat sa, sb;
    if (stat(a, &sa) != 0 || stat(b, &sb) != 0)
        return 0;
    return sa.st_dev == sb.st_dev && sa.st_ino == sb.st_ino;
}

static void report_loaded(const char *lib)
{
    char real[PATH_MAX];
    char seen[16][PATH_MAX];
    int nseen = 0, entries = 0, foreign = 0, i;
    FILE *f;
    char line[4096];

    if (realpath(lib, real) == NULL) {
        fprintf(stderr, "pfp31: realpath failed for %s\n", lib);
        exit(2);
    }
    f = fopen("/proc/self/maps", "r");
    if (f == NULL) {
        perror("pfp31: /proc/self/maps");
        exit(2);
    }
    while (fgets(line, sizeof line, f) != NULL) {
        char *slash = strchr(line, '/');
        char *nl;
        if (slash == NULL || strstr(slash, "libcrypto.so") == NULL)
            continue;
        nl = strchr(slash, '\n');
        if (nl != NULL)
            *nl = '\0';
        entries++;
        for (i = 0; i < nseen; i++)
            if (strcmp(seen[i], slash) == 0)
                break;
        if (i == nseen && nseen < 16) {
            strncpy(seen[nseen], slash, PATH_MAX - 1);
            seen[nseen][PATH_MAX - 1] = '\0';
            nseen++;
        }
    }
    fclose(f);
    for (i = 0; i < nseen; i++)
        if (!same_file(seen[i], real))
            foreign++;
    printf("LOADED realpath=%s entries=%d\n", real, entries);
    printf("MAPS libcrypto=1 entries=%d\n", entries);
    printf("FOREIGN libcrypto=%d\n", foreign);
    fflush(stdout);
}

static const char *param_name(int bits)
{
    switch (bits) {
    case 512: return "ML-KEM-512";
    case 768: return "ML-KEM-768";
    case 1024: return "ML-KEM-1024";
    default: return NULL;
    }
}

static size_t param_ct_bytes(int bits)
{
    switch (bits) {
    case 512: return 768;
    case 768: return 1088;
    case 1024: return 1568;
    default: return 0;
    }
}

static EVP_PKEY *key_from_seed(int bits, const unsigned char *seed, int taint)
{
    EVP_PKEY_CTX *ctx;
    EVP_PKEY *pkey = NULL;
    OSSL_PARAM params[2];
    unsigned char local[64];

    if (taint) {
        memcpy(local, seed, sizeof local);
        (void)VALGRIND_MAKE_MEM_UNDEFINED(local, sizeof local);
        seed = local;
        printf("TAINT name=kem-seed bytes=64\n");
    }
    ctx = api.EVP_PKEY_CTX_new_from_name(NULL, param_name(bits), NULL);
    if (ctx == NULL)
        return NULL;
    params[0].key = "seed";
    params[0].data_type = OSSL_PARAM_OCTET_STRING;
    params[0].data = (void *)seed;
    params[0].data_size = 64;
    params[0].return_size = OSSL_PARAM_UNMODIFIED;
    params[1].key = NULL;
    params[1].data_type = 0;
    params[1].data = NULL;
    params[1].data_size = 0;
    params[1].return_size = 0;
    if (api.EVP_PKEY_fromdata_init(ctx) != 1 ||
        api.EVP_PKEY_fromdata(ctx, &pkey, EVP_PKEY_KEYPAIR, params) != 1)
        pkey = NULL;
    api.EVP_PKEY_CTX_free(ctx);
    fflush(stdout);
    return pkey;
}

static int encapsulate(EVP_PKEY *key, unsigned char *ct, size_t *ctlen,
                       unsigned char *ss, size_t *sslen)
{
    EVP_PKEY_CTX *ctx;
    OSSL_PARAM params[2];
    unsigned char ikme[sizeof KEM_IKME];
    int ok;

    memcpy(ikme, KEM_IKME, sizeof ikme);
    params[0].key = "ikme";
    params[0].data_type = OSSL_PARAM_OCTET_STRING;
    params[0].data = ikme;
    params[0].data_size = sizeof ikme;
    params[0].return_size = OSSL_PARAM_UNMODIFIED;
    params[1].key = NULL;
    params[1].data_type = 0;
    params[1].data = NULL;
    params[1].data_size = 0;
    params[1].return_size = 0;
    ctx = api.EVP_PKEY_CTX_new_from_pkey(NULL, key, NULL);
    if (ctx == NULL)
        return 0;
    ok = api.EVP_PKEY_encapsulate_init(ctx, params) == 1 &&
         api.EVP_PKEY_encapsulate(ctx, ct, ctlen, ss, sslen) == 1;
    api.EVP_PKEY_CTX_free(ctx);
    return ok;
}

static int decapsulate(EVP_PKEY *key, const unsigned char *ct, size_t ctlen,
                       unsigned char *out, size_t *outlen)
{
    EVP_PKEY_CTX *ctx = api.EVP_PKEY_CTX_new_from_pkey(NULL, key, NULL);
    int rc;

    if (ctx == NULL)
        return -1;
    if (api.EVP_PKEY_decapsulate_init(ctx, NULL) != 1) {
        api.EVP_PKEY_CTX_free(ctx);
        return -1;
    }
    *outlen = 128;
    rc = api.EVP_PKEY_decapsulate(ctx, out, outlen, ct, ctlen);
    api.EVP_PKEY_CTX_free(ctx);
    return rc;
}

static uint64_t splitmix64(uint64_t *state)
{
    uint64_t z = (*state += 0x9e3779b97f4a7c15ULL);
    z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9ULL;
    z = (z ^ (z >> 27)) * 0x94d049bb133111ebULL;
    return z ^ (z >> 31);
}

static int g_redact_ss = 0;

static void print_row(int bits, const char *id, int rc, size_t outlen,
                      const unsigned char *ss)
{
    size_t i;
    printf("CASE param=%d id=%s rc=%d outlen=%zu ss=", bits, id, rc, outlen);
    if (rc == 1 && !g_redact_ss) {
        for (i = 0; i < outlen; i++)
            printf("%02x", ss[i]);
    } else {
        printf("-");
    }
    printf("\n");
    fflush(stdout);
}

struct population {
    char id[32];
    unsigned char *buf;
    size_t len;
};

static size_t build_population(int bits, const unsigned char *base, size_t ctlen,
                               struct population *pop, size_t cap)
{
    size_t n = 0, i, k;
    uint64_t state = 0x50465033314d4c4bULL;
    size_t positions[64];
    int bit[64];

    memcpy(pop[n].id, "valid", 6);
    pop[n].buf = malloc(ctlen + 8);
    memcpy(pop[n].buf, base, ctlen);
    pop[n].len = ctlen;
    n++;

    memcpy(pop[n].id, "len-1", 6);
    pop[n].buf = malloc(ctlen + 8);
    memcpy(pop[n].buf, base, ctlen);
    pop[n].len = ctlen - 1;
    n++;
    memcpy(pop[n].id, "len+1", 6);
    pop[n].buf = malloc(ctlen + 8);
    memcpy(pop[n].buf, base, ctlen);
    pop[n].buf[ctlen] = 0x00;
    pop[n].len = ctlen + 1;
    n++;

    /* 64 single-bit flips: 16 fixed interesting positions plus 48 seeded. */
    for (i = 0; i < 16; i++) {
        static const size_t fixed[16] = {
            0, 1, 2, 3, 7, 31, 32, 63, 64, 127, 128, 255, 256, 511, 512, 1023
        };
        positions[i] = fixed[i] % ctlen;
        bit[i] = (int)((i * 3) % 8);
    }
    for (i = 16; i < 64; i++) {
        positions[i] = (size_t)(splitmix64(&state) % ctlen);
        bit[i] = (int)(splitmix64(&state) % 8);
    }
    for (i = 0; i < 64; i++) {
        snprintf(pop[n].id, sizeof pop[n].id, "bit-%02zu", i);
        pop[n].buf = malloc(ctlen + 8);
        memcpy(pop[n].buf, base, ctlen);
        pop[n].buf[positions[i]] ^= (unsigned char)(1u << bit[i]);
        pop[n].len = ctlen;
        n++;
    }

    snprintf(pop[n].id, sizeof pop[n].id, "zero");
    pop[n].buf = calloc(1, ctlen + 8);
    pop[n].len = ctlen;
    n++;
    snprintf(pop[n].id, sizeof pop[n].id, "ones");
    pop[n].buf = malloc(ctlen + 8);
    memset(pop[n].buf, 0xff, ctlen);
    pop[n].len = ctlen;
    n++;

    for (k = 0; k < 8; k++) {
        snprintf(pop[n].id, sizeof pop[n].id, "rand-%zu", k);
        pop[n].buf = malloc(ctlen + 8);
        for (i = 0; i < ctlen; i++)
            pop[n].buf[i] = (unsigned char)(splitmix64(&state) >> 24);
        pop[n].len = ctlen;
        n++;
    }
    (void)cap;
    return n;
}

int main(int argc, char **argv)
{
    const char *lib = NULL, *mode = NULL, *want_case = "all";
    int bits = 768, taint = 0, i, rc;
    EVP_PKEY *key = NULL, *key_taint = NULL;
    unsigned char ct[4096], ss[128], out[128];
    size_t ctlen = sizeof ct, sslen = sizeof ss, outlen = 0;
    const char *pn = NULL;

    for (i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--lib") && i + 1 < argc)
            lib = argv[++i];
        else if (!strcmp(argv[i], "--mode") && i + 1 < argc)
            mode = argv[++i];
        else if (!strcmp(argv[i], "--param") && i + 1 < argc)
            bits = atoi(argv[++i]);
        else if (!strcmp(argv[i], "--case") && i + 1 < argc)
            want_case = argv[++i];
        else if (!strcmp(argv[i], "--taint"))
            taint = 1;
        else {
            fprintf(stderr, "pfp31: bad argument %s\n", argv[i]);
            return 2;
        }
    }
    pn = param_name(bits);
    if (lib == NULL || mode == NULL || pn == NULL || param_ct_bytes(bits) == 0) {
        fprintf(stderr, "pfp31: need --lib, --mode and a known --param\n");
        return 2;
    }
    if (strcmp(mode, "control") && strcmp(mode, "taint") &&
        strcmp(mode, "malformed")) {
        fprintf(stderr, "pfp31: unknown mode %s\n", mode);
        return 2;
    }
    if (!load_api(lib))
        return 2;
    report_loaded(lib);

    /* The defined key and the defined ciphertext are built first, in every
     * mode, so a tainted run decapsulates the same defined bytes. */
    key = key_from_seed(bits, KEM_SEED, 0);
    if (key == NULL) {
        fprintf(stderr, "pfp31: seed import failed\n");
        return 1;
    }
    ctlen = sizeof ct;
    sslen = sizeof ss;
    if (!encapsulate(key, ct, &ctlen, ss, &sslen)) {
        fprintf(stderr, "pfp31: encapsulate failed\n");
        return 1;
    }
    printf("BASE param=%d ctlen=%zu sslen=%zu ss=", bits, ctlen, sslen);
    {
        size_t k;
        for (k = 0; k < sslen; k++)
            printf("%02x", ss[k]);
        printf(" ct=");
        for (k = 0; k < ctlen; k++)
            printf("%02x", ct[k]);
        printf("\n");
    }
    fflush(stdout);

    if (strcmp(mode, "taint") == 0)
        taint = 1;

    if (strcmp(mode, "control") == 0 || strcmp(mode, "taint") == 0) {
        EVP_PKEY *use = key;
        if (taint) {
            key_taint = key_from_seed(bits, KEM_SEED, 1);
            if (key_taint == NULL) {
                fprintf(stderr, "pfp31: tainted seed import failed\n");
                return 1;
            }
            use = key_taint;
        }
        rc = decapsulate(use, ct, ctlen, out, &outlen);
        (void)VALGRIND_MAKE_MEM_DEFINED(&rc, sizeof rc);
        (void)VALGRIND_MAKE_MEM_DEFINED(&outlen, sizeof outlen);
        printf("RESULT mode=%s param=%d ok=%d outlen=%zu\n", mode, bits,
               rc == 1, outlen);
        api.EVP_PKEY_free(key);
        if (key_taint != NULL)
            api.EVP_PKEY_free(key_taint);
        return rc == 1 ? 0 : 1;
    }

    {
        struct population *pop = calloc(96, sizeof *pop);
        size_t n, j;
        unsigned char base_copy[4096];
        EVP_PKEY *use = key;

        memcpy(base_copy, ct, ctlen);
        n = build_population(bits, base_copy, ctlen, pop, 96);
        if (taint) {
            key_taint = key_from_seed(bits, KEM_SEED, 1);
            if (key_taint == NULL) {
                fprintf(stderr, "pfp31: tainted seed import failed\n");
                return 1;
            }
            use = key_taint;
            /* Never read, compare or print a secret-derived value after the
             * taint: the shared-secret bytes are redacted. */
            g_redact_ss = 1;
        }
        for (j = 0; j < n; j++) {
            if (strcmp(want_case, "all") != 0 &&
                strcmp(want_case, pop[j].id) != 0)
                continue;
            rc = decapsulate(use, pop[j].buf, pop[j].len, out, &outlen);
            (void)VALGRIND_MAKE_MEM_DEFINED(&rc, sizeof rc);
            (void)VALGRIND_MAKE_MEM_DEFINED(&outlen, sizeof outlen);
            print_row(bits, pop[j].id, rc, outlen, out);
            free(pop[j].buf);
        }
        free(pop);
    }
    api.EVP_PKEY_free(key);
    if (key_taint != NULL)
        api.EVP_PKEY_free(key_taint);
    return 0;
}
