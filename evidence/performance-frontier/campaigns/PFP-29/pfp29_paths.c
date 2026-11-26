/*
 * pfp29_paths.c — PFP-29 per-path ctgrind, timing and differential harness.
 *
 * One process, one explicitly dlopen()ed libcrypto.so.3, exported entry points
 * only.  The process proves which file it mapped by printing
 * `LOADED realpath=… dev=… ino=… size=…` from the mapping and the number of
 * /proc/self/maps entries for it; the runner compares those with stat(2).  It
 * also counts any *other* mapped file whose name contains "libcrypto.so".
 *
 * Modes (--mode).  Each exercises exactly ONE secret-bearing path; paths are
 * never merged:
 *
 *   control        no taint at all; every path once.  Negative control.
 *   ecdsa-sign     ECDSA P-256 sign: the private scalar d and the nonce are
 *                  tainted.  The nonce is tainted where the library computes
 *                  k^-1 and k*G (its own BN_mod_inverse and EC_POINT_mul), and
 *                  the (kinv, r) pair handed to ECDSA_do_sign_ex is tainted.
 *   ecdsa-sign-default
 *                  the shipped default ECDSA_do_sign path (library draws the
 *                  nonce): only d can be tainted at this boundary.  This is
 *                  the mode whose wall time is the signing path; ecdsa-sign
 *                  supplies kinv/r and therefore skips the ladder.
 *   ecdsa-verify   ECDSA P-256 verify.  NOT tainted: every input (public key,
 *                  signature, digest) is public, so there is no secret in
 *                  scope; it is run defined as a behavioural control and is
 *                  covered by the differential, not by the taint claim.
 *   ecdh           ECDH P-256: the private scalar d is tainted.
 *   rsa-crt        RSA-2048 private, CRT arms: d, p, q, dmp1, dmq1, iqmp are
 *                  tainted; RSA_NO_PADDING isolates the exponentiation.
 *   rsa-nocrt      RSA-2048 private with only n, e, d (no CRT): d is tainted.
 *   rsa-crt-pkcs1  the CRT key with PKCS#1 v1.5 padding, the shipped path; the
 *                  padding check is reported separately from rsa-crt.
 *   dh             DH ffdhe2048: the private exponent is tainted;
 *                  DH_compute_key_padded gives a fixed-length secret.
 *   mlkem-decaps   ML-KEM-768 decapsulation.  The 64-byte private-key seed is
 *                  tainted at the documented EVP_PKEY_fromdata import boundary
 *                  (the analogue of mul-g-bytes: the imported secret is
 *                  undefined), the ciphertext stays defined, and the measured
 *                  operation is EVP_PKEY_decapsulate.
 *
 * Taint is placed on limb *values* only and the limb pointer is not trusted:
 * the harness reads it from the documented layout offset and verifies every
 * live limb against the same BIGNUM's own big-endian export before marking
 * anything.  A layout drift fails the operation (exit 13) rather than tainting
 * the wrong bytes.
 *
 * Nothing inspects, compares or prints a secret-derived value after tainting.
 * The only value read afterwards is the success flag, marked defined because it
 * is public, and in timing mode the elapsed time, which is the measurement.
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
#include <time.h>
#include <unistd.h>

#include <valgrind/memcheck.h>

typedef struct bignum_st BIGNUM;
typedef struct bignum_ctx BN_CTX;
typedef struct ec_group_st EC_GROUP;
typedef struct ec_point_st EC_POINT;
typedef struct ec_key_st EC_KEY;
typedef struct ECDSA_SIG_st ECDSA_SIG;
typedef struct rsa_st RSA;
typedef struct dh_st DH;
typedef struct evp_pkey_st EVP_PKEY;
typedef struct evp_pkey_ctx_st EVP_PKEY_CTX;

#define NID_X9_62_prime256v1 415
#define NID_ffdhe2048 1126

/* OSSL_PARAM, core.h:106/123 and params.h:19.  No OpenSSL header is included,
 * so the layout and the two constants are restated here. */
typedef struct ossl_param_st {
    const char *key;
    unsigned int data_type;
    void *data;
    size_t data_size;
    size_t return_size;
} OSSL_PARAM;

#define OSSL_PARAM_OCTET_STRING 5
#define OSSL_PARAM_UNMODIFIED ((size_t)-1)
#define OSSL_PARAM_END_ENTRY                                                   \
    { NULL, 0, NULL, 0, 0 }

#define EVP_PKEY_KEYPAIR 3

#define BN_D_PTR_OFFSET 8

struct api {
    EC_GROUP *(*EC_GROUP_new_by_curve_name)(int);
    void (*EC_GROUP_free)(EC_GROUP *);
    const EC_POINT *(*EC_GROUP_get0_generator)(const EC_GROUP *);
    const BIGNUM *(*EC_GROUP_get0_order)(const EC_GROUP *);
    EC_POINT *(*EC_POINT_new)(const EC_GROUP *);
    void (*EC_POINT_free)(EC_POINT *);
    int (*EC_POINT_mul)(const EC_GROUP *, EC_POINT *, const BIGNUM *,
                        const EC_POINT *, const BIGNUM *, BN_CTX *);
    int (*EC_POINT_get_affine_coordinates)(const EC_GROUP *, const EC_POINT *,
                                           BIGNUM *, BIGNUM *, BN_CTX *);
    EC_KEY *(*EC_KEY_new_by_curve_name)(int);
    void (*EC_KEY_free)(EC_KEY *);
    int (*EC_KEY_set_private_key)(EC_KEY *, const BIGNUM *);
    int (*EC_KEY_set_public_key)(EC_KEY *, const EC_POINT *);
    const BIGNUM *(*EC_KEY_get0_private_key)(const EC_KEY *);
    int (*ECDH_compute_key)(void *, size_t, const EC_POINT *, const EC_KEY *,
                            void *);
    BN_CTX *(*BN_CTX_new)(void);
    void (*BN_CTX_free)(BN_CTX *);
    BIGNUM *(*BN_new)(void);
    void (*BN_free)(BIGNUM *);
    BIGNUM *(*BN_dup)(const BIGNUM *);
    BIGNUM *(*BN_bin2bn)(const unsigned char *, int, BIGNUM *);
    int (*BN_bn2binpad)(const BIGNUM *, unsigned char *, int);
    int (*BN_num_bits)(const BIGNUM *);
    int (*BN_hex2bn)(BIGNUM **, const char *);
    int (*BN_mod_exp)(BIGNUM *, const BIGNUM *, const BIGNUM *, const BIGNUM *,
                      BN_CTX *);
    BIGNUM *(*BN_mod_inverse)(BIGNUM *, const BIGNUM *, const BIGNUM *, BN_CTX *);
    int (*BN_nnmod)(BIGNUM *, const BIGNUM *, const BIGNUM *, BN_CTX *);
    ECDSA_SIG *(*ECDSA_do_sign)(const unsigned char *, int, EC_KEY *);
    ECDSA_SIG *(*ECDSA_do_sign_ex)(const unsigned char *, int, const BIGNUM *,
                                   const BIGNUM *, EC_KEY *);
    int (*ECDSA_do_verify)(const unsigned char *, int, const ECDSA_SIG *,
                           EC_KEY *);
    ECDSA_SIG *(*ECDSA_SIG_new)(void);
    int (*ECDSA_SIG_set0)(ECDSA_SIG *, BIGNUM *, BIGNUM *);
    void (*ECDSA_SIG_get0)(const ECDSA_SIG *, const BIGNUM **,
                           const BIGNUM **);
    void (*ECDSA_SIG_free)(ECDSA_SIG *);
    RSA *(*RSA_new)(void);
    void (*RSA_free)(RSA *);
    void (*RSA_get0_key)(const RSA *, const BIGNUM **, const BIGNUM **,
                         const BIGNUM **);
    int (*RSA_set0_key)(RSA *, BIGNUM *, BIGNUM *, BIGNUM *);
    void (*RSA_get0_factors)(const RSA *, const BIGNUM **, const BIGNUM **);
    int (*RSA_set0_factors)(RSA *, BIGNUM *, BIGNUM *);
    void (*RSA_get0_crt_params)(const RSA *, const BIGNUM **, const BIGNUM **,
                                const BIGNUM **);
    int (*RSA_set0_crt_params)(RSA *, BIGNUM *, BIGNUM *, BIGNUM *);
    int (*RSA_private_decrypt)(int, const unsigned char *, unsigned char *,
                               RSA *, int);
    DH *(*DH_new_by_nid)(int);
    void (*DH_free)(DH *);
    void (*DH_get0_pqg)(const DH *, const BIGNUM **, const BIGNUM **,
                        const BIGNUM **);
    int (*DH_set0_key)(DH *, BIGNUM *, BIGNUM *);
    const BIGNUM *(*DH_get0_priv_key)(const DH *);
    int (*DH_compute_key_padded)(unsigned char *, const BIGNUM *, DH *);
    EVP_PKEY_CTX *(*EVP_PKEY_CTX_new_from_name)(void *, const char *,
                                                const char *);
    EVP_PKEY_CTX *(*EVP_PKEY_CTX_new_from_pkey)(void *, EVP_PKEY *,
                                                 const char *);
    void (*EVP_PKEY_CTX_free)(EVP_PKEY_CTX *);
    void (*EVP_PKEY_free)(EVP_PKEY *);
    int (*EVP_PKEY_keygen_init)(EVP_PKEY_CTX *);
    int (*EVP_PKEY_keygen)(EVP_PKEY_CTX *, EVP_PKEY **);
    int (*EVP_PKEY_CTX_set_params)(EVP_PKEY_CTX *, const OSSL_PARAM *);
    int (*EVP_PKEY_fromdata_init)(EVP_PKEY_CTX *);
    int (*EVP_PKEY_fromdata)(EVP_PKEY_CTX *, EVP_PKEY **, int, OSSL_PARAM *);
    int (*EVP_PKEY_encapsulate_init)(EVP_PKEY_CTX *, const OSSL_PARAM *);
    int (*EVP_PKEY_encapsulate)(EVP_PKEY_CTX *, unsigned char *, size_t *,
                                unsigned char *, size_t *);
    int (*EVP_PKEY_decapsulate_init)(EVP_PKEY_CTX *, const OSSL_PARAM *);
    int (*EVP_PKEY_decapsulate)(EVP_PKEY_CTX *, unsigned char *, size_t *,
                                const unsigned char *, size_t);
    unsigned long (*ERR_get_error)(void);
    void (*ERR_error_string_n)(unsigned long, char *, size_t);
};

static struct api api;
static const char *g_mode = "?";
static int g_taint = 0;
static int g_marked = 0;

/* Fixed public fixtures.  d and k are below the P-256 group order; the DH
 * exponents are fixed 255-bit values in the ffdhe2048 subgroup range; the
 * ML-KEM seed and encapsulation randomness are fixed so the population is
 * frozen, not sampled. */
static const unsigned char D_BYTES[32] = {
    0x1f, 0x2e, 0x3d, 0x4c, 0x5b, 0x6a, 0x79, 0x88,
    0x97, 0xa6, 0xb5, 0xc4, 0xd3, 0xe2, 0xf1, 0x00,
    0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
    0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x07,
};
static const unsigned char K_BYTES[32] = {
    0x2b, 0x3c, 0x4d, 0x5e, 0x6f, 0x70, 0x81, 0x92,
    0xa3, 0xb4, 0xc5, 0xd6, 0xe7, 0xf8, 0x09, 0x1a,
    0x2b, 0x3c, 0x4d, 0x5e, 0x6f, 0x70, 0x81, 0x92,
    0xa3, 0xb4, 0xc5, 0xd6, 0xe7, 0xf8, 0x09, 0x3c,
};
static const unsigned char DGST[32] = {
    0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a,
    0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a,
    0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a,
    0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a,
};
static const unsigned char DH_X[32] = {
    0x11, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
    0x11, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
    0x11, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
    0x11, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
};
static const unsigned char DH_Y[32] = {
    0x0f, 0x1e, 0x2d, 0x3c, 0x4b, 0x5a, 0x69, 0x78,
    0x87, 0x96, 0xa5, 0xb4, 0xc3, 0xd2, 0xe1, 0xf0,
    0x0f, 0x1e, 0x2d, 0x3c, 0x4b, 0x5a, 0x69, 0x78,
    0x87, 0x96, 0xa5, 0xb4, 0xc3, 0xd2, 0xe1, 0xf0,
};
static const unsigned char KEM_SEED[64] = {
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
    0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
    0x10, 0x21, 0x32, 0x43, 0x54, 0x65, 0x76, 0x87,
    0x98, 0xa9, 0xba, 0xcb, 0xdc, 0xed, 0xfe, 0x0f,
    0x20, 0x31, 0x42, 0x53, 0x64, 0x75, 0x86, 0x97,
    0xa8, 0xb9, 0xca, 0xdb, 0xec, 0xfd, 0x0e, 0x1f,
    0x30, 0x41, 0x52, 0x63, 0x74, 0x85, 0x96, 0xa7,
    0xb8, 0xc9, 0xda, 0xeb, 0xfc, 0x0d, 0x1e, 0x2f,
};
/* FIPS 203 encapsulation randomness is ML_KEM_RANDOM_BYTES = 32 bytes; the
 * keygen seed is 64.  Passing 64 to "ikme" is a too-small-buffer refusal. */
static const unsigned char KEM_IKME[32] = {
    0x5a, 0x5b, 0x5c, 0x5d, 0x5e, 0x5f, 0x60, 0x61,
    0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69,
    0x6a, 0x6b, 0x6c, 0x6d, 0x6e, 0x6f, 0x70, 0x71,
    0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79,
};

/* --- identity ----------------------------------------------------------- */

static int report_loaded(void *sym, const char *requested)
{
    Dl_info info;
    const char *name = requested;
    char resolved[PATH_MAX];
    char line[4096];
    struct stat st;
    FILE *maps;
    int entries = 0, foreign = 0;

    if (sym != NULL && dladdr(sym, &info) != 0 && info.dli_fname != NULL)
        name = info.dli_fname;
    if (realpath(name, resolved) == NULL)
        return 0;
    if (stat(resolved, &st) != 0)
        return 0;
    printf("LOADED realpath=%s dev=%ju ino=%ju size=%lld\n", resolved,
           (uintmax_t)st.st_dev, (uintmax_t)st.st_ino, (long long)st.st_size);
    maps = fopen("/proc/self/maps", "r");
    if (maps == NULL)
        return 0;
    while (fgets(line, sizeof(line), maps) != NULL) {
        if (strstr(line, resolved) != NULL)
            entries++;
        else if (strstr(line, "libcrypto.so") != NULL && strchr(line, '/'))
            foreign++;
    }
    fclose(maps);
    printf("MAPS realpath=%s entries=%d\n", resolved, entries);
    printf("FOREIGN libcrypto=%d\n", foreign);
    fflush(stdout);
    return entries >= 1;
}

static int load_api(const char *path)
{
    void *h = dlopen(path, RTLD_NOW | RTLD_LOCAL);

    if (h == NULL) {
        fprintf(stderr, "pfp29: dlopen(%s): %s\n", path, dlerror());
        return 0;
    }
#define LOAD(field, symbol)                                                    \
    do {                                                                       \
        void *s = dlsym(h, symbol);                                            \
        if (s == NULL) {                                                       \
            fprintf(stderr, "pfp29: missing %s\n", symbol);                    \
            return 0;                                                          \
        }                                                                      \
        memcpy(&api.field, &s, sizeof(s));                                     \
    } while (0)
    LOAD(EC_GROUP_new_by_curve_name, "EC_GROUP_new_by_curve_name");
    LOAD(EC_GROUP_free, "EC_GROUP_free");
    LOAD(EC_GROUP_get0_generator, "EC_GROUP_get0_generator");
    LOAD(EC_GROUP_get0_order, "EC_GROUP_get0_order");
    LOAD(EC_POINT_new, "EC_POINT_new");
    LOAD(EC_POINT_free, "EC_POINT_free");
    LOAD(EC_POINT_mul, "EC_POINT_mul");
    LOAD(EC_POINT_get_affine_coordinates, "EC_POINT_get_affine_coordinates");
    LOAD(EC_KEY_new_by_curve_name, "EC_KEY_new_by_curve_name");
    LOAD(EC_KEY_free, "EC_KEY_free");
    LOAD(EC_KEY_set_private_key, "EC_KEY_set_private_key");
    LOAD(EC_KEY_set_public_key, "EC_KEY_set_public_key");
    LOAD(EC_KEY_get0_private_key, "EC_KEY_get0_private_key");
    LOAD(ECDH_compute_key, "ECDH_compute_key");
    LOAD(BN_CTX_new, "BN_CTX_new");
    LOAD(BN_CTX_free, "BN_CTX_free");
    LOAD(BN_new, "BN_new");
    LOAD(BN_free, "BN_free");
    LOAD(BN_dup, "BN_dup");
    LOAD(BN_bin2bn, "BN_bin2bn");
    LOAD(BN_bn2binpad, "BN_bn2binpad");
    LOAD(BN_num_bits, "BN_num_bits");
    LOAD(BN_hex2bn, "BN_hex2bn");
    LOAD(BN_mod_exp, "BN_mod_exp");
    LOAD(BN_mod_inverse, "BN_mod_inverse");
    LOAD(BN_nnmod, "BN_nnmod");
    LOAD(ECDSA_do_sign, "ECDSA_do_sign");
    LOAD(ECDSA_do_sign_ex, "ECDSA_do_sign_ex");
    LOAD(ECDSA_do_verify, "ECDSA_do_verify");
    LOAD(ECDSA_SIG_new, "ECDSA_SIG_new");
    LOAD(ECDSA_SIG_set0, "ECDSA_SIG_set0");
    LOAD(ECDSA_SIG_get0, "ECDSA_SIG_get0");
    LOAD(ECDSA_SIG_free, "ECDSA_SIG_free");
    LOAD(RSA_new, "RSA_new");
    LOAD(RSA_free, "RSA_free");
    LOAD(RSA_get0_key, "RSA_get0_key");
    LOAD(RSA_set0_key, "RSA_set0_key");
    LOAD(RSA_get0_factors, "RSA_get0_factors");
    LOAD(RSA_set0_factors, "RSA_set0_factors");
    LOAD(RSA_get0_crt_params, "RSA_get0_crt_params");
    LOAD(RSA_set0_crt_params, "RSA_set0_crt_params");
    LOAD(RSA_private_decrypt, "RSA_private_decrypt");
    LOAD(DH_new_by_nid, "DH_new_by_nid");
    LOAD(DH_free, "DH_free");
    LOAD(DH_get0_pqg, "DH_get0_pqg");
    LOAD(DH_set0_key, "DH_set0_key");
    LOAD(DH_get0_priv_key, "DH_get0_priv_key");
    LOAD(DH_compute_key_padded, "DH_compute_key_padded");
    LOAD(EVP_PKEY_CTX_new_from_name, "EVP_PKEY_CTX_new_from_name");
    LOAD(EVP_PKEY_CTX_new_from_pkey, "EVP_PKEY_CTX_new_from_pkey");
    LOAD(EVP_PKEY_CTX_free, "EVP_PKEY_CTX_free");
    LOAD(EVP_PKEY_free, "EVP_PKEY_free");
    LOAD(EVP_PKEY_keygen_init, "EVP_PKEY_keygen_init");
    LOAD(EVP_PKEY_keygen, "EVP_PKEY_keygen");
    LOAD(EVP_PKEY_CTX_set_params, "EVP_PKEY_CTX_set_params");
    LOAD(EVP_PKEY_fromdata_init, "EVP_PKEY_fromdata_init");
    LOAD(EVP_PKEY_fromdata, "EVP_PKEY_fromdata");
    LOAD(EVP_PKEY_encapsulate_init, "EVP_PKEY_encapsulate_init");
    LOAD(EVP_PKEY_encapsulate, "EVP_PKEY_encapsulate");
    LOAD(EVP_PKEY_decapsulate_init, "EVP_PKEY_decapsulate_init");
    LOAD(EVP_PKEY_decapsulate, "EVP_PKEY_decapsulate");
    LOAD(ERR_get_error, "ERR_get_error");
    LOAD(ERR_error_string_n, "ERR_error_string_n");
#undef LOAD

    return report_loaded((void *)api.EC_POINT_mul, path);
}

/* --- taint -------------------------------------------------------------- */

static int mark_bn_values(const char *what, BIGNUM *bn)
{
    int bits = api.BN_num_bits(bn);
    int n, lim, i, j, k;
    unsigned char *be;
    uint64_t *p = NULL;
    size_t first = 0;

    if (bits <= 0)
        return 0;
    n = (bits + 7) / 8;
    be = malloc((size_t)n);
    if (be == NULL)
        return 0;
    if (api.BN_bn2binpad(bn, be, n) != n) {
        free(be);
        return 0;
    }
    while (first < (size_t)n && be[first] == 0)
        first++;
    if (first == (size_t)n) {
        free(be);
        return 0;
    }
    lim = (int)((size_t)n - first + 7) / 8;
    memcpy(&p, (const unsigned char *)bn + BN_D_PTR_OFFSET, sizeof p);
    if (p == NULL) {
        free(be);
        return 0;
    }
    for (i = 0; i < lim; i++) {
        uint64_t limb = p[i];
        for (j = 0; j < 8; j++) {
            k = n - 1 - (i * 8 + j);
            if (be[k] != (unsigned char)((limb >> (8 * j)) & 0xff)) {
                free(be);
                return 0;
            }
        }
    }
    VALGRIND_MAKE_MEM_UNDEFINED(p, (size_t)lim * sizeof(uint64_t));
    printf("TAINT what=%s limbs=%d bits=%d\n", what, lim, lim * 64);
    free(be);
    g_marked = 1;
    return 1;
}

static int mark_bytes(const char *what, unsigned char *buf, size_t len)
{
    VALGRIND_MAKE_MEM_UNDEFINED(buf, len);
    printf("TAINT what=%s bytes=%zu\n", what, len);
    g_marked = 1;
    return 1;
}

/* --- EC fixtures -------------------------------------------------------- */

struct ec_fx {
    EC_GROUP *group;
    EC_KEY *key;
    const BIGNUM *order;
    EC_POINT *p5;
    BN_CTX *ctx;
};

static void ec_free(struct ec_fx *f)
{
    if (f->p5 != NULL)
        api.EC_POINT_free(f->p5);
    if (f->key != NULL)
        api.EC_KEY_free(f->key);
    if (f->ctx != NULL)
        api.BN_CTX_free(f->ctx);
    if (f->group != NULL)
        api.EC_GROUP_free(f->group);
    memset(f, 0, sizeof *f);
}

static int ec_build(struct ec_fx *f)
{
    const EC_POINT *gen;
    EC_POINT *d_pub = NULL;
    BIGNUM *d = NULL, *five = NULL;
    int ok = 0;

    memset(f, 0, sizeof *f);
    f->group = api.EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
    f->ctx = api.BN_CTX_new();
    if (f->group == NULL || f->ctx == NULL)
        goto out;
    gen = api.EC_GROUP_get0_generator(f->group);
    f->order = api.EC_GROUP_get0_order(f->group);
    if (gen == NULL || f->order == NULL)
        goto out;
    f->key = api.EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    d = api.BN_bin2bn(D_BYTES, (int)sizeof D_BYTES, NULL);
    if (f->key == NULL || d == NULL)
        goto out;
    if (api.EC_KEY_set_private_key(f->key, d) != 1)
        goto out;
    d_pub = api.EC_POINT_new(f->group);
    if (d_pub == NULL)
        goto out;
    if (api.EC_POINT_mul(f->group, d_pub, NULL, gen, d, f->ctx) != 1)
        goto out;
    if (api.EC_KEY_set_public_key(f->key, d_pub) != 1)
        goto out;
    f->p5 = api.EC_POINT_new(f->group);
    five = api.BN_bin2bn((const unsigned char *)"\x05", 1, NULL);
    if (f->p5 == NULL || five == NULL)
        goto out;
    if (api.EC_POINT_mul(f->group, f->p5, NULL, gen, five, f->ctx) != 1)
        goto out;
    ok = 1;
out:
    if (five != NULL)
        api.BN_free(five);
    if (d_pub != NULL)
        api.EC_POINT_free(d_pub);
    if (d != NULL)
        api.BN_free(d);
    return ok;
}

/* (kinv, r = x(k*G) mod n) for the fixed k, computed with everything defined. */
static int nonce_fixture(struct ec_fx *f, BIGNUM **kinv_out, BIGNUM **rp_out)
{
    BIGNUM *k = NULL, *x = NULL, *kinv = NULL, *rp = NULL;
    EC_POINT *q = NULL;
    int ok = 0;

    k = api.BN_bin2bn(K_BYTES, (int)sizeof K_BYTES, NULL);
    q = api.EC_POINT_new(f->group);
    x = api.BN_new();
    rp = api.BN_new();
    if (k == NULL || q == NULL || x == NULL || rp == NULL)
        goto out;
    kinv = api.BN_mod_inverse(NULL, k, f->order, f->ctx);
    if (kinv == NULL)
        goto out;
    if (api.EC_POINT_mul(f->group, q, NULL,
                         api.EC_GROUP_get0_generator(f->group), k,
                         f->ctx) != 1)
        goto out;
    if (api.EC_POINT_get_affine_coordinates(f->group, q, x, NULL, f->ctx) != 1)
        goto out;
    if (api.BN_nnmod(rp, x, f->order, f->ctx) != 1)
        goto out;
    ok = 1;
out:
    if (k != NULL)
        api.BN_free(k);
    if (x != NULL)
        api.BN_free(x);
    if (q != NULL)
        api.EC_POINT_free(q);
    if (!ok) {
        if (kinv != NULL)
            api.BN_free(kinv);
        if (rp != NULL)
            api.BN_free(rp);
        return 0;
    }
    *kinv_out = kinv;
    *rp_out = rp;
    return 1;
}

static void mark_public_inputs(void)
{
    VALGRIND_MAKE_MEM_DEFINED(DGST, sizeof DGST);
    VALGRIND_MAKE_MEM_DEFINED(D_BYTES, sizeof D_BYTES);
    VALGRIND_MAKE_MEM_DEFINED(K_BYTES, sizeof K_BYTES);
    VALGRIND_MAKE_MEM_DEFINED(DH_X, sizeof DH_X);
    VALGRIND_MAKE_MEM_DEFINED(DH_Y, sizeof DH_Y);
    VALGRIND_MAKE_MEM_DEFINED(KEM_SEED, sizeof KEM_SEED);
    VALGRIND_MAKE_MEM_DEFINED(KEM_IKME, sizeof KEM_IKME);
}

/* --- paths -------------------------------------------------------------- */

static int op_ecdsa_sign(struct ec_fx *f, int iters, double *ns)
{
    BIGNUM *kinv = NULL, *rp = NULL, *k = NULL, *inv_t = NULL;
    EC_POINT *q_t = NULL;
    ECDSA_SIG *sig;
    int rc = 0, i;
    struct timespec t0, t1;

    if (nonce_fixture(f, &kinv, &rp) == 0)
        return 0;

    if (g_taint) {
        /* The nonce path inside the measured region: k is tainted and the
         * library's own inverse and generator ladder run on it.  Their results
         * are released without inspection; the pair handed to the signer is
         * the defined fixture above, itself tainted below. */
        k = api.BN_bin2bn(K_BYTES, (int)sizeof K_BYTES, NULL);
        q_t = api.EC_POINT_new(f->group);
        if (k == NULL || q_t == NULL)
            goto out;
        if (mark_bn_values("k", k) == 0)
            goto out;
        inv_t = api.BN_mod_inverse(NULL, k, f->order, f->ctx);
        if (inv_t == NULL)
            goto out;
        if (api.EC_POINT_mul(f->group, q_t, NULL,
                             api.EC_GROUP_get0_generator(f->group), k,
                             f->ctx) != 1)
            goto out;
        api.BN_free(inv_t);
        inv_t = NULL;
        api.EC_POINT_free(q_t);
        q_t = NULL;
        api.BN_free(k);
        k = NULL;

        if (mark_bn_values("kinv", kinv) == 0)
            goto out;
        if (mark_bn_values("d", (BIGNUM *)api.EC_KEY_get0_private_key(f->key)) == 0)
            goto out;
    }

    if (iters > 0) {
        clock_gettime(CLOCK_MONOTONIC, &t0);
        for (i = 0; i < iters; i++) {
            sig = api.ECDSA_do_sign_ex(DGST, (int)sizeof DGST, kinv, rp, f->key);
            if (sig == NULL)
                goto out;
            api.ECDSA_SIG_free(sig);
        }
        clock_gettime(CLOCK_MONOTONIC, &t1);
        *ns = ((double)(t1.tv_sec - t0.tv_sec) * 1e9 +
               (double)(t1.tv_nsec - t0.tv_nsec)) / (double)iters;
    } else {
        sig = api.ECDSA_do_sign_ex(DGST, (int)sizeof DGST, kinv, rp, f->key);
        if (sig == NULL)
            goto out;
        api.ECDSA_SIG_free(sig);
    }
    rc = 1;
out:
    if (k != NULL)
        api.BN_free(k);
    if (inv_t != NULL)
        api.BN_free(inv_t);
    if (q_t != NULL)
        api.EC_POINT_free(q_t);
    if (kinv != NULL)
        api.BN_free(kinv);
    if (rp != NULL)
        api.BN_free(rp);
    return rc;
}

/* The shipped default: ECDSA_do_sign draws its own nonce, so only d can be
 * tainted at this boundary.  This is the mode whose wall time is the signing
 * path; the `ecdsa-sign` mode above supplies kinv/r and therefore skips the
 * ladder by construction, so its time is not the signing path. */
static int op_ecdsa_sign_default(struct ec_fx *f, int iters, double *ns)
{
    ECDSA_SIG *sig;
    int rc = 0, i;
    struct timespec t0, t1;

    if (g_taint &&
        mark_bn_values("d", (BIGNUM *)api.EC_KEY_get0_private_key(f->key)) == 0)
        return 0;
    if (iters > 0) {
        clock_gettime(CLOCK_MONOTONIC, &t0);
        for (i = 0; i < iters; i++) {
            sig = api.ECDSA_do_sign(DGST, (int)sizeof DGST, f->key);
            if (sig == NULL)
                goto out;
            api.ECDSA_SIG_free(sig);
        }
        clock_gettime(CLOCK_MONOTONIC, &t1);
        *ns = ((double)(t1.tv_sec - t0.tv_sec) * 1e9 +
               (double)(t1.tv_nsec - t0.tv_nsec)) / (double)iters;
    } else {
        sig = api.ECDSA_do_sign(DGST, (int)sizeof DGST, f->key);
        if (sig == NULL)
            goto out;
        api.ECDSA_SIG_free(sig);
    }
    rc = 1;
out:
    return rc;
}

/* Verify has no secret in scope: the key is public, the signature is published
 * and the digest is public, so this mode is deliberately untainted. */
static int op_ecdsa_verify(struct ec_fx *f, int iters, double *ns)
{
    ECDSA_SIG *sig;
    int rc = 0, i;
    struct timespec t0, t1;

    sig = api.ECDSA_do_sign(DGST, (int)sizeof DGST, f->key);
    if (sig == NULL)
        return 0;
    if (iters > 0) {
        clock_gettime(CLOCK_MONOTONIC, &t0);
        for (i = 0; i < iters; i++)
            if (api.ECDSA_do_verify(DGST, (int)sizeof DGST, sig, f->key) != 1)
                goto out;
        clock_gettime(CLOCK_MONOTONIC, &t1);
        *ns = ((double)(t1.tv_sec - t0.tv_sec) * 1e9 +
               (double)(t1.tv_nsec - t0.tv_nsec)) / (double)iters;
    } else if (api.ECDSA_do_verify(DGST, (int)sizeof DGST, sig, f->key) != 1) {
        goto out;
    }
    rc = 1;
out:
    api.ECDSA_SIG_free(sig);
    return rc;
}

static int op_ecdh(struct ec_fx *f, int iters, double *ns)
{
    unsigned char out[32];
    EC_KEY *k;
    BIGNUM *d;
    int rc = 0, i, n;
    struct timespec t0, t1;

    k = api.EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    d = api.BN_bin2bn(D_BYTES, (int)sizeof D_BYTES, NULL);
    if (k == NULL || d == NULL) {
        if (k != NULL)
            api.EC_KEY_free(k);
        if (d != NULL)
            api.BN_free(d);
        return 0;
    }
    if (api.EC_KEY_set_private_key(k, d) != 1)
        goto out;
    if (api.EC_KEY_set_public_key(k,
            api.EC_GROUP_get0_generator(f->group)) != 1)
        goto out;
    if (g_taint &&
        mark_bn_values("d", (BIGNUM *)api.EC_KEY_get0_private_key(k)) == 0)
        goto out;
    if (iters > 0) {
        clock_gettime(CLOCK_MONOTONIC, &t0);
        for (i = 0; i < iters; i++) {
            n = api.ECDH_compute_key(out, sizeof out, f->p5, k, NULL);
            if (n <= 0)
                goto out;
        }
        clock_gettime(CLOCK_MONOTONIC, &t1);
        *ns = ((double)(t1.tv_sec - t0.tv_sec) * 1e9 +
               (double)(t1.tv_nsec - t0.tv_nsec)) / (double)iters;
    } else if (api.ECDH_compute_key(out, sizeof out, f->p5, k, NULL) <= 0) {
        goto out;
    }
    rc = 1;
out:
    api.EC_KEY_free(k);
    return rc;
}

/* --- RSA ---------------------------------------------------------------- */

struct rsa_fx {
    RSA *rsa;
    unsigned char ct[512];
    int ctlen;
    unsigned char msg[128];
    int msglen;
    BIGNUM *spare[8];
    int nspare;
};

static BIGNUM *hex_bn(struct rsa_fx *f, const char *hex)
{
    BIGNUM *bn = NULL;

    (void)f;

    if (api.BN_hex2bn(&bn, hex) <= 0)
        return NULL;
    return bn;
}

static int hexbytes(const char *hex, unsigned char *out, int max)
{
    int n = (int)strlen(hex) / 2, i;
    unsigned v;

    if (n > max)
        return -1;
    for (i = 0; i < n; i++) {
        if (sscanf(hex + 2 * i, "%2x", &v) != 1)
            return -1;
        out[i] = (unsigned char)v;
    }
    return n;
}

/* Read the frozen fixture.  crt=0 keeps only n, e, d on the RSA object. */
static int rsa_build(struct rsa_fx *f, const char *path, int crt)
{
    FILE *fp;
    char line[16384];
    BIGNUM *n = NULL, *e = NULL, *d = NULL, *p = NULL, *q = NULL;
    BIGNUM *dmp1 = NULL, *dmq1 = NULL, *iqmp = NULL;
    int ok = 0;

    memset(f, 0, sizeof *f);
    fp = fopen(path, "r");
    if (fp == NULL) {
        fprintf(stderr, "pfp29: cannot open RSA fixture %s\n", path);
        return 0;
    }
    while (fgets(line, sizeof line, fp) != NULL) {
        char name[32], hex[16000];
        if (line[0] == '#' || line[0] == '\n')
            continue;
        if (sscanf(line, "%31s %15999s", name, hex) != 2)
            continue;
        if (strcmp(name, "n") == 0)
            n = hex_bn(f, hex);
        else if (strcmp(name, "e") == 0)
            e = hex_bn(f, hex);
        else if (strcmp(name, "d") == 0)
            d = hex_bn(f, hex);
        else if (strcmp(name, "p") == 0)
            p = hex_bn(f, hex);
        else if (strcmp(name, "q") == 0)
            q = hex_bn(f, hex);
        else if (strcmp(name, "dmp1") == 0)
            dmp1 = hex_bn(f, hex);
        else if (strcmp(name, "dmq1") == 0)
            dmq1 = hex_bn(f, hex);
        else if (strcmp(name, "iqmp") == 0)
            iqmp = hex_bn(f, hex);
        else if (strcmp(name, "ct") == 0)
            f->ctlen = hexbytes(hex, f->ct, (int)sizeof f->ct);
        else if (strcmp(name, "msg") == 0)
            f->msglen = hexbytes(hex, f->msg, (int)sizeof f->msg);
    }
    fclose(fp);
    f->spare[f->nspare++] = n;
    f->spare[f->nspare++] = e;
    f->spare[f->nspare++] = d;
    f->spare[f->nspare++] = p;
    f->spare[f->nspare++] = q;
    f->spare[f->nspare++] = dmp1;
    f->spare[f->nspare++] = dmq1;
    f->spare[f->nspare++] = iqmp;
    if (n == NULL || e == NULL || d == NULL || f->ctlen <= 0 || f->msglen <= 0)
        goto out;
    f->rsa = api.RSA_new();
    if (f->rsa == NULL)
        goto out;
    if (crt) {
        if (p == NULL || q == NULL || dmp1 == NULL || dmq1 == NULL || iqmp == NULL)
            goto out;
        if (api.RSA_set0_key(f->rsa, n, e, d) != 1)
            goto out;
        if (api.RSA_set0_factors(f->rsa, p, q) != 1)
            goto out;
        if (api.RSA_set0_crt_params(f->rsa, dmp1, dmq1, iqmp) != 1)
            goto out;
        /* ownership transferred to the RSA object */
        f->spare[0] = f->spare[2] = f->spare[3] = f->spare[4] = NULL;
        f->spare[5] = f->spare[6] = f->spare[7] = NULL;
        f->spare[1] = NULL;
    } else {
        BIGNUM *n2 = api.BN_dup(n), *e2 = api.BN_dup(e), *d2 = api.BN_dup(d);
        if (n2 == NULL || e2 == NULL || d2 == NULL) {
            if (n2)
                api.BN_free(n2);
            if (e2)
                api.BN_free(e2);
            if (d2)
                api.BN_free(d2);
            goto out;
        }
        if (api.RSA_set0_key(f->rsa, n2, e2, d2) != 1) {
            api.BN_free(n2);
            api.BN_free(e2);
            api.BN_free(d2);
            goto out;
        }
    }
    ok = 1;
out:
    return ok;
}

static void rsa_free(struct rsa_fx *f)
{
    int i;
    if (f->rsa != NULL)
        api.RSA_free(f->rsa);
    for (i = 0; i < f->nspare; i++)
        if (f->spare[i] != NULL)
            api.BN_free(f->spare[i]);
    memset(f, 0, sizeof *f);
}

static int op_rsa(struct rsa_fx *f, int crt, int padding, int taint, int iters,
                  double *ns)
{
    const BIGNUM *n, *e, *d, *p, *q, *dmp1, *dmq1, *iqmp;
    unsigned char out[512];
    int rc = 0, i, r;
    struct timespec t0, t1;

    if (!crt && taint) {
        api.RSA_get0_key(f->rsa, &n, &e, &d);
        if (d == NULL || mark_bn_values("d", (BIGNUM *)d) == 0)
            return 0;
    } else if (crt && taint) {
        api.RSA_get0_key(f->rsa, &n, &e, &d);
        api.RSA_get0_factors(f->rsa, &p, &q);
        api.RSA_get0_crt_params(f->rsa, &dmp1, &dmq1, &iqmp);
        if (d == NULL || p == NULL || q == NULL || dmp1 == NULL ||
            dmq1 == NULL || iqmp == NULL)
            return 0;
        if (mark_bn_values("d", (BIGNUM *)d) == 0 ||
            mark_bn_values("p", (BIGNUM *)p) == 0 ||
            mark_bn_values("q", (BIGNUM *)q) == 0 ||
            mark_bn_values("dmp1", (BIGNUM *)dmp1) == 0 ||
            mark_bn_values("dmq1", (BIGNUM *)dmq1) == 0 ||
            mark_bn_values("iqmp", (BIGNUM *)iqmp) == 0)
            return 0;
    }

    if (iters > 0) {
        clock_gettime(CLOCK_MONOTONIC, &t0);
        for (i = 0; i < iters; i++) {
            r = api.RSA_private_decrypt(f->ctlen, f->ct, out, f->rsa, padding);
            if (r <= 0)
                goto out;
        }
        clock_gettime(CLOCK_MONOTONIC, &t1);
        *ns = ((double)(t1.tv_sec - t0.tv_sec) * 1e9 +
               (double)(t1.tv_nsec - t0.tv_nsec)) / (double)iters;
    } else if (api.RSA_private_decrypt(f->ctlen, f->ct, out, f->rsa, padding) <= 0) {
        goto out;
    }
    rc = 1;
out:
    return rc;
}

/* --- DH ----------------------------------------------------------------- */

struct dh_fx {
    DH *dh;
    BIGNUM *peer;
};

static int dh_build(struct dh_fx *f)
{
    const BIGNUM *p, *q, *g;
    BIGNUM *x = NULL, *pub = NULL, *y = NULL;
    BN_CTX *ctx;
    int ok = 0;

    memset(f, 0, sizeof *f);
    f->dh = api.DH_new_by_nid(NID_ffdhe2048);
    ctx = api.BN_CTX_new();
    if (f->dh == NULL || ctx == NULL)
        goto out;
    api.DH_get0_pqg(f->dh, &p, &q, &g);
    if (p == NULL || g == NULL)
        goto out;
    x = api.BN_bin2bn(DH_X, (int)sizeof DH_X, NULL);
    pub = api.BN_new();
    y = api.BN_bin2bn(DH_Y, (int)sizeof DH_Y, NULL);
    f->peer = api.BN_new();
    if (x == NULL || pub == NULL || y == NULL || f->peer == NULL)
        goto out;
    if (api.BN_mod_exp(pub, g, x, p, ctx) != 1)
        goto out;
    if (api.BN_mod_exp(f->peer, g, y, p, ctx) != 1)
        goto out;
    if (api.DH_set0_key(f->dh, pub, x) != 1)
        goto out;
    pub = NULL;
    x = NULL;
    ok = 1;
out:
    if (ctx != NULL)
        api.BN_CTX_free(ctx);
    if (x != NULL)
        api.BN_free(x);
    if (pub != NULL)
        api.BN_free(pub);
    if (y != NULL)
        api.BN_free(y);
    if (!ok) {
        if (f->peer != NULL) {
            api.BN_free(f->peer);
            f->peer = NULL;
        }
        if (f->dh != NULL) {
            api.DH_free(f->dh);
            f->dh = NULL;
        }
    }
    return ok;
}

static int op_dh(struct dh_fx *f, int taint, int iters, double *ns)
{
    unsigned char out[512];
    int rc = 0, i, r;
    struct timespec t0, t1;

    if (taint &&
        mark_bn_values("dh-priv", (BIGNUM *)api.DH_get0_priv_key(f->dh)) == 0)
        return 0;
    if (iters > 0) {
        clock_gettime(CLOCK_MONOTONIC, &t0);
        for (i = 0; i < iters; i++) {
            r = api.DH_compute_key_padded(out, f->peer, f->dh);
            if (r <= 0)
                goto out;
        }
        clock_gettime(CLOCK_MONOTONIC, &t1);
        *ns = ((double)(t1.tv_sec - t0.tv_sec) * 1e9 +
               (double)(t1.tv_nsec - t0.tv_nsec)) / (double)iters;
    } else if (api.DH_compute_key_padded(out, f->peer, f->dh) <= 0) {
        goto out;
    }
    rc = 1;
out:
    return rc;
}

/* --- ML-KEM ------------------------------------------------------------- */

struct kem_fx {
    EVP_PKEY *key;          /* defined-seed key (public key source) */
    unsigned char ct[4096];
    size_t ctlen;
    unsigned char ss[128];
    size_t sslen;
};

static EVP_PKEY *kem_key_from_seed(const unsigned char *seed, size_t seedlen)
{
    EVP_PKEY_CTX *ctx = api.EVP_PKEY_CTX_new_from_name(NULL, "ML-KEM-768", NULL);
    EVP_PKEY *pkey = NULL;
    OSSL_PARAM params[2];

    if (ctx == NULL)
        return NULL;
    params[0].key = "seed";
    params[0].data_type = OSSL_PARAM_OCTET_STRING;
    params[0].data = (void *)seed;
    params[0].data_size = seedlen;
    params[0].return_size = OSSL_PARAM_UNMODIFIED;
    params[1].key = NULL;
    params[1].data_type = 0;
    params[1].data = NULL;
    params[1].data_size = 0;
    params[1].return_size = 0;
    if (api.EVP_PKEY_fromdata_init(ctx) != 1 ||
        api.EVP_PKEY_fromdata(ctx, &pkey, EVP_PKEY_KEYPAIR, params) != 1) {
        pkey = NULL;
    }
    api.EVP_PKEY_CTX_free(ctx);
    return pkey;
}

static int kem_encapsulate(struct kem_fx *f)
{
    EVP_PKEY_CTX *ctx;
    OSSL_PARAM params[2];
    unsigned char ikme[sizeof KEM_IKME];
    int ok = 0;

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

    ctx = api.EVP_PKEY_CTX_new_from_pkey(NULL, f->key, NULL);
    if (ctx == NULL) {
        fprintf(stderr, "pfp29: encapsulate ctx new failed\n");
        return 0;
    }
    if (api.EVP_PKEY_encapsulate_init(ctx, params) != 1)
        goto out;
    f->ctlen = sizeof f->ct;
    f->sslen = sizeof f->ss;
    if (api.EVP_PKEY_encapsulate(ctx, f->ct, &f->ctlen, f->ss, &f->sslen) != 1)
        goto out;
    ok = 1;
out:
    api.EVP_PKEY_CTX_free(ctx);
    return ok;
}

static int kem_build(struct kem_fx *f)
{
    memset(f, 0, sizeof *f);
    f->key = kem_key_from_seed(KEM_SEED, sizeof KEM_SEED);
    if (f->key == NULL) {
        fprintf(stderr, "pfp29: ML-KEM-768 seed import failed\n");
        return 0;
    }
    if (!kem_encapsulate(f)) {
        fprintf(stderr, "pfp29: ML-KEM-768 encapsulate failed\n");
        return 0;
    }
    return 1;
}

static void kem_free(struct kem_fx *f)
{
    if (f->key != NULL)
        api.EVP_PKEY_free(f->key);
    memset(f, 0, sizeof *f);
}

static int op_kem_decaps(struct kem_fx *f, int taint, int iters, double *ns)
{
    EVP_PKEY *key;
    EVP_PKEY_CTX *ctx;
    unsigned char seed[64];
    unsigned char out[128];
    size_t outlen;
    int rc = 0, i, r;
    struct timespec t0, t1;

    if (taint) {
        /* The private-key seed is the secret.  It is tainted at the documented
         * EVP_PKEY_fromdata boundary and imported; the ciphertext stays
         * defined.  The import of the tainted key is inside the process. */
        memcpy(seed, KEM_SEED, sizeof seed);
        mark_bytes("kem-seed", seed, sizeof seed);
        key = kem_key_from_seed(seed, sizeof seed);
        if (key == NULL) {
            fprintf(stderr, "pfp29: tainted-seed import failed\n");
            return 0;
        }
    } else {
        key = f->key;
    }
    ctx = api.EVP_PKEY_CTX_new_from_pkey(NULL, key, NULL);
    if (ctx == NULL) {
        if (taint)
            api.EVP_PKEY_free(key);
        return 0;
    }
    if (api.EVP_PKEY_decapsulate_init(ctx, NULL) != 1)
        goto out;

    if (iters > 0) {
        clock_gettime(CLOCK_MONOTONIC, &t0);
        for (i = 0; i < iters; i++) {
            outlen = sizeof out;
            r = api.EVP_PKEY_decapsulate(ctx, out, &outlen, f->ct, f->ctlen);
            if (r != 1)
                goto out;
        }
        clock_gettime(CLOCK_MONOTONIC, &t1);
        *ns = ((double)(t1.tv_sec - t0.tv_sec) * 1e9 +
               (double)(t1.tv_nsec - t0.tv_nsec)) / (double)iters;
    } else {
        outlen = sizeof out;
        if (api.EVP_PKEY_decapsulate(ctx, out, &outlen, f->ct, f->ctlen) != 1)
            goto out;
    }
    rc = 1;
out:
    api.EVP_PKEY_CTX_free(ctx);
    if (taint)
        api.EVP_PKEY_free(key);
    return rc;
}

/* --- differential (defined) -------------------------------------------- */

static void put_hex(const char *name, const unsigned char *buf, size_t len)
{
    size_t i;
    printf("%s ", name);
    for (i = 0; i < len; i++)
        printf("%02x", buf[i]);
    printf("\n");
}

static int bn_fixed32(const BIGNUM *bn, unsigned char out[32])
{
    return api.BN_bn2binpad(bn, out, 32) == 32;
}

/* Print the deterministic observables of every path for the differential.
 * Nothing here is secret: the fixtures are fixed and public. */
static int emit_all(const char *rsa_fixture, const char *sigout)
{
    struct ec_fx ec;
    struct rsa_fx rsa;
    struct dh_fx dh;
    struct kem_fx kem;
    ECDSA_SIG *sig = NULL;
    BIGNUM *kinv = NULL, *rp = NULL;
    const BIGNUM *sr = NULL, *ss = NULL;
    unsigned char ecdh_out[32], rsa_out[512], dh_out[512];
    unsigned char sigbuf[64], kem_out[128];
    size_t kem_outlen;
    FILE *fp;
    int rc = 0, n;

    memset(&ec, 0, sizeof ec);
    memset(&rsa, 0, sizeof rsa);
    memset(&dh, 0, sizeof dh);
    memset(&kem, 0, sizeof kem);

    if (!ec_build(&ec) || !nonce_fixture(&ec, &kinv, &rp))
        goto out;
    sig = api.ECDSA_do_sign_ex(DGST, (int)sizeof DGST, kinv, rp, ec.key);
    if (sig == NULL)
        goto out;
    api.ECDSA_SIG_get0(sig, &sr, &ss);
    if (sr == NULL || ss == NULL || !bn_fixed32(sr, sigbuf) ||
        !bn_fixed32(ss, sigbuf + 32))
        goto out;
    put_hex("ECDSA_R", sigbuf, 32);
    put_hex("ECDSA_S", sigbuf + 32, 32);
    if (sigout != NULL) {
        fp = fopen(sigout, "wb");
        if (fp == NULL || fwrite(sigbuf, 1, sizeof sigbuf, fp) != sizeof sigbuf) {
            if (fp != NULL)
                fclose(fp);
            goto out;
        }
        fclose(fp);
    }

    if (api.ECDH_compute_key(ecdh_out, sizeof ecdh_out, ec.p5, ec.key, NULL) <= 0)
        goto out;

    if (!rsa_build(&rsa, rsa_fixture, 1))
        goto out;
    if (api.RSA_private_decrypt(rsa.ctlen, rsa.ct, rsa_out, rsa.rsa, 3) <= 0)
        goto out;

    if (!dh_build(&dh))
        goto out;
    n = api.DH_compute_key_padded(dh_out, dh.peer, dh.dh);
    if (n <= 0)
        goto out;

    if (!kem_build(&kem))
        goto out;
    {
        EVP_PKEY_CTX *ctx = api.EVP_PKEY_CTX_new_from_pkey(NULL, kem.key, NULL);
        kem_outlen = sizeof kem_out;
        if (ctx == NULL || api.EVP_PKEY_decapsulate_init(ctx, NULL) != 1 ||
            api.EVP_PKEY_decapsulate(ctx, kem_out, &kem_outlen, kem.ct,
                                     kem.ctlen) != 1) {
            if (ctx != NULL)
                api.EVP_PKEY_CTX_free(ctx);
            goto out;
        }
        api.EVP_PKEY_CTX_free(ctx);
    }

    put_hex("ECDH_SS", ecdh_out, sizeof ecdh_out);
    put_hex("RSA_PT", rsa_out, (size_t)rsa.ctlen);
    put_hex("DH_SS", dh_out, (size_t)n);
    put_hex("MLKEM_CT", kem.ct, kem.ctlen);
    put_hex("MLKEM_ENCAP_SS", kem.ss, kem.sslen);
    put_hex("MLKEM_DECAP_SS", kem_out, kem_outlen);
    rc = 1;
out:
    if (sig != NULL)
        api.ECDSA_SIG_free(sig);
    if (kinv != NULL)
        api.BN_free(kinv);
    if (rp != NULL)
        api.BN_free(rp);
    ec_free(&ec);
    rsa_free(&rsa);
    if (dh.dh != NULL)
        api.DH_free(dh.dh);
    if (dh.peer != NULL)
        api.BN_free(dh.peer);
    kem_free(&kem);
    return rc;
}

static int verify_sig_file(const char *path)
{
    struct ec_fx ec;
    ECDSA_SIG *sig = NULL;
    BIGNUM *r = NULL, *s = NULL;
    unsigned char buf[64];
    FILE *fp;
    int rc = 0;

    memset(&ec, 0, sizeof ec);
    fp = fopen(path, "rb");
    if (fp == NULL || fread(buf, 1, sizeof buf, fp) != sizeof buf) {
        if (fp != NULL)
            fclose(fp);
        return 0;
    }
    fclose(fp);
    if (!ec_build(&ec))
        goto out;
    sig = api.ECDSA_SIG_new();
    r = api.BN_bin2bn(buf, 32, NULL);
    s = api.BN_bin2bn(buf + 32, 32, NULL);
    if (sig == NULL || r == NULL || s == NULL)
        goto out;
    if (api.ECDSA_SIG_set0(sig, r, s) != 1)
        goto out;
    r = NULL;
    s = NULL;
    if (api.ECDSA_do_verify(DGST, (int)sizeof DGST, sig, ec.key) != 1)
        goto out;
    rc = 1;
out:
    if (r != NULL)
        api.BN_free(r);
    if (s != NULL)
        api.BN_free(s);
    if (sig != NULL)
        api.ECDSA_SIG_free(sig);
    ec_free(&ec);
    return rc;
}

/* --- 64-case seeded differential sweep --------------------------------- */

#define SWEEP_BASE 0x5046503239505032ULL
#define SWEEP_CASES 64

static uint64_t sm64(uint64_t z)
{
    z += 0x9E3779B97F4A7C15ULL;
    z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ULL;
    z = (z ^ (z >> 27)) * 0x94D049BB133111EBULL;
    return z ^ (z >> 31);
}

static void bytes_from(uint64_t seed, unsigned char *out, size_t n)
{
    size_t i;
    uint64_t x = seed;
    for (i = 0; i < n; i++) {
        if (i % 8 == 0)
            x = sm64(x + (uint64_t)(i / 8) + 1);
        out[i] = (unsigned char)((x >> (8 * (i % 8))) & 0xff);
    }
}

/* 32 bytes reduced to a non-zero scalar below 2^255, hence below the P-256
 * order and below the ffdhe2048 prime. */
static void scalar_from(uint64_t seed, unsigned char out[32])
{
    int i, nz = 0;
    bytes_from(seed, out, 32);
    out[0] &= 0x7f;
    for (i = 0; i < 32; i++)
        nz |= out[i];
    if (nz == 0)
        out[31] = 1;
}

static int write_file(const char *dir, int i, const unsigned char *buf,
                      size_t len)
{
    char path[PATH_MAX];
    FILE *fp;
    snprintf(path, sizeof path, "%s/sig-%03d.bin", dir, i);
    fp = fopen(path, "wb");
    if (fp == NULL)
        return 0;
    if (fwrite(buf, 1, len, fp) != len) {
        fclose(fp);
        return 0;
    }
    fclose(fp);
    return 1;
}

static int read_file(const char *dir, int i, unsigned char *buf, size_t len)
{
    char path[PATH_MAX];
    FILE *fp;
    snprintf(path, sizeof path, "%s/sig-%03d.bin", dir, i);
    fp = fopen(path, "rb");
    if (fp == NULL)
        return 0;
    if (fread(buf, 1, len, fp) != len) {
        fclose(fp);
        return 0;
    }
    fclose(fp);
    return 1;
}

/* Per-case key and digest, so verification re-derives them without needing the
 * signer's nonce. */
static void case_material(int i, unsigned char d[32], unsigned char dgst[32])
{
    scalar_from(sm64(SWEEP_BASE ^ (2 * (uint64_t)i)), d);
    bytes_from(sm64(SWEEP_BASE ^ (2 * (uint64_t)i + 1)), dgst, 32);
}

static int ec_key_with_scalar(struct ec_fx *f, const unsigned char d[32],
                              EC_KEY **key_out)
{
    EC_KEY *key = api.EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    BIGNUM *bn = api.BN_bin2bn(d, 32, NULL);
    EC_POINT *pub = api.EC_POINT_new(f->group);
    int ok = 0;

    if (key == NULL || bn == NULL || pub == NULL)
        goto out;
    if (api.EC_KEY_set_private_key(key, bn) != 1)
        goto out;
    if (api.EC_POINT_mul(f->group, pub, NULL,
                         api.EC_GROUP_get0_generator(f->group), bn, f->ctx) != 1)
        goto out;
    if (api.EC_KEY_set_public_key(key, pub) != 1)
        goto out;
    ok = 1;
out:
    if (bn != NULL && !ok)
        api.BN_free(bn);
    if (pub != NULL)
        api.EC_POINT_free(pub);
    if (!ok) {
        if (key != NULL)
            api.EC_KEY_free(key);
        return 0;
    }
    *key_out = key;
    return 1;
}

static int sweep(const char *rsa_fixture, const char *sigdir, int cases)
{
    struct ec_fx ec;
    struct rsa_fx rsa;
    const BIGNUM *rn, *re, *rd;
    unsigned char d[32], dgst[32], kbuf[32], sigbuf[64];
    unsigned char rsa_block[256], rsa_out[512], ct[512];
    unsigned char dh_out[512], kem_ct[4096], kem_ss[128], kem_out[128];
    int i, rc = 0, n;

    memset(&ec, 0, sizeof ec);
    memset(&rsa, 0, sizeof rsa);
    if (!ec_build(&ec) || !rsa_build(&rsa, rsa_fixture, 1))
        goto out;
    api.RSA_get0_key(rsa.rsa, &rn, &re, &rd);
    if (rn == NULL || re == NULL || rd == NULL)
        goto out;

    for (i = 0; i < cases; i++) {
        EC_KEY *key = NULL;
        BIGNUM *kb = NULL, *kinv = NULL, *rp = NULL, *x = NULL;
        EC_POINT *q = NULL;
        ECDSA_SIG *sig = NULL;
        const BIGNUM *sr = NULL, *ss = NULL;
        BN_CTX *ctx = api.BN_CTX_new();
        DH *dh = NULL;
        const BIGNUM *p, *qq, *g;
        BIGNUM *pub = NULL, *peer = NULL, *y = NULL;
        EVP_PKEY *kkey = NULL;
        EVP_PKEY_CTX *kctx = NULL;
        unsigned char seed[64], ikme[32];
        int case_ok = 0;

        if (ctx == NULL)
            goto out;
        case_material(i, d, dgst);

        /* ECDSA sign with nonce k, then emit r||s. */
        if (!ec_key_with_scalar(&ec, d, &key))
            goto case_out;
        scalar_from(sm64(SWEEP_BASE ^ (2 * (uint64_t)i + 0x10000)), kbuf);
        kb = api.BN_bin2bn(kbuf, 32, NULL);
        q = api.EC_POINT_new(ec.group);
        x = api.BN_new();
        rp = api.BN_new();
        if (kb == NULL || q == NULL || x == NULL || rp == NULL)
            goto case_out;
        kinv = api.BN_mod_inverse(NULL, kb, ec.order, ctx);
        if (kinv == NULL)
            goto case_out;
        if (api.EC_POINT_mul(ec.group, q, NULL,
                             api.EC_GROUP_get0_generator(ec.group), kb, ctx) != 1)
            goto case_out;
        if (api.EC_POINT_get_affine_coordinates(ec.group, q, x, NULL, ctx) != 1)
            goto case_out;
        if (api.BN_nnmod(rp, x, ec.order, ctx) != 1)
            goto case_out;
        sig = api.ECDSA_do_sign_ex(dgst, 32, kinv, rp, key);
        if (sig == NULL)
            goto case_out;
        api.ECDSA_SIG_get0(sig, &sr, &ss);
        if (sr == NULL || ss == NULL || !bn_fixed32(sr, sigbuf) ||
            !bn_fixed32(ss, sigbuf + 32))
            goto case_out;
        printf("ECDSA %d ", i);
        {
            int j;
            for (j = 0; j < 64; j++)
                printf("%02x", sigbuf[j]);
        }
        printf("\n");
        if (sigdir != NULL && !write_file(sigdir, i, sigbuf, 64))
            goto case_out;

        /* ECDH with the same private d and peer k*G. */
        if (api.ECDH_compute_key(dh_out, 32, q, key, NULL) != 32)
            goto case_out;
        printf("ECDH %d ", i);
        {
            int j;
            for (j = 0; j < 32; j++)
                printf("%02x", dh_out[j]);
        }
        printf("\n");

        /* RSA: a fixed PKCS#1 block, encrypted deterministically with e,n. */
        memset(rsa_block, 0xff, sizeof rsa_block);
        rsa_block[0] = 0x00;
        rsa_block[1] = 0x02;
        bytes_from(sm64(SWEEP_BASE ^ (2 * (uint64_t)i + 0x20000)),
                   rsa_block + 256 - 33, 32);
        rsa_block[256 - 33 - 1] = 0x00;
        {
            BIGNUM *m = api.BN_bin2bn(rsa_block, 256, NULL);
            BIGNUM *c = api.BN_new();
            if (m == NULL || c == NULL || api.BN_mod_exp(c, m, re, rn, ctx) != 1) {
                if (m)
                    api.BN_free(m);
                if (c)
                    api.BN_free(c);
                goto case_out;
            }
            if (api.BN_bn2binpad(c, ct, 256) != 256) {
                api.BN_free(m);
                api.BN_free(c);
                goto case_out;
            }
            api.BN_free(m);
            api.BN_free(c);
        }
        if (api.RSA_private_decrypt(256, ct, rsa_out, rsa.rsa, 1) <= 0)
            goto case_out;
        printf("RSA %d ", i);
        {
            int j;
            for (j = 0; j < 32; j++)
                printf("%02x", rsa_out[j]);
        }
        printf("\n");

        /* DH: fresh ffdhe2048 key per case. */
        dh = api.DH_new_by_nid(NID_ffdhe2048);
        if (dh == NULL)
            goto case_out;
        api.DH_get0_pqg(dh, &p, &qq, &g);
        if (p == NULL || g == NULL)
            goto case_out;
        scalar_from(sm64(SWEEP_BASE ^ (2 * (uint64_t)i + 0x30000)), d);
        scalar_from(sm64(SWEEP_BASE ^ (2 * (uint64_t)i + 0x30001)), kbuf);
        x = api.BN_bin2bn(d, 32, NULL);
        y = api.BN_bin2bn(kbuf, 32, NULL);
        pub = api.BN_new();
        peer = api.BN_new();
        if (x == NULL || y == NULL || pub == NULL || peer == NULL)
            goto case_out;
        if (api.BN_mod_exp(pub, g, x, p, ctx) != 1 ||
            api.BN_mod_exp(peer, g, y, p, ctx) != 1)
            goto case_out;
        if (api.DH_set0_key(dh, pub, x) != 1)
            goto case_out;
        pub = NULL;
        x = NULL;
        n = api.DH_compute_key_padded(dh_out, peer, dh);
        if (n <= 0)
            goto case_out;
        printf("DH %d ", i);
        {
            int j;
            for (j = 0; j < n; j++)
                printf("%02x", dh_out[j]);
        }
        printf("\n");

        /* ML-KEM-768: seed and encapsulation randomness both from the case. */
        bytes_from(sm64(SWEEP_BASE ^ (2 * (uint64_t)i + 0x40000)), seed, 64);
        bytes_from(sm64(SWEEP_BASE ^ (2 * (uint64_t)i + 0x40001)), ikme, 32);
        kkey = kem_key_from_seed(seed, 64);
        if (kkey == NULL)
            goto case_out;
        kctx = api.EVP_PKEY_CTX_new_from_pkey(NULL, kkey, NULL);
        if (kctx == NULL)
            goto case_out;
        {
            OSSL_PARAM kp[2];
            kp[0].key = "ikme";
            kp[0].data_type = OSSL_PARAM_OCTET_STRING;
            kp[0].data = ikme;
            kp[0].data_size = sizeof ikme;
            kp[0].return_size = OSSL_PARAM_UNMODIFIED;
            kp[1].key = NULL;
            kp[1].data_type = 0;
            kp[1].data = NULL;
            kp[1].data_size = 0;
            kp[1].return_size = 0;
            n = (int)sizeof kem_ct;
            {
                size_t kl = (size_t)n, sl = sizeof kem_ss;
                if (api.EVP_PKEY_encapsulate_init(kctx, kp) != 1 ||
                    api.EVP_PKEY_encapsulate(kctx, kem_ct, &kl, kem_ss, &sl) != 1)
                    goto case_out;
                n = (int)kl;
            }
        }
        api.EVP_PKEY_CTX_free(kctx);
        kctx = NULL;
        kctx = api.EVP_PKEY_CTX_new_from_pkey(NULL, kkey, NULL);
        if (kctx == NULL || api.EVP_PKEY_decapsulate_init(kctx, NULL) != 1)
            goto case_out;
        {
            size_t ol = sizeof kem_out;
            if (api.EVP_PKEY_decapsulate(kctx, kem_out, &ol, kem_ct,
                                         (size_t)n) != 1)
                goto case_out;
            printf("KEM_CT %d ", i);
            {
                int j;
                for (j = 0; j < n; j++)
                    printf("%02x", kem_ct[j]);
            }
            printf("\n");
            printf("KEM_SS %d ", i);
            {
                size_t j;
                for (j = 0; j < ol; j++)
                    printf("%02x", kem_out[j]);
            }
            printf("\n");
        }
        case_ok = 1;

case_out:
        if (sig != NULL)
            api.ECDSA_SIG_free(sig);
        if (kinv != NULL)
            api.BN_free(kinv);
        if (rp != NULL)
            api.BN_free(rp);
        if (x != NULL)
            api.BN_free(x);
        if (y != NULL)
            api.BN_free(y);
        if (peer != NULL)
            api.BN_free(peer);
        if (pub != NULL)
            api.BN_free(pub);
        if (kb != NULL)
            api.BN_free(kb);
        if (q != NULL)
            api.EC_POINT_free(q);
        if (key != NULL)
            api.EC_KEY_free(key);
        if (dh != NULL)
            api.DH_free(dh);
        if (kctx != NULL)
            api.EVP_PKEY_CTX_free(kctx);
        if (kkey != NULL)
            api.EVP_PKEY_free(kkey);
        if (ctx != NULL)
            api.BN_CTX_free(ctx);
        if (!case_ok)
            goto out;
    }
    rc = 1;
out:
    ec_free(&ec);
    rsa_free(&rsa);
    return rc;
}

static int verify_sweep(const char *sigdir, int cases)
{
    struct ec_fx ec;
    unsigned char d[32], dgst[32], sigbuf[64];
    int i, ok = 0, rc = 0;

    memset(&ec, 0, sizeof ec);
    if (!ec_build(&ec))
        return 0;
    for (i = 0; i < cases; i++) {
        EC_KEY *key = NULL;
        ECDSA_SIG *sig = NULL;
        BIGNUM *r = NULL, *s = NULL;
        case_material(i, d, dgst);
        if (!read_file(sigdir, i, sigbuf, 64))
            break;
        if (!ec_key_with_scalar(&ec, d, &key))
            break;
        sig = api.ECDSA_SIG_new();
        r = api.BN_bin2bn(sigbuf, 32, NULL);
        s = api.BN_bin2bn(sigbuf + 32, 32, NULL);
        if (sig == NULL || r == NULL || s == NULL) {
            if (r) api.BN_free(r);
            if (s) api.BN_free(s);
            if (sig) api.ECDSA_SIG_free(sig);
            api.EC_KEY_free(key);
            break;
        }
        api.ECDSA_SIG_set0(sig, r, s);
        if (api.ECDSA_do_verify(dgst, 32, sig, key) == 1)
            ok++;
        api.ECDSA_SIG_free(sig);
        api.EC_KEY_free(key);
    }
    ec_free(&ec);
    printf("VERIFY_SWEEP ok=%d cases=%d\n", ok, cases);
    rc = (ok == cases);
    return rc;
}

int main(int argc, char **argv)
{
    const char *lib = NULL, *mode = "control", *rsa_fixture = NULL;
    const char *sigout = NULL, *sigin = NULL, *sigdir = NULL;
    int iters = 0, timing = 0, rc = 0, i;
    double ns = 0.0;

    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--lib") == 0 && i + 1 < argc)
            lib = argv[++i];
        else if (strcmp(argv[i], "--mode") == 0 && i + 1 < argc)
            mode = argv[++i];
        else if (strcmp(argv[i], "--iters") == 0 && i + 1 < argc) {
            iters = atoi(argv[++i]);
            timing = 1;
        } else if (strcmp(argv[i], "--rsa-fixture") == 0 && i + 1 < argc)
            rsa_fixture = argv[++i];
        else if (strcmp(argv[i], "--sig-out") == 0 && i + 1 < argc)
            sigout = argv[++i];
        else if (strcmp(argv[i], "--sig-in") == 0 && i + 1 < argc)
            sigin = argv[++i];
        else if (strcmp(argv[i], "--sig-dir") == 0 && i + 1 < argc)
            sigdir = argv[++i];
        else {
            fprintf(stderr, "pfp29: unknown argument %s\n", argv[i]);
            return 2;
        }
    }
    if (lib == NULL) {
        fprintf(stderr, "pfp29: --lib is required\n");
        return 2;
    }
    g_mode = mode;
    g_taint = (strcmp(mode, "control") != 0) &&
              (strcmp(mode, "ecdsa-verify") != 0) &&
              (strcmp(mode, "emit") != 0) &&
              (strcmp(mode, "sweep") != 0) &&
              (strcmp(mode, "verify-sweep") != 0);

    if (load_api(lib) == 0)
        return 3;
    mark_public_inputs();
    printf("HARNESS mode=%s iters=%d taint=%d\n", mode, iters, g_taint);
    fflush(stdout);

    if (strcmp(mode, "control") == 0) {
        struct ec_fx ec;
        struct rsa_fx rsa;
        struct dh_fx dh;
        struct kem_fx kem;
        int ok;
        ok = ec_build(&ec) &&
             op_ecdsa_sign(&ec, 0, &ns) &&
             op_ecdsa_sign_default(&ec, 0, &ns) &&
             op_ecdsa_verify(&ec, 0, &ns) &&
             op_ecdh(&ec, 0, &ns);
        ec_free(&ec);
        if (ok) {
            ok = rsa_build(&rsa, rsa_fixture, 1) &&
                 op_rsa(&rsa, 1, 3, 0, 0, &ns) &&
                 op_rsa(&rsa, 1, 1, 0, 0, &ns);
            rsa_free(&rsa);
        }
        if (ok && rsa_fixture != NULL) {
            ok = rsa_build(&rsa, rsa_fixture, 0) &&
                 op_rsa(&rsa, 0, 3, 0, 0, &ns);
            rsa_free(&rsa);
        }
        ok = ok && dh_build(&dh) && op_dh(&dh, 0, 0, &ns);
        if (dh.dh != NULL) {
            api.DH_free(dh.dh);
            api.BN_free(dh.peer);
        }
        ok = ok && kem_build(&kem) && op_kem_decaps(&kem, 0, 0, &ns);
        if (kem.key != NULL)
            kem_free(&kem);
        rc = ok;
    } else if (strcmp(mode, "ecdsa-sign") == 0) {
        struct ec_fx ec;
        rc = ec_build(&ec) && op_ecdsa_sign(&ec, iters, &ns);
        ec_free(&ec);
    } else if (strcmp(mode, "ecdsa-sign-default") == 0) {
        struct ec_fx ec;
        rc = ec_build(&ec) && op_ecdsa_sign_default(&ec, iters, &ns);
        ec_free(&ec);
    } else if (strcmp(mode, "ecdsa-verify") == 0) {
        struct ec_fx ec;
        rc = ec_build(&ec) && op_ecdsa_verify(&ec, iters, &ns);
        ec_free(&ec);
    } else if (strcmp(mode, "ecdh") == 0) {
        struct ec_fx ec;
        rc = ec_build(&ec) && op_ecdh(&ec, iters, &ns);
        ec_free(&ec);
    } else if (strcmp(mode, "rsa-crt") == 0 || strcmp(mode, "rsa-nocrt") == 0 ||
               strcmp(mode, "rsa-crt-pkcs1") == 0) {
        struct rsa_fx rsa;
        int crt = (strcmp(mode, "rsa-nocrt") != 0);
        int pad = (strcmp(mode, "rsa-crt-pkcs1") == 0) ? 1 : 3;
        if (rsa_fixture == NULL) {
            fprintf(stderr, "pfp29: %s needs --rsa-fixture\n", mode);
            return 2;
        }
        rc = rsa_build(&rsa, rsa_fixture, crt) && op_rsa(&rsa, crt, pad, 1, iters, &ns);
        rsa_free(&rsa);
    } else if (strcmp(mode, "dh") == 0) {
        struct dh_fx dh;
        rc = dh_build(&dh) && op_dh(&dh, 1, iters, &ns);
        if (dh.dh != NULL) {
            api.DH_free(dh.dh);
            api.BN_free(dh.peer);
        }
    } else if (strcmp(mode, "mlkem-decaps") == 0) {
        struct kem_fx kem;
        rc = kem_build(&kem) && op_kem_decaps(&kem, 1, iters, &ns);
        if (kem.key != NULL)
            kem_free(&kem);
    } else if (strcmp(mode, "sweep") == 0) {
        if (rsa_fixture == NULL) {
            fprintf(stderr, "pfp29: sweep needs --rsa-fixture\n");
            return 2;
        }
        rc = sweep(rsa_fixture, sigdir, SWEEP_CASES);
    } else if (strcmp(mode, "verify-sweep") == 0) {
        if (sigdir == NULL) {
            fprintf(stderr, "pfp29: verify-sweep needs --sig-dir\n");
            return 2;
        }
        rc = verify_sweep(sigdir, SWEEP_CASES);
    } else if (strcmp(mode, "emit") == 0) {
        if (rsa_fixture == NULL) {
            fprintf(stderr, "pfp29: emit needs --rsa-fixture\n");
            return 2;
        }
        rc = emit_all(rsa_fixture, sigout);
    } else if (strcmp(mode, "verify-sig") == 0) {
        if (sigin == NULL) {
            fprintf(stderr, "pfp29: verify-sig needs --sig-in\n");
            return 2;
        }
        rc = verify_sig_file(sigin);
    } else {
        fprintf(stderr, "pfp29: unknown mode %s\n", mode);
        return 2;
    }

    VALGRIND_MAKE_MEM_DEFINED(&rc, sizeof rc);
    printf("RESULT mode=%s ok=%d marked=%d\n", mode, rc, g_marked);
    if (timing)
        printf("TIME mode=%s iters=%d ns_per_op=%.1f\n", mode, iters, ns);
    fflush(stdout);
    return rc ? 0 : 6;
}
