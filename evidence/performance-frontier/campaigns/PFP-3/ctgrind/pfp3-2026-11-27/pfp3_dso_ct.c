/*
 * pfp21_dso_ct.c — PFP-21 DSO-level ctgrind and mutation-control harness.
 *
 * One process, one explicitly dlopen()ed candidate libcrypto.so.3, exported
 * entry points only.  The process proves which file it actually mapped by
 * printing `LOADED realpath=… dev=… ino=… size=…` (from the mapping) and the
 * number of /proc/self/maps entries for that path; the runner compares those
 * fields with stat(2) on the expected on-disk DSO.  It also counts any *other*
 * mapped file whose name contains "libcrypto.so", so the court cannot pass by
 * loading a different crypto library than the one it names.
 *
 * Populations (--mode):
 *
 *   control      no taint at all; runs every operation once.  Negative control:
 *                a non-zero memcheck count here means the instrument or the
 *                harness is at fault, not the candidate.
 *   mul-g        k*G through EC_POINT_mul(…, NULL, generator, k, …); the four
 *                limb *values* of k are marked undefined, the limb count and
 *                every public input stay defined.  This is the VARIABLE-base
 *                form (num == 1); it does NOT reach the PFP-3 fixed-base arm.
 *   mul-g-fixed  k*G through EC_POINT_mul(…, k, NULL, NULL, …) — the form the
 *                PFP-3 admission arm is entered from (ossl_ec_wNAF_mul with
 *                scalar != NULL and num == 0).  Same taint, same fixtures.
 *                This population is the one addition to the PFP-21 harness;
 *                the taint, identity, negative-control and attribution logic
 *                are unchanged.
 *   mul-p        k*P for a public point P = 5*G; same taint.
 *   mul-g-bytes  comparison population: the 32 scalar input bytes are marked
 *                undefined *before* BN_bin2bn, so the importer's length
 *                derivation is tainted too.  Reported separately, never mixed
 *                into the admitted population.
 *   sign         ECDSA_do_sign on a fixed key whose private scalar d has its
 *                limb values marked undefined.  The per-signature nonce is
 *                generated inside the library and has no exported entry point,
 *                so it cannot be marked here; see sign-ex / sign-ex-k.
 *   sign-ex      ECDSA_do_sign_ex with a caller-supplied nonce inverse: kinv's
 *                limb values and d's limb values are undefined, r (= x(k*G)
 *                mod n) is defined because it is published in the signature.
 *                Fixture generation happens before the taint boundary.
 *   sign-ex-k    sign-ex plus the whole nonce computation inside the measured
 *                region: k is marked undefined, then BN_mod_inverse(k) and
 *                k*G run on the tainted value.  Their results are discarded
 *                without inspection; the (kinv, r) pair passed to the signer
 *                is recomputed from the defined fixture.  Nothing that touches
 *                the secret is left outside the instrument.
 *
 * No assertion, comparison or print inspects a secret-derived value before the
 * taint ends.  The only value read afterwards is the operation's success flag,
 * which is marked defined first because it is public (the caller learns
 * whether signing succeeded).  Signature and point results are never inspected.
 *
 * The BigNum limb pointer is not trusted blindly: the harness reads the limb
 * pointer from the documented layout offset, then verifies every live limb
 * against the same BIGNUM's own big-endian export before any taint.  A layout
 * drift aborts with exit 13 instead of tainting the wrong bytes.
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

/* Opaque handles: this harness links no libcrypto and includes no OpenSSL
 * header, so nothing but the dlopen()ed candidate can resolve the symbols. */
typedef struct bignum_st BIGNUM;
typedef struct bignum_ctx BN_CTX;
typedef struct ec_group_st EC_GROUP;
typedef struct ec_point_st EC_POINT;
typedef struct ec_key_st EC_KEY;
typedef struct ECDSA_SIG_st ECDSA_SIG;

#define NID_X9_62_prime256v1 415

/* The crate's BigNum is repr(Rust); on this target the compiler lays it out as
 * neg, flags, then Vec<u64> whose element pointer is at byte offset 8.  The
 * pointer is validated against the value it must represent before it is used. */
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
    BN_CTX *(*BN_CTX_new)(void);
    void (*BN_CTX_free)(BN_CTX *);
    BIGNUM *(*BN_new)(void);
    void (*BN_free)(BIGNUM *);
    BIGNUM *(*BN_bin2bn)(const unsigned char *, int, BIGNUM *);
    int (*BN_bn2binpad)(const BIGNUM *, unsigned char *, int);
    BIGNUM *(*BN_mod_inverse)(BIGNUM *, const BIGNUM *, const BIGNUM *, BN_CTX *);
    int (*BN_nnmod)(BIGNUM *, const BIGNUM *, const BIGNUM *, BN_CTX *);
    ECDSA_SIG *(*ECDSA_do_sign)(const unsigned char *, int, EC_KEY *);
    ECDSA_SIG *(*ECDSA_do_sign_ex)(const unsigned char *, int, const BIGNUM *,
                                   const BIGNUM *, EC_KEY *);
    void (*ECDSA_SIG_free)(ECDSA_SIG *);
};

/* Fixed, public fixtures.  Both scalars are below the P-256 group order and
 * have a non-zero top byte, so they occupy exactly four limbs. */
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

static struct api api;
static const char *g_mode = "?";
static int g_taint = 0;   /* this mode marks a secret */
static int g_fixed = 0;   /* mul-g-fixed: use the fixed-base call form */
static int g_bytes = 0;   /* mul-g-bytes: taint the input bytes */
static int g_marked = 0;  /* at least one secret has been marked */

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
    if (sym != NULL && dladdr(sym, &info) != 0)
        printf("BASE fbase=0x%lx saddr=0x%lx\n",
               (unsigned long)info.dli_fbase, (unsigned long)info.dli_saddr);
    if (realpath(name, resolved) == NULL) {
        fprintf(stderr, "pfp21: realpath(%s) failed\n", name);
        return 0;
    }
    if (stat(resolved, &st) != 0) {
        fprintf(stderr, "pfp21: stat(%s) failed\n", resolved);
        return 0;
    }
    printf("LOADED realpath=%s dev=%ju ino=%ju size=%lld\n", resolved,
           (uintmax_t)st.st_dev, (uintmax_t)st.st_ino, (long long)st.st_size);

    maps = fopen("/proc/self/maps", "r");
    if (maps == NULL) {
        fprintf(stderr, "pfp21: cannot read /proc/self/maps\n");
        return 0;
    }
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
    if (entries < 1) {
        fprintf(stderr, "pfp21: %s is not present in /proc/self/maps\n", resolved);
        return 0;
    }
    return 1;
}

static int load_api(const char *path)
{
    void *h = dlopen(path, RTLD_NOW | RTLD_LOCAL);

    if (h == NULL) {
        fprintf(stderr, "pfp21: dlopen(%s): %s\n", path, dlerror());
        return 0;
    }
#define LOAD(field, symbol)                                                    \
    do {                                                                       \
        void *s = dlsym(h, symbol);                                            \
        if (s == NULL) {                                                       \
            fprintf(stderr, "pfp21: missing %s\n", symbol);                    \
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
    LOAD(BN_CTX_new, "BN_CTX_new");
    LOAD(BN_CTX_free, "BN_CTX_free");
    LOAD(BN_new, "BN_new");
    LOAD(BN_free, "BN_free");
    LOAD(BN_bin2bn, "BN_bin2bn");
    LOAD(BN_bn2binpad, "BN_bn2binpad");
    LOAD(BN_mod_inverse, "BN_mod_inverse");
    LOAD(BN_nnmod, "BN_nnmod");
    LOAD(ECDSA_do_sign, "ECDSA_do_sign");
    LOAD(ECDSA_do_sign_ex, "ECDSA_do_sign_ex");
    LOAD(ECDSA_SIG_free, "ECDSA_SIG_free");
#undef LOAD

    return report_loaded((void *)api.EC_POINT_mul, path);
}

/* --- taint -------------------------------------------------------------- */

/* Mark the live limb *values* of `bn` undefined.  The limb pointer is read from
 * the documented layout offset and verified, before any taint, against the same
 * BIGNUM's own big-endian export: a drifted layout returns 0 and the caller
 * aborts (exit 13) rather than tainting the wrong bytes. */
static int mark_bn_values(const char *what, BIGNUM *bn)
{
    unsigned char be[64];
    uint64_t *p = NULL;
    size_t n = 32, first = 0, lim, i, j;

    if (api.BN_bn2binpad(bn, be, (int)n) != (int)n)
        return 0;
    while (first < n && be[first] == 0)
        first++;
    if (first == n)
        return 0; /* zero: no live limb to mark */
    lim = (n - first + 7) / 8;
    if (lim > 4)
        return 0;
    memcpy(&p, (const unsigned char *)bn + BN_D_PTR_OFFSET, sizeof p);
    if (p == NULL)
        return 0;
    for (i = 0; i < lim; i++) {
        uint64_t limb = p[i];
        for (j = 0; j < 8; j++) {
            size_t k = n - 1 - (i * 8 + j);
            if (be[k] != (unsigned char)((limb >> (8 * j)) & 0xff))
                return 0;
        }
    }
    VALGRIND_MAKE_MEM_UNDEFINED(p, lim * sizeof(uint64_t));
    printf("TAINT what=%s limbs=%zu bits=%zu\n", what, lim, lim * 64);
    g_marked = 1;
    return 1;
}

/* --- fixtures ----------------------------------------------------------- */

struct fixture {
    EC_GROUP *group;
    EC_KEY *key;      /* fixed key, public key set from the fixed d */
    BIGNUM *order;
    EC_POINT *p5;     /* public variable-base operand 5*G */
    BN_CTX *ctx;
};

static void fixture_free(struct fixture *f)
{
    if (f->p5 != NULL)
        api.EC_POINT_free(f->p5);
    if (f->key != NULL)
        api.EC_KEY_free(f->key);
    if (f->ctx != NULL)
        api.BN_CTX_free(f->ctx);
    if (f->group != NULL)
        api.EC_GROUP_free(f->group);
}

/* Build the key from the fixed d, with its public key set (public data).  All
 * of this is before the taint boundary. */
static int fixture_build(struct fixture *f)
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
    f->order = (BIGNUM *)api.EC_GROUP_get0_order(f->group);
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

    /* Public variable-base operand: 5*G. Public scalar, public point. */
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

/* Taint the key's own private scalar (the object the sign path reads). */
static int taint_key(struct fixture *f)
{
    const BIGNUM *priv = api.EC_KEY_get0_private_key(f->key);

    if (priv == NULL) {
        fprintf(stderr, "pfp21: key has no private scalar\n");
        return 0;
    }
    return mark_bn_values("d", (BIGNUM *)priv);
}

/* (kinv, r = x(k*G) mod n) for the fixed public-shape fixture k, computed with
 * everything defined.  Used to supply ECDSA_do_sign_ex. */
static int nonce_fixture(struct fixture *f, BIGNUM **kinv_out, BIGNUM **rp_out)
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

/* --- operations --------------------------------------------------------- */

/* The digest and the fixture scalars are public; state that explicitly so the
 * population is a decision, not an accident. */
static void mark_public_inputs(void)
{
    VALGRIND_MAKE_MEM_DEFINED(DGST, sizeof DGST);
    VALGRIND_MAKE_MEM_DEFINED(D_BYTES, sizeof D_BYTES);
    VALGRIND_MAKE_MEM_DEFINED(K_BYTES, sizeof K_BYTES);
}

static int op_mul(struct fixture *f, int variable_base, int iters, double *ns)
{
    const EC_POINT *base = variable_base ? f->p5
                                         : api.EC_GROUP_get0_generator(f->group);
    EC_POINT *r = api.EC_POINT_new(f->group);
    BIGNUM *k;
    int rc = 1, i;
    struct timespec t0, t1;

    if (r == NULL) {
        fprintf(stderr, "pfp21: EC_POINT_new failed\n");
        return 0;
    }
    if (g_bytes) {
        unsigned char buf[32];
        memcpy(buf, K_BYTES, sizeof buf);
        VALGRIND_MAKE_MEM_UNDEFINED(buf, sizeof buf);
        printf("TAINT what=k-bytes bytes=%zu\n", sizeof buf);
        g_marked = 1;
        k = api.BN_bin2bn(buf, (int)sizeof buf, NULL);
    } else {
        k = api.BN_bin2bn(K_BYTES, (int)sizeof K_BYTES, NULL);
    }
    if (k == NULL) {
        api.EC_POINT_free(r);
        return 0;
    }
    if (g_taint && !g_bytes && mark_bn_values("k", k) == 0) {
        api.BN_free(k);
        api.EC_POINT_free(r);
        return 0;
    }
    if (g_fixed) {
        if (api.EC_POINT_mul(f->group, r, k, NULL, NULL, f->ctx) != 1) {
            api.BN_free(k);
            api.EC_POINT_free(r);
            return 0;
        }
    } else if (api.EC_POINT_mul(f->group, r, NULL, base, k, f->ctx) != 1) {
        api.BN_free(k);
        api.EC_POINT_free(r);
        return 0;
    }
    if (iters > 0) {
        clock_gettime(CLOCK_MONOTONIC, &t0);
        for (i = 0; i < iters; i++)
            rc &= g_fixed
                      ? api.EC_POINT_mul(f->group, r, k, NULL, NULL, f->ctx)
                      : api.EC_POINT_mul(f->group, r, NULL, base, k, f->ctx);
        clock_gettime(CLOCK_MONOTONIC, &t1);
        *ns = ((double)(t1.tv_sec - t0.tv_sec) * 1e9 +
               (double)(t1.tv_nsec - t0.tv_nsec)) / (double)iters;
    }
    /* r holds a secret-derived point from here on; nothing reads it. */
    api.BN_free(k);
    api.EC_POINT_free(r);
    return rc;
}

/* sign_ex: 0 = ECDSA_do_sign, 1 = ECDSA_do_sign_ex with the fixture nonce,
 * 2 = sign_ex plus the nonce computation performed on the tainted k. */
static int op_sign(struct fixture *f, int sign_ex, int iters, double *ns)
{
    BIGNUM *kinv = NULL, *rp = NULL, *k = NULL, *inv_t = NULL;
    EC_POINT *q_t = NULL;
    ECDSA_SIG *sig;
    int rc = 0, i;
    struct timespec t0, t1;

    if (sign_ex != 0) {
        if (nonce_fixture(f, &kinv, &rp) == 0) {
            fprintf(stderr, "pfp21: nonce fixture failed\n");
            goto out;
        }
    }

    if (sign_ex == 2 && g_taint) {
        /* The nonce path inside the measured region.  The inverse and the
         * ladder run on the tainted k; their results are released without
         * being inspected, and the pair handed to the signer below is the
         * defined fixture above. */
        k = api.BN_bin2bn(K_BYTES, (int)sizeof K_BYTES, NULL);
        q_t = api.EC_POINT_new(f->group);
        if (k == NULL || q_t == NULL) {
            fprintf(stderr, "pfp21: nonce-path fixture failed\n");
            goto out;
        }
        if (mark_bn_values("k", k) == 0)
            goto out;
        inv_t = api.BN_mod_inverse(NULL, k, f->order, f->ctx);
        if (inv_t == NULL)
            goto out;
        if (api.EC_POINT_mul(f->group, q_t, NULL,
                             api.EC_GROUP_get0_generator(f->group), k,
                             f->ctx) != 1)
            goto out;
        /* Both results are secret-derived; nothing reads them. */
        api.BN_free(inv_t);
        inv_t = NULL;
        api.EC_POINT_free(q_t);
        q_t = NULL;
        api.BN_free(k);
        k = NULL;
    }

    if (g_taint) {
        if (sign_ex != 0 && mark_bn_values("kinv", kinv) == 0)
            goto out;
        if (taint_key(f) == 0)
            goto out;
    }

    if (iters > 0) {
        clock_gettime(CLOCK_MONOTONIC, &t0);
        for (i = 0; i < iters; i++) {
            sig = (sign_ex != 0)
                      ? api.ECDSA_do_sign_ex(DGST, (int)sizeof DGST, kinv, rp,
                                             f->key)
                      : api.ECDSA_do_sign(DGST, (int)sizeof DGST, f->key);
            if (sig == NULL)
                goto out;
            api.ECDSA_SIG_free(sig);
        }
        clock_gettime(CLOCK_MONOTONIC, &t1);
        *ns = ((double)(t1.tv_sec - t0.tv_sec) * 1e9 +
               (double)(t1.tv_nsec - t0.tv_nsec)) / (double)iters;
        rc = 1;
    } else {
        sig = (sign_ex != 0)
                  ? api.ECDSA_do_sign_ex(DGST, (int)sizeof DGST, kinv, rp,
                                         f->key)
                  : api.ECDSA_do_sign(DGST, (int)sizeof DGST, f->key);
        if (sig == NULL)
            goto out;
        api.ECDSA_SIG_free(sig);
        rc = 1;
    }
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

int main(int argc, char **argv)
{
    const char *lib = NULL, *mode = "control";
    int iters = 0, timing = 0, rc = 0, i;
    double ns = 0.0;
    struct fixture f;

    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--lib") == 0 && i + 1 < argc)
            lib = argv[++i];
        else if (strcmp(argv[i], "--mode") == 0 && i + 1 < argc)
            mode = argv[++i];
        else if (strcmp(argv[i], "--iters") == 0 && i + 1 < argc) {
            iters = atoi(argv[++i]);
            timing = 1;
        } else {
            fprintf(stderr, "pfp21: unknown argument %s\n", argv[i]);
            return 2;
        }
    }
    if (lib == NULL) {
        fprintf(stderr, "pfp21: --lib is required\n");
        return 2;
    }
    g_mode = mode;
    g_taint = (strcmp(mode, "control") != 0);
    g_fixed = (strcmp(mode, "mul-g-fixed") == 0);
    g_bytes = (strcmp(mode, "mul-g-bytes") == 0);

    if (load_api(lib) == 0)
        return 3;
    mark_public_inputs();
    printf("HARNESS mode=%s iters=%d taint=%d\n", mode, iters, g_taint);
    fflush(stdout);

    if (fixture_build(&f) == 0) {
        fprintf(stderr, "pfp21: fixture build failed\n");
        return 4;
    }

    if (strcmp(mode, "control") == 0) {
        rc = op_mul(&f, 0, 0, &ns) && op_mul(&f, 1, 0, &ns) &&
             op_sign(&f, 0, 0, &ns) && op_sign(&f, 1, 0, &ns) &&
             op_sign(&f, 2, 0, &ns);
    } else if (strcmp(mode, "mul-g") == 0 || g_bytes) {
        rc = op_mul(&f, 0, iters, &ns);
    } else if (strcmp(mode, "mul-g-fixed") == 0) {
        rc = op_mul(&f, 0, iters, &ns);
    } else if (strcmp(mode, "mul-p") == 0) {
        rc = op_mul(&f, 1, iters, &ns);
    } else if (strcmp(mode, "sign") == 0) {
        rc = op_sign(&f, 0, iters, &ns);
    } else if (strcmp(mode, "sign-ex") == 0) {
        rc = op_sign(&f, 1, iters, &ns);
    } else if (strcmp(mode, "sign-ex-k") == 0) {
        rc = op_sign(&f, 2, iters, &ns);
    } else {
        fprintf(stderr, "pfp21: unknown mode %s\n", mode);
        fixture_free(&f);
        return 2;
    }

    /* The success flag is public (the caller learns whether the operation
     * succeeded), so it is declared defined before it is inspected. */
    VALGRIND_MAKE_MEM_DEFINED(&rc, sizeof rc);
    printf("RESULT mode=%s ok=%d marked=%d\n", mode, rc, g_marked);
    if (timing)
        printf("TIME mode=%s iters=%d ns_per_op=%.1f\n", mode, iters, ns);
    fflush(stdout);
    fixture_free(&f);
    return rc ? 0 : 6;
}
