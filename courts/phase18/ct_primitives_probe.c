/*
 * CT-PRIMITIVES — the Phase 18 candidate-only secret-independence court over the
 * primitive-bearing paths (BN, RSA, EC, the AEADs and the TLS key schedule).
 *
 * What it measures, and how
 * -------------------------
 * There is no authority transcript for a secret-independence property, so this probe is compiled
 * **once**, against the candidate distribution shell alone, and answers a property question rather
 * than a differential one (docs/PHASE-18-SUBPHASES.md section 3.2). For each measured path it
 * drives the operation under two *secret classes* that differ only in the secret operand (an
 * exponent's Hamming weight, a private key's CRT exponents, a scalar, the position of a tag
 * mismatch, a key-schedule IKM), interleaves the two classes, and times a batch of `reps` with a
 * serialising timestamp counter (`__rdtscp` after `_mm_lfence`). It keeps the **minimum** batch
 * time per class — the noise-free execution floor, which a secret-dependent branch cannot hide
 * behind — and classifies the path `separated` when the two minima differ by more than
 * `SEP_PCT` percent, `independent` otherwise.
 *
 * The statistic is a ratio of minima, not a wall-clock claim: nothing about absolute speed,
 * frequency, cache state or a real attacker is asserted. It is a *bounded* work-independence
 * screen: it can only see a secret dependence that changes the executed work by more than the
 * calibrated threshold on this host, and a path it does not drive it says nothing about
 * (section 3.1). It is not a proof of constant-time behaviour.
 *
 * The RSA fixtures
 * ----------------
 * `courts/phase18/fixtures/rsa-ct-lo.pem` and `rsa-ct-hi.pem` are committed 1024-bit private
 * keys, generated once with `RSA_generate_key_ex` and selected from a batch of 400 for the widest
 * spread of CRT-exponent Hamming weight (471 versus 570 set bits across `dmp1`+`dmq1`). They are
 * fixed fixtures rather than a re-derivable generator. That spread produces a measured work
 * difference of only about 3.5 percent, which is *below* this screen's 50 percent resolution, so
 * the RSA path is reported `independent` -- a limitation of the instrument's resolution, not
 * evidence that the path is constant-time.
 *
 * The sensitivity control
 * -----------------------
 * A control that cannot fail is not evidence (section 3.2). `control-branchy-tag` is a deliberately
 * branch-on-secret variant of the tag-comparison path: it returns early on the first mismatching
 * byte and does a long dependent multiply on every matching byte, so a tag that differs at its
 * last byte does vastly more work than one that differs at its first. The real tag path
 * (`aead-tag-memcmp`, `CRYPTO_memcmp`, the primitive GCM's finish and the Poly1305 check use) is
 * measured by the same harness. The probe prints the control's class beside the real path's, so a
 * court can require the control to be `separated` exactly where the real path is `independent`.
 *
 * What the transcript is
 * ----------------------
 * The transcript is a function of the library alone: no clock value, address or measured duration
 * is printed, only the `ran` and `class` fields and the fixed sample geometry. That is what lets
 * `forensics/tools/probe_hygiene.py` compile it at -O0/-O1/-O2 and require the same answer.
 *
 * argv: [fixtures-dir]   (default /work/courts/phase18/fixtures)
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <x86intrin.h>

#include <openssl/bn.h>
#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/obj_mac.h>
#include <openssl/params.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>

#define DEFAULT_FIXTURES "/work/courts/phase18/fixtures"

/* The tag-comparison buffers. `a` and `b` are cache-line aligned and the same length, and both
 * secret classes are driven over them unchanged -- only the position of the single mismatching
 * byte in `b` differs (set up outside the timed region) -- so the two classes touch exactly the
 * same addresses and cache lines and a constant-time comparison cannot separate them on memory
 * layout alone. A 16-byte GCM tag is too small to measure without the buffers' addresses
 * dominating the result (measured), so the same primitive is driven over 4 KiB. */
#define TAG_LEN 4096

/* Samples and warmup per class; `reps` batch multiplier is per path. */
#define WARMUP 32
#define SAMPLES 320

/* The tag-comparison paths (the real `aead-tag-memcmp` and its branch-on-secret control) time a
 * single 4 KiB comparison per sample, which on this host is only a few hundred cycles -- short
 * enough that a fixed per-timed-region scheduling or cache offset of a few tens of cycles is a
 * double-digit percentage of the batch, and a genuinely constant-time path can wobble across a
 * tight threshold from run to run and level to level. Both paths therefore time `TAG_REPS` calls
 * per batch, so that same fixed offset is diluted to a low single-digit percentage and the minima
 * reflect the work rather than the scheduler. The other paths already time work measured in
 * thousands of cycles and keep `reps` 1. */
#define TAG_REPS 32

/* A path is `separated` when max(min)/min(min) exceeds SEP_PCT percent. The threshold is set with
 * margin on both sides. Above it: the residual run-to-run spread of a genuinely constant-time
 * path on this host with the shared-buffer, longer-batch measurement above (measured at or below
 * about 2 percent across -O0/-O1/-O2 and repeated runs). Below it: the work ratio every branch-on-
 * secret path this probe drives produces (BN square-and-multiply ~2x and the modular inverse ~4.7x,
 * the control ~2700x-10000x, and measured as low as ~1.97x for the BN exponentiation). A 1.5x
 * threshold sits clear of both, so nothing near it can flip a class; a dependence subtler than it
 * is reported `independent`: the screen has that resolution and no better. */
#define SEP_PCT 150

/* The deliberately branch-on-secret control's per-matching-byte work. */
#define CONTROL_WORK 64

static volatile uint64_t g_sink;

static inline uint64_t tsc(void)
{
    unsigned int aux;

    _mm_lfence();
    return __rdtscp(&aux);
}

typedef uint64_t (*op_fn)(void *arg, int cls);
typedef void (*setup_fn)(void *arg, int cls);

/* Time `reps` invocations of `f(cls)` per sample, interleaving the two classes, and keep the
 * minimum per class. `setup`, when non-NULL, runs just before each class's timed batch and
 * *outside* it, so a path can drive its two secret classes over the same bytes at the same
 * addresses and let only the values differ: any address, page or cache-set asymmetry between the
 * classes is then removed from the measurement rather than read as a separation. Returns the
 * classification and writes the two minima (for the caller's summary only; they are never
 * printed). */
static int measure_core(op_fn f, setup_fn setup, void *arg, int reps, uint64_t *lo, uint64_t *hi)
{
    uint64_t min0 = UINT64_MAX, min1 = UINT64_MAX;
    int i, j;

    for (i = 0; i < WARMUP; i++) {
        if (setup)
            setup(arg, 0);
        g_sink += f(arg, 0);
        if (setup)
            setup(arg, 1);
        g_sink += f(arg, 1);
    }
    for (i = 0; i < SAMPLES; i++) {
        uint64_t t0, t1, d0, d1, acc = 0;

        if (setup)
            setup(arg, 0);
        t0 = tsc();
        for (j = 0; j < reps; j++)
            acc += f(arg, 0);
        t1 = tsc();
        d0 = t1 - t0;
        g_sink += acc;

        if (setup)
            setup(arg, 1);
        t0 = tsc();
        for (j = 0; j < reps; j++)
            acc += f(arg, 1);
        t1 = tsc();
        d1 = t1 - t0;
        g_sink += acc;

        if (d0 < min0)
            min0 = d0;
        if (d1 < min1)
            min1 = d1;
    }
    if (min0 == 0 || min1 == 0)
        return -1; /* a zero-length timed region cannot be classified */
    *lo = min0 < min1 ? min0 : min1;
    *hi = min0 < min1 ? min1 : min0;
    /* max/min > SEP_PCT/100  <=>  100*hi > SEP_PCT*lo */
    return (100.0 * (double)*hi) > (SEP_PCT * (double)*lo) ? 1 : 0;
}

/* The no-`setup` form the primitive paths use; see `measure_core`. */
static int measure(op_fn f, void *arg, int reps, uint64_t *lo, uint64_t *hi)
{
    return measure_core(f, NULL, arg, reps, lo, hi);
}

/* The measured minima are host- and run-dependent, so they are printed only to stderr and only
 * when `CT_PRIMITIVES_DEBUG` is set: the stdout transcript that probe_hygiene.py and the court
 * compare stays a function of the library alone. */
static void dbg(const char *name, uint64_t lo, uint64_t hi)
{
    if (getenv("CT_PRIMITIVES_DEBUG") != NULL && lo != 0)
        fprintf(stderr, "ct-debug.%s.min=%llu/1.0 max=%llu ratio=%.3f\n", name,
                (unsigned long long)lo, (unsigned long long)hi,
                (double)hi / (double)lo);
}

static void emit(const char *name, int ran, int cls)
{
    printf("ct.%s.ran=%d\n", name, ran);
    if (ran) {
        if (cls < 0)
            printf("ct.%s.class=inconclusive\n", name);
        else
            printf("ct.%s.class=%s\n", name, cls ? "separated" : "independent");
    }
}

/* ------------------------------------------------------------------------------------------- */
/* BN — modular exponentiation and modular inverse.                                             */

struct bn_exp {
    BIGNUM *r, *a, *m, *e0, *e1;
    BN_CTX *ctx;
};

static uint64_t bn_exp_op(void *arg, int cls)
{
    struct bn_exp *s = arg;

    if (BN_mod_exp_mont_consttime(s->r, s->a, cls ? s->e1 : s->e0, s->m, s->ctx, NULL) != 1)
        return 0;
    return (uint64_t)BN_num_bits(s->r);
}

static int bn_exp_run(void)
{
    struct bn_exp s;
    uint64_t lo = 0, hi = 0;
    int cls;

    memset(&s, 0, sizeof s);
    s.ctx = BN_CTX_new();
    s.r = BN_new();
    s.a = BN_new();
    s.m = BN_new();
    s.e0 = BN_new();
    s.e1 = BN_new();
    if (!s.ctx || !s.r || !s.a || !s.m || !s.e0 || !s.e1)
        goto fail;
    /* m = 2^255 - 19, an odd (prime) modulus the consttime path accepts. a = 5. */
    if (!BN_one(s.m) || !BN_lshift(s.m, s.m, 255) || !BN_sub_word(s.m, 19))
        goto fail;
    if (!BN_set_word(s.a, 5))
        goto fail;
    /* Two 255-bit exponents: e0 has Hamming weight 2, e1 has 255 — equal public length, different
     * secret value. A constant-time modexp's work is independent of which one it is. */
    if (!BN_one(s.e0) || !BN_lshift(s.e0, s.e0, 254) || !BN_add_word(s.e0, 1))
        goto fail;
    if (!BN_one(s.e1) || !BN_lshift(s.e1, s.e1, 255) || !BN_sub_word(s.e1, 1))
        goto fail;

    cls = measure(bn_exp_op, &s, 1, &lo, &hi);
    dbg("bn-modexp", lo, hi);
    emit("bn-modexp", 1, cls);
    BN_CTX_free(s.ctx);
    BN_free(s.r);
    BN_free(s.a);
    BN_free(s.m);
    BN_free(s.e0);
    BN_free(s.e1);
    return 0;
fail:
    emit("bn-modexp", 0, 0);
    BN_CTX_free(s.ctx);
    BN_free(s.r);
    BN_free(s.a);
    BN_free(s.m);
    BN_free(s.e0);
    BN_free(s.e1);
    return 0;
}

struct bn_inv {
    BIGNUM *r, *m, *a0, *a1;
    BN_CTX *ctx;
};

static uint64_t bn_inv_op(void *arg, int cls)
{
    struct bn_inv *s = arg;
    BIGNUM *got = BN_mod_inverse(s->r, cls ? s->a1 : s->a0, s->m, s->ctx);

    return got != NULL ? (uint64_t)BN_num_bits(got) : 0;
}

static int bn_inv_run(void)
{
    struct bn_inv s;
    uint64_t lo = 0, hi = 0;
    int cls;

    memset(&s, 0, sizeof s);
    s.ctx = BN_CTX_new();
    s.r = BN_new();
    s.m = BN_new();
    s.a0 = BN_new();
    s.a1 = BN_new();
    if (!s.ctx || !s.r || !s.m || !s.a0 || !s.a1)
        goto fail;
    if (!BN_one(s.m) || !BN_lshift(s.m, s.m, 255) || !BN_sub_word(s.m, 19))
        goto fail;
    /* Two coprime operands of the same width; the binary/euclidean inverse's iteration count is a
     * function of the operands, so a variable-time inverse separates them. */
    if (!BN_one(s.a0) || !BN_lshift(s.a0, s.a0, 200) || !BN_add_word(s.a0, 1))
        goto fail;
    if (!BN_one(s.a1) || !BN_lshift(s.a1, s.a1, 254) || !BN_sub_word(s.a1, 3))
        goto fail;

    cls = measure(bn_inv_op, &s, 1, &lo, &hi);
    dbg("bn-inverse", lo, hi);
    emit("bn-inverse", 1, cls);
    BN_CTX_free(s.ctx);
    BN_free(s.r);
    BN_free(s.m);
    BN_free(s.a0);
    BN_free(s.a1);
    return 0;
fail:
    emit("bn-inverse", 0, 0);
    BN_CTX_free(s.ctx);
    BN_free(s.r);
    BN_free(s.m);
    BN_free(s.a0);
    BN_free(s.a1);
    return 0;
}

/* ------------------------------------------------------------------------------------------- */
/* RSA — the private-key operation, over two keys whose CRT exponents differ in Hamming weight. */

struct rsa_dec {
    RSA *k0, *k1;
    unsigned char ct[256];
    unsigned char out[256];
    int ctlen;
};

static uint64_t rsa_op(void *arg, int cls)
{
    struct rsa_dec *s = arg;
    int r;

    ERR_clear_error();
    r = RSA_private_decrypt(s->ctlen, s->ct, s->out, cls ? s->k1 : s->k0,
                            RSA_PKCS1_PADDING);
    /* The disposition is a function of the key only for a fixed ciphertext; for timing we only
     * need the call to have run, so the return code is folded in as a checksum bit. */
    return (uint64_t)(r & 1);
}

static RSA *load_rsa(const char *path)
{
    FILE *f = fopen(path, "r");
    RSA *k;

    if (f == NULL)
        return NULL;
    k = PEM_read_RSAPrivateKey(f, NULL, NULL, NULL);
    fclose(f);
    return k;
}

static int rsa_run(const char *dir)
{
    struct rsa_dec s;
    char p0[512], p1[512];
    uint64_t lo = 0, hi = 0;
    int cls, i;

    memset(&s, 0, sizeof s);
    snprintf(p0, sizeof p0, "%s/rsa-ct-lo.pem", dir);
    snprintf(p1, sizeof p1, "%s/rsa-ct-hi.pem", dir);
    s.k0 = load_rsa(p0);
    s.k1 = load_rsa(p1);
    if (s.k0 == NULL || s.k1 == NULL)
        goto fail;
    /* A fixed 1024-bit ciphertext below both moduli; both keys run their full private op. */
    s.ctlen = 128;
    s.ct[0] = 0x01;
    for (i = 1; i < s.ctlen; i++)
        s.ct[i] = (unsigned char)(0x20 + (i & 0x1f));

    cls = measure(rsa_op, &s, 1, &lo, &hi);
    dbg("rsa-private", lo, hi);
    emit("rsa-private", 1, cls);
    RSA_free(s.k0);
    RSA_free(s.k1);
    return 0;
fail:
    emit("rsa-private", 0, 0);
    RSA_free(s.k0);
    RSA_free(s.k1);
    return 0;
}

/* ------------------------------------------------------------------------------------------- */
/* EC — P-256 scalar multiplication, which the reduced engine routes through its constant-time
 * ladder for the single-scalar case. */

struct ec_mul {
    EC_GROUP *g;
    EC_POINT *r, *p;
    BIGNUM *s0, *s1;
    BN_CTX *ctx;
};

static uint64_t ec_op(void *arg, int cls)
{
    struct ec_mul *s = arg;

    if (EC_POINT_mul(s->g, s->r, NULL, s->p, cls ? s->s1 : s->s0, s->ctx) != 1)
        return 0;
    return (uint64_t)EC_POINT_is_at_infinity(s->g, s->r);
}

static int ec_run(void)
{
    struct ec_mul s;
    uint64_t lo = 0, hi = 0;
    int cls;

    memset(&s, 0, sizeof s);
    s.g = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
    s.r = EC_POINT_new(s.g);
    s.p = EC_POINT_new(s.g);
    s.s0 = BN_new();
    s.s1 = BN_new();
    s.ctx = BN_CTX_new();
    if (s.g == NULL || s.r == NULL || s.p == NULL || s.s0 == NULL || s.s1 == NULL || s.ctx == NULL)
        goto fail;
    /* p = the generator. s0 = 1 (Hamming weight 1), s1 = order - 1 (~255 set bits). */
    if (EC_POINT_copy(s.p, EC_GROUP_get0_generator(s.g)) != 1)
        goto fail;
    if (!BN_one(s.s0))
        goto fail;
    if (EC_GROUP_get_order(s.g, s.s1, s.ctx) != 1 || !BN_sub_word(s.s1, 1))
        goto fail;

    cls = measure(ec_op, &s, 1, &lo, &hi);
    dbg("ec-scalar-mul", lo, hi);
    emit("ec-scalar-mul", 1, cls);
    EC_GROUP_free(s.g);
    EC_POINT_free(s.r);
    EC_POINT_free(s.p);
    BN_free(s.s0);
    BN_free(s.s1);
    BN_CTX_free(s.ctx);
    return 0;
fail:
    emit("ec-scalar-mul", 0, 0);
    EC_GROUP_free(s.g);
    EC_POINT_free(s.r);
    EC_POINT_free(s.p);
    BN_free(s.s0);
    BN_free(s.s1);
    BN_CTX_free(s.ctx);
    return 0;
}

/* ------------------------------------------------------------------------------------------- */
/* The AEADs — the tag comparison both GCM's finish and the Poly1305 check are built on. */

struct tag_pair {
    unsigned char a[TAG_LEN];
    unsigned char b[TAG_LEN];
} __attribute__((aligned(64)));

/* One shared pair of buffers for the real tag path *and* its control: `a` is fixed, and `b` matches
 * it everywhere except one byte -- at the first position for the class-0 secret and the last for
 * the class-1 secret. Both secret classes are therefore driven over the same addresses and the same
 * cache lines, so only the byte values differ; a constant-time comparison does the same work either
 * way and a comparison that branches on the secret does not. The mismatch is set up outside the
 * timed region. */
static void tag_setup(void *arg, int cls)
{
    struct tag_pair *s = arg;

    if (cls) {
        s->b[0] = s->a[0];
        s->b[TAG_LEN - 1] = (unsigned char)(s->a[TAG_LEN - 1] ^ 0x01);
    } else {
        s->b[0] = (unsigned char)(s->a[0] ^ 0x01);
        s->b[TAG_LEN - 1] = s->a[TAG_LEN - 1];
    }
}

static uint64_t tag_cmp_op(void *arg, int cls)
{
    struct tag_pair *s = arg;

    (void)cls;  /* the class is realised by `tag_setup` over the shared buffer `b` */
    return (uint64_t)CRYPTO_memcmp(s->a, s->b, TAG_LEN);
}

static int tag_run(void)
{
    struct tag_pair s;
    uint64_t lo = 0, hi = 0;
    int cls;

    memset(&s, 0, sizeof s);
    memset(s.a, 0xa5, TAG_LEN);
    memset(s.b, 0xa5, TAG_LEN);

    cls = measure_core(tag_cmp_op, tag_setup, &s, TAG_REPS, &lo, &hi);
    dbg("aead-tag-memcmp", lo, hi);
    emit("aead-tag-memcmp", 1, cls);
    return 0;
}

/* ------------------------------------------------------------------------------------------- */
/* The TLS key schedule — the HKDF extract/expand the TLS 1.3 schedule is built from. */

struct hkdf {
    EVP_KDF *kdf;
    EVP_KDF_CTX *ctx;
    unsigned char key0[32];
    unsigned char key1[32];
    unsigned char salt[16];
    unsigned char info[8];
    unsigned char out[32];
};

static uint64_t hkdf_op(void *arg, int cls)
{
    struct hkdf *s = arg;
    const unsigned char *key = cls ? s->key1 : s->key0;
    OSSL_PARAM params[5];
    size_t outlen = 0;

    params[0] = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST, "SHA256", 0);
    params[1] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_KEY, (void *)key,
                                                   sizeof s->key0);
    params[2] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SALT, s->salt, sizeof s->salt);
    params[3] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_INFO, s->info, sizeof s->info);
    params[4] = OSSL_PARAM_construct_end();

    if (EVP_KDF_derive(s->ctx, s->out, sizeof s->out, params) != 1)
        return 0;
    for (outlen = 0; outlen < sizeof s->out; outlen++)
        if (s->out[outlen] != 0)
            break;
    return (uint64_t)outlen;
}

static int hkdf_run(void)
{
    struct hkdf s;
    uint64_t lo = 0, hi = 0;
    int cls, i;

    memset(&s, 0, sizeof s);
    s.kdf = EVP_KDF_fetch(NULL, "HKDF", NULL);
    if (s.kdf == NULL)
        goto fail;
    s.ctx = EVP_KDF_CTX_new(s.kdf);
    if (s.ctx == NULL)
        goto fail;
    for (i = 0; i < 32; i++) {
        s.key0[i] = (unsigned char)(0x10 + i);
        s.key1[i] = (unsigned char)(0x90 + i);
    }
    for (i = 0; i < 16; i++)
        s.salt[i] = (unsigned char)(0x40 + i);
    for (i = 0; i < 8; i++)
        s.info[i] = (unsigned char)(0x60 + i);

    cls = measure(hkdf_op, &s, 1, &lo, &hi);
    dbg("tls-key-schedule-hkdf", lo, hi);
    emit("tls-key-schedule-hkdf", 1, cls);
    EVP_KDF_CTX_free(s.ctx);
    EVP_KDF_free(s.kdf);
    return 0;
fail:
    emit("tls-key-schedule-hkdf", 0, 0);
    if (s.ctx)
        EVP_KDF_CTX_free(s.ctx);
    if (s.kdf)
        EVP_KDF_free(s.kdf);
    return 0;
}

/* ------------------------------------------------------------------------------------------- */
/* The sensitivity control — a deliberately branch-on-secret tag comparison.                     */

/* Early-return comparison that does `CONTROL_WORK` dependent multiplies per matching byte, so a
 * tag differing at its last byte does ~15x the work of one differing at its first. It is driven by
 * the same `tag_pair` buffers and the same `tag_setup` as the real path above, so the control
 * differs from `aead-tag-memcmp` in exactly one respect: it branches on the secret. */
static uint64_t branchy_cmp(const unsigned char *a, const unsigned char *b, size_t n)
{
    size_t i;
    int j;

    for (i = 0; i < n; i++) {
        uint64_t x;

        if (a[i] != b[i])
            return 1;
        x = (uint64_t)a[i] + 1;
        for (j = 0; j < CONTROL_WORK; j++)
            x = x * 2654435761u + 1u;
        g_sink += x;
    }
    return 0;
}

static uint64_t ctrl_op(void *arg, int cls)
{
    struct tag_pair *s = arg;

    (void)cls;  /* the class is realised by `tag_setup` over the shared buffer `b` */
    return branchy_cmp(s->a, s->b, TAG_LEN);
}

static int ctrl_run(void)
{
    struct tag_pair s;
    uint64_t lo = 0, hi = 0;
    int cls;

    memset(&s, 0, sizeof s);
    memset(s.a, 0xa5, TAG_LEN);
    memset(s.b, 0xa5, TAG_LEN);

    cls = measure_core(ctrl_op, tag_setup, &s, TAG_REPS, &lo, &hi);
    dbg("control-branchy-tag", lo, hi);
    emit("control-branchy-tag", 1, cls);
    return 0;
}

int main(int argc, char **argv)
{
    const char *dir = argc > 1 ? argv[1] : DEFAULT_FIXTURES;

    bn_exp_run();
    bn_inv_run();
    rsa_run(dir);
    ec_run();
    tag_run();
    hkdf_run();
    ctrl_run();

    /* The control's reference is the real tag path it varies; state it explicitly so a reader
     * does not have to infer the pairing. */
    printf("ct.control.path=aead-tag-memcmp\n");
    printf("ct.paths=6\n");

    /* A sink the optimiser cannot remove, so no measured call is dead code. */
    if (g_sink == 0x1234567890abcdefULL)
        fprintf(stderr, "impossible\n");
    return 0;
}
