/*
 * RT-PERFORMANCE-WORK — the Phase 19.3 deterministic work court.
 *
 * What it measures, and why it is not wall-clock
 * ----------------------------------------------
 * 19.1 audited the CPU-capability surface and 19.2 the dispatch decision that surface feeds.
 * 19.3 measures the *work the primitive-bearing paths do*, compared between the admitted
 * authority and the candidate over the same fixed inputs. A wall-clock figure on a shared host is
 * not reproducible and would make the court's verdict a function of the machine, so no clock,
 * duration or address is printed; every `key=value` line below is a deterministic function of the
 * library under test and the fixed inputs (docs/PHASE-19-SUBPHASES.md section 3.3).
 *
 * The work counter the court introduces
 * -------------------------------------
 * The library exposes no total instruction, block or operation counter. What it does expose is a
 * *settable allocator* (`CRYPTO_set_mem_functions`, called before the first allocation) and the
 * public method geometry (`EVP_CIPHER_get_block_size`, `EVP_MD_get_block_size`, `EVP_PKEY_get_bits`,
 * `EC_GROUP_get_degree`). The instrument is therefore two deterministic measures, and the probe is
 * explicit that only the first is a direct count of library work:
 *
 *   * a **counting `CRYPTO` allocator**: the number of `malloc`/`realloc` operations the library
 *     performs and the total bytes it requests while a fixed primitive runs. This is the
 *     instrument the stratum introduces -- a deterministic *instruction-path proxy* for the
 *     library's own memory work. It changes no library behaviour: the shims forward to the default
 *     allocator and are installed before the first allocation, so the library's allocations are
 *     only observed, never altered.
 *   * the **method-derived work vector**: the input bytes, the primitive blocks the input implies
 *     (`ceil(in / block_size)` for a cipher, `ceil((in + 9) / block_size)` for a digest, the
 *     field/modulus degree for EC/RSA), the output bytes and the AEAD tag length. These are a
 *     function of the fixed input and the selected method's public geometry; where a block count
 *     cannot be read from a counter it is a stated arithmetic proxy, not a measured one.
 *
 * A *path whose deterministic work-vector differs* between the authority and the candidate is a
 * **finding** -- a divisor-of-work difference -- never a `fail`; the court's verdict is about
 * whether the surface was driven and every observation recorded (sections 3.1, 3.2, 3.6). The
 * counting allocator observes heap operations, not total CPU instructions, and the block counts are
 * input-implied: the court therefore makes **no benchmark-parity claim** and **no
 * assembly-versus-Rust equivalence claim**.
 *
 * The same source compiles twice, once against the admitted authority and once against the
 * candidate distribution shell; the court diffs the two transcripts. No address, clock or duration
 * is printed, so `forensics/tools/probe_hygiene.py` sees the same transcript at `-O0`, `-O1` and
 * `-O2`.
 *
 * Not a claim
 * -----------
 * The fixed operation set is AES-128/256-CBC, AES-128/256-GCM, ChaCha20-Poly1305, SHA-256, a P-256
 * scalar multiplication and an RSA-1024 private decrypt. A path the probe cannot drive (for
 * example, a fixture it cannot read) is recorded `ran=0` with every numeric field `n/a` rather than
 * assumed. `calls` is a driver-side count -- the primitive invocations the probe itself issues --
 * and is recorded as the denominator, never as a library-work finding.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/crypto.h>
#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/pem.h>
#include <openssl/provider.h>
#include <openssl/rsa.h>

/* ------------------------------------------------------------------------------------------- */
/* The instrument: a counting `CRYPTO` allocator.                                              */

static unsigned long long g_allocs, g_reallocs, g_bytes;
static int g_counting;

static void *work_malloc(size_t n, const char *file, int line)
{
    (void)file; (void)line;
    if (g_counting) {
        g_allocs++;
        g_bytes += (unsigned long long)n;
    }
    return malloc(n);
}

static void *work_realloc(void *p, size_t n, const char *file, int line)
{
    (void)file; (void)line;
    if (g_counting) {
        g_reallocs++;
        g_bytes += (unsigned long long)n;
    }
    return realloc(p, n);
}

static void work_free(void *p, const char *file, int line)
{
    (void)file; (void)line;
    free(p);
}

struct work {
    unsigned long long allocs, reallocs, bytes;
};

static struct work work_since(struct work base)
{
    struct work w;

    w.allocs = g_allocs - base.allocs;
    w.reallocs = g_reallocs - base.reallocs;
    w.bytes = g_bytes - base.bytes;
    return w;
}

/* A work-vector: the deterministic observations one path produced. `ran` is 1 when the path
 * completed and every numeric field is then meaningful; when it is 0 every numeric field is printed
 * `n/a`, so both sides' transcripts carry the same keys. */
struct wvec {
    int ran;
    long long in;      /* input bytes the path was driven over */
    long long blocks;  /* primitive blocks the input implies (method-derived) */
    long long calls;   /* primitive invocations the driver issued (driver-side) */
    long long out;     /* bytes the library produced */
    long long tag;     /* AEAD tag bytes, or -1 where the path has no tag */
    long long ret;     /* operation success */
    struct work w;     /* the counting-allocator work vector */
};

static void kfield_num(const char *id, const char *field, int ran, long long value)
{
    char k[160];

    snprintf(k, sizeof k, "work.%s.%s", id, field);
    if (ran)
        printf("%s=%lld\n", k, value);
    else
        printf("%s=n/a\n", k);
}

static void emit(const char *id, const struct wvec *v)
{
    kfield_num(id, "ran", 1, v->ran);
    kfield_num(id, "in", v->ran, v->in);
    kfield_num(id, "blocks", v->ran, v->blocks);
    kfield_num(id, "calls", v->ran, v->calls);
    kfield_num(id, "out", v->ran, v->out);
    kfield_num(id, "tag", v->ran, v->tag);
    kfield_num(id, "allocs", v->ran, (long long)v->w.allocs);
    kfield_num(id, "reallocs", v->ran, (long long)v->w.reallocs);
    kfield_num(id, "bytes", v->ran, (long long)v->w.bytes);
    kfield_num(id, "ret", v->ran, v->ret);
}

/* The fixed inputs every path is driven over: a fixed key, IV, plaintext and AAD, so the only
 * variation between the two sides is the library. */
static unsigned char KEY[32];
static unsigned char IV[16];
static unsigned char IN[64];
static unsigned char AAD[16];

static void init_inputs(void)
{
    int i;

    for (i = 0; i < 32; i++)
        KEY[i] = (unsigned char)(i + 1);
    for (i = 0; i < 16; i++)
        IV[i] = (unsigned char)(0xa0 + i);
    for (i = 0; i < 64; i++)
        IN[i] = (unsigned char)(i * 3 + 1);
    memset(AAD, 0x11, sizeof AAD);
}

/* ------------------------------------------------------------------------------------------- */
/* The cipher paths: one one-shot encrypt over the fixed plaintext, optionally with the AEAD tag
 * path. `inlen` is the plaintext length; the AAD is the fixed 16 bytes above for AEAD paths. */

struct cipher_spec {
    const char *id;
    const char *name;
    int keylen;
    int ivlen;
    int inlen;
    int aead;
    int taglen;   /* 0 for a non-AEAD cipher */
};

static void cipher_once(const struct cipher_spec *s, struct wvec *v)
{
    EVP_CIPHER *c = NULL;
    EVP_CIPHER_CTX *ctx = NULL;
    unsigned char out[256];
    unsigned char tag[16];
    int ol = 0, tl = 0, fl = 0;
    long long calls = 0, outb = 0;
    int ok = 1;

    memset(out, 0, sizeof out);
    memset(tag, 0, sizeof tag);

    c = EVP_CIPHER_fetch(NULL, s->name, NULL);
    calls++;
    if (c == NULL) { v->ran = 0; return; }
    ctx = EVP_CIPHER_CTX_new();
    calls++;
    if (ctx == NULL) { EVP_CIPHER_free(c); v->ran = 0; return; }

    if (EVP_EncryptInit_ex2(ctx, c, KEY, s->ivlen ? IV : NULL, NULL) != 1)
        ok = 0;
    calls++;
    if (ok && s->aead) {
        if (EVP_EncryptUpdate(ctx, NULL, &tl, AAD, (int)sizeof AAD) != 1)
            ok = 0;
        calls++;
    }
    if (ok) {
        if (EVP_EncryptUpdate(ctx, out, &ol, IN, s->inlen) != 1)
            ok = 0;
        outb += ol;
        calls++;
    }
    if (ok) {
        if (EVP_EncryptFinal_ex(ctx, out + outb, &fl) != 1)
            ok = 0;
        outb += fl;
        calls++;
    }
    if (ok && s->aead && s->taglen > 0) {
        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, s->taglen, tag) != 1)
            ok = 0;
        calls++;
    }

    v->ran = ok;
    v->in = s->inlen;
    v->blocks = (s->inlen + EVP_CIPHER_get_block_size(c) - 1) /
                (EVP_CIPHER_get_block_size(c) > 0 ? EVP_CIPHER_get_block_size(c) : 1);
    v->calls = calls;
    v->out = outb;
    v->tag = s->aead ? s->taglen : -1;
    v->ret = ok;

    EVP_CIPHER_CTX_free(ctx);
    calls++;
    EVP_CIPHER_free(c);
    calls++;
    /* `calls` is driver-side; the two frees are folded into it after the measured region. */
    v->calls = calls;
}

static void run_cipher(const struct cipher_spec *s)
{
    struct wvec v;
    struct work base;

    memset(&v, 0, sizeof v);
    g_counting = 0;
    cipher_once(s, &v);            /* warm every lazy allocation and cache */
    base.allocs = g_allocs; base.reallocs = g_reallocs; base.bytes = g_bytes;
    g_counting = 1;
    cipher_once(s, &v);
    g_counting = 0;
    v.w = work_since(base);
    emit(s->id, &v);
}

/* ------------------------------------------------------------------------------------------- */
/* The digest path: SHA-256 over the fixed plaintext. */

static void digest_once(const char *name, int inlen, struct wvec *v)
{
    EVP_MD *m = NULL;
    EVP_MD_CTX *ctx = NULL;
    unsigned char out[64];
    unsigned int ol = 0;
    long long calls = 0;
    int ok = 1;

    m = EVP_MD_fetch(NULL, name, NULL);
    calls++;
    if (m == NULL) { v->ran = 0; return; }
    ctx = EVP_MD_CTX_new();
    calls++;
    if (ctx == NULL) { EVP_MD_free(m); v->ran = 0; return; }

    if (EVP_DigestInit_ex2(ctx, m, NULL) != 1)
        ok = 0;
    calls++;
    if (ok && EVP_DigestUpdate(ctx, IN, inlen) != 1)
        ok = 0;
    calls++;
    if (ok && EVP_DigestFinal_ex(ctx, out, &ol) != 1)
        ok = 0;
    calls++;

    v->ran = ok;
    v->in = inlen;
    v->blocks = (inlen + 9 + EVP_MD_get_block_size(m) - 1) /
                (EVP_MD_get_block_size(m) > 0 ? EVP_MD_get_block_size(m) : 1);
    v->calls = calls;
    v->out = (long long)ol;
    v->tag = -1;
    v->ret = ok;

    EVP_MD_CTX_free(ctx);
    calls++;
    EVP_MD_free(m);
    calls++;
    v->calls = calls;
}

static void run_digest(const char *id, const char *name, int inlen)
{
    struct wvec v;
    struct work base;

    memset(&v, 0, sizeof v);
    g_counting = 0;
    digest_once(name, inlen, &v);
    base.allocs = g_allocs; base.reallocs = g_reallocs; base.bytes = g_bytes;
    g_counting = 1;
    digest_once(name, inlen, &v);
    g_counting = 0;
    v.w = work_since(base);
    emit(id, &v);
}

/* ------------------------------------------------------------------------------------------- */
/* The P-256 scalar multiplication: the reduced engine's constant-time ladder for the single-scalar
 * case. `blocks` is the field degree; the input is the fixed scalar (order - 1) in bytes. */

struct ec_state {
    EC_GROUP *group;
    EC_POINT *point;
    EC_POINT *result;
    BIGNUM *scalar;
    BN_CTX *bnctx;
};

static int ec_once(const struct ec_state *s)
{
    return EC_POINT_mul(s->group, s->result, NULL, s->point, s->scalar, s->bnctx) == 1;
}

static void run_ec(const char *id)
{
    struct ec_state s;
    struct wvec v;
    struct work base;
    long long calls = 0;

    memset(&s, 0, sizeof s);
    memset(&v, 0, sizeof v);
    s.group = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
    calls++;
    s.point = EC_POINT_new(s.group);
    calls++;
    s.result = EC_POINT_new(s.group);
    calls++;
    s.scalar = BN_new();
    calls++;
    s.bnctx = BN_CTX_new();
    calls++;
    if (s.group == NULL || s.point == NULL || s.result == NULL || s.scalar == NULL ||
        s.bnctx == NULL) {
        v.ran = 0;
        goto out;
    }
    if (EC_POINT_copy(s.point, EC_GROUP_get0_generator(s.group)) != 1 ||
        EC_GROUP_get_order(s.group, s.scalar, s.bnctx) != 1 ||
        BN_sub_word(s.scalar, 1) != 1) {
        v.ran = 0;
        goto out;
    }

    g_counting = 0;
    ec_once(&s);                   /* warm the BN/point allocations the multiply may cache */
    base.allocs = g_allocs; base.reallocs = g_reallocs; base.bytes = g_bytes;
    g_counting = 1;
    v.ret = ec_once(&s);
    g_counting = 0;
    v.w = work_since(base);
    v.ran = 1;
    v.in = BN_num_bytes(s.scalar);
    v.blocks = EC_GROUP_get_degree(s.group);
    v.calls = calls + 1;           /* the measured `EC_POINT_mul` itself */
    v.out = (long long)EC_POINT_point2oct(s.group, s.result, POINT_CONVERSION_UNCOMPRESSED,
                                          NULL, 0, s.bnctx);
    v.tag = -1;

out:
    if (!v.ran) {
        v.in = v.blocks = v.calls = v.out = v.ret = 0;
    }
    emit(id, &v);
    EC_GROUP_free(s.group);
    EC_POINT_free(s.point);
    EC_POINT_free(s.result);
    BN_free(s.scalar);
    BN_CTX_free(s.bnctx);
}

/* ------------------------------------------------------------------------------------------- */
/* The RSA private operation: a fixed 1024-bit ciphertext under the committed 1024-bit test key. */

static EVP_PKEY *load_rsa(const char *path)
{
    FILE *f = fopen(path, "rb");
    EVP_PKEY *k;

    if (f == NULL)
        return NULL;
    k = PEM_read_PrivateKey(f, NULL, NULL, NULL);
    fclose(f);
    return k;
}

struct rsa_state {
    EVP_PKEY *key;
    unsigned char ct[128];
    unsigned char out[256];
    int ctlen;
};

static long long rsa_once(struct rsa_state *s)
{
    EVP_PKEY_CTX *ctx;
    size_t outl = sizeof s->out;
    int r;

    ctx = EVP_PKEY_CTX_new(s->key, NULL);
    if (ctx == NULL)
        return -1;
    if (EVP_PKEY_decrypt_init(ctx) <= 0 ||
        EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PADDING) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        return -2;
    }
    r = EVP_PKEY_decrypt(ctx, s->out, &outl, s->ct, (size_t)s->ctlen);
    EVP_PKEY_CTX_free(ctx);
    if (r <= 0)
        return -3;
    return (long long)outl;
}

static void run_rsa(const char *id, const char *path)
{
    struct rsa_state s;
    struct wvec v;
    struct work base;
    int i;

    memset(&s, 0, sizeof s);
    memset(&v, 0, sizeof v);
    s.key = load_rsa(path);
    if (s.key == NULL) {
        v.ran = 0;
        emit(id, &v);
        return;
    }
    s.ctlen = 128;
    s.ct[0] = 1;
    for (i = 1; i < s.ctlen; i++)
        s.ct[i] = (unsigned char)(0x20 + (i & 0x1f));

    g_counting = 0;
    rsa_once(&s);                  /* warm the per-operation context allocations */
    base.allocs = g_allocs; base.reallocs = g_reallocs; base.bytes = g_bytes;
    g_counting = 1;
    v.ret = rsa_once(&s);
    g_counting = 0;
    v.w = work_since(base);
    v.ran = 1;
    if (v.ret < 0) {
        v.ran = 0;
        v.ret = -1;
    }
    v.in = s.ctlen;
    v.blocks = EVP_PKEY_get_bits(s.key);
    v.calls = 1;                   /* the measured `EVP_PKEY_decrypt` itself */
    v.out = v.ran ? v.ret : 0;
    v.tag = -1;

    emit(id, &v);
    EVP_PKEY_free(s.key);
}

int main(int argc, char **argv)
{
    const char *fixtures = argc > 1 ? argv[1] : "courts/phase19/fixtures";
    char rsapath[512];
    int installed;

    printf("probe.kind=performance-work\n");

    /* The instrument is installed before the library's first allocation; the shims only observe. */
    installed = CRYPTO_set_mem_functions(work_malloc, work_realloc, work_free);
    printf("work.hook.install=%d\n", installed);

    if (OSSL_PROVIDER_load(NULL, "default") == NULL)
        printf("work.default_provider=0\n");
    else
        printf("work.default_provider=1\n");

    init_inputs();

    {
        static const struct cipher_spec specs[] = {
            { "aes-128-cbc", "AES-128-CBC", 16, 16, 64, 0, 0 },
            { "aes-256-cbc", "AES-256-CBC", 32, 16, 64, 0, 0 },
            { "aes-128-gcm", "AES-128-GCM", 16, 12, 64, 1, 16 },
            { "aes-256-gcm", "AES-256-GCM", 32, 12, 64, 1, 16 },
            { "chacha20-poly1305", "CHACHA20-POLY1305", 32, 12, 64, 1, 16 },
        };
        size_t i;

        for (i = 0; i < sizeof specs / sizeof specs[0]; i++)
            run_cipher(&specs[i]);
    }

    run_digest("sha256", "SHA256", 64);
    run_ec("ec-p256-mul");

    snprintf(rsapath, sizeof rsapath, "%s/rsa-work.pem", fixtures);
    run_rsa("rsa-1024-private", rsapath);

    printf("probe.done=1\n");
    return 0;
}
