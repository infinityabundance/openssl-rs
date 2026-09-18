/*
 * RT-HMAC -- the legacy one-shot interface `crypto/hmac/hmac.c`.
 *
 * What this court is, and what it deliberately is not
 * ---------------------------------------------------
 * `crypto/hmac/hmac.c` is *not* the HMAC implementation underneath `EVP_MAC`: that is a provider
 * (`providers/implementations/macs/hmac_prov.c`, Phase 13) which `EVP_MAC_fetch` reaches. What
 * this file transcribes is the pre-3.0 construction written directly over `EVP_MD_CTX`, and this
 * probe observes *that*: the twelve `HMAC_*` exports, against a digest the probe publishes its own
 * provider for.
 *
 * That is what makes the digest below necessary rather than convenient. `HMAC_Init_ex` takes an
 * `EVP_MD *`, not an `EVP_MAC *`, so the only way a probe can drive it is to have a digest to hand
 * it -- and a real one, because the court's whole method is a **known-answer vector**: the probe
 * implements SHA-256 itself, checks its own implementation against the RFC 4231 HMAC-SHA-256
 * vectors, and then compares the crate's answer against *that*. A stub digest that answered a
 * constant would make every arm agree and prove nothing.
 *
 * The arms
 * --------
 *   * `HMAC_Init_ex`'s two special cases, which are the whole contract: a **NULL `key` reuses the
 *     previous key** (`hmac.c:60`, the `if (key != NULL)` block is the only one that re-keys) and
 *     a **NULL `md` reuses `ctx->md`** (`:38`), while both NULL is `return 0` at `:43`. The
 *     "changing MD requires a key" refusal at `:35` needs a *second* digest, which is why the
 *     provider publishes two names.
 *   * `HMAC_size` **before and after** init. Before, `ctx->md` is NULL, `EVP_MD_get_size(NULL)`
 *     answers -1 with `EVP_R_MESSAGE_DIGEST_IS_NULL`, and the `size < 0` fold makes the answer 0.
 *   * `HMAC_CTX_copy` independence: the copy is advanced with one message and the original with
 *     another, and each is compared against the probe's own HMAC of *its* message, so a copy that
 *     shared state would be visible as a wrong digest rather than as a wrong pointer.
 *   * `HMAC_CTX_reset` then reuse.
 *   * `HMAC_CTX_set_flags`'s effect on the final: the public `EVP_MD_CTX_FLAG_FINALISE` has none on
 *     a *provider* final (`EVP_DigestFinal_ex` does not read it in that arm), and the flag that
 *     does is the internal `EVP_MD_CTX_FLAG_FINALISED` (`include/crypto/evp.h`, 0x0800): setting
 *     it makes `HMAC_Final`'s first `EVP_DigestFinal_ex` refuse. Both are driven, with the
 *     internal value spelled out and its header named.
 *   * the RFC 4231 vectors, including the 131-byte key that is longer than the digest's block and
 *     so takes `HMAC_Init_ex`'s key-hashing arm (`hmac.c:68`).
 *
 * Deliberately not observed
 * -------------------------
 *   * **`HMAC()`'s success arm.** Its whole body past the size check is
 *     `EVP_Q_mac(NULL, "HMAC", NULL, EVP_MD_get0_name(evp_md), ...)` (`crypto/hmac/hmac.c:260`),
 *     and `EVP_Q_mac` resolves `"HMAC"` in the **default** library context -- where the authority's
 *     own provider publishes a real HMAC that has no `COURT-SHA256` digest. Which of the two the
 *     store returns is not a fact this probe can pin on both sides, and the `EVP_Q_mac` path is
 *     `RT-EVP-MAC`'s subject. The refusal arm (`evp_md == NULL`, so `size > 0` is false) *is* driven
 *     and needs no provider at all.
 *   * **`HMAC_Init_ex`'s XOF refusal** (`hmac.c:49`, `EVP_MD_xof(md)`), which needs a
 *     `SHAKE`-like digest; the provider publishes none, because a digest whose `xof` flag is set
 *     is a different contract from the ones above and `RT-EVP-MD` owns that flag.
 *   * **`HMAC_CTX_reset(NULL)`**, which faults the authority (`hmac_ctx_cleanup` dereferences it).
 *
 * Every observation is a return code, a size, a pointer relation or the bytes of a digest the
 * probe computed itself. No address is printed.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Every export in `hmac.h` is `OSSL_DEPRECATEDIN_3_0` and is still the subject of this court; the
 * attribute is what is suppressed here, not the API, and the attribute is identical on both
 * lanes. */
#define OPENSSL_SUPPRESS_DEPRECATED

#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/params.h>
#include <openssl/provider.h>

static void sayn(const char *key, long long v)
{
    printf("%s=%lld err=%lu\n", key, v, ERR_peek_error());
    ERR_clear_error();
}

/* The error chain, drained and formatted. Nothing here is an address. */
static char *chain(char *buf, size_t n)
{
    unsigned long e;
    const char *file, *func, *data;
    int line, flags, first = 1;
    size_t at = 0;

    buf[0] = '\0';
    while ((e = ERR_get_error_all(&file, &line, &func, &data, &flags)) != 0) {
        const char *rsn = ERR_reason_error_string(e);
        int k = snprintf(buf + at, n - at, "%s%s@%s/%d", first ? "" : ",",
                         rsn == NULL ? "<no-string>" : rsn, func == NULL ? "<no-func>" : func, line);

        if (k < 0 || (size_t)k >= n - at)
            break;
        at += (size_t)k;
        first = 0;
    }
    if (first)
        snprintf(buf, n, "<empty>");
    ERR_clear_error();
    return buf;
}

/* -------------------------------------------------------------------------------------------- */
/* The probe's own SHA-256.                                                                      */
/* -------------------------------------------------------------------------------------------- */

struct sha256_ctx {
    unsigned int h[8];
    unsigned long long len;
    unsigned char buf[64];
    size_t buflen;
};

static const unsigned int K256[64] = {
    0x428a2f98u, 0x71374491u, 0xb5c0fbcfu, 0xe9b5dba5u, 0x3956c25bu, 0x59f111f1u, 0x923f82a4u,
    0xab1c5ed5u, 0xd807aa98u, 0x12835b01u, 0x243185beu, 0x550c7dc3u, 0x72be5d74u, 0x80deb1feu,
    0x9bdc06a7u, 0xc19bf174u, 0xe49b69c1u, 0xefbe4786u, 0x0fc19dc6u, 0x240ca1ccu, 0x2de92c6fu,
    0x4a7484aau, 0x5cb0a9dcu, 0x76f988dau, 0x983e5152u, 0xa831c66du, 0xb00327c8u, 0xbf597fc7u,
    0xc6e00bf3u, 0xd5a79147u, 0x06ca6351u, 0x14292967u, 0x27b70a85u, 0x2e1b2138u, 0x4d2c6dfcu,
    0x53380d13u, 0x650a7354u, 0x766a0abbu, 0x81c2c92eu, 0x92722c85u, 0xa2bfe8a1u, 0xa81a664bu,
    0xc24b8b70u, 0xc76c51a3u, 0xd192e819u, 0xd6990624u, 0xf40e3585u, 0x106aa070u, 0x19a4c116u,
    0x1e376c08u, 0x2748774cu, 0x34b0bcb5u, 0x391c0cb3u, 0x4ed8aa4au, 0x5b9cca4fu, 0x682e6ff3u,
    0x748f82eeu, 0x78a5636fu, 0x84c87814u, 0x8cc70208u, 0x90befffau, 0xa4506cebu, 0xbef9a3f7u,
    0xc67178f2u
};

#define ROTR32(x, n) (((x) >> (n)) | ((x) << (32 - (n))))

static void sha256_block(struct sha256_ctx *c, const unsigned char *p)
{
    unsigned int w[64];
    unsigned int a, b, cc, d, e, f, g, h;
    int i;

    for (i = 0; i < 16; i++)
        w[i] = ((unsigned int)p[i * 4] << 24) | ((unsigned int)p[i * 4 + 1] << 16)
               | ((unsigned int)p[i * 4 + 2] << 8) | (unsigned int)p[i * 4 + 3];
    for (i = 16; i < 64; i++) {
        unsigned int s0 = ROTR32(w[i - 15], 7) ^ ROTR32(w[i - 15], 18) ^ (w[i - 15] >> 3);
        unsigned int s1 = ROTR32(w[i - 2], 17) ^ ROTR32(w[i - 2], 19) ^ (w[i - 2] >> 10);

        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }
    a = c->h[0]; b = c->h[1]; cc = c->h[2]; d = c->h[3];
    e = c->h[4]; f = c->h[5]; g = c->h[6]; h = c->h[7];
    for (i = 0; i < 64; i++) {
        unsigned int S1 = ROTR32(e, 6) ^ ROTR32(e, 11) ^ ROTR32(e, 25);
        unsigned int ch = (e & f) ^ ((~e) & g);
        unsigned int t1 = h + S1 + ch + K256[i] + w[i];
        unsigned int S0 = ROTR32(a, 2) ^ ROTR32(a, 13) ^ ROTR32(a, 22);
        unsigned int maj = (a & b) ^ (a & cc) ^ (b & cc);
        unsigned int t2 = S0 + maj;

        h = g; g = f; f = e; e = d + t1;
        d = cc; cc = b; b = a; a = t1 + t2;
    }
    c->h[0] += a; c->h[1] += b; c->h[2] += cc; c->h[3] += d;
    c->h[4] += e; c->h[5] += f; c->h[6] += g; c->h[7] += h;
}

static void sha256_init(struct sha256_ctx *c)
{
    static const unsigned int iv[8] = {
        0x6a09e667u, 0xbb67ae85u, 0x3c6ef372u, 0xa54ff53au,
        0x510e527fu, 0x9b05688cu, 0x1f83d9abu, 0x5be0cd19u
    };

    memcpy(c->h, iv, sizeof iv);
    c->len = 0;
    c->buflen = 0;
}

static void sha256_update(struct sha256_ctx *c, const unsigned char *in, size_t inl)
{
    c->len += inl;
    while (inl > 0) {
        size_t take = 64 - c->buflen;

        if (take > inl)
            take = inl;
        memcpy(c->buf + c->buflen, in, take);
        c->buflen += take;
        in += take;
        inl -= take;
        if (c->buflen == 64) {
            sha256_block(c, c->buf);
            c->buflen = 0;
        }
    }
}

static void sha256_final(struct sha256_ctx *c, unsigned char out[32])
{
    unsigned long long bits = c->len * 8;
    unsigned char pad = 0x80;
    unsigned char zero = 0x00;
    unsigned char lenbe[8];
    int i;

    sha256_update(c, &pad, 1);
    while (c->buflen != 56)
        sha256_update(c, &zero, 1);
    for (i = 0; i < 8; i++)
        lenbe[i] = (unsigned char)(bits >> (56 - 8 * i));
    sha256_update(c, lenbe, 8);
    for (i = 0; i < 8; i++) {
        out[i * 4] = (unsigned char)(c->h[i] >> 24);
        out[i * 4 + 1] = (unsigned char)(c->h[i] >> 16);
        out[i * 4 + 2] = (unsigned char)(c->h[i] >> 8);
        out[i * 4 + 3] = (unsigned char)c->h[i];
    }
}

/* The probe's own HMAC-SHA-256, so every arm has an independent expectation. */
static void own_hmac(const unsigned char *key, size_t keylen,
                     const unsigned char *msg, size_t msglen,
                     unsigned char out[32])
{
    unsigned char k[64];
    unsigned char ipad[64];
    unsigned char opad[64];
    unsigned char inner[32];
    struct sha256_ctx c;
    size_t i;

    memset(k, 0, sizeof k);
    if (keylen > 64) {
        sha256_init(&c);
        sha256_update(&c, key, keylen);
        sha256_final(&c, k);
    } else if (keylen > 0) {
        memcpy(k, key, keylen);
    }
    for (i = 0; i < 64; i++) {
        ipad[i] = (unsigned char)(k[i] ^ 0x36);
        opad[i] = (unsigned char)(k[i] ^ 0x5c);
    }
    sha256_init(&c);
    sha256_update(&c, ipad, 64);
    sha256_update(&c, msg, msglen);
    sha256_final(&c, inner);
    sha256_init(&c);
    sha256_update(&c, opad, 64);
    sha256_update(&c, inner, 32);
    sha256_final(&c, out);
}

static int hexeq(const unsigned char *have, const char *hex)
{
    size_t i;

    for (i = 0; i < 32; i++) {
        unsigned int b;

        if (sscanf(hex + i * 2, "%2x", &b) != 1 || (unsigned char)b != have[i])
            return 0;
    }
    return 1;
}

/* -------------------------------------------------------------------------------------------- */
/* The probe's provider: two digests with the same SHA-256.                                      */
/* -------------------------------------------------------------------------------------------- */

static char ct_marker;

static void *ct_md_newctx(void *provctx)
{
    (void)provctx;
    return calloc(1, sizeof(struct sha256_ctx));
}

static void ct_md_freectx(void *vctx)
{
    free(vctx);
}

static void *ct_md_dupctx(void *vctx)
{
    struct sha256_ctx *src = vctx;
    struct sha256_ctx *dst = calloc(1, sizeof *dst);

    if (dst == NULL || src == NULL) {
        free(dst);
        return NULL;
    }
    memcpy(dst, src, sizeof *dst);
    return dst;
}

static int ct_md_init(void *vctx)
{
    if (vctx == NULL)
        return 0;
    sha256_init(vctx);
    return 1;
}

static int ct_md_update(void *vctx, const unsigned char *in, size_t inl)
{
    if (vctx == NULL || (in == NULL && inl != 0))
        return 0;
    sha256_update(vctx, in, inl);
    return 1;
}

static int ct_md_final(void *vctx, unsigned char *out, size_t *outl, size_t outsz)
{
    if (vctx == NULL || outl == NULL)
        return 0;
    if (out == NULL) {
        *outl = 32;
        return 1;
    }
    if (outsz < 32)
        return 0;
    sha256_final(vctx, out);
    *outl = 32;
    return 1;
}

static int ct_md_get_params(OSSL_PARAM params[])
{
    OSSL_PARAM *p;

    p = OSSL_PARAM_locate(params, OSSL_DIGEST_PARAM_BLOCK_SIZE);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, 64))
        return 0;
    p = OSSL_PARAM_locate(params, OSSL_DIGEST_PARAM_SIZE);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, 32))
        return 0;
    return 1;
}

static const OSSL_PARAM *ct_md_gettable_params(void *provctx)
{
    static const OSSL_PARAM table[] = {
        OSSL_PARAM_size_t(OSSL_DIGEST_PARAM_BLOCK_SIZE, NULL),
        OSSL_PARAM_size_t(OSSL_DIGEST_PARAM_SIZE, NULL),
        OSSL_PARAM_END
    };

    (void)provctx;
    return table;
}

static const OSSL_DISPATCH ct_md_fns[] = {
    { OSSL_FUNC_DIGEST_NEWCTX, (void (*)(void))ct_md_newctx },
    { OSSL_FUNC_DIGEST_FREECTX, (void (*)(void))ct_md_freectx },
    { OSSL_FUNC_DIGEST_DUPCTX, (void (*)(void))ct_md_dupctx },
    { OSSL_FUNC_DIGEST_INIT, (void (*)(void))ct_md_init },
    { OSSL_FUNC_DIGEST_UPDATE, (void (*)(void))ct_md_update },
    { OSSL_FUNC_DIGEST_FINAL, (void (*)(void))ct_md_final },
    { OSSL_FUNC_DIGEST_GET_PARAMS, (void (*)(void))ct_md_get_params },
    { OSSL_FUNC_DIGEST_GETTABLE_PARAMS, (void (*)(void))ct_md_gettable_params },
    { 0, NULL }
};

static const OSSL_ALGORITHM ct_digests[] = {
    { "COURT-SHA256", "provider=court-hmac", ct_md_fns, "the probe's own SHA-256" },
    { "COURT-SHA256B", "provider=court-hmac", ct_md_fns, "a second name, same method" },
    { NULL, NULL, NULL, NULL }
};

static const OSSL_ALGORITHM *ct_query(void *provctx, int operation_id, int *no_cache)
{
    (void)provctx;
    *no_cache = 0;
    if (operation_id == OSSL_OP_DIGEST)
        return ct_digests;
    return NULL;
}

static const OSSL_DISPATCH ct_provider_fns[] = {
    { OSSL_FUNC_PROVIDER_QUERY_OPERATION, (void (*)(void))ct_query },
    { 0, NULL }
};

static int ct_provider_init(const OSSL_CORE_HANDLE *handle, const OSSL_DISPATCH *in,
                            const OSSL_DISPATCH **out, void **provctx)
{
    (void)handle;
    (void)in;
    *out = ct_provider_fns;
    *provctx = &ct_marker;
    return 1;
}

/* -------------------------------------------------------------------------------------------- */
/* The arms.                                                                                     */
/* -------------------------------------------------------------------------------------------- */

/* RFC 4231's HMAC-SHA-256 vectors, checked against the probe's own implementation first so that
 * the vector's authority is the RFC and not the implementation under test. */
static const struct {
    const char *name;
    unsigned char fill;
    size_t keylen;
    const char *msg;
    const char *hex;
} KAT[] = {
    { "tc1", 0x0b, 20, "Hi There",
      "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7" },
    { "tc2", 0x00, 4, "what do ya want for nothing?",
      "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843" },
    { "tc5", 0x0c, 20, "Test With Truncation",
      "a3b6167473100ee06e0c796c2955552bfa6f7c0a6a8aef8b93f860aab0cd20c5" },
    { "tc6", 0xaa, 131, "Test Using Larger Than Block-Size Key - Hash Key First",
      "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54" },
};

static void known_answers(EVP_MD *md)
{
    unsigned char key[131];
    size_t i;

    for (i = 0; i < sizeof KAT / sizeof KAT[0]; i++) {
        unsigned char own[32];
        HMAC_CTX *ctx = HMAC_CTX_new();
        unsigned char got[EVP_MAX_MD_SIZE];
        unsigned int gotlen = 0;
        int init, upd, fin;

        memset(key, 0, sizeof key);
        if (i == 1)
            memcpy(key, "Jefe", 4);   /* RFC 4231's Test Case 2 key is the literal "Jefe". */
        else
            memset(key, KAT[i].fill, KAT[i].keylen);
        memset(own, 0, sizeof own);
        own_hmac(key, KAT[i].keylen, (const unsigned char *)KAT[i].msg, strlen(KAT[i].msg), own);
        printf("kat.%s.self=%d", KAT[i].name, hexeq(own, KAT[i].hex));
        init = HMAC_Init_ex(ctx, key, (int)KAT[i].keylen, md, NULL);
        upd = HMAC_Update(ctx, (const unsigned char *)KAT[i].msg, strlen(KAT[i].msg));
        fin = HMAC_Final(ctx, got, &gotlen);
        printf(" rv=%d%d%d len=%u vec=%d own=%d\n", init, upd, fin, gotlen,
               hexeq(got, KAT[i].hex), (int)(gotlen == 32 && memcmp(got, own, 32) == 0));
        HMAC_CTX_free(ctx);
    }
}

static void init_special_cases(EVP_MD *md, EVP_MD *md2)
{
    static const unsigned char k1[20] = { 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
                                          0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
                                          0x0b, 0x0b };
    static const char *m1 = "Hi There";
    static const char *m2 = "what do ya want for nothing?";
    static const unsigned char k2[4] = { 'J', 'e', 'f', 'e' };
    char errbuf[512];
    HMAC_CTX *ctx = HMAC_CTX_new();
    unsigned char a[EVP_MAX_MD_SIZE], b[EVP_MAX_MD_SIZE];
    unsigned int alen = 0, blen = 0;
    int rv;

    /* A fresh context answers 0 for `_size` and NULL for `_get_md`, and refuses both operations. */
    printf("fresh.size=%zu md_null=%d upd=%d fin=%d err=%s\n", HMAC_size(ctx),
           (int)(HMAC_CTX_get_md(ctx) == NULL), HMAC_Update(ctx, (const unsigned char *)"x", 1),
           HMAC_Final(ctx, a, &alen), chain(errbuf, sizeof errbuf));

    /* Both NULL: `md == NULL && ctx->md == NULL` is `return 0` at hmac.c:43. */
    rv = HMAC_Init_ex(ctx, k1, sizeof k1, NULL, NULL);
    sayn("both_null", rv);

    /* Set the key and method once, then reuse the key with a NULL `key`. */
    rv = HMAC_Init_ex(ctx, k1, sizeof k1, md, NULL);
    sayn("reuse_key.init", rv);
    printf("reuse_key.size=%zu md_is_md=%d\n", HMAC_size(ctx), (int)(HMAC_CTX_get_md(ctx) == md));
    HMAC_Update(ctx, (const unsigned char *)m1, strlen(m1));
    HMAC_Final(ctx, a, &alen);
    /* A NULL key, with `md` NULL too, re-arms from the remembered ipad state and re-keys nothing. */
    rv = HMAC_Init_ex(ctx, NULL, 0, NULL, NULL);
    sayn("reuse_key.reinit", rv);
    HMAC_Update(ctx, (const unsigned char *)m1, strlen(m1));
    HMAC_Final(ctx, b, &blen);
    printf("reuse_key.same=%d len=%u err=%s\n",
           (int)(alen == blen && alen == 32 && memcmp(a, b, alen) == 0), blen,
           chain(errbuf, sizeof errbuf));

    /* A new key with `md == NULL` reuses `ctx->md` and re-keys. */
    rv = HMAC_Init_ex(ctx, k2, sizeof k2, NULL, NULL);
    sayn("reuse_md.init", rv);
    printf("reuse_md.md_is_md=%d\n", (int)(HMAC_CTX_get_md(ctx) == md));
    HMAC_Update(ctx, (const unsigned char *)m2, strlen(m2));
    HMAC_Final(ctx, b, &blen);
    {
        unsigned char own[32];

        own_hmac(k2, sizeof k2, (const unsigned char *)m2, strlen(m2), own);
        printf("reuse_md.own=%d len=%u err=%s\n",
               (int)(blen == 32 && memcmp(b, own, 32) == 0), blen, chain(errbuf, sizeof errbuf));
    }

    /* Changing the method with a NULL key is the refusal at hmac.c:35. */
    rv = HMAC_Init_ex(ctx, k1, sizeof k1, md, NULL);
    sayn("changing_md.setup", rv);
    rv = HMAC_Init_ex(ctx, NULL, 0, md2, NULL);
    sayn("changing_md.nullkey", rv);
    printf("changing_md.md_unchanged=%d err=%s\n", (int)(HMAC_CTX_get_md(ctx) == md),
           chain(errbuf, sizeof errbuf));

    /* The legacy `HMAC_Init` spelling resets first when both `key` and `md` are non-NULL. */
    rv = HMAC_Init(ctx, k2, sizeof k2, md);
    sayn("hmac_init.spelling", rv);
    HMAC_Update(ctx, (const unsigned char *)m2, strlen(m2));
    HMAC_Final(ctx, b, &blen);
    {
        unsigned char own[32];

        own_hmac(k2, sizeof k2, (const unsigned char *)m2, strlen(m2), own);
        printf("hmac_init.own=%d len=%u err=%s\n",
               (int)(blen == 32 && memcmp(b, own, 32) == 0), blen, chain(errbuf, sizeof errbuf));
    }

    HMAC_CTX_free(ctx);
}

/* Small helper that recomputes the digest for a single-message arm without repeating the buffer
 * juggling. Declared here because `copy_and_reset` uses it. */
static int HH_own(const unsigned char *key, size_t keylen, const char *msg,
                  const unsigned char *have)
{
    unsigned char own[32];

    own_hmac(key, keylen, (const unsigned char *)msg, strlen(msg), own);
    return memcmp(own, have, 32) == 0;
}

static void copy_and_reset(EVP_MD *md)
{
    static const unsigned char key[20] = { 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
                                           0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
                                           0xaa, 0xaa };
    static const char *prefix = "shared prefix ";
    static const char *ma = "message A";
    static const char *mb = "message B";
    char errbuf[512];
    HMAC_CTX *src = HMAC_CTX_new();
    HMAC_CTX *cp = HMAC_CTX_new();
    unsigned char da[EVP_MAX_MD_SIZE], db[EVP_MAX_MD_SIZE];
    unsigned int la = 0, lb = 0;
    int rv;

    rv = HMAC_Init_ex(src, key, sizeof key, md, NULL);
    HMAC_Update(src, (const unsigned char *)prefix, strlen(prefix));
    sayn("copy.src_init", rv);
    rv = HMAC_CTX_copy(cp, src);
    sayn("copy.rv", rv);
    /* The copy takes A, the original B; each is compared against the probe's own HMAC of its own
     * message, so a shared context would show as a wrong digest. */
    HMAC_Update(cp, (const unsigned char *)ma, strlen(ma));
    HMAC_Final(cp, da, &la);
    HMAC_Update(src, (const unsigned char *)mb, strlen(mb));
    HMAC_Final(src, db, &lb);
    {
        unsigned char owna[32], ownb[32], cat[128];

        snprintf((char *)cat, sizeof cat, "%s%s", prefix, ma);
        own_hmac(key, sizeof key, cat, strlen((char *)cat), owna);
        snprintf((char *)cat, sizeof cat, "%s%s", prefix, mb);
        own_hmac(key, sizeof key, cat, strlen((char *)cat), ownb);
        printf("copy.independent=%d own_a=%d own_b=%d la=%u lb=%u err=%s\n",
               (int)(la == 32 && lb == 32 && memcmp(da, db, 32) != 0),
               (int)(la == 32 && memcmp(da, owna, 32) == 0),
               (int)(lb == 32 && memcmp(db, ownb, 32) == 0), la, lb, chain(errbuf, sizeof errbuf));
    }

    /* A reset returns the context to the fresh state and it is reusable. */
    rv = HMAC_CTX_reset(src);
    sayn("reset.rv", rv);
    printf("reset.size=%zu md_null=%d\n", HMAC_size(src), (int)(HMAC_CTX_get_md(src) == NULL));
    rv = HMAC_Init_ex(src, key, sizeof key, md, NULL);
    HMAC_Update(src, (const unsigned char *)ma, strlen(ma));
    HMAC_Final(src, da, &la);
    printf("reset.reused=%d len=%u err=%s\n",
           (int)(la == 32 && HH_own(key, sizeof key, ma, da)), la,
           chain(errbuf, sizeof errbuf));

    HMAC_CTX_free(cp);
    HMAC_CTX_free(src);
}

static void flag_effect(EVP_MD *md)
{
    static const unsigned char key[20] = { 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
                                           0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
                                           0x0b, 0x0b };
    char errbuf[512];
    HMAC_CTX *ctx;
    unsigned char got[EVP_MAX_MD_SIZE];
    unsigned int gotlen = 0;
    int rv;

    /* Zero: no effect, the final succeeds. */
    ctx = HMAC_CTX_new();
    HMAC_Init_ex(ctx, key, sizeof key, md, NULL);
    HMAC_CTX_set_flags(ctx, 0);
    HMAC_Update(ctx, (const unsigned char *)"Hi There", 8);
    rv = HMAC_Final(ctx, got, &gotlen);
    printf("flags.zero.final=%d len=%u err=%s\n", rv, gotlen, chain(errbuf, sizeof errbuf));
    HMAC_CTX_free(ctx);

    /* `EVP_MD_CTX_FLAG_FINALISE` (0x0200, include/openssl/evp.h): no effect on a *provider* final. */
    ctx = HMAC_CTX_new();
    HMAC_Init_ex(ctx, key, sizeof key, md, NULL);
    HMAC_CTX_set_flags(ctx, EVP_MD_CTX_FLAG_FINALISE);
    HMAC_Update(ctx, (const unsigned char *)"Hi There", 8);
    rv = HMAC_Final(ctx, got, &gotlen);
    printf("flags.finalise.final=%d len=%u err=%s\n", rv, gotlen, chain(errbuf, sizeof errbuf));
    HMAC_CTX_free(ctx);

    /* `EVP_MD_CTX_FLAG_FINALISED` (0x0800, include/crypto/evp.h, uninstalled): `HMAC_Final`'s first
     * `EVP_DigestFinal_ex` sees the bit and refuses. The value is spelled out because the header is
     * internal; the observation is exactly that bit's effect. */
    ctx = HMAC_CTX_new();
    HMAC_Init_ex(ctx, key, sizeof key, md, NULL);
    HMAC_CTX_set_flags(ctx, 0x0800UL);
    HMAC_Update(ctx, (const unsigned char *)"Hi There", 8);
    rv = HMAC_Final(ctx, got, &gotlen);
    printf("flags.finalised.final=%d len=%u err=%s\n", rv, gotlen, chain(errbuf, sizeof errbuf));
    HMAC_CTX_free(ctx);
}

static void one_shot_refusal(void)
{
    char errbuf[512];
    unsigned char out[64];
    unsigned int outlen = 0;

    /* `evp_md == NULL` makes `size > 0` false, so `EVP_Q_mac` is never reached and the answer is
     * NULL with `EVP_MD_get_size`'s own reason on the queue. */
    printf("oneshot.null_md=%d outlen=%u err=%s\n",
           (int)(HMAC(NULL, (const unsigned char *)"k", 1, (const unsigned char *)"m", 1, out,
                      &outlen) == NULL),
           outlen, chain(errbuf, sizeof errbuf));
}

int main(void)
{
    OSSL_LIB_CTX *libctx = OSSL_LIB_CTX_new();
    OSSL_PROVIDER *prov = NULL;
    EVP_MD *md = NULL, *md2 = NULL;

    setvbuf(stdout, NULL, _IOLBF, 0);

    if (OSSL_PROVIDER_add_builtin(libctx, "court-hmac", ct_provider_init))
        prov = OSSL_PROVIDER_load(libctx, "court-hmac");
    sayn("provider.loaded", prov != NULL);
    if (prov != NULL)
        md = EVP_MD_fetch(libctx, "COURT-SHA256", NULL);
    if (prov != NULL)
        md2 = EVP_MD_fetch(libctx, "COURT-SHA256B", NULL);
    sayn("md.fetched", md != NULL && md2 != NULL);

    if (md != NULL && md2 != NULL) {
        known_answers(md);
        init_special_cases(md, md2);
        copy_and_reset(md);
        flag_effect(md);
        one_shot_refusal();
    }

    /* `HMAC()`'s success arm and the XOF refusal are named in the header comment. */
    printf("HMAC=NOT_MEASURED_DEFAULT_LIBCTX_HMAC_FETCH_hmac_c_260\n");
    printf("HMAC_Init_ex=NOT_MEASURED_XOF_REFUSAL_hmac_c_49\n");

    EVP_MD_free(md2);
    EVP_MD_free(md);
    if (prov != NULL)
        OSSL_PROVIDER_unload(prov);
    OSSL_LIB_CTX_free(libctx);
    return 0;
}
