/*
 * openssl-rs — the differential digest probe (RT-DIGEST).
 *
 * This program is compiled **twice**, once against the admitted authority and once against
 * the candidate distribution shell, and the two `key=value` transcripts are diffed. It never
 * decides anything: a residual is a difference between two executions, so the expectation
 * cannot drift with the crate. `forensics/tools/phase8_courts.py` owns the comparison.
 *
 * What this probe establishes
 * ---------------------------
 * **It is the evidence that the crate's portable C arm agrees with the authority's perlasm
 * fast path.** The authority's build has `asm` enabled and `perlasm_scheme => "elf"`, so
 * `sha1_block_data_order` and its siblings are chosen at run time by `OPENSSL_ia32cap`; the
 * crate has no assembly and computes the same function in portable C. A published test vector
 * proves a construction is *some* correct implementation; only a differential court proves it
 * is *this* implementation's observable behaviour, which is why every message below that is
 * long enough to run the multi-block path is the point of the court rather than filler.
 *
 * What it observes, per construction
 * ----------------------------------
 *   * the block size and the digest size, as the headers declare them;
 *   * the digest, printed as hex, for: the empty message, `abc`, the 55/56/64-byte padding
 *     boundaries, a two-call `Update` split, a 1000-byte message (the multi-block path), and
 *     `Transform` on a buffer that is one block plus five bytes (a non-multiple-of-block call,
 *     which advances the state without touching `num`);
 *   * a bounded `memcmp` of the one-call and split transcripts, so the collector's partial
 *     block is compared as bytes and never reported as a pointer.
 *
 * The provider-mediated path
 * --------------------------
 * After the low-level loop this probe also drives the *provider* path, which is the half 8.1b
 * lands: `OSSL_PROVIDER_load(NULL, "default")` and `OSSL_PROVIDER_available`, then
 * `EVP_MD_fetch(NULL, "SHA256", NULL)` and `EVP_DigestInit_ex`/`EVP_DigestUpdate`/
 * `EVP_DigestFinal_ex` through the fetched method. Those are the observations that D117's
 * residual is about — before 8.1b the candidate's fallback walk failed at `DSO_load`, so the
 * load and the fetch both answered 0 while the authority answered 1. The digest bytes are the
 * point: a fetch that resolves to a method whose callbacks are wrong is worse than no fetch.
 * The table's edge is observed too: the rows `defltprov.c` carries resolve, and `MD4` and
 * `WHIRLPOOL`, which are `legacyprov.c`'s rows and which no loaded provider answers, do not.
 *
 * Since 8.1c every row `defltprov.c`'s `deflt_digests[]` publishes is fetched **by its primary
 * name** and run, so a row present in the table but not fetchable or runnable is a residual rather
 * than an assumption. The fixed-width SHA-2 alternates, SHA-3, Keccak, BLAKE2, SM3, `MD5-SHA1`
 * and `NULL` are provider-only constructions (no exported low-level entry point), so the fetch
 * *is* the surface. `NULL`'s answers are observed rather than assumed: size 0, block size 0, and
 * a `Final` that succeeds with `*outl == 0` and writes nothing. `MD5-SHA1`'s
 * `OSSL_DIGEST_PARAM_SSL3_MS` arm is driven through the fetched method's `set_ctx_params`, since
 * that switch is the only interesting thing about the construction. The XOF rows are driven
 * through `EVP_MD_xof` and a two-slice `EVP_DigestSqueeze`.
 *
 * The five exported `sha.h` one-shots are observed directly, once with the caller's buffer and
 * once with `md == NULL` (the file's shared `static` buffer). See `rt_one_shot_exports`.
 *
 * No address is ever printed, stdout is line-buffered, and no NULL-dereferencing entry point
 * is called — a probe that aborts the harness compares nothing.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/md4.h>
#include <openssl/md5.h>
#include <openssl/mdc2.h>
#include <openssl/ripemd.h>
#include <openssl/sha.h>
#include <openssl/whrlpool.h>
#include <openssl/evp.h>
#include <openssl/provider.h>
#include <openssl/params.h>
#include <openssl/core_names.h>
#include <openssl/core_dispatch.h>
#include <openssl/err.h>

#define RT_MSG_MAX 2048u

typedef int (*rt_init_fn)(void *ctx);
typedef int (*rt_update_fn)(void *ctx, const void *data, size_t len);
typedef int (*rt_final_fn)(void *out, void *ctx);
typedef void (*rt_transform_fn)(void *ctx, const unsigned char *block);

union rt_ctx {
    MD4_CTX md4;
    MD5_CTX md5;
    RIPEMD160_CTX rmd;
    SHA_CTX sha1;
    SHA256_CTX sha256;
    SHA512_CTX sha512;
    WHIRLPOOL_CTX wp;
    MDC2_CTX mdc2;
};

struct rt_algo {
    const char *name;
    size_t blocksize;
    size_t outsize;
    int has_transform;
    rt_init_fn init;
    rt_update_fn update;
    rt_final_fn final;
    rt_transform_fn transform;
};

static int rt_w_md4_init(void *c) { return MD4_Init((MD4_CTX *)c); }
static int rt_w_md4_update(void *c, const void *d, size_t n)
{
    return MD4_Update((MD4_CTX *)c, d, n);
}
static int rt_w_md4_final(void *o, void *c) { return MD4_Final((unsigned char *)o, (MD4_CTX *)c); }
static void rt_w_md4_transform(void *c, const unsigned char *b) { MD4_Transform((MD4_CTX *)c, b); }

static int rt_w_md5_init(void *c) { return MD5_Init((MD5_CTX *)c); }
static int rt_w_md5_update(void *c, const void *d, size_t n)
{
    return MD5_Update((MD5_CTX *)c, d, n);
}
static int rt_w_md5_final(void *o, void *c) { return MD5_Final((unsigned char *)o, (MD5_CTX *)c); }
static void rt_w_md5_transform(void *c, const unsigned char *b) { MD5_Transform((MD5_CTX *)c, b); }

static int rt_w_rmd_init(void *c) { return RIPEMD160_Init((RIPEMD160_CTX *)c); }
static int rt_w_rmd_update(void *c, const void *d, size_t n)
{
    return RIPEMD160_Update((RIPEMD160_CTX *)c, d, n);
}
static int rt_w_rmd_final(void *o, void *c)
{
    return RIPEMD160_Final((unsigned char *)o, (RIPEMD160_CTX *)c);
}
static void rt_w_rmd_transform(void *c, const unsigned char *b)
{
    RIPEMD160_Transform((RIPEMD160_CTX *)c, b);
}

static int rt_w_sha1_init(void *c) { return SHA1_Init((SHA_CTX *)c); }
static int rt_w_sha1_update(void *c, const void *d, size_t n)
{
    return SHA1_Update((SHA_CTX *)c, d, n);
}
static int rt_w_sha1_final(void *o, void *c) { return SHA1_Final((unsigned char *)o, (SHA_CTX *)c); }
static void rt_w_sha1_transform(void *c, const unsigned char *b) { SHA1_Transform((SHA_CTX *)c, b); }

static int rt_w_sha224_init(void *c) { return SHA224_Init((SHA256_CTX *)c); }
static int rt_w_sha224_update(void *c, const void *d, size_t n)
{
    return SHA224_Update((SHA256_CTX *)c, d, n);
}
static int rt_w_sha224_final(void *o, void *c)
{
    return SHA224_Final((unsigned char *)o, (SHA256_CTX *)c);
}
static void rt_w_sha224_transform(void *c, const unsigned char *b)
{
    SHA256_Transform((SHA256_CTX *)c, b);
}

static int rt_w_sha256_init(void *c) { return SHA256_Init((SHA256_CTX *)c); }
static int rt_w_sha256_update(void *c, const void *d, size_t n)
{
    return SHA256_Update((SHA256_CTX *)c, d, n);
}
static int rt_w_sha256_final(void *o, void *c)
{
    return SHA256_Final((unsigned char *)o, (SHA256_CTX *)c);
}
static void rt_w_sha256_transform(void *c, const unsigned char *b)
{
    SHA256_Transform((SHA256_CTX *)c, b);
}

static int rt_w_sha384_init(void *c) { return SHA384_Init((SHA512_CTX *)c); }
static int rt_w_sha384_update(void *c, const void *d, size_t n)
{
    return SHA384_Update((SHA512_CTX *)c, d, n);
}
static int rt_w_sha384_final(void *o, void *c)
{
    return SHA384_Final((unsigned char *)o, (SHA512_CTX *)c);
}
static void rt_w_sha384_transform(void *c, const unsigned char *b)
{
    SHA512_Transform((SHA512_CTX *)c, b);
}

static int rt_w_sha512_init(void *c) { return SHA512_Init((SHA512_CTX *)c); }
static int rt_w_sha512_update(void *c, const void *d, size_t n)
{
    return SHA512_Update((SHA512_CTX *)c, d, n);
}
static int rt_w_sha512_final(void *o, void *c)
{
    return SHA512_Final((unsigned char *)o, (SHA512_CTX *)c);
}
static void rt_w_sha512_transform(void *c, const unsigned char *b)
{
    SHA512_Transform((SHA512_CTX *)c, b);
}

static int rt_w_wp_init(void *c) { return WHIRLPOOL_Init((WHIRLPOOL_CTX *)c); }
static int rt_w_wp_update(void *c, const void *d, size_t n)
{
    return WHIRLPOOL_Update((WHIRLPOOL_CTX *)c, d, n);
}
static int rt_w_wp_final(void *o, void *c)
{
    return WHIRLPOOL_Final((unsigned char *)o, (WHIRLPOOL_CTX *)c);
}

static int rt_w_mdc2_init(void *c) { return MDC2_Init((MDC2_CTX *)c); }
static int rt_w_mdc2_update(void *c, const void *d, size_t n)
{
    return MDC2_Update((MDC2_CTX *)c, d, n);
}
static int rt_w_mdc2_final(void *o, void *c) { return MDC2_Final((unsigned char *)o, (MDC2_CTX *)c); }

static const struct rt_algo RT_ALGORITHMS[] = {
    {"md4", MD4_CBLOCK, MD4_DIGEST_LENGTH, 1, rt_w_md4_init, rt_w_md4_update, rt_w_md4_final,
     rt_w_md4_transform},
    {"md5", MD5_CBLOCK, MD5_DIGEST_LENGTH, 1, rt_w_md5_init, rt_w_md5_update, rt_w_md5_final,
     rt_w_md5_transform},
    {"ripemd160", RIPEMD160_CBLOCK, RIPEMD160_DIGEST_LENGTH, 1, rt_w_rmd_init, rt_w_rmd_update,
     rt_w_rmd_final, rt_w_rmd_transform},
    {"sha1", SHA_CBLOCK, SHA_DIGEST_LENGTH, 1, rt_w_sha1_init, rt_w_sha1_update, rt_w_sha1_final,
     rt_w_sha1_transform},
    {"sha224", SHA256_CBLOCK, SHA224_DIGEST_LENGTH, 1, rt_w_sha224_init, rt_w_sha224_update,
     rt_w_sha224_final, rt_w_sha224_transform},
    {"sha256", SHA256_CBLOCK, SHA256_DIGEST_LENGTH, 1, rt_w_sha256_init, rt_w_sha256_update,
     rt_w_sha256_final, rt_w_sha256_transform},
    {"sha384", SHA512_CBLOCK, SHA384_DIGEST_LENGTH, 1, rt_w_sha384_init, rt_w_sha384_update,
     rt_w_sha384_final, rt_w_sha384_transform},
    {"sha512", SHA512_CBLOCK, SHA512_DIGEST_LENGTH, 1, rt_w_sha512_init, rt_w_sha512_update,
     rt_w_sha512_final, rt_w_sha512_transform},
    {"whirlpool", WHIRLPOOL_BBLOCK / 8, WHIRLPOOL_DIGEST_LENGTH, 0, rt_w_wp_init, rt_w_wp_update,
     rt_w_wp_final, NULL},
    {"mdc2", MDC2_BLOCK, MDC2_DIGEST_LENGTH, 0, rt_w_mdc2_init, rt_w_mdc2_update,
     rt_w_mdc2_final, NULL},
};

/* The message is the probe's own; every observation below is derived from it, so the two
 * transcripts can only differ where the two libraries differ. */
static unsigned char rt_msg[RT_MSG_MAX];

static void rt_fill_msg(void)
{
    size_t i;

    for (i = 0; i < sizeof(rt_msg); i++)
        rt_msg[i] = (unsigned char)((i * 31u + 7u) & 0xffu);
}

static int rt_one_shot(const struct rt_algo *a, const unsigned char *d, size_t n,
                       unsigned char *out)
{
    union rt_ctx ctx;

    if (!a->init(&ctx))
        return 0;
    if (n != 0 && !a->update(&ctx, d, n))
        return 0;
    if (!a->final(out, &ctx))
        return 0;
    return 1;
}

static int rt_split(const struct rt_algo *a, const unsigned char *d, size_t n,
                    unsigned char *out)
{
    union rt_ctx ctx;
    size_t at = n / 2;

    if (!a->init(&ctx))
        return 0;
    if (!a->update(&ctx, d, at))
        return 0;
    if (!a->update(&ctx, d + at, n - at))
        return 0;
    if (!a->final(out, &ctx))
        return 0;
    return 1;
}

static int rt_transformed(const struct rt_algo *a, unsigned char *out)
{
    union rt_ctx ctx;

    if (!a->has_transform)
        return 0;
    if (!a->init(&ctx))
        return 0;
    /* One block is compressed straight through: `num` is not touched, so the five bytes that
     * follow are the whole staged remainder. The readable region is one block plus five, which
     * is not a multiple of the block size. */
    a->transform(&ctx, rt_msg);
    if (!a->update(&ctx, rt_msg + a->blocksize, 5))
        return 0;
    if (!a->final(out, &ctx))
        return 0;
    return 1;
}

static void rt_print_hex(const unsigned char *bytes, size_t n)
{
    size_t i;

    for (i = 0; i < n; i++)
        printf("%02x", bytes[i]);
}

static void rt_observation(const struct rt_algo *a, const char *label,
                           const unsigned char *out)
{
    printf("%s.digest.%s=", a->name, label);
    rt_print_hex(out, a->outsize);
    printf("\n");
}

static void rt_run(const struct rt_algo *a)
{
    unsigned char out[64];
    unsigned char split[64];
    static const unsigned char abc[3] = {'a', 'b', 'c'};

    printf("%s.blocksize=%zu\n", a->name, a->blocksize);
    printf("%s.outsize=%zu\n", a->name, a->outsize);

    memset(out, 0, sizeof(out));
    if (rt_one_shot(a, rt_msg, 0, out))
        rt_observation(a, "empty", out);
    else
        printf("%s.digest.empty=error\n", a->name);

    if (rt_one_shot(a, abc, sizeof(abc), out))
        rt_observation(a, "abc", out);
    else
        printf("%s.digest.abc=error\n", a->name);

    /* 55 and 56 straddle the point at which the 64-byte collector needs a second block;
     * 64 is a whole block. All three are run for every construction, including the 128-byte
     * block sizes, where they exercise the partial-block buffer instead. */
    if (rt_one_shot(a, rt_msg, 55, out))
        rt_observation(a, "len55", out);
    if (rt_one_shot(a, rt_msg, 56, out))
        rt_observation(a, "len56", out);
    if (rt_one_shot(a, rt_msg, 64, out))
        rt_observation(a, "len64", out);

    /* 1000 bytes is more than seven 128-byte blocks and more than fifteen 64-byte ones, so the
     * multi-block arm runs — and that arm is the authority's perlasm on its side. */
    if (rt_one_shot(a, rt_msg, 1000, out))
        rt_observation(a, "long", out);
    else
        printf("%s.digest.long=error\n", a->name);

    if (rt_split(a, rt_msg, 1000, split))
        rt_observation(a, "split", split);
    else
        printf("%s.digest.split=error\n", a->name);

    /* A bounded byte comparison of the probe's own two transcripts: never a pointer. */
    printf("%s.split_matches=%s\n", a->name,
           memcmp(out, split, a->outsize) == 0 ? "same" : "differ");

    memset(out, 0, sizeof(out));
    if (rt_transformed(a, out))
        rt_observation(a, "transform_then_update", out);
    else if (a->has_transform)
        printf("%s.digest.transform_then_update=error\n", a->name);
}

/* Fetch `name` through the default library context and, if it resolves, run `abc` through the
 * fetched method. The presence and the digest are both observed: the first pins which rows the
 * default provider publishes, and the second pins that the name resolved to the right
 * construction. `label` is a key-safe spelling of the algorithm. */
static void rt_provider_digest(const char *name, const char *label)
{
    EVP_MD *md = EVP_MD_fetch(NULL, name, NULL);
    unsigned char out[64];
    unsigned int outl = 0;
    EVP_MD_CTX *ctx;

    printf("provider.fetch.%s=%s\n", label, md != NULL ? "yes" : "no");
    if (md == NULL) {
        printf("provider.%s.abc=no-fetch\n", label);
        return;
    }
    printf("provider.%s.size=%d\n", label, EVP_MD_get_size(md));
    printf("provider.%s.blocksize=%d\n", label, EVP_MD_get_block_size(md));
    /*
     * The published parameter list, in full: key, type and size, in order. Only the
     * provider-level list is reachable here -- a digest has no `EVP_MD_gettable_ctx_params` -- and
     * the size is printed because `OSSL_PARAM_size_t` and `OSSL_PARAM_uint` share the
     * `UNSIGNED_INTEGER` type and differ only in it. `BLAKE2S-256` and `BLAKE2B-512` genuinely
     * declare their `size` with the *uint* macro, so the two digests that look like the others are
     * exactly the ones a keys-only comparison would miss (D253).
     */
    {
        const OSSL_PARAM *p = EVP_MD_gettable_params(md);
        size_t n = 0;

        printf("provider.%s.gp.present=%d\n", label, p != NULL);
        for (; p != NULL && p->key != NULL; p++, n++)
            printf("provider.%s.gp.%zu=%s:%u:%zu\n", label, n, p->key, p->data_type,
                   p->data_size);
        printf("provider.%s.gp.count=%zu\n", label, n);
    }
    ctx = EVP_MD_CTX_new();
    memset(out, 0, sizeof(out));
    if (EVP_DigestInit_ex(ctx, md, NULL) == 1
        && EVP_DigestUpdate(ctx, "abc", 3) == 1
        && EVP_DigestFinal_ex(ctx, out, &outl) == 1) {
        printf("provider.%s.abc=", label);
        rt_print_hex(out, outl);
        printf("\n");
        printf("provider.%s.outl=%u\n", label, outl);
    } else {
        printf("provider.%s.abc=error\n", label);
    }
    EVP_MD_CTX_free(ctx);
    EVP_MD_free(md);
}

/* Fetch an XOF by name and squeeze two slices. `EVP_MD_xof` says the fetched method claims to be
 * extendable; the two slice lengths are coprime with every rate in `sha3_prov.c`, so a loop that
 * permuted at the wrong boundary would show in the concatenated bytes. */
static void rt_provider_xof(const char *name, const char *label, size_t first, size_t second)
{
    EVP_MD *md = EVP_MD_fetch(NULL, name, NULL);
    EVP_MD_CTX *ctx;
    unsigned char out[64];
    int s1 = 0, s2 = 0;

    printf("provider.fetch.%s=%s\n", label, md != NULL ? "yes" : "no");
    if (md == NULL) {
        printf("provider.%s.squeeze=no-fetch\n", label);
        return;
    }
    printf("provider.%s.xof=%d\n", label, EVP_MD_xof(md));
    printf("provider.%s.size=%d\n", label, EVP_MD_get_size(md));
    printf("provider.%s.blocksize=%d\n", label, EVP_MD_get_block_size(md));
    ctx = EVP_MD_CTX_new();
    memset(out, 0, sizeof(out));
    if (EVP_DigestInit_ex(ctx, md, NULL) == 1 && EVP_DigestUpdate(ctx, "abc", 3) == 1) {
        s1 = EVP_DigestSqueeze(ctx, out, first);
        s2 = EVP_DigestSqueeze(ctx, out + first, second);
    } else {
        printf("provider.%s.squeeze=error\n", label);
        EVP_MD_CTX_free(ctx);
        EVP_MD_free(md);
        return;
    }
    printf("provider.%s.squeeze_first=%d\n", label, s1);
    printf("provider.%s.squeeze_second=%d\n", label, s2);
    if (s1 == 1 && s2 == 1) {
        printf("provider.%s.squeeze=", label);
        rt_print_hex(out, first + second);
        printf("\n");
    } else {
        printf("provider.%s.squeeze=refused\n", label);
    }
    EVP_MD_CTX_free(ctx);
    EVP_MD_free(md);
}

/* `MD5-SHA1`'s only interesting property is its `set_ctx_params`
 * `OSSL_DIGEST_PARAM_SSL3_MS` arm (`md5_sha1_prov.c:40-55`). A 48-byte master secret switches
 * the context to the RFC 6101 §5.6.8 construction (`crypto/md5/md5_sha1.c:41-107`), so the digest
 * that follows is not `md5(ms)||sha1(ms)`; a length other than 48 answers 0 and leaves the
 * context untouched. Both are observed, on the fetched method rather than the low-level ctrl. */
static void rt_provider_md5_sha1_ssl3(void)
{
    EVP_MD *md = EVP_MD_fetch(NULL, "MD5-SHA1", NULL);
    EVP_MD_CTX *ctx;
    unsigned char out[80];
    unsigned int outl = 0;
    unsigned char ms[48];
    unsigned char ms_short[47];
    OSSL_PARAM params[2];
    size_t i;
    int ok;

    printf("provider.md5_sha1.ssl3_fetch=%s\n", md != NULL ? "yes" : "no");
    if (md == NULL) {
        printf("provider.md5_sha1.ssl3=no-fetch\n");
        return;
    }
    for (i = 0; i < sizeof(ms); i++)
        ms[i] = (unsigned char)((i * 13u + 1u) & 0xffu);
    memset(ms_short, 0x11, sizeof(ms_short));

    /* A master secret that is not 48 bytes is refused (`mslen != 48` -> 0). */
    ctx = EVP_MD_CTX_new();
    if (EVP_DigestInit_ex(ctx, md, NULL) == 1 && EVP_DigestUpdate(ctx, "abc", 3) == 1) {
        params[0] = OSSL_PARAM_construct_octet_string(OSSL_DIGEST_PARAM_SSL3_MS, ms_short,
                                                      sizeof(ms_short));
        params[1] = OSSL_PARAM_construct_end();
        printf("provider.md5_sha1.ssl3_short=%d\n", EVP_MD_CTX_set_params(ctx, params));
    } else {
        printf("provider.md5_sha1.ssl3_short=init-error\n");
    }
    EVP_MD_CTX_free(ctx);

    /* The 48-byte arm rewrites the state, so the digest that follows is the SSLv3 one. */
    ctx = EVP_MD_CTX_new();
    memset(out, 0, sizeof(out));
    if (EVP_DigestInit_ex(ctx, md, NULL) == 1 && EVP_DigestUpdate(ctx, "abc", 3) == 1) {
        params[0] = OSSL_PARAM_construct_octet_string(OSSL_DIGEST_PARAM_SSL3_MS, ms,
                                                      sizeof(ms));
        params[1] = OSSL_PARAM_construct_end();
        ok = EVP_MD_CTX_set_params(ctx, params);
        printf("provider.md5_sha1.ssl3_set=%d\n", ok);
        if (ok == 1 && EVP_DigestFinal_ex(ctx, out, &outl) == 1) {
            printf("provider.md5_sha1.ssl3_digest=");
            rt_print_hex(out, outl);
            printf("\n");
            printf("provider.md5_sha1.ssl3_outl=%u\n", outl);
        } else {
            printf("provider.md5_sha1.ssl3_digest=error\n");
        }
    } else {
        printf("provider.md5_sha1.ssl3_set=init-error\n");
    }
    EVP_MD_CTX_free(ctx);
    EVP_MD_free(md);
}

static void rt_provider_section(void)
{
    OSSL_PROVIDER *def;
    EVP_MD *md;
    EVP_MD_CTX *ctx;
    unsigned char out[64];
    unsigned int outl = 0;

    def = OSSL_PROVIDER_load(NULL, "default");
    printf("provider.load_default=%s\n", def != NULL ? "yes" : "no");
    printf("provider.available_default=%d\n", OSSL_PROVIDER_available(NULL, "default"));

    md = EVP_MD_fetch(NULL, "SHA256", NULL);
    printf("provider.fetch_sha256=%s\n", md != NULL ? "yes" : "no");
    if (md == NULL) {
        printf("provider.sha256.abc=no-fetch\n");
    } else {
        printf("provider.sha256.size=%d\n", EVP_MD_get_size(md));
        printf("provider.sha256.blocksize=%d\n", EVP_MD_get_block_size(md));
        ctx = EVP_MD_CTX_new();
        memset(out, 0, sizeof(out));
        if (EVP_DigestInit_ex(ctx, md, NULL) == 1
            && EVP_DigestUpdate(ctx, "abc", 3) == 1
            && EVP_DigestFinal_ex(ctx, out, &outl) == 1) {
            printf("provider.sha256.abc=");
            rt_print_hex(out, outl);
            printf("\n");
            printf("provider.sha256.outl=%u\n", outl);
        } else {
            printf("provider.sha256.abc=error\n");
        }
        EVP_MD_CTX_free(ctx);
        EVP_MD_free(md);
    }
    /* The default provider publishes the seven rows 8.1a built **and** that `defltprov.c`
     * carries. MD4 and Whirlpool are `legacyprov.c`'s rows and no legacy provider is loaded, so
     * both must answer NULL here, exactly as the authority does; `RMD160` is one of
     * `PROV_NAMES_RIPEMD_160`'s four aliases. */
    rt_provider_digest("MD5", "md5");
    rt_provider_digest("SHA1", "sha1");
    rt_provider_digest("SHA512", "sha512");
    rt_provider_digest("SHA2-224", "sha2_224");
    rt_provider_digest("SHA2-384", "sha2_384");
    rt_provider_digest("RIPEMD160", "ripemd160");
    rt_provider_digest("RMD160", "rmd160");
    rt_provider_digest("MD4", "md4");
    rt_provider_digest("WHIRLPOOL", "whirlpool");
    /* The rows 8.1's second half adds: the SHA-2 alternates, the SHA-3 and Keccak fixed widths,
     * BLAKE2, SM3, the MD5||SHA-1 concatenation and the NULL digest. Each is provider-only --
     * none of these constructions has an exported low-level entry point (D197) -- so the fetch
     * *is* the surface, and the digest bytes are what say the fetched method is the right one. */
    rt_provider_digest("SHA2-256/192", "sha2_256_192");
    rt_provider_digest("SHA2-512/224", "sha2_512_224");
    rt_provider_digest("SHA2-512/256", "sha2_512_256");
    rt_provider_digest("SHA3-224", "sha3_224");
    rt_provider_digest("SHA3-256", "sha3_256");
    rt_provider_digest("SHA3-384", "sha3_384");
    rt_provider_digest("SHA3-512", "sha3_512");
    rt_provider_digest("KECCAK-224", "keccak_224");
    rt_provider_digest("KECCAK-256", "keccak_256");
    rt_provider_digest("KECCAK-384", "keccak_384");
    rt_provider_digest("KECCAK-512", "keccak_512");
    rt_provider_digest("BLAKE2S-256", "blake2s256");
    rt_provider_digest("BLAKE2B-512", "blake2b512");
    rt_provider_digest("SM3", "sm3");
    rt_provider_digest("MD5-SHA1", "md5_sha1");
    rt_provider_digest("NULL", "null");
    /* `MD5-SHA1` is the one row whose `set_ctx_params` changes the construction, so its SSLv3
     * master-secret arm is driven separately after the digest above. */
    rt_provider_md5_sha1_ssl3();
    /* The XOF rows: the squeeze is the surface `EVP_MD_xof`/`EVP_DigestSqueeze` reach, and a
     * two-slice squeeze is where a transcription of the loop stops agreeing. */
    rt_provider_xof("SHAKE-128", "shake128", 17, 15);
    rt_provider_xof("SHAKE-256", "shake256", 17, 15);
    rt_provider_xof("KECCAK-KMAC-128", "keccak_kmac_128", 17, 15);
    rt_provider_xof("KECCAK-KMAC-256", "keccak_kmac_256", 17, 15);
    if (def != NULL)
        OSSL_PROVIDER_unload(def);
}

/* The five `sha.h` one-shots are exported (`crypto/sha/sha1_one.c:36-70`), so they are observed
 * directly rather than through the provider. Each is `EVP_Q_digest(NULL, <name>, NULL, d, n, md,
 * NULL)` in the authority, and each answers NULL when the fetch cannot resolve -- which is what a
 * missing default provider would show. `rt_msg` is the probe's own input, so the two transcripts
 * can only differ where the two libraries differ.
 *
 * Each construction is driven **twice**: once with the caller's `out` buffer, and once with
 * `md == NULL`, which selects the file's own `static unsigned char m[<len>]` (`sha1_one.c:38-45`
 * and its four siblings). The returned pointer is never printed; the bytes it points at are, and
 * the two answers are compared as bytes because the whole point of the static arm is that it is
 * the same construction reached through a different buffer. */
static void rt_one_shot_exports(void)
{
    unsigned char out[64];
    const char *labels[5] = {"sha1", "sha224", "sha256", "sha384", "sha512"};
    size_t sizes[5] = {20u, 28u, 32u, 48u, 64u};
    size_t i;

    for (i = 0; i < 5; i++) {
        unsigned char *ret = NULL;
        unsigned char *stat = NULL;

        memset(out, 0, sizeof(out));
        switch (i) {
        case 0: ret = SHA1(rt_msg, 1000, out); break;
        case 1: ret = SHA224(rt_msg, 1000, out); break;
        case 2: ret = SHA256(rt_msg, 1000, out); break;
        case 3: ret = SHA384(rt_msg, 1000, out); break;
        default: ret = SHA512(rt_msg, 1000, out); break;
        }
        printf("oneshot.%s=%s\n", labels[i], ret == NULL ? "null" : "ok");
        if (ret != NULL) {
            printf("oneshot.%s.digest=", labels[i]);
            rt_print_hex(out, sizes[i]);
            printf("\n");
        }

        /* `md == NULL`: the authority's static-buffer arm. Reading the returned pointer is
         * what the authority itself does with it, and the bytes are the observation. */
        switch (i) {
        case 0: stat = SHA1(rt_msg, 1000, NULL); break;
        case 1: stat = SHA224(rt_msg, 1000, NULL); break;
        case 2: stat = SHA256(rt_msg, 1000, NULL); break;
        case 3: stat = SHA384(rt_msg, 1000, NULL); break;
        default: stat = SHA512(rt_msg, 1000, NULL); break;
        }
        printf("oneshot.%s.static=%s\n", labels[i], stat == NULL ? "null" : "ok");
        if (stat != NULL) {
            printf("oneshot.%s.static_digest=", labels[i]);
            rt_print_hex(stat, sizes[i]);
            printf("\n");
            printf("oneshot.%s.static_matches=%s\n", labels[i],
                   ret != NULL && memcmp(stat, out, sizes[i]) == 0 ? "same" : "differ");
        }
    }
}

/* The five one-shot exports of `md4.h`, `md5.h`, `mdc2.h`, `ripemd.h` and `whrlpool.h`.
 *
 * They are a different shape from the `sha.h` five above: nothing else in this probe calls them,
 * so they were neither directly nor indirectly courted and the court-coverage atlas -- which now
 * covers the in-progress stratum -- named them the moment its invariant moved off
 * completed-only. They are driven exactly as the SHA five are: the caller's buffer, then
 * `md == NULL`, which is the file's own `static` buffer. `MDC2`'s one-shot is the `pad_type = 1`
 * arm the context loop below also drives through the context. */
static void rt_one_shot_exports_legacy(void)
{
    typedef unsigned char *(*rt_oneshot_fn)(const unsigned char *, size_t, unsigned char *);
    static const char *labels[5] = {"md4", "md5", "mdc2", "ripemd160", "whirlpool"};
    static const size_t sizes[5] = {16u, 16u, 16u, 20u, 64u};
    static rt_oneshot_fn const fns[5] = {
        (rt_oneshot_fn)MD4, (rt_oneshot_fn)MD5, (rt_oneshot_fn)MDC2,
        (rt_oneshot_fn)RIPEMD160, (rt_oneshot_fn)WHIRLPOOL
    };
    unsigned char out[64];
    size_t i;

    for (i = 0; i < 5; i++) {
        unsigned char *ret = NULL;
        unsigned char *stat = NULL;

        memset(out, 0, sizeof(out));
        ret = fns[i](rt_msg, 1000, out);
        printf("oneshot.%s=%s\n", labels[i], ret == NULL ? "null" : "ok");
        if (ret != NULL) {
            printf("oneshot.%s.digest=", labels[i]);
            rt_print_hex(out, sizes[i]);
            printf("\n");
        }

        stat = fns[i](rt_msg, 1000, NULL);
        printf("oneshot.%s.static=%s\n", labels[i], stat == NULL ? "null" : "ok");
        if (stat != NULL) {
            printf("oneshot.%s.static_digest=", labels[i]);
            rt_print_hex(stat, sizes[i]);
            printf("\n");
            printf("oneshot.%s.static_matches=%s\n", labels[i],
                   ret != NULL && memcmp(stat, out, sizes[i]) == 0 ? "same" : "differ");
        }
    }
}

static void rt_mdc2_padding(void)
{
    static const unsigned char msg[] = "Now is the time for all ";
    MDC2_CTX c;
    unsigned char md[MDC2_DIGEST_LENGTH];

    /* The context's two padding arms. `MDC2` (the one-shot) is `pad_type = 1`; the second arm
     * is reachable only through the context, so the differential plane is where it is seen. */
    memset(&c, 0, sizeof(c));
    MDC2_Init(&c);
    c.pad_type = 1;
    MDC2_Update(&c, msg, sizeof(msg) - 1);
    MDC2_Final(md, &c);
    printf("mdc2.pad1=");
    rt_print_hex(md, MDC2_DIGEST_LENGTH);
    printf("\n");

    memset(&c, 0, sizeof(c));
    MDC2_Init(&c);
    c.pad_type = 2;
    MDC2_Update(&c, msg, sizeof(msg) - 1);
    MDC2_Final(md, &c);
    printf("mdc2.pad2=");
    rt_print_hex(md, MDC2_DIGEST_LENGTH);
    printf("\n");
}

/* ------------------------------------------------------------------------------------------
 * The provider-dispatch failure arm (`ERROR_PASS`)
 * ------------------------------------------------------------------------------------------
 *
 * `providers/implementations/digests/digestcommon.c` is generated and every default-provider
 * digest row shares it. Its `get_params` answers two refusals that raise `PROV_R_*` errors: the
 * generated decoder's repeated-key refusal, and a parameter whose setter cannot write the value.
 * Neither is reachable through `EVP_MD_get_params`, which builds its own single-key arrays, so
 * the arm drives the row's `OSSL_DISPATCH` through `OSSL_PROVIDER_query_operation` and chooses
 * the arrays itself. The queue is drained and printed; a refusal the candidate answers without
 * the authority's error is then a difference rather than a silence.
 */
static const OSSL_DISPATCH *rt_disp(const OSSL_ALGORITHM *algs, const char *name)
{
    for (; algs != NULL && algs->algorithm_names != NULL; algs++) {
        const char *s = algs->algorithm_names;
        size_t n = strlen(name);

        while (*s != '\0') {
            const char *e = strchr(s, ':');
            size_t len = e == NULL ? strlen(s) : (size_t)(e - s);

            if (len == n && strncmp(s, name, n) == 0)
                return algs->implementation;
            if (e == NULL)
                break;
            s = e + 1;
        }
    }
    return NULL;
}

static void *rt_fn(const OSSL_DISPATCH *d, int id)
{
    for (; d != NULL && d->function_id != 0; d++)
        if (d->function_id == id)
            return d->function;
    return NULL;
}

static void rt_errq(const char *tag)
{
    unsigned long e;
    const char *file = NULL, *func = NULL, *data = NULL;
    int line = 0, flags = 0;
    int n = 0;

    while ((e = ERR_get_error_all(&file, &line, &func, &data, &flags)) != 0) {
        printf("q.%s.%d=lib%d:reason%d:%s:%d:%s\n", tag, n, ERR_GET_LIB(e),
               ERR_GET_REASON(e), file != NULL ? file : "", line,
               func != NULL ? func : "");
        n++;
    }
    printf("q.%s.count=%d\n", tag, n);
}

static void rt_disp_errors(void)
{
    OSSL_PROVIDER *prov;
    const OSSL_ALGORITHM *algs;
    const OSSL_DISPATCH *d;
    int (*getparams)(OSSL_PARAM *) = NULL;
    OSSL_PARAM dup[3];
    unsigned char octet[8];
    size_t sz = 0;
    int nocache = 0;
    int r;

    prov = OSSL_PROVIDER_load(NULL, "default");
    printf("disp.provider=%d\n", prov != NULL);
    if (prov == NULL)
        return;
    algs = OSSL_PROVIDER_query_operation(prov, OSSL_OP_DIGEST, &nocache);
    printf("disp.algorithms=%d\n", algs != NULL);
    d = rt_disp(algs, "SHA256");
    printf("disp.sha256=%d\n", d != NULL);
    getparams = (int (*)(OSSL_PARAM *))rt_fn(d, OSSL_FUNC_DIGEST_GET_PARAMS);
    printf("disp.getparams=%d\n", getparams != NULL);
    if (getparams == NULL)
        return;

    /* A key the generated decoder knows, supplied twice: `digestcommon.c:78` for `size`. */
    dup[0] = OSSL_PARAM_construct_size_t(OSSL_DIGEST_PARAM_SIZE, &sz);
    dup[1] = OSSL_PARAM_construct_size_t(OSSL_DIGEST_PARAM_SIZE, &sz);
    dup[2] = OSSL_PARAM_construct_end();
    ERR_clear_error();
    r = getparams(dup);
    printf("disp.dupsize.ret=%d\n", r);
    rt_errq("dupsize");

    /* `blocksize` with a type `OSSL_PARAM_set_size_t` cannot write: the setter refuses and the
     * body raises (`digestcommon.c:111`, the first arm). */
    memset(octet, 0, sizeof(octet));
    dup[0] = OSSL_PARAM_construct_octet_string(OSSL_DIGEST_PARAM_BLOCK_SIZE, octet,
                                               sizeof(octet));
    dup[1] = OSSL_PARAM_construct_end();
    ERR_clear_error();
    r = getparams(dup);
    printf("disp.badbsize.ret=%d\n", r);
    rt_errq("badbsize");

    OSSL_PROVIDER_unload(prov);
}

int main(void)
{
    size_t i;

    setvbuf(stdout, NULL, _IOLBF, 0);
    rt_fill_msg();

    for (i = 0; i < sizeof(RT_ALGORITHMS) / sizeof(RT_ALGORITHMS[0]); i++)
        rt_run(&RT_ALGORITHMS[i]);

    rt_mdc2_padding();
    rt_one_shot_exports();
    rt_one_shot_exports_legacy();
    rt_provider_section();
    rt_disp_errors();

    return 0;
}
