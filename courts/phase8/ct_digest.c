/*
 * openssl-rs — the correctness-vector driver for the digest constructions (CT-DIGEST).
 *
 * This is **not** a differential probe and deliberately is not named `*_probe.c`: the
 * differential shape compiles one program twice and diffs two transcripts, while this one
 * compiles against the candidate alone and compares its output with committed expected
 * bytes. `forensics/tools/probe_hygiene.py` holds only `courts/phase<N>/*_probe.c` to the
 * authority/candidate determinism rule, which is the right scope: there is no authority
 * transcript here to be deterministic with respect to.
 *
 * Protocol
 * --------
 * The program is invoked with one argument, the path of a call file, and writes one result
 * line per call to stdout:
 *
 *     <index>\t<ok|err>\t<digest-hex or reason>
 *
 * and a call-file line is
 *
 *     <index>\t<algorithm>\t<mode>\t<input-hex>
 *
 * The **mode** is the update shape, and it is what makes the collector part of the check
 * rather than only the compression function:
 *
 *     one        one `Update` over the whole input
 *     two        two `Update`s, split at `len / 2`
 *     byte       one `Update` per byte
 *     count:<n>  the input repeated `n` times, one `Update` per copy
 *
 * Every mode must answer the same committed expected bytes. Self-consistency alone is not
 * enough — three equally wrong splits agree with each other — so the tool compares each mode
 * to the expected bytes, not to another mode's answer.
 *
 * `forensics/tools/correctness_vectors.py` owns the call file, the expected bytes and the
 * comparison. The probe only computes: it never compares and never decides a verdict, so a
 * probe defect cannot be mistaken for a passing vector.
 *
 * The low-level `X_Init`/`X_Update`/`X_Final` entry points are the ones 8.1a lands, which is
 * the point of the plane: this exercises the *construction*, not the provider dispatch, and
 * a construction that agrees with the published vectors is what CT-DIGEST claims.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/md4.h>
#include <openssl/md5.h>
#include <openssl/ripemd.h>
#include <openssl/sha.h>
#include <openssl/whrlpool.h>
#include <openssl/evp.h>

#define CT_MAX_INPUT (1u << 16)

/* Large enough for every context in the table below and aligned for any of them. */
typedef union {
    unsigned char bytes[512];
    unsigned long long align;
    void *ptr;
} ct_ctx;

typedef int (*ct_init_fn)(void *ctx);
typedef int (*ct_update_fn)(void *ctx, const void *data, size_t len);
typedef int (*ct_final_fn)(void *ctx, unsigned char *out);

struct ct_algorithm {
    const char *name;
    ct_init_fn init;
    ct_update_fn update;
    ct_final_fn final;
    size_t out_len;
};

#define CT_DEFINE(lc, CTX, INIT, UPDATE, FINAL)                                    \
    static int lc##_init(void *c) { return INIT((CTX *)c); }                       \
    static int lc##_update(void *c, const void *d, size_t n)                       \
    {                                                                              \
        return UPDATE((CTX *)c, d, n);                                             \
    }                                                                              \
    static int lc##_final(void *c, unsigned char *o) { return FINAL(o, (CTX *)c); }

CT_DEFINE(md4, MD4_CTX, MD4_Init, MD4_Update, MD4_Final)
CT_DEFINE(md5, MD5_CTX, MD5_Init, MD5_Update, MD5_Final)
CT_DEFINE(ripemd160, RIPEMD160_CTX, RIPEMD160_Init, RIPEMD160_Update, RIPEMD160_Final)
CT_DEFINE(sha1, SHA_CTX, SHA1_Init, SHA1_Update, SHA1_Final)
CT_DEFINE(sha224, SHA256_CTX, SHA224_Init, SHA224_Update, SHA224_Final)
CT_DEFINE(sha256, SHA256_CTX, SHA256_Init, SHA256_Update, SHA256_Final)
CT_DEFINE(sha384, SHA512_CTX, SHA384_Init, SHA384_Update, SHA384_Final)
CT_DEFINE(sha512, SHA512_CTX, SHA512_Init, SHA512_Update, SHA512_Final)
CT_DEFINE(whirlpool, WHIRLPOOL_CTX, WHIRLPOOL_Init, WHIRLPOOL_Update, WHIRLPOOL_Final)

static const struct ct_algorithm CT_ALGORITHMS[] = {
    {"md4", md4_init, md4_update, md4_final, 16u},
    {"md5", md5_init, md5_update, md5_final, 16u},
    {"ripemd160", ripemd160_init, ripemd160_update, ripemd160_final, 20u},
    {"sha1", sha1_init, sha1_update, sha1_final, 20u},
    {"sha224", sha224_init, sha224_update, sha224_final, 28u},
    {"sha256", sha256_init, sha256_update, sha256_final, 32u},
    {"sha384", sha384_init, sha384_update, sha384_final, 48u},
    {"sha512", sha512_init, sha512_update, sha512_final, 64u},
    {"whirlpool", whirlpool_init, whirlpool_update, whirlpool_final, 64u},
};

/* The provider-only constructions. None of these has an exported low-level `X_Init`/`X_Update`
 * entry point -- D197 read that from `include/openssl/sha.h` and the symbol inventory -- so the
 * fetch *is* the surface, exactly as it is in `rt_digest_probe.c`'s provider section. `xof` rows
 * are finalised with `EVP_DigestFinalXOF` at `out_len`; the fixed rows use `EVP_DigestFinal_ex`
 * and the digest length must match `out_len`. */
struct ct_evp_algorithm {
    const char *name;
    const char *fetch;
    size_t out_len;
    int xof;
};

static const struct ct_evp_algorithm CT_EVP_ALGORITHMS[] = {
    {"sha256_192", "SHA2-256/192", 24u, 0},
    {"sha512_224", "SHA2-512/224", 28u, 0},
    {"sha512_256", "SHA2-512/256", 32u, 0},
    {"sha3_224", "SHA3-224", 28u, 0},
    {"sha3_256", "SHA3-256", 32u, 0},
    {"sha3_384", "SHA3-384", 48u, 0},
    {"sha3_512", "SHA3-512", 64u, 0},
    {"shake128", "SHAKE-128", 32u, 1},
    {"shake256", "SHAKE-256", 64u, 1},
    {"blake2s256", "BLAKE2S-256", 32u, 0},
    {"blake2b512", "BLAKE2B-512", 64u, 0},
    {"sm3", "SM3", 32u, 0},
    {"md5_sha1", "MD5-SHA1", 36u, 0},
};

static const struct ct_evp_algorithm *ct_evp_lookup(const char *name)
{
    size_t i;

    for (i = 0; i < sizeof(CT_EVP_ALGORITHMS) / sizeof(CT_EVP_ALGORITHMS[0]); i++) {
        if (strcmp(CT_EVP_ALGORITHMS[i].name, name) == 0)
            return &CT_EVP_ALGORITHMS[i];
    }
    return NULL;
}

static const struct ct_algorithm *ct_lookup(const char *name)
{
    size_t i;

    for (i = 0; i < sizeof(CT_ALGORITHMS) / sizeof(CT_ALGORITHMS[0]); i++) {
        if (strcmp(CT_ALGORITHMS[i].name, name) == 0)
            return &CT_ALGORITHMS[i];
    }
    return NULL;
}

static int ct_hexval(int ch)
{
    if (ch >= '0' && ch <= '9')
        return ch - '0';
    if (ch >= 'a' && ch <= 'f')
        return ch - 'a' + 10;
    if (ch >= 'A' && ch <= 'F')
        return ch - 'A' + 10;
    return -1;
}

static int ct_hexdecode(const char *hex, unsigned char *out, size_t *out_len)
{
    size_t n = strlen(hex);
    size_t i;

    if (n % 2 != 0)
        return 0;
    if (n / 2 > CT_MAX_INPUT)
        return 0;
    for (i = 0; i < n; i += 2) {
        int hi = ct_hexval((unsigned char)hex[i]);
        int lo = ct_hexval((unsigned char)hex[i + 1]);
        if (hi < 0 || lo < 0)
            return 0;
        out[i / 2] = (unsigned char)((hi << 4) | lo);
    }
    *out_len = n / 2;
    return 1;
}

/* Run one (algorithm, mode) call. Answers 0 only when an entry point refused. */
static int ct_compute(const struct ct_algorithm *algo, const unsigned char *data,
                      size_t len, const char *mode, unsigned char *out)
{
    ct_ctx ctx;
    size_t i;

    if (strncmp(mode, "count:", 6) == 0 && mode[6] != '\0') {
        unsigned long reps = strtoul(mode + 6, NULL, 10);
        unsigned long r;

        if (reps == 0)
            return 0;
        if (!algo->init(ctx.bytes))
            return 0;
        for (r = 0; r < reps; r++) {
            if (!algo->update(ctx.bytes, data, len))
                return 0;
        }
        return algo->final(ctx.bytes, out);
    }
    if (strcmp(mode, "one") == 0) {
        return algo->init(ctx.bytes) && algo->update(ctx.bytes, data, len)
               && algo->final(ctx.bytes, out);
    }
    if (strcmp(mode, "two") == 0) {
        size_t half = len / 2;

        return algo->init(ctx.bytes) && algo->update(ctx.bytes, data, half)
               && algo->update(ctx.bytes, data + half, len - half)
               && algo->final(ctx.bytes, out);
    }
    if (strcmp(mode, "byte") == 0) {
        if (!algo->init(ctx.bytes))
            return 0;
        for (i = 0; i < len; i++) {
            if (!algo->update(ctx.bytes, data + i, 1))
                return 0;
        }
        return algo->final(ctx.bytes, out);
    }
    return 0;
}

/* Apply one update shape to an EVP digest context. Answers 1 on success. */
static int ct_evp_updates(EVP_MD_CTX *ctx, const unsigned char *data, size_t len,
                          const char *mode)
{
    size_t i;

    if (strncmp(mode, "count:", 6) == 0 && mode[6] != '\0') {
        unsigned long reps = strtoul(mode + 6, NULL, 10);
        unsigned long r;

        if (reps == 0)
            return 0;
        for (r = 0; r < reps; r++) {
            if (EVP_DigestUpdate(ctx, data, len) != 1)
                return 0;
        }
        return 1;
    }
    if (strcmp(mode, "one") == 0)
        return EVP_DigestUpdate(ctx, data, len) == 1;
    if (strcmp(mode, "two") == 0) {
        size_t half = len / 2;

        return EVP_DigestUpdate(ctx, data, half) == 1
               && EVP_DigestUpdate(ctx, data + half, len - half) == 1;
    }
    if (strcmp(mode, "byte") == 0) {
        for (i = 0; i < len; i++) {
            if (EVP_DigestUpdate(ctx, data + i, 1) != 1)
                return 0;
        }
        return 1;
    }
    return 0;
}

/* One provider-mediated (algorithm, mode) call. Answers 0 only when a fetch or a call refused. */
static int ct_evp_compute(const struct ct_evp_algorithm *algo, const unsigned char *data,
                          size_t len, const char *mode, unsigned char *out)
{
    EVP_MD *md = EVP_MD_fetch(NULL, algo->fetch, NULL);
    EVP_MD_CTX *ctx = NULL;
    int ok = 0;

    if (md == NULL)
        return 0;
    ctx = EVP_MD_CTX_new();
    if (ctx != NULL && EVP_DigestInit_ex(ctx, md, NULL) == 1
        && ct_evp_updates(ctx, data, len, mode)) {
        if (algo->xof) {
            ok = EVP_DigestFinalXOF(ctx, out, algo->out_len);
        } else {
            unsigned int outl = 0;

            if (EVP_DigestFinal_ex(ctx, out, &outl) == 1 && outl == algo->out_len)
                ok = 1;
        }
    }
    EVP_MD_CTX_free(ctx);
    EVP_MD_free(md);
    return ok;
}

static void ct_print_hex(const unsigned char *bytes, size_t n)
{
    size_t i;

    for (i = 0; i < n; i++)
        printf("%02x", bytes[i]);
}

int main(int argc, char **argv)
{
    static char line[4 * CT_MAX_INPUT + 64];
    static unsigned char input[CT_MAX_INPUT];
    unsigned char out[64];
    FILE *calls;
    const struct ct_algorithm *algo;
    char *index, *name, *mode, *hex, *cursor;
    size_t len;

    if (argc != 2) {
        fprintf(stderr, "usage: %s <call-file>\n", argv[0]);
        return 2;
    }
    calls = fopen(argv[1], "r");
    if (calls == NULL) {
        fprintf(stderr, "ct_digest: cannot open call file %s\n", argv[1]);
        return 2;
    }

    while (fgets(line, sizeof(line), calls) != NULL) {
        line[strcspn(line, "\r\n")] = '\0';
        if (line[0] == '\0')
            continue;

        /* `strsep` rather than `strtok_r`: tokenisation must not collapse an empty field,
         * because the empty message is a vector and its hex field is deliberately empty. */
        cursor = line;
        index = strsep(&cursor, "\t");
        name = strsep(&cursor, "\t");
        mode = strsep(&cursor, "\t");
        hex = strsep(&cursor, "\t");
        if (index == NULL || name == NULL || mode == NULL || hex == NULL) {
            printf("%s\terr\tmalformed-call\n", index == NULL ? "?" : index);
            continue;
        }

        algo = ct_lookup(name);
        if (algo == NULL) {
            const struct ct_evp_algorithm *ealgo = ct_evp_lookup(name);

            if (ealgo == NULL) {
                printf("%s\terr\tunknown-algorithm\n", index);
                continue;
            }
            if (!ct_hexdecode(hex, input, &len)) {
                printf("%s\terr\tbad-hex\n", index);
                continue;
            }
            memset(out, 0, sizeof(out));
            if (!ct_evp_compute(ealgo, input, len, mode, out)) {
                printf("%s\terr\tinit-update-final-failed\n", index);
                continue;
            }
            printf("%s\tok\t", index);
            ct_print_hex(out, ealgo->out_len);
            printf("\n");
            continue;
        }
        if (!ct_hexdecode(hex, input, &len)) {
            printf("%s\terr\tbad-hex\n", index);
            continue;
        }
        memset(out, 0, sizeof(out));
        if (!ct_compute(algo, input, len, mode, out)) {
            printf("%s\terr\tinit-update-final-failed\n", index);
            continue;
        }
        printf("%s\tok\t", index);
        ct_print_hex(out, algo->out_len);
        printf("\n");
    }

    fclose(calls);
    return 0;
}
