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
            printf("%s\terr\tunknown-algorithm\n", index);
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
