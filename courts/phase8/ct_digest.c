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
 *     <index>\t<algorithm>\t<input-hex>
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

typedef int (*digest_fn)(const unsigned char *data, size_t len, unsigned char *out);

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

static int ct_md4(const unsigned char *d, size_t n, unsigned char *o)
{
    MD4_CTX c;
    return MD4_Init(&c) && MD4_Update(&c, d, n) && MD4_Final(o, &c);
}

static int ct_md5(const unsigned char *d, size_t n, unsigned char *o)
{
    MD5_CTX c;
    return MD5_Init(&c) && MD5_Update(&c, d, n) && MD5_Final(o, &c);
}

static int ct_ripemd160(const unsigned char *d, size_t n, unsigned char *o)
{
    RIPEMD160_CTX c;
    return RIPEMD160_Init(&c) && RIPEMD160_Update(&c, d, n) && RIPEMD160_Final(o, &c);
}

static int ct_sha1(const unsigned char *d, size_t n, unsigned char *o)
{
    SHA_CTX c;
    return SHA1_Init(&c) && SHA1_Update(&c, d, n) && SHA1_Final(o, &c);
}

static int ct_sha224(const unsigned char *d, size_t n, unsigned char *o)
{
    SHA256_CTX c;
    return SHA224_Init(&c) && SHA224_Update(&c, d, n) && SHA224_Final(o, &c);
}

static int ct_sha256(const unsigned char *d, size_t n, unsigned char *o)
{
    SHA256_CTX c;
    return SHA256_Init(&c) && SHA256_Update(&c, d, n) && SHA256_Final(o, &c);
}

static int ct_sha384(const unsigned char *d, size_t n, unsigned char *o)
{
    SHA512_CTX c;
    return SHA384_Init(&c) && SHA384_Update(&c, d, n) && SHA384_Final(o, &c);
}

static int ct_sha512(const unsigned char *d, size_t n, unsigned char *o)
{
    SHA512_CTX c;
    return SHA512_Init(&c) && SHA512_Update(&c, d, n) && SHA512_Final(o, &c);
}

static int ct_whirlpool(const unsigned char *d, size_t n, unsigned char *o)
{
    WHIRLPOOL_CTX c;
    return WHIRLPOOL_Init(&c) && WHIRLPOOL_Update(&c, d, n) && WHIRLPOOL_Final(o, &c);
}

struct ct_algorithm {
    const char *name;
    digest_fn fn;
    size_t out_len;
};

static const struct ct_algorithm CT_ALGORITHMS[] = {
    {"md4", ct_md4, 16u},
    {"md5", ct_md5, 16u},
    {"ripemd160", ct_ripemd160, 20u},
    {"sha1", ct_sha1, 20u},
    {"sha224", ct_sha224, 28u},
    {"sha256", ct_sha256, 32u},
    {"sha384", ct_sha384, 48u},
    {"sha512", ct_sha512, 64u},
    {"whirlpool", ct_whirlpool, 64u},
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
    char *index, *name, *hex, *cursor;
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
        hex = strsep(&cursor, "\t");
        if (index == NULL || name == NULL || hex == NULL) {
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
        if (!algo->fn(input, len, out)) {
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
