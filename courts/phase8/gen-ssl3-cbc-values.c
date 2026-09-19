/*
 * Generate the `ssl3_cbc_digest_record` expectations for `src/mac/ssl3_cbc.rs` by compiling the
 * authority's own `ssl/record/methods/ssl3_cbc.c` against the authority's libcrypto. The
 * transcription's oracle is the unit it transcribes.
 *
 * `ssl3_cbc.c` is built into **libcrypto** as well as libssl -- the build tree carries
 * `ssl/record/methods/libdefault-lib-ssl3_cbc.o` -- because it is shared with the providers, which
 * the file's own header says. So compiling it here is the same object the default provider links.
 *
 * The whole of `ssl3_cbc.c` is the provider-shared half -- it is `ssl3_cbc_digest_record` and the
 * four `tls1_*_final_raw` serialisers, and nothing else -- so this compiles the unit whole.
 * `ssl3_cbc_record_digest_supported`, which the header also declares, is in
 * `ssl/record/methods/tls_common.c` and is **libssl's**: it is built into libssl.a and not
 * libcrypto.a, and `hmac_prov.c` does not call it. It is Phase 14's.
 */
#include <stdio.h>
#include <string.h>

#include <openssl/evp.h>
#include <openssl/ssl.h>

#include "internal/ssl3_cbc.h"

#define BIG 512

/* A deterministic byte source, so both sides of the differential see the same message. */
static void fill(unsigned char *p, size_t n, unsigned seed)
{
    size_t i;
    unsigned x = seed * 2654435761u + 1u;

    for (i = 0; i < n; i++) {
        x = x * 1103515245u + 12345u;
        p[i] = (unsigned char)(x >> 16);
    }
}

static void one(const char *name, const EVP_MD *md, int is_sslv3, size_t data_size,
                size_t mac_size, size_t padding)
{
    unsigned char header[BIG];
    unsigned char data[BIG];
    unsigned char secret[BIG];
    unsigned char out[EVP_MAX_MD_SIZE];
    size_t out_size = 0;
    size_t header_length, dpmps;
    char suffix[64];
    size_t i;

    fill(header, sizeof(header), (unsigned)(data_size + 7));
    fill(data, sizeof(data), (unsigned)(data_size + 11));
    fill(secret, sizeof(secret), (unsigned)(mac_size + 13));

    header_length = 13;
    if (is_sslv3)
        header_length = 16 /* mac_secret_length */ + 40 + 8 + 1 + 2;

    dpmps = data_size + mac_size + padding;

    memset(out, 0, sizeof(out));
    printf("/* %s, is_sslv3=%d, data=%zu, mac=%zu, pad=%zu */\n", name, is_sslv3, data_size,
           mac_size, padding);
    printf("    (\"%s\", %d, %zu, %zu, %zu, ", name, is_sslv3, data_size, mac_size, padding);
    (void)suffix;

    if (ssl3_cbc_digest_record(md, out, &out_size, header, data, data_size, dpmps, secret,
                               16, (char)is_sslv3) != 1) {
        printf("0, NULL, 0),\n");
        return;
    }
    printf("1, \"");
    for (i = 0; i < out_size; i++)
        printf("%02x", out[i]);
    printf("\", %zu),\n", out_size);
}

int main(void)
{
    static const struct {
        const char *name;
        const EVP_MD *(*md)(void);
    } mds[] = {
        { "MD5", EVP_md5 },
        { "SHA1", EVP_sha1 },
        { "SHA2-224", EVP_sha224 },
        { "SHA2-256", EVP_sha256 },
        { "SHA2-384", EVP_sha384 },
        { "SHA2-512", EVP_sha512 },
    };
    static const size_t sizes[] = { 0, 1, 5, 16, 31, 32, 63, 64, 100, 255 };
    size_t i, j, k;
    int s;

    /* The digests the record layer rejects reach the `ossl_assert(0)` arm, which under `-DNDEBUG`
     * -- which this profile's Makefile sets -- returns 0 rather than dying. Observed directly. */
    {
        static const char *unsupported[] = { "SHA3-256", "BLAKE2B-512", "SM3" };
        static const EVP_MD *(*const mds_unsupported[])(void) = {
            EVP_sha3_256, EVP_blake2b512, EVP_sm3
        };
        unsigned char header[BIG], data[BIG], secret[BIG], out[EVP_MAX_MD_SIZE];
        size_t out_size = 0;
        EVP_MD_CTX *ctx = EVP_MD_CTX_new();

        fill(header, sizeof(header), 3);
        fill(data, sizeof(data), 5);
        fill(secret, sizeof(secret), 7);
        printf("/* ssl3_cbc_digest_record on a digest the record layer does not support */\n");
        for (i = 0; i < sizeof(unsupported) / sizeof(unsupported[0]); i++) {
            EVP_DigestInit_ex(ctx, mds_unsupported[i](), NULL);
            out_size = 12345;
            printf("    (\"%s\", %d, %zu),\n", unsupported[i],
                   ssl3_cbc_digest_record(mds_unsupported[i](), out, &out_size, header, data, 16,
                                          16 + 32 + 16, secret, 16, 0),
                   out_size);
        }
        EVP_MD_CTX_free(ctx);
    }

    printf("\n/* ssl3_cbc_digest_record */\n");
    for (i = 0; i < sizeof(mds) / sizeof(mds[0]); i++) {
        /* The MAC length the record layer uses for each digest is its own size. */
        size_t mac = (size_t)EVP_MD_get_size(mds[i].md());

        for (s = 0; s < 2; s++) {
            for (j = 0; j < sizeof(sizes) / sizeof(sizes[0]); j++) {
                for (k = 0; k < 2; k++) {
                    /* `data_plus_mac_plus_padding_size` must be at least data+mac+pad, and the
                     * padding is what the constant-time path exists to hide, so both a zero and a
                     * block-filling padding are exercised. */
                    one(mds[i].name, mds[i].md(), s, sizes[j], mac, k ? 0 : 16);
                }
            }
        }
    }
    return 0;
}
