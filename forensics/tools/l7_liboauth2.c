/*
 * Phase-25 L7 workload for the `liboauth2` family.
 *
 * liboauth2's OpenSSL consumer path is its JOSE layer (src/jose.c): oauth2_jose_hash_bytes uses
 * the OpenSSL EVP interface directly, and oauth2_jose_encrypt/decrypt build a cjose JWS/JWE whose
 * HMAC-SHA256 and AES-GCM operations use the subject libcrypto. The harness checks the SHA-256
 * digest of "abc" against its published value, round-trips a payload through the JWE, and flips a
 * ciphertext byte as the negative control (decryption must fail).
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include <oauth2/jose.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const unsigned char SHA256_ABC[32] = {
    0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea,
    0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
    0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c,
    0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad,
};

static int digest_ok(void)
{
    unsigned char *digest = NULL;
    unsigned int len = 0;
    int ok;

    if (!oauth2_jose_hash_bytes(NULL, OAUTH2_JOSE_OPENSSL_ALG_SHA256,
                                (const unsigned char *)"abc", 3, &digest, &len))
        return 0;
    ok = (len == sizeof(SHA256_ABC) && memcmp(digest, SHA256_ABC, len) == 0);
    free(digest);
    return ok;
}

int main(int argc, char **argv)
{
    const char *secret = "liboauth2-l7-secret";
    const char *payload = "liboauth2-l7-payload";
    char *jwe = NULL;
    char *plain = NULL;
    char *tampered = NULL;
    int digest, roundtrip = 0, tamper = 0, ok;

    if (argc == 2 && strcmp(argv[1], "--version") == 0) {
        printf("liboauth2-l7-harness 1\n");
        return 0;
    }

    digest = digest_ok();
    printf("sha256=%s\n", digest ? "ok" : "failed");

    if (oauth2_jose_encrypt(NULL, secret, payload, &jwe) && jwe != NULL &&
        oauth2_jose_decrypt(NULL, secret, jwe, &plain) && plain != NULL &&
        strcmp(plain, payload) == 0) {
        roundtrip = 1;
    }
    printf("jwe_roundtrip=%s\n", roundtrip ? "ok" : "failed");

    if (jwe != NULL) {
        size_t n = strlen(jwe), i;
        tampered = malloc(n + 1);
        if (tampered != NULL) {
            memcpy(tampered, jwe, n + 1);
            for (i = n / 2; i < n; i++) {
                if (tampered[i] != '.' && tampered[i] != '-' && tampered[i] != '_' &&
                    tampered[i] != '=') {
                    tampered[i] = (tampered[i] == 'A') ? 'B' : 'A';
                    break;
                }
            }
            tamper = (oauth2_jose_decrypt(NULL, secret, tampered, &plain) == false);
        }
    }
    printf("tamper=%s\n", tamper ? "rejected" : "accepted");

    ok = digest && roundtrip && tamper;
    free(jwe);
    free(plain);
    free(tampered);
    printf("result=%s\n", ok ? "ok" : "fail");
    return ok ? 0 : 1;
}
