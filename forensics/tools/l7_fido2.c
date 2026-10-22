/*
 * Phase-25 L7 workload for the library-only `fido2` (libfido2) family.
 *
 * libfido2 signs on an authenticator, not in software, so the admitted local
 * workload exercises the library's own ES256 key representation: a P-256 key
 * generated with libcrypto is imported with es256_pk_from_EVP_PKEY, converted
 * back with es256_pk_to_EVP_PKEY, and an ES256 (ECDSA P-256 / SHA-256)
 * signature made with the original key must verify against the key that
 * round-tripped through libfido2. A single flipped signature byte must be
 * rejected.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include <fido.h>
#include <fido/es256.h>

#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/obj_mac.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const char MESSAGE[] = "phase25-l7-fido2-es256-message";

static EVP_PKEY *gen_ec_key(void)
{
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
    EVP_PKEY *pkey = NULL;

    if (ctx == NULL)
        return NULL;
    if (EVP_PKEY_keygen_init(ctx) <= 0 ||
        EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx, NID_X9_62_prime256v1) <= 0 ||
        EVP_PKEY_keygen(ctx, &pkey) <= 0)
        pkey = NULL;
    EVP_PKEY_CTX_free(ctx);
    return pkey;
}

static int digest_sign(EVP_PKEY *pkey, unsigned char **sig, size_t *siglen)
{
    EVP_MD_CTX *m = EVP_MD_CTX_new();
    int rc = -1;

    if (m == NULL)
        return -1;
    if (EVP_DigestSignInit(m, NULL, EVP_sha256(), NULL, pkey) != 1 ||
        EVP_DigestSignUpdate(m, MESSAGE, strlen(MESSAGE)) != 1 ||
        EVP_DigestSignFinal(m, NULL, siglen) != 1)
        goto out;
    *sig = malloc(*siglen);
    if (*sig == NULL)
        goto out;
    if (EVP_DigestSignFinal(m, *sig, siglen) != 1)
        goto out;
    rc = 0;
 out:
    EVP_MD_CTX_free(m);
    return rc;
}

static int digest_verify(EVP_PKEY *pkey, const unsigned char *sig, size_t siglen)
{
    EVP_MD_CTX *m = EVP_MD_CTX_new();
    int rc = -1;

    if (m == NULL)
        return -1;
    if (EVP_DigestVerifyInit(m, NULL, EVP_sha256(), NULL, pkey) == 1 &&
        EVP_DigestVerifyUpdate(m, MESSAGE, strlen(MESSAGE)) == 1 &&
        EVP_DigestVerifyFinal(m, sig, siglen) == 1)
        rc = 0;
    EVP_MD_CTX_free(m);
    return rc;
}

int main(int argc, char **argv)
{
    EVP_PKEY *pkey = NULL, *roundtrip = NULL;
    es256_pk_t *pk = NULL;
    unsigned char *sig = NULL;
    size_t siglen = 0;
    int rc = 1;

    if (argc > 1 && strcmp(argv[1], "--version") == 0) {
        printf("fido2-l7-harness (libfido2)\n");
        return 0;
    }

    pkey = gen_ec_key();
    if (pkey == NULL)
        goto out;
    pk = es256_pk_new();
    if (pk == NULL)
        goto out;
    if (es256_pk_from_EVP_PKEY(pk, pkey) != FIDO_OK) {
        fprintf(stderr, "libfido2: es256_pk_from_EVP_PKEY failed\n");
        goto out;
    }
    roundtrip = es256_pk_to_EVP_PKEY(pk);
    if (roundtrip == NULL) {
        fprintf(stderr, "libfido2: es256_pk_to_EVP_PKEY failed\n");
        goto out;
    }
    if (digest_sign(pkey, &sig, &siglen) != 0) {
        fprintf(stderr, "fido2: the ES256 signature could not be produced\n");
        goto out;
    }
    printf("es256_sign=ok\n");
    if (digest_verify(roundtrip, sig, siglen) != 0) {
        fprintf(stderr, "fido2: the ES256 signature did not verify with the libfido2 key\n");
        goto out;
    }
    printf("es256_verify=ok\n");

    sig[siglen / 2] ^= 0x01;
    if (digest_verify(roundtrip, sig, siglen) == 0) {
        fprintf(stderr, "fido2: the altered signature was accepted\n");
        goto out;
    }
    printf("altered_signature=rejected\n");
    rc = 0;
 out:
    free(sig);
    EVP_PKEY_free(pkey);
    EVP_PKEY_free(roundtrip);
    es256_pk_free(&pk);
    return rc;
}
