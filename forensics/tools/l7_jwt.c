/*
 * Phase-25 L7 workload for the library-only `jwt` (libjwt) family.
 *
 * libjwt ships no executable of its own, so the admitted workload is this
 * small program. It generates a local RSA key and a local P-256 key with
 * libcrypto, signs a claims set with libjwt under RS256 and ES256, decodes
 * each token back with the matching public key and reads the claims, then
 * flips one signature character and requires libjwt to reject the tampered
 * token. The keys never leave the process.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include <jwt.h>

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/obj_mac.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const char CLAIM[] = "phase25-l7-jwt";

static EVP_PKEY *gen_key(int rsa)
{
    EVP_PKEY_CTX *ctx = NULL;
    EVP_PKEY *pkey = NULL;

    if (rsa) {
        ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
        if (ctx == NULL || EVP_PKEY_keygen_init(ctx) <= 0 ||
            EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 2048) <= 0)
            goto out;
    } else {
        ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
        if (ctx == NULL || EVP_PKEY_keygen_init(ctx) <= 0 ||
            EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx, NID_X9_62_prime256v1) <= 0)
            goto out;
    }
    if (EVP_PKEY_keygen(ctx, &pkey) <= 0)
        pkey = NULL;
 out:
    EVP_PKEY_CTX_free(ctx);
    return pkey;
}

static char *pem_string(EVP_PKEY *pkey, int priv, size_t *len)
{
    BIO *bio = BIO_new(BIO_s_mem());
    char *data = NULL;
    char *out;
    long n;
    int ok;

    if (bio == NULL)
        return NULL;
    ok = priv ? PEM_write_bio_PrivateKey(bio, pkey, NULL, NULL, 0, NULL, NULL)
              : PEM_write_bio_PUBKEY(bio, pkey);
    if (!ok) {
        BIO_free(bio);
        return NULL;
    }
    n = BIO_get_mem_data(bio, &data);
    out = malloc((size_t)n + 1);
    if (out != NULL) {
        memcpy(out, data, (size_t)n);
        out[n] = '\0';
        *len = (size_t)n;
    }
    BIO_free(bio);
    return out;
}

static int test_alg(jwt_alg_t alg, const char *name, int rsa)
{
    EVP_PKEY *pkey = gen_key(rsa);
    char *priv = NULL, *pub = NULL, *token = NULL, *bad = NULL;
    size_t privlen = 0, publen = 0, n, last;
    jwt_t *jwt = NULL, *dec = NULL;
    int rc = -1;

    if (pkey == NULL)
        return -1;
    priv = pem_string(pkey, 1, &privlen);
    pub = pem_string(pkey, 0, &publen);
    EVP_PKEY_free(pkey);
    if (priv == NULL || pub == NULL)
        goto out;

    if (jwt_new(&jwt) != 0)
        goto out;
    if (jwt_add_grant(jwt, "iss", "openssl-rs") != 0 ||
        jwt_add_grant(jwt, "sub", CLAIM) != 0 ||
        jwt_set_alg(jwt, alg, (const unsigned char *)priv, (int)privlen) != 0)
        goto out;
    token = jwt_encode_str(jwt);
    jwt_free(jwt);
    jwt = NULL;
    if (token == NULL)
        goto out;

    if (jwt_decode(&dec, token, (const unsigned char *)pub, (int)publen) != 0)
        goto out;
    if (jwt_get_grant(dec, "sub") == NULL ||
        strcmp(jwt_get_grant(dec, "sub"), CLAIM) != 0)
        goto out;
    jwt_free(dec);
    dec = NULL;

    n = strlen(token);
    bad = strdup(token);
    if (bad == NULL || n == 0)
        goto out;
    last = (size_t)(strrchr(bad, '.') - bad) + 1;
    if (last >= n)
        last = n - 1;
    bad[last] = (bad[last] == 'A') ? 'B' : 'A';
    if (jwt_decode(&dec, bad, (const unsigned char *)pub, (int)publen) == 0) {
        fprintf(stderr, "%s: the tampered signature was accepted\n", name);
        goto out;
    }
    jwt_free(dec);
    dec = NULL;

    printf("%s_sign=ok\n%s_verify=ok\n%s_claims=%s\n%s_tamper=rejected\n",
           name, name, name, CLAIM, name);
    rc = 0;
 out:
    jwt_free(jwt);
    jwt_free(dec);
    jwt_free_str(token);
    free(bad);
    free(priv);
    free(pub);
    return rc;
}

int main(int argc, char **argv)
{
    if (argc > 1 && strcmp(argv[1], "--version") == 0) {
        printf("jwt-l7-harness (libjwt)\n");
        return 0;
    }
    if (test_alg(JWT_ALG_RS256, "rs256", 1) != 0)
        return 1;
    if (test_alg(JWT_ALG_ES256, "es256", 0) != 0)
        return 1;
    return 0;
}
