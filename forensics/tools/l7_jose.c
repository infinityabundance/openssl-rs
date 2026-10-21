/*
 * Phase-25 L7 workload for the library-only `libjose` (jose) family.
 *
 * jose ships no executable of its own. This program generates an ES256 JWK
 * in-process, signs a payload with jose_jws_sig, verifies the JWS with the
 * same JWK, and then requires a second, freshly generated key to be rejected
 * by jose_jws_ver.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include <jose/jose.h>
#include <jansson.h>

#include <stdio.h>
#include <string.h>

static const char PAYLOAD[] = "phase25-l7-jose-payload";

int main(int argc, char **argv)
{
    json_t *jwk = NULL, *other = NULL, *jws = NULL;
    int rc = 1;

    if (argc > 1 && strcmp(argv[1], "--version") == 0) {
        printf("jose-l7-harness (libjose)\n");
        return 0;
    }

    jwk = json_pack("{s:s}", "alg", "ES256");
    other = json_pack("{s:s}", "alg", "ES256");
    jws = json_pack("{s:s}", "payload", PAYLOAD);
    if (jwk == NULL || other == NULL || jws == NULL)
        goto out;
    if (!jose_jwk_gen(NULL, jwk) || !jose_jwk_gen(NULL, other))
        goto out;
    if (!jose_jws_sig(NULL, jws, NULL, jwk))
        goto out;
    if (!jose_jws_ver(NULL, jws, NULL, jwk, false)) {
        fprintf(stderr, "libjose: the signed JWS did not verify with its own key\n");
        goto out;
    }
    if (jose_jws_ver(NULL, jws, NULL, other, false)) {
        fprintf(stderr, "libjose: the wrong key verified the JWS\n");
        goto out;
    }
    printf("jws_sign=ok\njws_verify=ok\nwrong_key=rejected\n");
    rc = 0;
 out:
    json_decref(jwk);
    json_decref(other);
    json_decref(jws);
    return rc;
}
